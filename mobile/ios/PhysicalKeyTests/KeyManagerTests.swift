import XCTest
import Security
@testable import PhysicalKey

final class KeyManagerSPKITests: XCTestCase {

    /// Generates a real, software EC P-256 key pair (no Secure Enclave required, so this
    /// runs fine in the Simulator — the private key material itself is irrelevant here,
    /// only the public key's raw X9.62 point shape matters).
    private func makeRawP256Point() throws -> Data {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            XCTFail("SecKeyCopyPublicKey unexpectedly returned nil")
            fatalError()
        }
        var exportError: Unmanaged<CFError>?
        guard let rawPoint = SecKeyCopyExternalRepresentation(publicKey, &exportError) as Data? else {
            throw exportError!.takeRetainedValue() as Error
        }
        return rawPoint
    }

    func testRawPointIsThe65ByteX962FormatThisFunctionAssumes() throws {
        // Sanity check on the test's own fixture, not the function under test — if this
        // ever stops being 65 bytes starting with 0x04, every assumption below is invalid.
        let rawPoint = try makeRawP256Point()
        XCTAssertEqual(rawPoint.count, 65, "P-256 X9.62 uncompressed point should be 1 + 32 + 32 bytes")
        XCTAssertEqual(rawPoint.first, 0x04, "expected the uncompressed-point marker byte")
    }

    func testPrependsTheExactRFC5480HeaderForP256() throws {
        let rawPoint = try makeRawP256Point()
        let der = KeyManager.p256SPKIDER(fromRawPoint: rawPoint)

        // The well-known, constant DER encoding of SEQUENCE{ SEQUENCE{ OID id-ecPublicKey,
        // OID prime256v1 }, BIT STRING } up to (not including) the actual key bits — written
        // out here independently from RFC 5480 / SEC1, not copied from the source file under
        // test, so this actually catches a wrong-but-plausible header rather than just
        // re-asserting whatever KeyManager happens to produce.
        let expectedHeader: [UInt8] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
        ]
        XCTAssertEqual(der.count, expectedHeader.count + rawPoint.count)
        XCTAssertEqual(Array(der.prefix(expectedHeader.count)), expectedHeader)
    }

    func testDoesNotMangleTheRawPointDuringConcatenation() throws {
        let rawPoint = try makeRawP256Point()
        let der = KeyManager.p256SPKIDER(fromRawPoint: rawPoint)
        XCTAssertEqual(der.suffix(rawPoint.count), rawPoint, "the original point bytes must survive unchanged, in order")
    }

    func testIsStableAcrossMultipleRealKeysNotJustOneLuckyCase() throws {
        for _ in 0..<10 {
            let rawPoint = try makeRawP256Point()
            let der = KeyManager.p256SPKIDER(fromRawPoint: rawPoint)
            XCTAssertEqual(der.count, 91, "26-byte header + 65-byte P-256 point")
        }
    }
}

final class KeyManagerErrorTests: XCTestCase {

    func testKeychainErrorsMapToActionableMessagesNotRawOSStatusCodes() {
        // These specific mappings are the actual user-facing UX — a regression here means a
        // real person sees "Keychain error (code -25291)" instead of being told to enroll
        // Face ID, which is exactly the kind of thing that's easy to silently break.
        XCTAssertEqual(
            KeyManagerError.keychainWrite(errSecNotAvailable).errorDescription,
            "Set a passcode and enroll Face ID (or Touch ID) in Settings, then try again."
        )
        XCTAssertEqual(
            KeyManagerError.keychainRead(errSecItemNotFound).errorDescription,
            "No identity has been created on this device yet. Tap Create Identity first."
        )
        XCTAssertEqual(
            KeyManagerError.keychainRead(errSecUserCanceled).errorDescription,
            "Face ID authentication failed or was canceled."
        )
    }

    func testUnknownOSStatusFallsBackToACodeRatherThanCrashingOrGoingSilent() {
        let message = KeyManagerError.keychainWrite(-99999).errorDescription
        XCTAssertEqual(message, "Keychain error (code -99999).")
    }

    func testSecureEnclaveUnavailableExplainsWhySimulatorCantCreateAnIdentity() {
        XCTAssertEqual(
            KeyManagerError.secureEnclaveUnavailable.errorDescription,
            "This device has no Secure Enclave (e.g. the iOS Simulator) — PhysicalKey's identity key requires real hardware."
        )
    }
}
