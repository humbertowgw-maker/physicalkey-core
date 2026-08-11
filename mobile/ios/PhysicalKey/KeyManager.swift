import Foundation
import LocalAuthentication
import Security

/// Manages this phone's P-256 identity: a keypair generated once on first launch,
/// resident in the Secure Enclave, and gated behind Face ID / Touch ID for every use.
///
/// This used to be a software Ed25519 key (Keychain-encrypted, biometry-gated, but not
/// literally inside the secure co-processor) because Apple's Secure Enclave only supports
/// hardware-resident key generation for P-256, not Ed25519/Curve25519 — see git history
/// for that version. The backend verifies P-256/ECDSA-SHA256 signatures for phone
/// identities (`backend/auth/phone-auth.js`, dual-algorithm: still accepts already-
/// registered Ed25519 phones too).
///
/// This deliberately uses the raw Security framework (`SecKeyCreateRandomKey` /
/// `SecKeyCreateSignature`) instead of CryptoKit's `SecureEnclave.P256.Signing.PrivateKey`.
/// That wrapper was tried first and confirmed broken on a real device (iPhone 16 Pro Max,
/// iOS 26.5): key creation succeeded, but every `signature(for:)` call — with a correctly
/// generated key, `.privateKeyUsage` + `.biometryCurrentSet` both set, Face ID enrolled and
/// confirmed available (`canEvaluatePolicy` true), and even after an explicit successful
/// `LAContext.evaluateAccessControl(.useKeySign)` — failed identically every time with
/// `Error Domain=com.apple.LocalAuthentication Code=-1009 "ACL operation is not allowed:
/// 'osgn'"`. A controlled side-by-side test in the same session, on the same device, with
/// the identical access-control flags, showed the raw `SecKeyCreateRandomKey` +
/// `SecKeyCreateSignature` path signing successfully every time — isolating the bug to
/// CryptoKit's wrapper specifically, not the device, the ACL configuration, or Face ID.
enum KeyManagerError: Error, LocalizedError {
    case keychainWrite(OSStatus)
    case keychainRead(OSStatus)
    case keyGeneration(Error)
    case signing(Error)
    case secureEnclaveUnavailable

    var errorDescription: String? {
        switch self {
        case .keychainWrite(let status), .keychainRead(let status):
            switch status {
            case errSecNotAvailable, errSecParam:
                return "Set a passcode and enroll Face ID (or Touch ID) in Settings, then try again."
            case errSecItemNotFound:
                return "No identity has been created on this device yet. Tap Create Identity first."
            case errSecAuthFailed, errSecUserCanceled:
                return "Face ID authentication failed or was canceled."
            default:
                return "Keychain error (code \(status))."
            }
        case .keyGeneration(let error):
            return "Could not generate a Secure Enclave key: \(error.localizedDescription)"
        case .signing(let error):
            return "Face ID authentication failed or was canceled: \(error.localizedDescription)"
        case .secureEnclaveUnavailable:
            return "This device has no Secure Enclave (e.g. the iOS Simulator) — PhysicalKey's identity key requires real hardware."
        }
    }
}

// @unchecked Sendable: every stored property below is a `let` constant (no mutable
// instance state), and all methods either operate on function-local variables or talk to
// the Keychain/LAContext/Security-framework APIs, which are safe for concurrent access on
// their own — this class has nothing that actually needs actor isolation to share safely.
final class KeyManager: @unchecked Sendable {
    static let shared = KeyManager()

    private let keyTag = Data("com.physicalkey.identity.privatekey".utf8)
    private let deviceIdDefaultsKey = "com.physicalkey.identity.deviceId"

    private init() {}

    /// A stable per-install identifier sent as `phoneAttestation.deviceId`. Not a hardware
    /// identifier (Apple doesn't expose one to apps) — a random UUID generated once and
    /// persisted, which is exactly the granularity the backend's trust-on-first-use
    /// registration actually cares about.
    var deviceId: String {
        if let existing = UserDefaults.standard.string(forKey: deviceIdDefaultsKey) {
            return existing
        }
        let fresh = "iphone-\(UUID().uuidString)"
        UserDefaults.standard.set(fresh, forKey: deviceIdDefaultsKey)
        return fresh
    }

    /// True if a P-256 Secure Enclave identity has already been generated for this app.
    /// Existence-only check (no export/decode needed — the key never leaves the Secure
    /// Enclave, so there's no "wrong format" case to guard against the way the old
    /// CryptoKit `dataRepresentation` blob had).
    var hasIdentity: Bool {
        var query = keyQuery()
        query[kSecReturnRef as String] = false
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }

    /// Generates and stores a new identity, replacing any existing one. Call this once,
    /// on first launch (or explicitly if the user wants to reset/re-pair the device) —
    /// re-generating silently would desync from whatever the backend already has
    /// registered for this deviceId, which is rejected as a hijack attempt by design.
    @discardableResult
    func createIdentity() throws -> String {
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            nil
        ) else {
            throw KeyManagerError.keychainWrite(errSecParam)
        }

        SecItemDelete(keyQuery() as CFDictionary) // clear any previous identity first

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: keyTag,
                kSecAttrAccessControl as String: accessControl
            ]
        ]

        var genError: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &genError) else {
            if let genError {
                throw KeyManagerError.keyGeneration(genError.takeRetainedValue() as Error)
            }
            throw KeyManagerError.secureEnclaveUnavailable
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw KeyManagerError.keyGeneration(NSError(domain: "KeyManager", code: -1))
        }
        return try spkiDERBase64(for: publicKey)
    }

    /// Signs `message` with the stored Secure Enclave private key. `SecKeyCreateSignature`
    /// itself prompts Face ID / Touch ID here (per the access control baked in at
    /// `createIdentity()` time). Throws if the user cancels, biometrics fail, or no
    /// identity has been created yet.
    func sign(_ message: String) async throws -> String {
        let context = LAContext()
        context.localizedReason = "Authenticate to PhysicalKey"

        var query = keyQuery()
        query[kSecReturnRef as String] = true
        query[kSecUseAuthenticationContext as String] = context

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let privateKey = result else {
            throw KeyManagerError.keychainRead(status)
        }
        // swiftlint:disable:next force_cast — SecItemCopyMatching with kSecReturnRef on a
        // kSecClassKey query always returns a SecKey; there's no other CF type it could be.
        let secKey = privateKey as! SecKey

        var signError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            secKey,
            .ecdsaSignatureMessageX962SHA256,
            Data(message.utf8) as CFData,
            &signError
        ) else {
            throw KeyManagerError.signing(signError?.takeRetainedValue() as Error? ?? NSError(domain: "KeyManager", code: -1))
        }
        // Node's `crypto.sign`/`crypto.verify` default `dsaEncoding` is DER, matching what
        // ecdsaSignatureMessageX962SHA256 produces — no format negotiation needed backend-side.
        return (signature as Data).base64EncodedString()
    }

    /// Public key for the currently stored identity, if any. Reading the public key doesn't
    /// require biometrics — only signing with the private half does.
    func currentPublicKeyB64() async throws -> String {
        var query = keyQuery()
        query[kSecReturnRef as String] = true

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let privateKey = result else {
            throw KeyManagerError.keychainRead(status)
        }
        let secKey = privateKey as! SecKey

        guard let publicKey = SecKeyCopyPublicKey(secKey) else {
            throw KeyManagerError.keychainRead(errSecParam)
        }
        return try spkiDERBase64(for: publicKey)
    }

    /// `SecKeyCopyExternalRepresentation` on an EC public key returns the raw X9.62 point
    /// (0x04 || 32-byte X || 32-byte Y, 65 bytes for P-256) — not SPKI DER the way
    /// CryptoKit's `derRepresentation` was. The backend's `crypto.createPublicKey({type:
    /// 'spki', format: 'der'})` expects full SPKI DER, so the fixed RFC 5480 header for
    /// id-ecPublicKey / prime256v1 is prepended by hand here — a well-known, constant
    /// 26-byte prefix, the same one CryptoKit was generating under the hood.
    private func spkiDERBase64(for publicKey: SecKey) throws -> String {
        var error: Unmanaged<CFError>?
        guard let rawPoint = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw KeyManagerError.keyGeneration(error?.takeRetainedValue() as Error? ?? NSError(domain: "KeyManager", code: -1))
        }
        return Self.p256SPKIDER(fromRawPoint: rawPoint).base64EncodedString()
    }

    /// Pure byte-manipulation half of `spkiDERBase64`, split out so it's testable without a
    /// real Secure Enclave (the Simulator has none) — feed it a real X9.62 point from any
    /// EC key and check the result actually imports as a valid P-256 SPKI public key, not
    /// just that the bytes look plausible. Getting this header wrong is exactly the kind of
    /// silent bug that would make every phone signature fail backend verification, the same
    /// failure shape this class's own header comment describes debugging once already.
    static func p256SPKIDER(fromRawPoint rawPoint: Data) -> Data {
        let p256SPKIHeader: [UInt8] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
        ]
        return Data(p256SPKIHeader) + rawPoint
    }

    private func keyQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ]
    }
}
