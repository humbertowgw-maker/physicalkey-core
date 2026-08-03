import Foundation
import CryptoKit
import LocalAuthentication
import Security

/// Manages this phone's Ed25519 identity: a keypair generated once on first launch,
/// persisted in the Keychain, and gated behind Face ID / Touch ID for every use.
///
/// NOTE ON SECURE ENCLAVE: Apple's Secure Enclave only supports hardware-resident key
/// generation for P-256 (`SecureEnclave.P256.Signing.PrivateKey`), not Ed25519/Curve25519.
/// The PhysicalKey backend verifies Ed25519 signatures (see backend/auth/phone-auth.js),
/// which was proven to interop correctly with Swift's CryptoKit in
/// mobile/ios-crypto-poc — but that means this key is generated in software and stored in
/// the Keychain with a biometry-gated access control, not literally inside the secure
/// co-processor. It's still encrypted at rest and inaccessible without Face ID / device
/// passcode, but it is a materially weaker guarantee than true Secure Enclave residency.
/// If that distinction matters for this product, the real fix is switching the backend to
/// verify P-256/ECDSA signatures instead of Ed25519 so this can use
/// `SecureEnclave.P256.Signing.PrivateKey` — that's a backend change, not just an app one.
enum KeyManagerError: Error {
    case keychainWrite(OSStatus)
    case keychainRead(OSStatus)
    case biometricsUnavailable(Error)
}

final class KeyManager {
    static let shared = KeyManager()

    private let keyAccount = "com.physicalkey.identity.privatekey"
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

    /// Ed25519 SubjectPublicKeyInfo DER has no algorithm parameters, so this 12-byte
    /// prefix is fixed and identical for every Ed25519 key. Confirmed against what the
    /// backend's own scripts/keygen.js produces (Node's `publicKey.export({type: 'spki',
    /// format: 'der'})`) and verified end-to-end in mobile/ios-crypto-poc.
    private static let ed25519SPKIPrefix: [UInt8] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    ]

    private func spkiDERBase64(for publicKey: Curve25519.Signing.PublicKey) -> String {
        let der = Data(Self.ed25519SPKIPrefix) + publicKey.rawRepresentation
        return der.base64EncodedString()
    }

    /// True if a key has already been generated (i.e. this isn't first launch). Checking
    /// existence doesn't require a biometric prompt; reading the key material does.
    var hasIdentity: Bool {
        var query = baseQuery()
        query[kSecReturnData as String] = false
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    /// Generates and stores a new identity, replacing any existing one. Call this once,
    /// on first launch (or explicitly if the user wants to reset/re-pair the device) —
    /// re-generating silently would desync from whatever the backend already has
    /// registered for this deviceId, which is rejected as a hijack attempt by design.
    @discardableResult
    func createIdentity() throws -> String {
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKeyB64 = spkiDERBase64(for: privateKey.publicKey)

        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            .biometryCurrentSet,
            nil
        ) else {
            throw KeyManagerError.keychainWrite(errSecParam)
        }

        var query = baseQuery()
        query[kSecValueData as String] = privateKey.rawRepresentation
        query[kSecAttrAccessControl as String] = accessControl

        SecItemDelete(baseQuery() as CFDictionary) // clear any previous identity first
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeyManagerError.keychainWrite(status)
        }

        return publicKeyB64
    }

    /// Prompts Face ID / Touch ID, then signs `message` with the stored private key.
    /// Throws if the user cancels, biometrics fail, or no identity has been created yet.
    func sign(_ message: String) async throws -> String {
        let context = LAContext()
        context.localizedReason = "Authenticate to PhysicalKey"

        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecUseAuthenticationContext as String] = context

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let keyData = result as? Data else {
            throw KeyManagerError.keychainRead(status)
        }

        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: keyData)
        let signature = try privateKey.signature(for: Data(message.utf8))
        return signature.base64EncodedString()
    }

    /// Public key for the currently stored identity, if any — does not require biometrics
    /// (public keys aren't secret), but Keychain metadata reads for a key with a biometry
    /// ACL are also restricted, so this still reconstructs from a biometric-gated read
    /// the first time within a session. In practice, cache this after `createIdentity()`.
    func currentPublicKeyB64() async throws -> String {
        let context = LAContext()
        context.localizedReason = "Authenticate to PhysicalKey"

        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecUseAuthenticationContext as String] = context

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let keyData = result as? Data else {
            throw KeyManagerError.keychainRead(status)
        }

        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: keyData)
        return spkiDERBase64(for: privateKey.publicKey)
    }

    private func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keyAccount,
            kSecAttrService as String: "com.physicalkey.app"
        ]
    }
}
