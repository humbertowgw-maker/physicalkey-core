import Foundation
import CryptoKit
import LocalAuthentication
import Security

/// Manages this phone's P-256 identity: a keypair generated once on first launch,
/// resident in the Secure Enclave, and gated behind Face ID / Touch ID for every use.
///
/// This used to be a software Ed25519 key (Keychain-encrypted, biometry-gated, but not
/// literally inside the secure co-processor) because Apple's Secure Enclave only supports
/// hardware-resident key generation for P-256, not Ed25519/Curve25519 — see git history
/// for that version. The backend now verifies P-256/ECDSA-SHA256 signatures for phone
/// identities (`backend/auth/phone-auth.js`, dual-algorithm: still accepts already-
/// registered Ed25519 phones too), so this can use `SecureEnclave.P256.Signing.PrivateKey`
/// for a real hardware-residency guarantee instead of the weaker software-key one.
///
/// `dataRepresentation` (stored in the Keychain below) is an opaque, SE-wrapped reference,
/// not raw key material — Apple's own guidance is that it doesn't need its own Keychain
/// access control on top, since the actual gate is the access control baked into the SE
/// key itself at creation time, enforced by the Secure Enclave when `signature(for:)` is
/// called. Adding a second Keychain-level biometric gate on top would double-prompt Face
/// ID for no real security gain.
enum KeyManagerError: Error, LocalizedError {
    case keychainWrite(OSStatus)
    case keychainRead(OSStatus)
    case biometricsUnavailable(Error)
    case secureEnclaveUnavailable

    /// Maps the handful of OSStatus codes actually reachable from this file's Keychain
    /// calls to plain-language explanations. `errSecNotAvailable` on write is specifically
    /// what this app's `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` +
    /// `.biometryCurrentSet` access control returns when the device has no passcode set —
    /// confirmed against a real device in this state, not a guess (an earlier version of
    /// this mapping assumed `errSecParam` for this case, which was wrong). `errSecParam` is
    /// kept mapped to the same message since some iOS versions reportedly return that
    /// instead — better to over-match than fall through to a raw code for the single most
    /// common first-run failure.
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
        case .biometricsUnavailable:
            return "Face ID / Touch ID isn't available on this device. Set it up in Settings, then try again."
        case .secureEnclaveUnavailable:
            return "This device has no Secure Enclave (e.g. the iOS Simulator) — PhysicalKey's identity key requires real hardware."
        }
    }
}

// @unchecked Sendable: every stored property below is a `let` constant (no mutable
// instance state), and all methods either operate on function-local variables or talk to
// the Keychain/LAContext/SecureEnclave APIs, which are safe for concurrent access on their
// own — this class has nothing that actually needs actor isolation to share safely.
final class KeyManager: @unchecked Sendable {
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

    /// P-256 public keys carry their own X.509 SubjectPublicKeyInfo encoder in CryptoKit
    /// (unlike Curve25519, which only exposes raw bytes) — no hand-rolled prefix constant
    /// needed here. Confirmed to match what the backend's `crypto.createPublicKey({type:
    /// 'spki', format: 'der'})` expects: both follow the same RFC 5480 encoding for
    /// id-ecPublicKey / prime256v1.
    private func spkiDERBase64(for publicKey: P256.Signing.PublicKey) -> String {
        publicKey.derRepresentation.base64EncodedString()
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
        guard SecureEnclave.isAvailable else {
            throw KeyManagerError.secureEnclaveUnavailable
        }

        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            .biometryCurrentSet,
            nil
        ) else {
            throw KeyManagerError.keychainWrite(errSecParam)
        }

        let privateKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl)
        let publicKeyB64 = spkiDERBase64(for: privateKey.publicKey)

        var query = baseQuery()
        query[kSecValueData as String] = privateKey.dataRepresentation

        SecItemDelete(baseQuery() as CFDictionary) // clear any previous identity first
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeyManagerError.keychainWrite(status)
        }

        return publicKeyB64
    }

    /// Signs `message` with the stored Secure Enclave private key. The Secure Enclave
    /// itself prompts Face ID / Touch ID here (per the access control baked in at
    /// `createIdentity()` time) — no separate Keychain-level biometric read happens first.
    /// Throws if the user cancels, biometrics fail, or no identity has been created yet.
    func sign(_ message: String) async throws -> String {
        var query = baseQuery()
        query[kSecReturnData as String] = true

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let keyData = result as? Data else {
            throw KeyManagerError.keychainRead(status)
        }

        let context = LAContext()
        context.localizedReason = "Authenticate to PhysicalKey"
        let privateKey = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: keyData,
            authenticationContext: context
        )
        let signature = try privateKey.signature(for: Data(message.utf8))
        // DER is Node's `crypto.sign`/`crypto.verify` default encoding for EC signatures
        // (the `dsaEncoding` option defaults to `'der'`), so sending derRepresentation
        // here needs no format negotiation on the backend side.
        return signature.derRepresentation.base64EncodedString()
    }

    /// Public key for the currently stored identity, if any. Reconstructing the
    /// SecureEnclave key from its stored dataRepresentation just to read the public half
    /// doesn't require biometrics — CryptoKit doesn't gate deriving a public key, only
    /// signing with the private one.
    func currentPublicKeyB64() async throws -> String {
        var query = baseQuery()
        query[kSecReturnData as String] = true

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let keyData = result as? Data else {
            throw KeyManagerError.keychainRead(status)
        }

        let privateKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyData)
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
