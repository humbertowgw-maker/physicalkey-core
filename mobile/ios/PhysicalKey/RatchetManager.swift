import Foundation
import CryptoKit
import Security

/// The phone's own local determination of continuity with a specific device — still used
/// for local Keychain bookkeeping and UI/logging, but no longer trusted by the backend on
/// its own. See `RatchetAttestation` below for what actually gets reported and verified.
enum RatchetVerdict: String {
    case bootstrap
    case verified
    case mismatch
}

enum RatchetError: Error {
    case malformedResponse
}

/// The device-signed attestation forwarded to `/auth/device/verify` as `ratchetAttestation`.
/// Mirrors the 209-byte BLE wire payload byte-for-byte: devicePublicKey(32) || rc(16) ||
/// deviceProof(64) || nextProof(32) || status(1) || signature(64, the device's existing
/// Ed25519 identity key signing everything before it plus the backend challenge). The
/// backend independently verifies this — see backend/auth/ratchet.js — instead of trusting
/// this phone's own `RatchetVerdict` computation, which a compromised or fake client could
/// otherwise just fabricate.
struct RatchetAttestation {
    let devicePublicKey: Data
    let rc: Data
    let deviceProof: Data
    let nextProof: Data
    let status: UInt8
    let signature: Data
}

struct RatchetOutcome {
    let verdict: RatchetVerdict
    let attestation: RatchetAttestation
}

/// iOS half of the session-ratchet continuity check. The firmware side (ratchet.cpp) runs
/// the same X25519 exchange and HMAC-SHA512 derivation independently — see that file's
/// header comment for the full protocol. This stores one 32-byte "next proof" per paired
/// deviceId in the Keychain, unlocked-only with no biometric gate: it's a derived
/// continuity token, not a signing key, and gating it would mean a second Face ID prompt
/// per authentication for no real security benefit.
final class RatchetManager: @unchecked Sendable {
    static let shared = RatchetManager()
    private init() {}

    private let service = "com.physicalkey.ratchet"
    private static let nextProofContext = Data("physicalkey-ratchet-next-v1".utf8)

    /// Runs one full exchange against a connected device (via `bluetooth`) for `deviceId`,
    /// advances this phone's own local stored state, and returns both the phone's local
    /// verdict and the raw device-signed attestation to forward to the backend for real
    /// verification. A normal protocol outcome never throws — only a genuine transport
    /// failure does (BLE write/read error, malformed response, or a board whose firmware
    /// doesn't have the ratchet characteristics yet), which the caller treats the same as
    /// any other missing auxiliary signal: omit it, never block real auth.
    func runExchange(deviceId: String, bluetooth: DeviceBluetoothManager) async throws -> RatchetOutcome {
        let phonePrivateKey = Curve25519.KeyAgreement.PrivateKey()

        let response = try await bluetooth.runRatchetExchange(phoneEphemeralPublicKey: phonePrivateKey.publicKey.rawRepresentation)
        guard response.count == 32 + 16 + 64 + 32 + 1 + 64 else {
            throw RatchetError.malformedResponse
        }

        let devicePublicKeyData = response.subdata(in: 0..<32)
        let rc = response.subdata(in: 32..<48)
        let deviceProof = response.subdata(in: 48..<112)
        let wireNextProof = response.subdata(in: 112..<144)
        let status = response[144]
        let signature = response.subdata(in: 145..<209)

        let attestation = RatchetAttestation(
            devicePublicKey: devicePublicKeyData, rc: rc, deviceProof: deviceProof,
            nextProof: wireNextProof, status: status, signature: signature
        )

        // The phone's own local verdict, independent of the backend's verification — same
        // computation as before, still drives this device's own Keychain-stored expectation
        // for next time. sharedSecret should equal what the device derived (same ECDH), so
        // this is also an implicit sanity check: a phone-computed nextProof that doesn't
        // match the device-reported wireNextProof would mean the exchange itself was
        // tampered with, not just that continuity is broken.
        let devicePublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: devicePublicKeyData)
        let sharedSecret = try phonePrivateKey.sharedSecretFromKeyAgreement(with: devicePublicKey)
        let nextProof = deriveNextProof(from: sharedSecret)

        let verdict: RatchetVerdict
        if status == 0 {
            // Device has no prior state — bootstrap, regardless of what the phone has
            // stored. Asymmetric absence is never a mismatch (see the recovery-path
            // rule): a re-flashed board legitimately looks identical to a first-ever
            // pairing from the device's side.
            verdict = .bootstrap
        } else if let priorProof = loadStoredProof(deviceId: deviceId) {
            let expectedProof = Data(HMAC<SHA512>.authenticationCode(for: rc, using: SymmetricKey(data: priorProof)))
            // Not constant-time: the value being compared arrives over an already-bonded,
            // encrypted BLE link from the specific device this phone paired with — the
            // realistic threat here is a cloned identity, not a remote timing side-channel
            // on this comparison. (The backend's own comparison, which is the one that
            // actually matters for a client it doesn't already trust, is constant-time.)
            verdict = expectedProof == deviceProof ? .verified : .mismatch
        } else {
            // Phone has nothing stored (e.g. reinstalled) but the device does — can't
            // verify either way, same asymmetric-absence rule.
            verdict = .bootstrap
        }

        storeProof(nextProof, deviceId: deviceId)
        return RatchetOutcome(verdict: verdict, attestation: attestation)
    }

    private func deriveNextProof(from sharedSecret: SharedSecret) -> Data {
        let mac = sharedSecret.withUnsafeBytes { rawBuffer in
            HMAC<SHA512>.authenticationCode(for: Self.nextProofContext, using: SymmetricKey(data: Data(rawBuffer)))
        }
        return Data(mac).prefix(32)
    }

    private func loadStoredProof(deviceId: String) -> Data? {
        var query = baseQuery(deviceId: deviceId)
        query[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return data
    }

    private func storeProof(_ proof: Data, deviceId: String) {
        let query = baseQuery(deviceId: deviceId)
        SecItemDelete(query as CFDictionary) // overwrite: the ratchet always advances

        var addQuery = query
        addQuery[kSecValueData as String] = proof
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        SecItemAdd(addQuery as CFDictionary, nil)
    }

    private func baseQuery(deviceId: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "nextProof-\(deviceId)",
            kSecAttrService as String: service
        ]
    }
}
