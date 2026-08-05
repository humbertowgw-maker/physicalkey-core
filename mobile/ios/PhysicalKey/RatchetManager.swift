import Foundation
import CryptoKit
import Security

/// The phone's determination of continuity with a specific device, reported to the
/// backend as `ratchetStatus` (see backend/auth/ratchet.js — same three values). Only
/// `mismatch` is actually acted on server-side (logged, never blocking); `bootstrap` and
/// `verified` are informational.
enum RatchetVerdict: String {
    case bootstrap
    case verified
    case mismatch
}

enum RatchetError: Error {
    case malformedResponse
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
    /// advances this phone's stored state, and returns the verdict to report to the
    /// backend. A normal protocol outcome (bootstrap/verified/mismatch) never throws —
    /// only a genuine transport failure does (BLE write/read error, or a board whose
    /// firmware doesn't have the ratchet characteristics yet), which the caller treats
    /// the same as any other missing auxiliary signal: omit it, never block real auth.
    func runExchange(deviceId: String, bluetooth: DeviceBluetoothManager) async throws -> RatchetVerdict {
        let phonePrivateKey = Curve25519.KeyAgreement.PrivateKey()

        let response = try await bluetooth.runRatchetExchange(phoneEphemeralPublicKey: phonePrivateKey.publicKey.rawRepresentation)
        guard response.count == 32 + 16 + 64 + 1 else {
            throw RatchetError.malformedResponse
        }

        let devicePublicKeyData = response.subdata(in: 0..<32)
        let rc = response.subdata(in: 32..<48)
        let deviceProof = response.subdata(in: 48..<112)
        let status = response[112]

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
            // on this comparison.
            verdict = expectedProof == deviceProof ? .verified : .mismatch
        } else {
            // Phone has nothing stored (e.g. reinstalled) but the device does — can't
            // verify either way, same asymmetric-absence rule.
            verdict = .bootstrap
        }

        storeProof(nextProof, deviceId: deviceId)
        return verdict
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
