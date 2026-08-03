import Foundation
import SwiftUI

@MainActor
final class AuthViewModel: ObservableObject {
    enum Stage: Equatable {
        case notReady
        case ready
        case phoneVerifying
        case phoneVerified(deviceChallengeId: String) // waiting on real hardware for the device stage
        case failed(String)
    }

    @Published private(set) var stage: Stage = .notReady
    @Published private(set) var lastLog: [String] = []

    private let api = PhysicalKeyAPI(baseURL: URL(string: "https://physicalkey-core-production.up.railway.app")!)
    private let keyManager = KeyManager.shared

    func onAppear() {
        stage = keyManager.hasIdentity ? .ready : .notReady
    }

    func createIdentity() {
        do {
            let publicKey = try keyManager.createIdentity()
            log("Identity created. Public key: \(publicKey.prefix(16))…")
            stage = .ready
        } catch {
            stage = .failed("Could not create identity: \(error)")
        }
    }

    /// Runs the phone half of the auth flow for real: challenge -> Face ID -> sign ->
    /// verify. Stops there — the device stage needs a real IoT key fob talking over
    /// Bluetooth, which doesn't exist yet (see PhysicalKeyAPI.deviceVerify).
    func authenticatePhone() {
        Task {
            stage = .phoneVerifying
            do {
                let publicKey = try await keyManager.currentPublicKeyB64()
                let challenge = try await api.phoneChallenge(deviceId: keyManager.deviceId, publicKeyB64: publicKey)
                log("Got phone challenge: \(challenge.challengeId)")

                let signature = try await keyManager.sign(challenge.challenge)
                log("Signed challenge with Face ID-gated key")

                let verified = try await api.phoneVerify(challengeId: challenge.challengeId, signature: signature)
                log("Phone verified. deviceChallengeId: \(verified.deviceChallengeId)")

                stage = .phoneVerified(deviceChallengeId: verified.deviceChallengeId)
            } catch {
                log("Phone auth failed: \(error)")
                stage = .failed("\(error)")
            }
        }
    }

    private func log(_ message: String) {
        lastLog.append(message)
    }
}
