import Foundation
import SwiftUI

@MainActor
final class AuthViewModel: ObservableObject {
    enum Stage: Equatable {
        case notReady
        case ready
        case phoneVerifying
        case phoneVerified(deviceChallengeId: String, deviceChallenge: String)
        case connectingToDevice
        case authenticated(sessionToken: String)
        case failed(String)
    }

    @Published private(set) var stage: Stage = .notReady
    @Published private(set) var lastLog: [String] = []

    private let api = PhysicalKeyAPI(baseURL: URL(string: "https://physicalkey-core-production.up.railway.app")!)
    private let keyManager = KeyManager.shared
    private let bluetooth = DeviceBluetoothManager()

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

    /// Runs the phone half of the auth flow for real: challenge -> Face ID -> sign -> verify.
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

                stage = .phoneVerified(deviceChallengeId: verified.deviceChallengeId, deviceChallenge: verified.deviceChallenge)
            } catch {
                log("Phone auth failed: \(error)")
                stage = .failed("\(error)")
            }
        }
    }

    /// Runs the device half: scan/connect over Bluetooth to the key fob (see
    /// DeviceBluetoothManager — untested on real hardware, no board exists to pair with
    /// yet), have it sign the device challenge, then finish the backend flow.
    func connectAndAuthenticateDevice() {
        guard case .phoneVerified(let deviceChallengeId, let deviceChallenge) = stage else { return }

        Task {
            stage = .connectingToDevice
            do {
                log("Scanning for PhysicalKey device…")
                let identity = try await bluetooth.connectToDevice()
                log("Connected to \(identity.deviceId)")

                let signature = try await bluetooth.sign(challenge: deviceChallenge)
                log("Device signed the challenge")

                let verified = try await api.deviceVerify(
                    deviceChallengeId: deviceChallengeId,
                    deviceSignature: signature,
                    deviceId: identity.deviceId,
                    publicKeyB64: identity.publicKeyB64
                )
                log("Device verified. Full access granted.")

                bluetooth.disconnect()
                stage = .authenticated(sessionToken: verified.sessionToken)
            } catch {
                log("Device auth failed: \(error)")
                stage = .failed("\(error)")
            }
        }
    }

    private func log(_ message: String) {
        lastLog.append(message)
    }
}
