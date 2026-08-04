import Foundation
import SwiftUI
import CoreBluetooth

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
    /// Set once phone auth succeeds; independent of `stage` (a full device pairing isn't
    /// needed to use it, and it stays valid across further stage transitions until it
    /// expires server-side after 1h). Nil until the first successful phone auth this
    /// session.
    @Published private(set) var phoneSessionToken: String?

    /// This phone's own deviceId, needed for org membership calls — e.g. checking your
    /// own role in an org's member list. Exposed here rather than reaching into
    /// KeyManager directly from other views, matching how the rest of this view model
    /// already brokers access to it.
    var myDeviceId: String { keyManager.deviceId }

    /// Whether an identity currently exists, so the UI can route a `.failed` retry back to
    /// "Create Identity" (if creation itself failed — e.g. no passcode/Face ID set up on
    /// this device) rather than always to "Authenticate", which would just fail again with
    /// a confusing "no such keychain item" error that masks the real problem.
    var hasIdentity: Bool { keyManager.hasIdentity }

    // Not private: TeamView's OrganizationViewModel reuses this same client rather than
    // constructing its own duplicate instance pointed at the same backend.
    let api = PhysicalKeyAPI(baseURL: URL(string: "https://physicalkey-core-production.up.railway.app")!)
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
            stage = .failed(Self.describe(error, action: "create identity"))
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

                phoneSessionToken = verified.phoneSessionToken
                stage = .phoneVerified(deviceChallengeId: verified.deviceChallengeId, deviceChallenge: verified.deviceChallenge)
            } catch {
                log("Phone auth failed: \(error)")
                stage = .failed(Self.describe(error, action: "authenticate"))
            }
        }
    }

    /// Runs the device half: scan/connect over Bluetooth to the key fob (see
    /// DeviceBluetoothManager), have it sign the device challenge, then finish the
    /// backend flow.
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
                stage = .failed(Self.describe(error, action: "connect to the key device"))
            }
        }
    }

    private func log(_ message: String) {
        lastLog.append(message)
    }

    /// Prefers a `LocalizedError`'s human-readable message (e.g. KeyManagerError's Keychain
    /// explanations) over dumping the raw Swift error description, which for something like
    /// `keychainWrite(-50)` tells the user nothing actionable.
    private static func describe(_ error: Error, action: String) -> String {
        if let message = bluetoothPairingMessage(for: error) {
            return message
        }
        if let message = (error as? LocalizedError)?.errorDescription {
            return message
        }
        return "Could not \(action): \(error)"
    }

    /// `CBError.peerRemovedPairingInformation` is CoreBluetooth's specific signal that the
    /// phone has a stored Bluetooth pairing key for this device that the device itself no
    /// longer recognizes (e.g. the device's own key changed since they last paired) — iOS
    /// won't retry pairing on its own in this state. Confirmed against a real device during
    /// testing: the fix is always to forget the stale pairing and reconnect, so tell the
    /// user that directly instead of surfacing the raw CoreBluetooth error code.
    private static func bluetoothPairingMessage(for error: Error) -> String? {
        let nsError = error as NSError
        guard nsError.domain == CBErrorDomain,
              nsError.code == CBError.peerRemovedPairingInformation.rawValue else {
            return nil
        }
        return "This phone has an outdated pairing with this key device. Go to Settings → Bluetooth, tap the (i) next to \"PhysicalKey\", choose \"Forget This Device\", then try connecting again."
    }
}
