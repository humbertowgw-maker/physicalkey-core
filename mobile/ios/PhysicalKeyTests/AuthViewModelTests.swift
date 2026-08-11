import XCTest
import CoreBluetooth
@testable import PhysicalKey

@MainActor
final class AuthViewModelStageEqualityTests: XCTestCase {

    private func creds(username: String = "device-a", expiresAt: Double = 100) -> PhysicalKeyAPI.GitCredentials {
        PhysicalKeyAPI.GitCredentials(
            username: username, password: "pw", scope: "read_write",
            repositories: ["physicalkey-core"], createdAt: 0, expiresAt: expiresAt
        )
    }

    func testAuthenticatedStagesWithIdenticalPayloadsAreEqual() {
        let a: AuthViewModel.Stage = .authenticated(sessionToken: "tok", gitCredentials: creds())
        let b: AuthViewModel.Stage = .authenticated(sessionToken: "tok", gitCredentials: creds())
        XCTAssertEqual(a, b)
    }

    func testAuthenticatedStagesWithDifferentSessionTokensAreNotEqual() {
        let a: AuthViewModel.Stage = .authenticated(sessionToken: "tok-1", gitCredentials: creds())
        let b: AuthViewModel.Stage = .authenticated(sessionToken: "tok-2", gitCredentials: creds())
        XCTAssertNotEqual(a, b)
    }

    func testAuthenticatedStagesWithDifferentCredentialsAreNotEqual() {
        // Guards against a shallow Equatable that only compares sessionToken and ignores
        // the nested gitCredentials payload entirely.
        let a: AuthViewModel.Stage = .authenticated(sessionToken: "tok", gitCredentials: creds(username: "device-a"))
        let b: AuthViewModel.Stage = .authenticated(sessionToken: "tok", gitCredentials: creds(username: "device-b"))
        XCTAssertNotEqual(a, b)
    }

    func testDifferentStageCasesAreNeverEqualEvenWithOverlappingData() {
        XCTAssertNotEqual(AuthViewModel.Stage.notReady, AuthViewModel.Stage.ready)
        XCTAssertNotEqual(AuthViewModel.Stage.connectingToDevice, AuthViewModel.Stage.repairing)
        XCTAssertEqual(AuthViewModel.Stage.failed("same message"), AuthViewModel.Stage.failed("same message"))
        XCTAssertNotEqual(AuthViewModel.Stage.failed("a"), AuthViewModel.Stage.failed("b"))
    }
}

@MainActor
final class AuthViewModelErrorMessageTests: XCTestCase {

    func testBluetoothPairingMessageFiresOnlyForTheExactPeerRemovedPairingInfoError() {
        let matching = NSError(domain: CBErrorDomain, code: CBError.peerRemovedPairingInformation.rawValue)
        XCTAssertNotNil(AuthViewModel.bluetoothPairingMessage(for: matching))
        XCTAssertTrue(AuthViewModel.bluetoothPairingMessage(for: matching)!.contains("Forget This Device"))

        let wrongCode = NSError(domain: CBErrorDomain, code: CBError.connectionTimeout.rawValue)
        XCTAssertNil(AuthViewModel.bluetoothPairingMessage(for: wrongCode))

        let wrongDomain = NSError(domain: "SomeOtherDomain", code: CBError.peerRemovedPairingInformation.rawValue)
        XCTAssertNil(AuthViewModel.bluetoothPairingMessage(for: wrongDomain))
    }

    func testDescribePrefersTheBluetoothPairingExplanationWhenItApplies() {
        let error = NSError(domain: CBErrorDomain, code: CBError.peerRemovedPairingInformation.rawValue)
        let message = AuthViewModel.describe(error, action: "connect to the key device")
        XCTAssertTrue(message.contains("outdated pairing"))
    }

    func testDescribeUsesLocalizedErrorDescriptionWhenAvailable() {
        let message = AuthViewModel.describe(KeyManagerError.secureEnclaveUnavailable, action: "authenticate")
        XCTAssertEqual(message, "This device has no Secure Enclave (e.g. the iOS Simulator) — PhysicalKey's identity key requires real hardware.")
    }

    func testDescribeFallsBackToAGenericMessageForPlainErrors() {
        // A bare NSError with no LocalizedError conformance and no CoreBluetooth match —
        // this is the "tells the user nothing actionable" case the doc comment warns about,
        // still needs to at least name the action rather than crash or go silent.
        let error = NSError(domain: "Unrecognized", code: 1)
        let message = AuthViewModel.describe(error, action: "authenticate")
        XCTAssertTrue(message.hasPrefix("Could not authenticate:"))
    }
}
