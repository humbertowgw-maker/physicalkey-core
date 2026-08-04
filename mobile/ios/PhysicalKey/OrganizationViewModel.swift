import Foundation
import LocalAuthentication

/// Drives TeamView. The backend (backend/auth/organizations.js) has no "list my orgs"
/// endpoint — GET /orgs/:orgId requires already knowing the ID — so there's no way for
/// the app to discover an org a member was just added to. An owner gets the ID back
/// from createOrg(); a member has to be told it out-of-band (the same way you'd share
/// a room code) and enter it once. This view model persists whichever org ID is known
/// locally so it doesn't need re-entering every launch.
@MainActor
final class OrganizationViewModel: ObservableObject {
    @Published private(set) var org: PhysicalKeyAPI.OrgDetail?
    @Published private(set) var isLoading = false
    @Published var errorMessage: String?

    /// Team/member/device IDs are persistent identifiers tied to a specific phone or
    /// piece of hardware — worth the same shoulder-surf protection as anything else
    /// identity-related in this app, not shown in plaintext until re-confirmed. Gates
    /// the whole team screen for the session rather than per-field, matching how the
    /// rest of the app treats a Face ID confirmation as unlocking access for a while,
    /// not a one-shot per-item check.
    @Published private(set) var isRevealed = false

    /// This device's role in `org`, if it's a member at all — drives which actions the
    /// UI offers (only owner/admin can manage membership or device access).
    var myRole: String? {
        org?.members.first(where: { $0.deviceId == myDeviceId })?.role
    }
    var canManage: Bool { myRole == "owner" || myRole == "admin" }

    private let api: PhysicalKeyAPI
    private let myDeviceId: String
    private var phoneSessionToken: String
    private static let orgIdDefaultsKey = "com.physicalkey.myOrgId"

    init(api: PhysicalKeyAPI, myDeviceId: String, phoneSessionToken: String) {
        self.api = api
        self.myDeviceId = myDeviceId
        self.phoneSessionToken = phoneSessionToken
    }

    /// Call whenever a fresh phoneSessionToken is obtained (e.g. after a new
    /// authenticatePhone() call) — the one this was initialized with may have expired.
    func updateSessionToken(_ token: String) {
        phoneSessionToken = token
    }

    /// Prompts Face ID (or passcode fallback) and reveals IDs on success. A fresh
    /// LAContext each call, independent of KeyManager's Keychain-bound biometric gate —
    /// this isn't protecting a Keychain item, just gating what's on screen, so it uses
    /// LocalAuthentication directly rather than routing through a Keychain read.
    func revealIdentifiers() async {
        let context = LAContext()
        do {
            let success = try await context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: "Authenticate to view team and device IDs"
            )
            if success { isRevealed = true }
        } catch {
            // User cancelled or biometrics failed — stay hidden, no error banner needed
            // for a cancel, that's not a failure worth interrupting them over.
        }
    }

    func hideIdentifiers() {
        isRevealed = false
    }

    func loadKnownOrg() async {
        guard let orgId = UserDefaults.standard.string(forKey: Self.orgIdDefaultsKey) else { return }
        await refresh(orgId: orgId)
    }

    func refresh() async {
        guard let orgId = org?.id ?? UserDefaults.standard.string(forKey: Self.orgIdDefaultsKey) else { return }
        await refresh(orgId: orgId)
    }

    private func refresh(orgId: String) async {
        isLoading = true
        defer { isLoading = false }
        do {
            org = try await api.getOrg(orgId: orgId, phoneSessionToken: phoneSessionToken)
            errorMessage = nil
        } catch {
            errorMessage = Self.describe(error)
        }
    }

    func createOrg(name: String) async {
        isLoading = true
        defer { isLoading = false }
        do {
            let created = try await api.createOrg(name: name, phoneSessionToken: phoneSessionToken)
            UserDefaults.standard.set(created.id, forKey: Self.orgIdDefaultsKey)
            await refresh(orgId: created.id)
        } catch {
            errorMessage = Self.describe(error)
        }
    }

    func joinKnownOrg(orgId: String) async {
        UserDefaults.standard.set(orgId, forKey: Self.orgIdDefaultsKey)
        await refresh(orgId: orgId)
    }

    func addMember(deviceId: String, role: String) async {
        guard let orgId = org?.id else { return }
        do {
            try await api.addMember(orgId: orgId, deviceId: deviceId, role: role, phoneSessionToken: phoneSessionToken)
            await refresh(orgId: orgId)
        } catch {
            errorMessage = Self.describe(error)
        }
    }

    func removeMember(deviceId: String) async {
        guard let orgId = org?.id else { return }
        do {
            try await api.removeMember(orgId: orgId, deviceId: deviceId, phoneSessionToken: phoneSessionToken)
            await refresh(orgId: orgId)
        } catch {
            errorMessage = Self.describe(error)
        }
    }

    /// Scans for a nearby key device over Bluetooth and claims whichever one answers,
    /// rather than asking the user to type in a device ID by hand — nobody has that
    /// memorized, and the app already knows how to discover it (same BLE handshake the
    /// main auth flow uses). A fresh DeviceBluetoothManager per call, not shared with
    /// AuthViewModel's, since this is a one-shot scan-connect-read-disconnect, not a
    /// full auth session.
    func scanAndClaimNearbyDevice() async {
        guard let orgId = org?.id else { return }
        let bluetooth = DeviceBluetoothManager()
        do {
            let identity = try await bluetooth.connectToDevice()
            bluetooth.disconnect()
            try await api.claimDevice(orgId: orgId, deviceId: identity.deviceId, phoneSessionToken: phoneSessionToken)
            await refresh(orgId: orgId)
        } catch {
            bluetooth.disconnect()
            errorMessage = Self.describe(error)
        }
    }

    func releaseDevice(deviceId: String) async {
        guard let orgId = org?.id else { return }
        do {
            try await api.releaseDevice(orgId: orgId, deviceId: deviceId, phoneSessionToken: phoneSessionToken)
            await refresh(orgId: orgId)
        } catch {
            errorMessage = Self.describe(error)
        }
    }

    func listDeviceAccess(deviceId: String) async -> [PhysicalKeyAPI.DeviceAccessGrant] {
        guard let orgId = org?.id else { return [] }
        do {
            return try await api.listDeviceAccess(orgId: orgId, deviceId: deviceId, phoneSessionToken: phoneSessionToken)
        } catch {
            errorMessage = Self.describe(error)
            return []
        }
    }

    func grantDeviceAccess(deviceId: String, memberDeviceId: String) async {
        guard let orgId = org?.id else { return }
        do {
            try await api.grantDeviceAccess(orgId: orgId, deviceId: deviceId, memberDeviceId: memberDeviceId, phoneSessionToken: phoneSessionToken)
        } catch {
            errorMessage = Self.describe(error)
        }
    }

    func revokeDeviceAccess(deviceId: String, memberDeviceId: String) async {
        guard let orgId = org?.id else { return }
        do {
            try await api.revokeDeviceAccess(orgId: orgId, deviceId: deviceId, memberDeviceId: memberDeviceId, phoneSessionToken: phoneSessionToken)
        } catch {
            errorMessage = Self.describe(error)
        }
    }

    private static func describe(_ error: Error) -> String {
        if let apiError = error as? PhysicalKeyAPI.APIError {
            return apiError.error
        }
        return "\(error)"
    }
}
