import Foundation

/// Thin async/await client for the PhysicalKey backend's phone-auth endpoints.
/// See backend/server.js for the source of truth on request/response shapes.
/// @MainActor deliberately: every call site (AuthViewModel, OrganizationViewModel) is
/// already MainActor-isolated, and several endpoints pass [String: Any] JSON bodies (e.g.
/// the liveness result) that aren't Sendable — keeping this on the same actor as its only
/// callers avoids fighting Swift 6's cross-actor sending checks for a boundary that doesn't
/// actually exist in how this type is used.
@MainActor
struct PhysicalKeyAPI {
    let baseURL: URL

    struct PhoneChallengeResponse: Decodable {
        let challengeId: String
        let challenge: String
        let expiresIn: Int
    }

    struct PhoneVerifyResponse: Decodable {
        let status: String
        let deviceChallengeId: String
        let deviceChallenge: String
        let expiresIn: Int
        /// Scoped to org/team management only (`scope: 'phone_session'`, 1h expiry) —
        /// deliberately separate from the full_access sessionToken from deviceVerify,
        /// since managing a team (e.g. revoking someone who left) shouldn't require
        /// having your own physical key device on hand.
        let phoneSessionToken: String
    }

    struct GitCredentials: Decodable {
        let username: String
        let password: String
        let scope: String
        let repositories: [String]
        let createdAt: Double
        let expiresAt: Double
    }

    struct DeviceVerifyResponse: Decodable {
        let status: String
        let sessionToken: String
        let gitCredentials: GitCredentials
        let message: String
    }

    // MARK: - Organizations (Team accounts)
    // See backend/auth/organizations.js for the source of truth. All of these use the
    // phoneSessionToken from phoneVerify, not the full_access sessionToken.

    struct Organization: Decodable {
        let id: String
        let name: String
        let ownerDeviceId: String
        let createdAt: Double
        let status: String

        enum CodingKeys: String, CodingKey {
            case id, name, status
            case ownerDeviceId = "owner_device_id"
            case createdAt = "created_at"
        }
    }

    struct OrgMember: Decodable, Identifiable {
        var id: String { deviceId }
        let deviceId: String
        let role: String
        let addedAt: Double
        let status: String

        enum CodingKeys: String, CodingKey {
            case role, status
            case deviceId = "device_id"
            case addedAt = "added_at"
        }
    }

    struct OrgDevice: Decodable, Identifiable {
        var id: String { deviceId }
        let deviceId: String
        let addedAt: Double

        enum CodingKeys: String, CodingKey {
            case deviceId = "device_id"
            case addedAt = "added_at"
        }
    }

    struct OrgDetail: Decodable {
        let id: String
        let name: String
        let ownerDeviceId: String
        let createdAt: Double
        let status: String
        let members: [OrgMember]
        let devices: [OrgDevice]

        enum CodingKeys: String, CodingKey {
            case id, name, status, members, devices
            case ownerDeviceId = "owner_device_id"
            case createdAt = "created_at"
        }
    }

    struct DeviceAccessGrant: Decodable, Identifiable {
        var id: String { memberDeviceId }
        let memberDeviceId: String
        let grantedAt: Double

        enum CodingKeys: String, CodingKey {
            case memberDeviceId = "member_device_id"
            case grantedAt = "granted_at"
        }
    }

    private struct StatusResponse: Decodable { let status: String }

    func createOrg(name: String, phoneSessionToken: String) async throws -> Organization {
        try await post("/orgs", body: ["name": name], bearer: phoneSessionToken)
    }

    func getOrg(orgId: String, phoneSessionToken: String) async throws -> OrgDetail {
        try await get("/orgs/\(orgId)", bearer: phoneSessionToken)
    }

    @discardableResult
    func addMember(orgId: String, deviceId: String, role: String?, phoneSessionToken: String) async throws -> OrgMember {
        var body: [String: Any] = ["deviceId": deviceId]
        if let role { body["role"] = role }
        return try await post("/orgs/\(orgId)/members", body: body, bearer: phoneSessionToken)
    }

    func removeMember(orgId: String, deviceId: String, phoneSessionToken: String) async throws {
        let _: OrgMember = try await delete("/orgs/\(orgId)/members/\(deviceId)", bearer: phoneSessionToken)
    }

    @discardableResult
    func claimDevice(orgId: String, deviceId: String, phoneSessionToken: String) async throws -> OrgDevice {
        try await post("/orgs/\(orgId)/devices", body: ["deviceId": deviceId], bearer: phoneSessionToken)
    }

    func releaseDevice(orgId: String, deviceId: String, phoneSessionToken: String) async throws {
        let _: OrgDevice = try await delete("/orgs/\(orgId)/devices/\(deviceId)", bearer: phoneSessionToken)
    }

    func listDeviceAccess(orgId: String, deviceId: String, phoneSessionToken: String) async throws -> [DeviceAccessGrant] {
        try await get("/orgs/\(orgId)/devices/\(deviceId)/access", bearer: phoneSessionToken)
    }

    func grantDeviceAccess(orgId: String, deviceId: String, memberDeviceId: String, phoneSessionToken: String) async throws {
        let _: StatusResponse = try await post(
            "/orgs/\(orgId)/devices/\(deviceId)/access",
            body: ["memberDeviceId": memberDeviceId],
            bearer: phoneSessionToken
        )
    }

    func revokeDeviceAccess(orgId: String, deviceId: String, memberDeviceId: String, phoneSessionToken: String) async throws {
        let _: StatusResponse = try await delete("/orgs/\(orgId)/devices/\(deviceId)/access/\(memberDeviceId)", bearer: phoneSessionToken)
    }

    struct ProfileResponse: Decodable {
        let deviceId: String
        let authenticated: Bool
        let access: String
        let timestamp: String
    }

    struct APIError: Decodable, Error {
        let error: String
        let reason: String?
    }

    enum ClientError: Error {
        case unexpectedStatus(Int, Data)
    }

    private let decoder: JSONDecoder = JSONDecoder()
    private let encoder: JSONEncoder = JSONEncoder()

    func phoneChallenge(deviceId: String, publicKeyB64: String?) async throws -> PhoneChallengeResponse {
        var attestation: [String: Any] = [
            "platform": "iOS",
            "deviceId": deviceId,
            "imei": "unavailable-not-provided-by-ios", // iOS apps cannot read the real IMEI; kept only for shape-compatibility with the backend's demo field
            "bundleId": Bundle.main.bundleIdentifier ?? "com.physicalkey.app"
        ]
        if let publicKeyB64 { attestation["publicKey"] = publicKeyB64 }

        return try await post("/auth/phone/challenge", body: ["phoneAttestation": attestation])
    }

    func phoneVerify(challengeId: String, signature: String, livenessResult: [String: Any]? = nil) async throws -> PhoneVerifyResponse {
        var body: [String: Any] = [
            "challengeId": challengeId,
            "phoneSignature": signature
        ]
        if let livenessResult { body["livenessResult"] = livenessResult }
        return try await post("/auth/phone/verify", body: body)
    }

    func deviceVerify(deviceChallengeId: String, deviceSignature: String, deviceId: String, publicKeyB64: String?, ratchetAttestation: RatchetAttestation? = nil) async throws -> DeviceVerifyResponse {
        var body: [String: Any] = [
            "deviceChallengeId": deviceChallengeId,
            "deviceSignature": deviceSignature,
            "deviceId": deviceId
        ]
        if let publicKeyB64 { body["publicKey"] = publicKeyB64 }
        // Field names/shape must match backend/auth/ratchet.js's verifyAndRecordRatchetAttestation
        // exactly — this is the device-signed attestation the backend independently verifies,
        // not a trusted client claim (see RatchetAttestation's doc comment).
        if let ratchetAttestation {
            body["ratchetAttestation"] = [
                "devicePublicKey": ratchetAttestation.devicePublicKey.base64EncodedString(),
                "rc": ratchetAttestation.rc.base64EncodedString(),
                "deviceProof": ratchetAttestation.deviceProof.base64EncodedString(),
                "nextProof": ratchetAttestation.nextProof.base64EncodedString(),
                "status": Int(ratchetAttestation.status),
                "signature": ratchetAttestation.signature.base64EncodedString()
            ]
        }
        return try await post("/auth/device/verify", body: body)
    }

    func profile(sessionToken: String) async throws -> ProfileResponse {
        try await get("/api/profile", bearer: sessionToken)
    }

    private func post<T: Decodable>(_ path: String, body: [String: Any], bearer: String? = nil) async throws -> T {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        if let bearer { request.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization") }

        let (data, response) = try await URLSession.shared.data(for: request)
        return try decode(data: data, response: response)
    }

    private func get<T: Decodable>(_ path: String, bearer: String) async throws -> T {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await URLSession.shared.data(for: request)
        return try decode(data: data, response: response)
    }

    private func delete<T: Decodable>(_ path: String, bearer: String) async throws -> T {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "DELETE"
        request.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await URLSession.shared.data(for: request)
        return try decode(data: data, response: response)
    }

    private func decode<T: Decodable>(data: Data, response: URLResponse) throws -> T {
        let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200...299).contains(statusCode) else {
            if let apiError = try? decoder.decode(APIError.self, from: data) {
                throw apiError
            }
            throw ClientError.unexpectedStatus(statusCode, data)
        }
        return try decoder.decode(T.self, from: data)
    }
}
