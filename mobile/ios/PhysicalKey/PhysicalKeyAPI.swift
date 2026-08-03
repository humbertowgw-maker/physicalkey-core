import Foundation

/// Thin async/await client for the PhysicalKey backend's phone-auth endpoints.
/// See backend/server.js for the source of truth on request/response shapes.
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

    func phoneVerify(challengeId: String, signature: String) async throws -> PhoneVerifyResponse {
        try await post("/auth/phone/verify", body: [
            "challengeId": challengeId,
            "phoneSignature": signature
        ])
    }

    /// NOT YET WIRED TO REAL HARDWARE. There is no IoT key fob built yet (see
    /// hardware/README in the original project docs) — this call needs a Bluetooth
    /// handshake with the physical device to obtain `deviceId` and a signature from
    /// *its* key, not the phone's. Left here so the shape of the call is right and the
    /// rest of the auth flow can be wired up and tested, but do not treat a successful
    /// call here as "the device stage is real" — it isn't, until real hardware exists.
    func deviceVerify(deviceChallengeId: String, deviceSignature: String, deviceId: String, publicKeyB64: String?) async throws -> DeviceVerifyResponse {
        var body: [String: Any] = [
            "deviceChallengeId": deviceChallengeId,
            "deviceSignature": deviceSignature,
            "deviceId": deviceId
        ]
        if let publicKeyB64 { body["publicKey"] = publicKeyB64 }
        return try await post("/auth/device/verify", body: body)
    }

    func profile(sessionToken: String) async throws -> ProfileResponse {
        try await get("/api/profile", bearer: sessionToken)
    }

    private func post<T: Decodable>(_ path: String, body: [String: Any]) async throws -> T {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await URLSession.shared.data(for: request)
        return try decode(data: data, response: response)
    }

    private func get<T: Decodable>(_ path: String, bearer: String) async throws -> T {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
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
