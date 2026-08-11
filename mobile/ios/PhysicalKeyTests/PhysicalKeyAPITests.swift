import XCTest
@testable import PhysicalKey

/// Decode tests use hand-written JSON matching the real backend's response shape (see
/// backend/git/git-credentials.js and backend/server.js's /auth/device/verify handler) —
/// not round-tripped through the same Swift Encodable that wrote it, since that would
/// only catch Swift decoding itself, not a real field-name/type mismatch against what the
/// backend actually sends.
final class PhysicalKeyAPIDecodingTests: XCTestCase {

    func testDecodesARealGitCredentialsResponseFromTheBackend() throws {
        let json = """
        {
          "username": "physicalkey-device-680947e0684c",
          "password": "vfrjAPgwsxCW2ADWqjWe3eZX",
          "scope": "read_write",
          "repositories": ["physicalkey-core"],
          "createdAt": 1786355962469,
          "expiresAt": 1786442362469
        }
        """.data(using: .utf8)!

        let creds = try JSONDecoder().decode(PhysicalKeyAPI.GitCredentials.self, from: json)
        XCTAssertEqual(creds.username, "physicalkey-device-680947e0684c")
        XCTAssertEqual(creds.scope, "read_write")
        XCTAssertEqual(creds.repositories, ["physicalkey-core"])
        XCTAssertEqual(creds.expiresAt, 1786442362469)
    }

    func testGitCredentialsRoundTripsThroughEncodeDecodeUnchanged() throws {
        // Exercises the exact Codable conformance the devicectl debug-export path
        // (AuthViewModel.debugWriteCredentials) depends on.
        let original = PhysicalKeyAPI.GitCredentials(
            username: "device-abc",
            password: "secret123",
            scope: "read_write",
            repositories: ["physicalkey-core"],
            createdAt: 1000,
            expiresAt: 2000
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(PhysicalKeyAPI.GitCredentials.self, from: data)
        XCTAssertEqual(original, decoded)
    }

    func testDecodesARealDeviceVerifyResponseIncludingNestedGitCredentials() throws {
        let json = """
        {
          "status": "verified",
          "sessionToken": "eyJhbGciOiJIUzI1NiJ9.fake.token",
          "gitCredentials": {
            "username": "device-xyz",
            "password": "pw",
            "scope": "read_write",
            "repositories": ["physicalkey-core"],
            "createdAt": 1,
            "expiresAt": 2
          },
          "message": "Device verified. Full access granted."
        }
        """.data(using: .utf8)!

        let response = try JSONDecoder().decode(PhysicalKeyAPI.DeviceVerifyResponse.self, from: json)
        XCTAssertEqual(response.sessionToken, "eyJhbGciOiJIUzI1NiJ9.fake.token")
        XCTAssertEqual(response.gitCredentials.username, "device-xyz")
    }

    func testDecodesARealPhoneChallengeResponse() throws {
        let json = """
        { "challengeId": "abc-123", "challenge": "dGVzdC1jaGFsbGVuZ2U=", "expiresIn": 120 }
        """.data(using: .utf8)!

        let response = try JSONDecoder().decode(PhysicalKeyAPI.PhoneChallengeResponse.self, from: json)
        XCTAssertEqual(response.challengeId, "abc-123")
        XCTAssertEqual(response.expiresIn, 120)
    }

    func testMissingRequiredFieldFailsDecodingRatherThanSilentlyDefaulting() {
        // No `scope` field — every field in GitCredentials is required (no defaults), so
        // this must throw, not silently produce a credential with an empty scope.
        let json = """
        {
          "username": "device-abc",
          "password": "pw",
          "repositories": ["physicalkey-core"],
          "createdAt": 1,
          "expiresAt": 2
        }
        """.data(using: .utf8)!

        XCTAssertThrowsError(try JSONDecoder().decode(PhysicalKeyAPI.GitCredentials.self, from: json))
    }
}
