import Foundation
import CryptoKit

// Proves that Swift's CryptoKit Curve25519.Signing (Ed25519) can produce keys and
// signatures the PhysicalKey backend (Node's node:crypto, also Ed25519) actually accepts.
// This is the one piece of the iOS app that's genuinely risky to get right blind — the
// backend expects an SPKI DER-wrapped public key and a raw 64-byte Ed25519 signature over
// the exact UTF-8 bytes of the challenge string. Everything here runs against the live
// production backend, not a mock.

let baseURL = ProcessInfo.processInfo.environment["PK_BASE_URL"] ?? "https://physicalkey-core-production.up.railway.app"

// Ed25519 SubjectPublicKeyInfo DER has no algorithm parameters, so its ASN.1 prefix is
// fixed and identical for every Ed25519 key — this is the same 12-byte header Node
// produces via `publicKey.export({type:'spki', format:'der'})`, confirmed by decoding the
// base64 keys the backend's own scripts/keygen.js generates (they all start with the same
// "MCowBQYDK2VwAyEA" when base64-encoded, which decodes to exactly this prefix).
let ed25519SPKIPrefix: [UInt8] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
]

func spkiDERBase64(for publicKey: Curve25519.Signing.PublicKey) -> String {
    let der = Data(ed25519SPKIPrefix) + publicKey.rawRepresentation
    return der.base64EncodedString()
}

struct Identity {
    let privateKey: Curve25519.Signing.PrivateKey
    let publicKeyB64: String
    let id: String

    init(idPrefix: String) {
        self.privateKey = Curve25519.Signing.PrivateKey()
        self.publicKeyB64 = spkiDERBase64(for: privateKey.publicKey)
        self.id = "\(idPrefix)-\(Int.random(in: 100000...999999))"
    }

    func sign(_ message: String) throws -> String {
        let signature = try privateKey.signature(for: Data(message.utf8))
        return signature.base64EncodedString()
    }
}

func postJSON(_ path: String, body: [String: Any]) throws -> (Int, [String: Any]) {
    let url = URL(string: baseURL + path)!
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpBody = try JSONSerialization.data(withJSONObject: body)

    let semaphore = DispatchSemaphore(value: 0)
    var resultStatus = 0
    var resultBody: [String: Any] = [:]
    var resultError: Error?

    let task = URLSession.shared.dataTask(with: request) { data, response, error in
        defer { semaphore.signal() }
        if let error = error {
            resultError = error
            return
        }
        resultStatus = (response as? HTTPURLResponse)?.statusCode ?? 0
        if let data = data, let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            resultBody = json
        }
    }
    task.resume()
    semaphore.wait()

    if let resultError = resultError { throw resultError }
    return (resultStatus, resultBody)
}

func getJSON(_ path: String, bearer: String) throws -> (Int, [String: Any]) {
    let url = URL(string: baseURL + path)!
    var request = URLRequest(url: url)
    request.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization")

    let semaphore = DispatchSemaphore(value: 0)
    var resultStatus = 0
    var resultBody: [String: Any] = [:]
    var resultError: Error?

    let task = URLSession.shared.dataTask(with: request) { data, response, error in
        defer { semaphore.signal() }
        if let error = error {
            resultError = error
            return
        }
        resultStatus = (response as? HTTPURLResponse)?.statusCode ?? 0
        if let data = data, let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            resultBody = json
        }
    }
    task.resume()
    semaphore.wait()

    if let resultError = resultError { throw resultError }
    return (resultStatus, resultBody)
}

func fail(_ message: String) -> Never {
    print("\nFAILED: \(message)")
    exit(1)
}

print("Testing Swift CryptoKit <-> PhysicalKey backend Ed25519 interop against \(baseURL)\n")

let phone = Identity(idPrefix: "swift-phone")
let device = Identity(idPrefix: "swift-device")

print("=== Phone challenge ===")
let (challengeStatus, challengeBody) = try postJSON("/auth/phone/challenge", body: [
    "phoneAttestation": [
        "platform": "iOS",
        "deviceId": phone.id,
        "imei": "352657092923456",
        "bundleId": "com.physicalkey.app",
        "publicKey": phone.publicKeyB64
    ]
])
print(challengeStatus, challengeBody)
guard challengeStatus == 200,
      let challengeId = challengeBody["challengeId"] as? String,
      let challenge = challengeBody["challenge"] as? String else {
    fail("phone challenge did not return 200 with challengeId/challenge")
}

print("\n=== Phone verify (signed with Swift CryptoKit Ed25519 key) ===")
let phoneSignature = try phone.sign(challenge)
let (verifyStatus, verifyBody) = try postJSON("/auth/phone/verify", body: [
    "challengeId": challengeId,
    "phoneSignature": phoneSignature
])
print(verifyStatus, verifyBody)
guard verifyStatus == 200,
      let deviceChallengeId = verifyBody["deviceChallengeId"] as? String,
      let deviceChallenge = verifyBody["deviceChallenge"] as? String else {
    fail("phone verify did not return 200 — the Node backend rejected a Swift-generated Ed25519 signature")
}

print("\n=== Device verify (also signed with Swift CryptoKit) ===")
let deviceSignature = try device.sign(deviceChallenge)
let (deviceStatus, deviceBody) = try postJSON("/auth/device/verify", body: [
    "deviceChallengeId": deviceChallengeId,
    "deviceSignature": deviceSignature,
    "deviceId": device.id,
    "publicKey": device.publicKeyB64
])
print(deviceStatus, deviceBody)
guard deviceStatus == 200, let sessionToken = deviceBody["sessionToken"] as? String else {
    fail("device verify did not return 200 — the Node backend rejected a Swift-generated Ed25519 signature")
}

print("\n=== Forged signature — MUST be rejected ===")
let (forgedStatus, forgedBody) = try postJSON("/auth/phone/challenge", body: [
    "phoneAttestation": [
        "platform": "iOS",
        "deviceId": "swift-forge-test-\(Int.random(in: 100000...999999))",
        "imei": "352657092923456",
        "bundleId": "com.physicalkey.app",
        "publicKey": phone.publicKeyB64
    ]
])
if let forgedChallengeId = forgedBody["challengeId"] as? String {
    let (rejectedStatus, rejectedBody) = try postJSON("/auth/phone/verify", body: [
        "challengeId": forgedChallengeId,
        "phoneSignature": Data("not-a-real-signature".utf8).base64EncodedString()
    ])
    print(rejectedStatus, rejectedBody)
    if rejectedStatus == 200 { fail("SECURITY BUG: a garbage signature was accepted") }
} else {
    print(forgedStatus, forgedBody)
    fail("could not set up the forged-signature test")
}

print("\n=== Protected endpoint with the session token ===")
let (profileStatus, profileBody) = try getJSON("/api/profile", bearer: sessionToken)
print(profileStatus, profileBody)
guard profileStatus == 200, (profileBody["authenticated"] as? Bool) == true else {
    fail("protected endpoint did not authenticate the session issued from a Swift-signed auth flow")
}

print("\nSwift CryptoKit Ed25519 keys and signatures are fully compatible with the PhysicalKey backend: valid signatures accepted end-to-end (phone -> device -> session -> protected endpoint), forged signature rejected.")
