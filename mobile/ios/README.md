# PhysicalKey iOS App

## What's actually real here

- **`../ios-crypto-poc/`** — a standalone Swift command-line tool that generates a real
  Ed25519 keypair with Apple's `CryptoKit`, wraps the public key in the SPKI DER format the
  backend expects, and runs the **full phone → device → session → protected-endpoint auth
  flow against the live production backend**
  (`https://physicalkey-core-production.up.railway.app`), including a forged-signature
  rejection check. This actually ran and passed — see the conversation history, or run it
  again yourself:
  ```bash
  cd mobile/ios-crypto-poc
  swift run
  ```
  This is the one piece of the app that was genuinely risky to get right without a real
  device to test on (cross-language Ed25519 signature compatibility), and it's proven.

- **`PhysicalKey/*.swift`** — the actual app source: `PhysicalKeyApp.swift` (SwiftUI entry
  point), `ContentView.swift` (UI), `AuthViewModel.swift` (orchestration), `KeyManager.swift`
  (Keychain-backed identity, Face ID-gated), `PhysicalKeyAPI.swift` (networking client). All
  five files type-check cleanly with the Swift compiler (`swiftc -typecheck`), using the same
  proven crypto approach as the PoC.

## What's NOT real / not done

- **No Xcode project.** I don't have Xcode installed on this machine — only the Command
  Line Tools (enough to run `swift build`/`swiftc -typecheck`, not enough to build or run an
  actual iOS app, which needs the iOS SDK, a simulator or device, code signing, etc.). See
  "Getting this running" below for the ~5-minute manual step to fix that.
- **The device (IoT key fob) stage is stubbed, not implemented.** `PhysicalKeyAPI.deviceVerify()`
  has the right shape to call the backend, but there's no real key fob yet — the whole
  point of the device stage is that it's a *second*, physically separate piece of hardware
  signing with *its own* key over Bluetooth. The app UI (`AuthViewModel.authenticatePhone()`)
  intentionally stops after the phone stage succeeds and shows "waiting on IoT key device"
  rather than faking it. This can't be finished until the hardware exists.
  No Bluetooth code has been written at all yet.
- **Not literally Secure Enclave-resident.** The phone's private key is Ed25519, generated
  in software and stored in the Keychain with a biometry access-control flag
  (`.biometryCurrentSet`) — encrypted at rest, inaccessible without Face ID/passcode, but
  not living inside the secure co-processor the way a Secure Enclave key does. That's
  because Apple's Secure Enclave only supports hardware-resident generation for P-256 keys,
  and the backend currently verifies Ed25519. See the comment at the top of
  `KeyManager.swift` for the tradeoff and what switching to true Secure Enclave residency
  would require (a backend change to verify P-256/ECDSA instead).
- **No real IMEI, no Apple App Attest, no Google Play Integrity.** iOS apps can't read the
  device's real IMEI (that field is sent as a placeholder string purely for shape-compatibility
  with the backend's demo `phoneAttestation` structure), and this doesn't call Apple's actual
  App Attest API. That's a materially larger integration (requires a paid Apple Developer
  account, DeviceCheck entitlement, and Apple's own attestation servers) — this app proves
  identity via the Keychain + Face ID + Ed25519 signature instead, which is real
  cryptographic proof-of-possession, just not Apple's specific attestation service.

## Getting this running (steps only you can do — need Xcode)

1. Install Xcode from the App Store (not just Command Line Tools).
2. `File > New > Project > iOS > App`, name it `PhysicalKey`, interface: SwiftUI, language: Swift.
3. Delete the auto-generated `ContentView.swift` and `PhysicalKeyApp.swift` Xcode creates,
   and drag the 5 files from `mobile/ios/PhysicalKey/` into the project instead (check
   "Copy items if needed").
4. In the target's **Signing & Capabilities**: set your own Team (needs an Apple ID at
   minimum for local device testing; a paid Developer account only if you want to
   distribute via TestFlight/App Store).
5. In the target's **Info** tab, add key `Privacy - Face ID Usage Description`
   (`NSFaceIDUsageDescription`) with a value like "PhysicalKey uses Face ID to authenticate
   your identity." — required or the app will crash the first time it tries to use biometrics.
6. Build and run on a real device (Face ID doesn't work in the Simulator) — you'll need
   your iPhone connected and trusted.
7. Tap "Create Identity", then "Authenticate with Face ID" — this should complete the phone
   stage for real against the live backend and show "waiting on IoT key device."

## Next real steps, in order of what's actually blocking

1. **Try it on a real device once Xcode is set up** — this is the first point where the
   Keychain/Face ID code gets tested for real; nothing here has run inside an actual iOS
   sandbox yet, only type-checked.
2. **Build the IoT key fob** (hardware, not code) — nothing on the app side can finish
   without it.
3. **Bluetooth pairing code** — once there's a device to pair with, `AuthViewModel` and
   `PhysicalKeyAPI.deviceVerify()` need a real Bluetooth handshake feeding in the device's
   actual `deviceId`/signature instead of the stub.
