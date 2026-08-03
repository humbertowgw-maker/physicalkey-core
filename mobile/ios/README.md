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
  (Keychain-backed identity, Face ID-gated), `PhysicalKeyAPI.swift` (networking client),
  `DeviceBluetoothManager.swift` (CoreBluetooth client for the key fob). All six files
  type-check cleanly with the Swift compiler (`swiftc -typecheck`), using the same proven
  crypto approach as the PoC.
- **`DeviceBluetoothManager.swift` now implements the full device-stage flow** — scans for
  a PhysicalKey device by its GATT service UUID, connects, reads its public key + device ID,
  writes the backend's challenge to it, and waits for the signature notification. The UUIDs
  match `hardware/firmware/PhysicalKeyDevice/PhysicalKeyDevice.ino`'s `#define` block
  exactly, since both sides hardcode the same fixed contract rather than negotiating it.
  `AuthViewModel` now runs the complete phone → Bluetooth → device → session flow end to
  end, not just the phone half.

## What's NOT real / not done

- **No Xcode project.** I don't have Xcode installed on this machine — only the Command
  Line Tools (enough to run `swift build`/`swiftc -typecheck`, not enough to build or run an
  actual iOS app, which needs the iOS SDK, a simulator or device, code signing, etc.). See
  "Getting this running" below for the ~5-minute manual step to fix that.
- **The Bluetooth client code is written but never tested against real hardware.**
  `DeviceBluetoothManager` compiles and type-checks against the same protocol the firmware
  defines, but no physical ESP32 board exists to actually pair with and exercise it — both
  sides were written from the same spec, not verified against each other by actually
  running both. What IS independently verified: the Ed25519 signature format each side
  produces/expects (proven compatible with the backend in `mobile/ios-crypto-poc` and
  `hardware/firmware-crypto-poc` separately). What's unverified is specifically the
  Bluetooth transport in between — GATT discovery timing, MTU/write-size limits, whether
  the 15-second scan timeout is realistic, whether `CBCharacteristic` write-with-response
  semantics actually match what the firmware's `BLECharacteristic::PROPERTY_WRITE` does in
  practice. All plausible based on how both APIs are documented to behave, none confirmed.
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
5. In the target's **Info** tab, add two keys — both required or the app will crash the
   first time it tries to use the corresponding API:
   - `Privacy - Face ID Usage Description` (`NSFaceIDUsageDescription`): e.g. "PhysicalKey
     uses Face ID to authenticate your identity."
   - `Privacy - Bluetooth Always Usage Description` (`NSBluetoothAlwaysUsageDescription`):
     e.g. "PhysicalKey uses Bluetooth to connect to your physical key device."
6. Build and run on a real device (Face ID doesn't work in the Simulator, and there'd be no
   real Bluetooth peripheral to scan for either way) — you'll need your iPhone connected
   and trusted.
7. Tap "Create Identity", then "Authenticate with Face ID" — this should complete the phone
   stage for real against the live backend. "Connect to Key Device" is there next, but has
   nothing to actually connect to until the firmware is flashed onto real hardware
   (see `../../hardware/README.md`).

## Next real steps, in order of what's actually blocking

1. **Try it on a real device once Xcode is set up** — this is the first point where the
   Keychain/Face ID code gets tested for real; nothing here has run inside an actual iOS
   sandbox yet, only type-checked.
2. **Flash the firmware onto a real ESP32 board** (see `../../hardware/README.md`) — the
   Bluetooth code on this side has nothing to talk to until that exists.
3. **Pair the two and see what breaks** — GATT discovery, MTU limits, and write/notify
   timing are all unverified assumptions until an actual phone talks to an actual board.
