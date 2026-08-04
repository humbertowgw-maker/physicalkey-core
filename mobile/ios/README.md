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
  `DeviceBluetoothManager.swift` (CoreBluetooth client for the key fob).
- **`DeviceBluetoothManager.swift` implements the full device-stage flow** — scans for
  a PhysicalKey device by its GATT service UUID, connects, reads its public key + device ID,
  writes the backend's challenge to it, and waits for the signature notification. The UUIDs
  match `hardware/firmware/PhysicalKeyDevice/PhysicalKeyDevice.ino`'s `#define` block
  exactly, since both sides hardcode the same fixed contract rather than negotiating it.
  `AuthViewModel` runs the complete phone → Bluetooth → device → session flow end to
  end, not just the phone half.
- **`PhysicalKey.xcodeproj` is a real, generated Xcode project** (via `xcodegen` from
  `project.yml` — regenerate with `xcodegen generate` if you edit `project.yml`), and it
  **actually builds with real Xcode** (`xcodebuild ... build`, confirmed both for
  `iOS Simulator` and `generic/platform=iOS`) — not just `swiftc -typecheck` anymore. Along
  the way this caught and fixed three real Swift 6 strict-concurrency issues that a bare
  `swiftc -typecheck` invocation hadn't surfaced: `CBUUID` static constants needed
  `nonisolated(unsafe)` (safe — they're immutable), `KeyManager` needed
  `@unchecked Sendable` (safe — it has no mutable stored state, verified by inspection), and
  `DeviceBluetoothManager`'s delegate conformances needed `@preconcurrency import
  CoreBluetooth` (Apple's own framework isn't yet Sendable-audited — this is the documented
  bridge for that, not a workaround).
- **The app was installed and launched in the iOS 26.5 Simulator and confirmed running**
  (`xcrun simctl install` / `launch`, verified alive via `launchctl list`, screenshotted) —
  showing the real `.notReady` state ("No identity on this device yet" / "Create Identity"),
  not the placeholder mockup that exists elsewhere on this machine. This is the first time
  any of this code has actually executed inside an iOS runtime, simulated or real.
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

## Xcode is now installed — what's left needs your Apple ID specifically

Xcode 26.6 is installed and `PhysicalKey.xcodeproj` builds and runs in the Simulator today.
Two things remain that genuinely can't be done without your Apple ID sitting in Xcode's own
account preferences (this isn't a shell command — it's Xcode's GUI, tied to your identity):

1. **Add your Apple ID to Xcode**: Xcode → Settings → Accounts → "+" → sign in.
2. **Set a Development Team** on the target: open `PhysicalKey.xcodeproj`, select the
   `PhysicalKey` target → Signing & Capabilities → Team → pick the team tied to your Apple
   ID (a free "Personal Team" is enough for local device testing; a paid Developer Program
   membership is only needed for TestFlight/App Store distribution).

Once that's done:
```bash
xcodebuild -project PhysicalKey.xcodeproj -scheme PhysicalKey -destination 'generic/platform=iOS' build
```
should succeed the same way the Simulator build already does (confirmed: `xcodebuild
-destination 'platform=iOS Simulator,name=iPhone 17' build` → **BUILD SUCCEEDED**, and the
app installs/launches/runs in the Simulator, screenshotted showing the real "No identity on
this device yet" / "Create Identity" screen — not the placeholder mockup elsewhere on this
machine).

Then: connect a real iPhone via USB, trust the computer on the phone, select it as the run
destination in Xcode, and hit Run. Face ID and real Bluetooth scanning both require an
actual device — neither works in the Simulator (Face ID has a "simulate" option under
Simulator → Features, but that's not the same as testing the real Keychain/biometry path).

## Next real steps, in order of what's actually blocking

1. **Add your Apple ID + Development Team in Xcode** (above) — first remaining thing that
   needs you specifically, not something to automate around.
2. **Run it on a real iPhone** — first point the Keychain/Face ID code gets tested against
   real biometric hardware; the Simulator build proves the code runs, not that Face ID
   itself works correctly.
3. **Flash the firmware onto a real ESP32 board** (see `../../hardware/README.md`) — the
   Bluetooth code on this side has nothing to talk to until that exists.
4. **Pair the two and see what breaks** — GATT discovery, MTU limits, and write/notify
   timing are all unverified assumptions until an actual phone talks to an actual board.
