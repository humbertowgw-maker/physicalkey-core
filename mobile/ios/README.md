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

## Running on a real device — done, as of this session

Xcode 26.6 is installed, an Apple ID (`achilleszepeda@icloud.com`) is signed into Xcode's
accounts, a free Personal Team (`9RYL8ZRC3U`) is set on the target, and the app has been
**installed and launched on a real, physical iPhone** (`iPhone17,2`) — not the Simulator.
Confirmed via `xcrun devicectl device info processes` that it stayed running (PID 590) after
launch, rather than crashing immediately.

Getting there required three device-side steps, each only doable by hand on the actual
hardware (none of these are scriptable):
1. **Developer Mode** enabled on the iPhone (Settings → Privacy & Security → Developer
   Mode → toggle on → restart → confirm).
2. **Trust the developer certificate** on first install (Settings → General → VPN & Device
   Management → tap the Apple ID under "Developer App" → Trust) — iOS blocks any
   personal-team-signed app from launching until this is done once.
3. **At least one device registered** with the team — Xcode/`xcodebuild
   -allowProvisioningUpdates` handles this automatically once the phone is connected via
   USB and trusts the Mac, but it can't register a device it's never seen.

Command that actually built and signed for the real device:
```bash
xcodebuild -project PhysicalKey.xcodeproj -scheme PhysicalKey \
  -destination 'id=<device-udid-from-xcrun-devicectl-list-devices>' \
  -allowProvisioningUpdates build
```
— confirmed **BUILD SUCCEEDED**, signed with `Apple Development: achilleszepeda@icloud.com`
and the auto-generated "iOS Team Provisioning Profile: com.physicalkey.app".

The Simulator build still works too (`xcodebuild -destination 'platform=iOS
Simulator,name=iPhone 17' build`) and remains useful for quick iteration, but Face ID and
real Bluetooth scanning only work on actual hardware — neither is meaningfully testable in
the Simulator.

**What hasn't been verified yet**: tapping through the actual UI on the device — "Create
Identity" (real Keychain write, biometry-gated) and "Authenticate with Face ID" (real
biometric prompt + real round-trip to the live backend). That requires an actual face at an
actual Face ID sensor, which is not something automatable from here — this is the next
thing to try by hand on the phone itself.

## Next real steps, in order of what's actually blocking

1. **Tap through the real flow on the device** — "Create Identity" then "Authenticate with
   Face ID" — and see what actually happens. First real end-to-end test of the phone half
   of this system.
2. **Flash the firmware onto a real ESP32 board** (see `../../hardware/README.md`) — the
   Bluetooth code on this side has nothing to talk to until that exists.
3. **Pair the two and see what breaks** — GATT discovery, MTU limits, and write/notify
   timing are all unverified assumptions until an actual phone talks to an actual board.
