# PhysicalKey iOS App

## Current state: real app, verified end to end on physical hardware

- **`PhysicalKey/*.swift`** — the app source:
  - `PhysicalKeyApp.swift` — SwiftUI entry point.
  - `ContentView.swift` — the main auth flow UI, plus a "Team" toolbar button once a
    phone session exists.
  - `AuthViewModel.swift` — orchestrates the phone → Bluetooth → device → session flow.
  - `KeyManager.swift` — Keychain-backed Ed25519 identity, Face ID/passcode-gated
    (`.biometryCurrentSet`).
  - `PhysicalKeyAPI.swift` — networking client for the backend
    (`https://physicalkey-core-production.up.railway.app`).
  - `DeviceBluetoothManager.swift` — CoreBluetooth client for the key fob.
  - `OrganizationViewModel.swift` / `TeamView.swift` — Team account management (see
    below).
- **Runs on real physical iPhones**, not just the Simulator — installed and launched via
  `xcrun devicectl`, confirmed staying alive (not crash-looping) after launch.
- **The full phone ↔ device ↔ backend auth flow is verified working**: real Face ID
  prompt, real Keychain-backed Ed25519 signing, real BLE pairing with a physical ESP32
  board (including BLE-level security — LE Secure Connections pairing, per-board
  bonding, see `../../hardware/README.md`), real backend challenge/response, real
  session issuance. This is not simulated or mocked at any layer.
- **Team accounts work end to end**: create/join a team, add/remove members, grant/
  revoke per-device access, and claim a physical key device by scanning for it over
  Bluetooth (not typing in a device ID by hand — the app already knows how to discover
  one via the same BLE handshake the main auth flow uses). Verified live on a physical
  iPhone. See `../../SETUP_COMPLETE.md`'s "Team accounts" section for the backend side
  of this.
- **`PhysicalKey.xcodeproj` is generated via `xcodegen`** from `project.yml` — regenerate
  with `xcodegen generate` after editing `project.yml`. `DEVELOPMENT_TEAM` /
  `CODE_SIGN_STYLE` are set explicitly in `project.yml` now (an earlier regeneration
  silently dropped code-signing config that had only ever lived in the generated
  `.xcodeproj`, not the source of truth — this is fixed).
- **Swift 6 strict concurrency**: `CBUUID` statics use `nonisolated(unsafe)` (safe —
  immutable), `KeyManager` is `@unchecked Sendable` (safe — no mutable stored state,
  verified by inspection), `DeviceBluetoothManager`'s delegate conformances use
  `@preconcurrency import CoreBluetooth` (Apple's own framework isn't yet
  Sendable-audited — the documented bridge for this, not a workaround). These only
  surface via real `xcodebuild`, never via a bare `swiftc -typecheck`.
- **Not literally Secure Enclave-resident.** The phone's private key is Ed25519,
  generated in software and stored in the Keychain with a biometry access-control flag —
  encrypted at rest, inaccessible without Face ID/passcode, but not living inside the
  secure co-processor the way a true Secure Enclave key does. Apple's Secure Enclave only
  supports hardware-resident generation for P-256 keys, and the backend verifies Ed25519.
  See the comment at the top of `KeyManager.swift` for what switching to true Secure
  Enclave residency would require (a backend change to verify P-256/ECDSA instead).
- **No real IMEI, no Apple App Attest, no Google Play Integrity.** iOS apps can't read
  the device's real IMEI; that field is a placeholder string for shape-compatibility
  with the backend's `phoneAttestation` structure. This doesn't call Apple's actual App
  Attest API — that's a materially larger integration (DeviceCheck entitlement, Apple's
  attestation servers). Identity here is proven via Keychain + Face ID + a real Ed25519
  signature instead — genuine cryptographic proof-of-possession, just not Apple's
  specific attestation service.

## Running on a real device

Requires the phone connected via USB and trusted, Developer Mode enabled on the phone
(Settings → Privacy & Security → Developer Mode), and — on first install only — trusting
the developer certificate (Settings → General → VPN & Device Management → the Apple ID
under "Developer App" → Trust).

```bash
xcodegen generate   # only needed after editing project.yml
xcrun devicectl list devices   # find the target device's identifier
xcodebuild -project PhysicalKey.xcodeproj -scheme PhysicalKey \
  -destination 'id=<device-identifier>' -allowProvisioningUpdates build

APP_PATH=$(find ~/Library/Developer/Xcode/DerivedData/PhysicalKey-*/Build/Products/Debug-iphoneos -maxdepth 1 -name "*.app")
xcrun devicectl device install app --device <device-identifier> "$APP_PATH"
xcrun devicectl device process launch --device <device-identifier> com.physicalkey.app
```

Two things worth knowing about the currently-signed-in Xcode account on this Mac,
counterintuitive but confirmed by testing: `DEVELOPMENT_TEAM: 9RYL8ZRC3U` in
`project.yml` is what actually works, even though the resulting build ends up signed
with a *different* team (`VDV59Q8X25`, from an existing cached provisioning profile) —
setting `VDV59Q8X25` directly fails with "No Account for Team". `CODE_SIGN_STYLE:
Automatic`'s real profile resolution figures out the right one regardless of what's set,
but needs a team ID that at least passes the initial "is this a valid signed-in account"
check first.

## Known gaps

- **BLE bond-reset UX**: if a phone's local Bluetooth pairing with a board goes stale
  (e.g. after the board's flash is erased), the fix today is manually forgetting the
  device in iOS Settings → Bluetooth. No in-app flow for this yet.
- **Team accounts have no "list my teams" support**: the backend has no endpoint to
  discover an org a phone was just added to (see `backend/auth/organizations.js`) — a
  member has to be told the team ID out-of-band (like a room code) and enter it once via
  "Join an existing team" in `TeamView`. Fine for now given there's no invite/notification
  system either; would need backend work to improve.
- **No TestFlight/App Store distribution** — installs only via direct cable from a Mac
  with the right Xcode account signed in. Needs an Apple Developer Program enrollment.
