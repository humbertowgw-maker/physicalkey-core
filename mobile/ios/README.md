# PhysicalKey iOS App

## Current state: real app, verified end to end on physical hardware

- **`PhysicalKey/*.swift`** — the app source:
  - `PhysicalKeyApp.swift` — SwiftUI entry point.
  - `ContentView.swift` — the main auth flow UI, plus a "Team" toolbar button once a
    phone session exists.
  - `AuthViewModel.swift` — orchestrates the phone → Bluetooth → device → session flow.
  - `KeyManager.swift` — Secure-Enclave-resident P-256 identity, raw Security-framework
    `SecKeyCreateRandomKey`/`SecKeyCreateSignature` (not CryptoKit — see the note below),
    Face ID/passcode-gated (`.biometryCurrentSet`). **Confirmed working live on real
    hardware.**
  - `PhysicalKeyAPI.swift` — networking client for the backend
    (`https://physicalkey-core-production.up.railway.app`).
  - `DeviceBluetoothManager.swift` — CoreBluetooth client for the key fob.
  - `OrganizationViewModel.swift` / `TeamView.swift` — Team account management (see
    below).
- **Runs on real physical iPhones**, not just the Simulator — installed and launched via
  `xcrun devicectl`, confirmed staying alive (not crash-looping) after launch.
- **The full phone ↔ device ↔ backend auth flow is verified working on real hardware,
  end to end, repeatedly** — most recently as the "real-access-gate" demo
  (`../../demo/git-gate-server.js`): real Face ID prompt → Secure-Enclave P-256 signing →
  real BLE pairing with a physical ESP32 board (LE Secure Connections, per-board bonding,
  see `../../hardware/README.md`) → real backend challenge/response → real git
  credentials → a real `git clone` against production landing actual files. Confirmed on
  production backend logs, the gate server's logs, and the filesystem simultaneously.
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
- **Secure-Enclave-resident P-256, confirmed working on real hardware — but not via
  CryptoKit.** The phone's private key used to be Ed25519, generated in software and
  stored in the Keychain — encrypted at rest, but not living inside the secure
  co-processor. CryptoKit's `SecureEnclave.P256.Signing.PrivateKey` was tried first and
  found genuinely broken on a real iPhone 16 Pro Max (iOS 26.5): key creation succeeded,
  but every `signature(for:)` call failed with `Code=-1009 "ACL operation is not
  allowed: 'osgn'"`, reproduced across a full uninstall/reinstall/fresh-key cycle, with
  Face ID enrolled and confirmed available. A side-by-side test on the same device, same
  moment, proved the raw Security framework (`SecKeyCreateRandomKey`/
  `SecKeyCreateSignature`) signs successfully with identical access-control flags —
  isolating the bug to CryptoKit's wrapper. `KeyManager.swift` now uses the raw Security
  framework directly; the backend accepts both P-256 (new registrations) and Ed25519
  (already-registered phones) via `backend/auth/phone-auth.js`. **Confirmed live,
  repeatedly**, most recently as part of the real-access-gate demo above. The Secure
  Enclave is unavailable on the Simulator (`SecureEnclave.isAvailable == false`) — real
  hardware is required for anything touching identity creation or signing; the SPKI
  DER-header byte manipulation itself is now covered by `PhysicalKeyTests/KeyManagerTests.swift`,
  which runs fine on the Simulator since it only needs a software EC key, not the Secure
  Enclave.
- **No real IMEI, no Apple App Attest, no Google Play Integrity.** iOS apps can't read
  the device's real IMEI; that field is a placeholder string for shape-compatibility
  with the backend's `phoneAttestation` structure. This doesn't call Apple's actual App
  Attest API — that's a materially larger integration (DeviceCheck entitlement, Apple's
  attestation servers). Identity here is proven via the Secure Enclave + Face ID + a real
  P-256 signature instead — genuine cryptographic proof-of-possession, just not Apple's
  specific attestation service.

## Automated tests

`PhysicalKeyTests/` (added 2026-08-10) — the first automated coverage for this app;
everything before this was manual, real-hardware verification only. Runs on the
Simulator, no physical device needed:

```bash
xcodegen generate   # only needed after editing project.yml
xcodebuild test -project PhysicalKey.xcodeproj -scheme PhysicalKey \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro'
```

20 tests, real assertions, not placeholders:
- **`KeyManagerTests.swift`** — the RFC 5480 SPKI DER header `KeyManager` hand-prepends
  onto a raw P-256 point (the exact kind of silent, subtle bug that already caused one
  real incident with CryptoKit — see above), verified against real EC keys generated on
  the Simulator; `KeyManagerError`'s OSStatus → user-facing message mapping.
- **`PhysicalKeyAPITests.swift`** — `Codable` round-trips and real-backend-shaped JSON
  decoding for `GitCredentials`, `DeviceVerifyResponse`, `PhoneChallengeResponse`.
- **`AuthViewModelTests.swift`** — `Stage` equality (including through nested
  `GitCredentials`, not just the session token), and the error-message logic that
  decides what a user actually sees when device auth fails.

What's still only manually verified: anything that needs the Secure Enclave, real BLE, or
real Face ID — none of that exists on the Simulator, so `createIdentity()`/`sign()`,
`DeviceBluetoothManager`, and the full end-to-end flow remain real-hardware-only
verification, same as before this test target existed.

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

**Symptom that cost real time to diagnose (2026-08-04): a rebuild can silently re-trigger
the "trust" requirement on an already-trusted phone.** After a full `rm -rf DerivedData` +
clean build, `xcodebuild`'s automatic signing resolution picked a *different* Apple ID
(`achilleszepeda@icloud.com`) than whatever had been in use before on that exact phone —
even though the phone had been running earlier builds of this same app all session with no
issue. The failure mode is confusing because it doesn't look like a signing problem at
first: `devicectl device install app` reports success and `device info apps` lists the app
as installed, but the app doesn't actually appear on the home screen or in Spotlight, and
`devicectl device process launch` fails with "invalid code signature, inadequate
entitlements or its profile has not been explicitly trusted by the user." Uninstalling,
reinstalling, and even a full phone restart do **not** fix this — the actual fix is tapping
the app's icon (or attempting to launch it) once to surface iOS's own "Untrusted
Developer" alert, then Settings → General → VPN & Device Management → tap the named
developer profile → Trust. One-time per (phone, certificate) pair; after that, reinstalls
work normally again. Worth checking this *first* if a build that was working suddenly
seems to not exist on a device that hasn't had this exact certificate trusted since the
last clean rebuild.

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
