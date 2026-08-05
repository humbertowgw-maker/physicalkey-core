# PhysicalKey Local Backend Setup — Results

## Security audit + fixes: three phases, all shipped (2026-08-05, later the same day)

Same day as the session-ratchet resolution below: ran a full attacker-scenario + code-level
security audit against the real codebase (backend, firmware, iOS — not assumptions), then
closed every finding it raised except the two that genuinely need a manufacturing/packaging
decision rather than code (device provenance, BLE out-of-band pairing — deferred, flagged,
not silently dropped).

**Phase A — quick wins** (commit `8807b67`): deleted a dead, unused permission-check module
that trusted a caller-supplied role with zero verification; wired the already-existing but
never-called `revokeGitAccess()` into the identity-reset escape hatch, so a stolen
device+phone pair's git access is actually revocable now instead of surviving up to 24h
past the reset; fixed the honeypot middleware logging every normal successful auth attempt
as an "event" indistinguishable from a real attack (it was gated on "no Authorization
header," which is true of every legitimate call to those endpoints by definition — narrowed
to real failures only).

**Phase B — the Critical finding** (commit `0e953dc`): the session-ratchet's result was a
bare, unsigned string self-reported by the phone app, with no cryptographic binding to the
actual BLE exchange — an attacker capable of cloning a device's Ed25519 key could just claim
`"verified"` without doing any real exchange. Fixed by having the ESP32 sign the ratchet
output with its existing Ed25519 identity key, bound to the session's challenge nonce; the
backend now independently verifies that signature and computes the continuity verdict
itself from its own mirrored HMAC chain, instead of trusting the client. Verified end-to-end
on the real spare board (`physicalkey-device-680947e00800`) and the Achilles iPhone: first
session after reflash → `unverifiable` (real prior board state, no backend record yet,
correctly not a false mismatch), second session → `verified`. A deliberately wrong proof
was also confirmed caught and honeypotted against the live deploy.

**Phase C — the remaining High-priority items** (commit `b399516`): session/credential
revocation (a single per-deviceId cutoff timestamp checked against each JWT's own embedded
`issuedAt` — no blacklist needed — wired into the same identity-reset escape hatch, so one
admin action now kills identity, ratchet trust, git access, *and* any already-issued session
all at once); org-scoped audit visibility (org membership/device-access changes are now
logged, and an org's own owner/admin can see their org's history via
`GET /orgs/:orgId/audit-log` without needing the single global admin device's credentials).

Full report (8 attack scenarios, code-level analysis, gap analysis, prioritized roadmap) was
published as an artifact during the session — not saved as a repo file; ask the user if you
need that level of narrative detail. The summary above plus the code itself should be enough
for anyone picking this up.

**What's still open, deliberately deferred pending a decision from the user, not a code
gap:** device provenance (TOFU currently accepts any new deviceId — closing this properly
needs factory-provisioned certs, or an interim admin allow-list, once there's an actual
manufacturing process to anchor it to) and BLE first-pairing MITM protection (needs
out-of-band pairing data, e.g. a per-unit passkey printed on the board/box — a packaging
decision). Also deferred, lower urgency: backend-compromise blast-radius reduction
(KMS-backed JWT signing, tamper-evident audit log — real architecture work, reasonable to
defer until there's a concrete compliance/enterprise reason) and iOS certificate pinning.

### Real troubleshooting wins from today — save future time on these

Genuine bugs and dead ends hit and resolved while shipping the three phases above, worth
knowing before they cost time again:

- **A "successful" health check does not mean the LATEST deploy is live.** The first Phase B
  deploy (`railway up --detach`) actually **failed the build**, but `railway status` still
  showed `● Online` and `curl .../health` still returned `200` — because Railway keeps the
  previous, still-working deployment serving traffic when a new one fails, exactly to avoid
  downtime. This produced ~20 minutes of genuinely confusing results: a whole battery of
  "production" tests (bootstrap/verified/mismatch flows) all passed, but were silently
  testing the OLD, pre-fix code the entire time. The real signal was buried in
  `railway status`'s deploy line (`Deploy failed (5m)`), not the health endpoint. **Always
  check `railway status` explicitly for `Deploy failed` after `railway up`, don't just trust
  `/health`.** Relatedly: `railway status`'s `● Online` also appears *during* an in-progress
  `Building`/`Deploying` state, not just once fully settled — a status check needs to confirm
  the absence of `Building`/`Deploying`, not just the presence of `Online`, or it'll report
  "done" mid-deploy.
- **The actual failure, once found:** the Dockerfile had a hardcoded
  `COPY access ./access` step for a directory that Phase A had deleted (a dead permission-
  check module removed as part of the audit fixes). Docker's `COPY` fails hard if the source
  path doesn't exist locally. **When deleting a module/directory, also grep the Dockerfile
  (and any other deploy manifests) for references to it** — nothing else catches this until
  the actual build.
- **`railway ssh` does not reliably show the live container's real data.** Querying the
  production SQLite file directly via `railway ssh "node -e ..."` returned stale/wrong
  results (old schema, or an empty freshly-created database) even when the actual running
  server had already migrated and had real data. It appears to spin up a separate ephemeral
  instance rather than truly shelling into the live container's filesystem. **Verify live
  server state through the actual API instead of `railway ssh` + direct file access** — it's
  slower per-check but the only means that's actually testing what's really running.
- **A literal backtick anywhere inside a JS template literal ends the string, even inside a
  SQL comment.** Writing `-- ...already embeds its own \`issuedAt\`: ...` inside a
  `` db.exec(`...`) `` block (meant as a SQL comment) closed the JS template literal early
  and produced a real `SyntaxError: missing ) after argument list` at server startup —
  because JS has no concept of "inside a SQL comment," it just sees the next raw backtick
  character. Caught immediately (every test server failed to start), but cost real time to
  localize. Don't use backtick-quoting for identifiers in SQL comments that live inside a JS
  template literal — plain text only.
- **A `CREATE INDEX` on a newly-added column must never live in the same `db.exec()` batch
  as the initial `CREATE TABLE IF NOT EXISTS`.** Adding `org_id` to `admin_actions` (Phase C)
  included a `CREATE INDEX ... ON admin_actions(org_id)` right after the `CREATE TABLE IF NOT
  EXISTS admin_actions (...)` statement, in the same SQL batch. Against a *fresh* database
  this is fine — the table is created with `org_id` already present. Against an *existing*
  database (i.e., actual production, which already had `admin_actions` from before this
  column existed), `CREATE TABLE IF NOT EXISTS` is a silent no-op, so the table still lacks
  `org_id` — and the `CREATE INDEX` in that same batch then fails with `no such column:
  org_id`, **before** the later `ALTER TABLE ... ADD COLUMN` migration code ever gets a
  chance to run. This was caught by explicitly testing the migration against a hand-built
  database matching production's real (pre-migration) shape before deploying — worth doing
  that for every future schema change here, not just trusting `CREATE TABLE IF NOT EXISTS`
  to be harmless. Fix: any index on a newly-added column goes *after* the migration that adds
  the column, never bundled with the initial schema statement.

## RESOLVED: Session ratchet — verified end-to-end on real hardware (2026-08-05)

**Update, later the same day:** the blocker below (Achilles iPhone Air stuck at
`ddiServicesAvailable: false` / `tunnelState: unavailable`) turned out to be exactly what it
looked like — a stale device connection, not a code or signing problem. A fresh unlock +
cable + Trust cycle brought the tunnel up clean (`ddiServicesAvailable: true`,
`tunnelState: connected`) on the first attempt. From there:

- Built and installed via `xcodebuild ... -destination 'id=00008150-001444890E92401C'`
  (explicit classic UDID, not by name), signed automatically with the
  `achilleszepeda@icloud.com` identity, one-time developer-profile trust on the phone.
- **First real connection to the spare board** (`physicalkey-device-680947e00800`) logged
  `[ratchet-debug] ... ratchetStatus="bootstrap"` — correct, expected result for a first-ever
  pairing.
- **Second connection** logged `ratchetStatus="verified"` — proof the ratchet chains forward
  correctly session-to-session, the actual thing this feature needed to demonstrate.
- The three temporary debug aids (button label, `AuthViewModel`'s debug-error passthrough,
  backend `console.log`) were reverted, `npm test` passes 46/46, backend redeployed to
  Railway and health-checked live, iOS rebuild confirmed clean, all committed and pushed
  (`debea05`).

The rest of this section is kept as-is below as a troubleshooting record — the device/tooling
issues it documents are still real and can recur with other phones/boards on this project.

**Original handoff, written before the above was resolved:**

This was a mid-feature handoff — the code existed and compiled/deployed, but the one thing
that hadn't been confirmed was whether it actually worked end-to-end on a real phone + real
board. A long previous session burned significant time on device/tooling confusion
(documented below) without resolving that confirmation, not because of a known code bug.

### What this feature is

A session-ratchet continuity layer, on top of the existing Ed25519 phone/device auth: an
ephemeral X25519 key exchange happens over BLE on every connection, chained forward via
HMAC-SHA512, so a *cloned* device identity (someone who somehow got the real ESP32's
private key) goes stale the moment the real phone+board pair completes one more real
session. Full design rationale, threat model, and protocol spec were written up as a plan
artifact earlier in the parent conversation — not saved as a repo file, so if you need that
level of detail and don't have it, ask the user; otherwise the summary below plus reading
the code directly should be enough.

Reported to the backend as `ratchetStatus`, one of:
- `bootstrap` — no prior state on one or both sides (first pairing, or a re-flash/reinstall
  wiped state). **Never treated as suspicious** — this is the single most important design
  rule, see "Recovery path" below.
- `verified` — both sides have prior state and it matches. Real continuity confirmed.
- `mismatch` — both sides have prior state and it *disagrees*. The actual signal worth
  logging (not blocking — see below).

**Warn-not-block by design, same as the earlier liveness-check layer**: a `mismatch` is
logged to the existing honeypot/forensics system but never rejects authentication. This was
a deliberate choice given this exact session already caused two costly false-lockout bugs
earlier from state going out of sync (a TOFU identity lockout, and a BLE-bond lockout after
a board erase) — treating absence-of-state as suspicious would recreate that class of bug.

### What's actually done and verified (not just written)

1. **Firmware** — `hardware/firmware-idf/PhysicalKeyDevice/main/ratchet.{h,cpp}`, plus 2 new
   GATT characteristics added to `gatt_svr.cpp` (`RatchetPubKey` write, `RatchetResponse`
   read+notify) and `CMakeLists.txt` updated to build the new source file. **Builds clean**
   via `idf.py build`. **Flashed to a spare ESP32 board** (deviceId
   `physicalkey-device-680947e00800`, connects via USB-serial, port name varies —
   was `/dev/cu.usbserial-0001` in the prior session but check `ls /dev/cu.*` fresh, it can
   renumber). **Boots clean, BLE advertises correctly** — confirmed via direct serial
   monitoring (see "Tooling notes" for how, since `idf.py monitor` needs a real TTY and
   won't work when driven non-interactively).
   - Uses the vendored crypto library's `Curve25519::dh1/dh2` (X25519 DH) and
     `SHA512::resetHMAC/finalizeHMAC` / the `hmac<SHA512>(...)` template helper — both
     confirmed present in `components/ed25519/include/` before use, nothing new vendored.
   - **This spare board's flash is encrypted** (Development Mode flash encryption + NVS
     encryption, from earlier work this session). Re-flashing it requires
     `idf.py -p <port> encrypted-flash`, **not** plain `idf.py flash` — using the plain
     command writes an unencrypted image to a chip that expects encrypted flash and bricks
     it into a boot loop (`invalid header: 0x4a7c...`, repeated `RTCWDT_RTC_RESET`). This
     happened once already and was recovered via `encrypted-flash`; don't repeat the
     mistake.

2. **Backend** — `backend/auth/ratchet.js` (new), changes in `backend/server.js`'s
   `/auth/device/verify` handler, new `ratchet_state` SQLite table in `backend/lib/db.js`.
   **40+ tests pass** (`npm test`), **deployed to Railway and verified live** — confirmed
   via direct `railway ssh` SQLite query that the table exists and via test coverage that
   backward-compatibility (no `ratchetStatus` field), warn-not-block, forensics logging,
   and the admin-reset escape hatch (`DELETE /admin/identities/:deviceId` now also clears
   ratchet state) all work correctly.
   - **Currently has a temporary debug line** — see "Temporary debug code" below.

3. **iOS** — `mobile/ios/PhysicalKey/RatchetManager.swift` (new), changes in
   `DeviceBluetoothManager.swift` (2 new characteristics, `runRatchetExchange` method) and
   `AuthViewModel.swift` (wired into `connectAndAuthenticateDevice`, runs right after the
   existing device-signature step). **Compiles clean. Confirmed running on a real phone**
   (Achilles iPhone Air) as of the 2026-08-05 update above — `bootstrap` then `verified`
   across two real connections to the spare board.

### The actual blocker: device/tooling confusion, not (necessarily) a code bug

**Two physically different phones got confused with each other, repeatedly, across a very
long troubleshooting session.** Independently verified via `xcrun devicectl device info
details --device <id> | grep -i "udid\|marketingName"`:

| Xcode/devicectl name | devicectl CoreDevice ID | Classic UDID | Model | Role |
|---|---|---|---|---|
| `iPhone` | `1FBAA9F4-0F90-50E4-9894-8D37F380D4FA` | `00008140-0002259E1EE1401C` | iPhone 16 Pro Max | **Humberto's existing, already-hardened prototype phone.** Used all session for the Phase 0 (liveness spike) and Phase 2 (liveness integration) work, which is legitimately part of hardening *this* phone/board pairing. |
| `Achilles iphone` | `AC6C3C43-1F60-5FB8-A8AE-9F9005326F58` | `00008150-001444890E92401C` | iPhone Air | **A second phone belonging to "Achilles."** This is the one that should be used to test the ratchet feature against the *spare* board, so the existing hardened prototype's phone+board pairing is never put at risk of being disrupted mid-test. |

**Every ratchet test this session actually ran against the iPhone 16 Pro Max** (the "don't
touch" one), connected to the *spare* board (not the hardened prototype's board, so no
actual harm was done to the working prototype's pairing — but it wasn't the intended test
device either). Every attempt showed `ratchetStatus=undefined` in the backend's debug log,
meaning **the ratchet exchange never actually executed on the phone, across every single
attempt** — not one single successful or even failed-with-a-real-error execution was ever
observed. Given how many *different* root causes were found and fixed along the way (see
below), each of which could plausibly have been *the* blocker, the honest state is: it's
unknown whether the Swift code itself works, because a clean, uninterrupted run was never
achieved.

**Real, confirmed issues found and fixed along the way** (in case any recur):
- An untrusted developer certificate. A full `rm -rf DerivedData` + clean rebuild caused
  Xcode's automatic signing resolution to switch to a *different* Apple ID
  (`achilleszepeda@icloud.com`) than whatever the phone had already trusted, and the
  failure mode is deeply misleading: `devicectl device install app` reports success, `device
  info apps` lists the app as installed, but it doesn't appear on the home screen or in
  Spotlight, and `devicectl device process launch` fails with "invalid code signature...
  profile has not been explicitly trusted." Fix: tap the app (triggers iOS's own
  "Untrusted Developer" alert) or go to Settings → General → VPN & Device Management →
  trust the named developer profile. One-time per (phone, certificate) pair. This is now
  documented in `mobile/ios/README.md`.
- `xcrun devicectl`'s `process launch` command proved unreliable for this specific phone
  all session — reported false "Locked" errors when the phone was confirmed unlocked (via
  the user directly looking at the home screen), and its `device info apps`/install
  success reporting did not reliably reflect actual on-device reality. **Recommendation:
  prefer Xcode's own GUI (Product → Destination → pick the explicit device, then Run) over
  `devicectl` CLI commands for this project going forward**, or at minimum treat
  `devicectl`'s success/failure reporting with real skepticism and cross-check against
  independent evidence (Railway logs, serial monitor) rather than trusting it at face
  value.
- Xcode's GUI destination picker silently defaulted to the **iOS Simulator** ("iPhone 17
  Pro") at one point instead of a real device — the simulator obviously has no real
  Bluetooth and can never reach a physical board. Always explicitly verify the destination
  says a real device name before hitting Run, not a simulator.
- A board flash-encryption bricking incident (see firmware section above) — recovered, but
  don't repeat with `idf.py flash` instead of `idf.py -p <port> encrypted-flash` on an
  already-encrypted board.

### Temporary debug code — reverted as of the 2026-08-05 update above (commit `debea05`)

Left here for historical context only; these no longer reflect the current code. They were
**committed as-is** at the time so nothing was at risk of being lost, then reverted once a
real device-verification run succeeded:

- `mobile/ios/PhysicalKey/ContentView.swift`: the "Connect to Key Device" button's label
  was changed to `"RATCHET-BUILD-CHECK-9F2 · Connect to Key Device"` — a build-freshness
  sanity check (seeing this exact string on-screen proves the currently-installed build is
  the one with the ratchet code, given how many stale-build red herrings came up). Revert
  to `"Connect to Key Device"` once done.
- `mobile/ios/PhysicalKey/AuthViewModel.swift`'s `runRatchetCheck` currently returns
  `String?` instead of `RatchetVerdict?`, and on failure returns `"debug-error:
  <description>"` instead of `nil` — this makes any Swift-side error visible in the
  backend's log (see next line) without needing reliable phone console access, which this
  session never achieved. To revert: change the return type back to `RatchetVerdict?`,
  return `nil` on catch, and update the call site in `connectAndAuthenticateDevice` to use
  `ratchetVerdict?.rawValue` when calling `api.deviceVerify`.
- `backend/server.js`'s `/auth/device/verify` handler has a temporary line:
  `console.log(\`[ratchet-debug] deviceId=${deviceId}
  ratchetStatus=${JSON.stringify(ratchetStatus)}
  bodyKeys=${Object.keys(req.body).join(',')}\`);` right after destructuring the request
  body. Remove once done, then `railway up --detach` to redeploy without it.

### Recommended next steps, in order

1. **Get the Achilles iPhone Air (`00008150-001444890E92401C`) reliably connected first**,
   before touching any code. It showed `ddiServicesAvailable: false` and "unavailable" all
   session despite unlock + "Trust This Computer" + cable swap — this was never actually
   resolved. Try: a full restart of both the Mac and the phone, a different USB-C
   cable/port, opening Xcode's Window → Devices and Simulators and waiting for developer
   disk image preparation to finish before doing anything else, and removing/re-adding any
   stale Xcode device pairing for just this phone. Confirm success via
   `xcrun devicectl device info details --device AC6C3C43-1F60-5FB8-A8AE-9F9005326F58 | grep -i "developerModeStatus\|ddiServicesAvailable"`
   showing `ddiServicesAvailable: true` before attempting an install.
2. **Build and install explicitly to that device's identifier**, not by name (names can
   become ambiguous) — `xcodebuild ... -destination 'id=00008150-001444890E92401C'` (or the
   devicectl CoreDevice ID form, `id=AC6C3C43-1F60-5FB8-A8AE-9F9005326F58`, for
   devicectl-based commands specifically — the two ID namespaces aren't interchangeable
   across tools, xcodebuild wants the classic UDID, devicectl wants its own CoreDevice ID).
3. **Confirm the `RATCHET-BUILD-CHECK-9F2` button label is visible on-screen** before doing
   anything else — this is the cheapest possible confirmation that a stale build isn't the
   problem again.
4. Go through the real auth flow on the Achilles phone, connect to the spare board
   (`physicalkey-device-680947e00800`), and check
   `cd ~/physicalkey-core/backend && railway logs` for a
   `[ratchet-debug] deviceId=physicalkey-device-680947e00800 ratchetStatus=...` line.
   `bootstrap` on the first-ever run against this phone+board pair is the expected,
   correct result (no prior state yet) — run it a **second** time and confirm `verified`
   this time, which is the real proof the ratchet is chaining correctly session-to-session.
5. If a genuine Swift-side error shows up (via the `debug-error:` string), fix it — likely
   candidates worth checking first, based on re-reading the code fresh: whether
   `DeviceBluetoothManager.runRatchetExchange` needs to wait for
   `didUpdateNotificationStateFor` to actually confirm the notify-subscription completed
   before writing the ephemeral public key (a possible race — the code currently fires the
   write immediately after calling `setNotifyValue`, without confirming the subscription
   landed first).
6. Once a real `verified` result is confirmed, revert the three temporary debug changes
   above, run `npm test` in `backend/`, redeploy (`railway up --detach`), and commit.

### Tooling notes for whoever picks this up

- `idf.py monitor` requires a real interactive TTY and will fail non-interactively
  ("Monitor requires standard input to be attached to TTY"). To read ESP32 serial output
  from a script/agent instead: reset the board via
  `python -m esptool --chip esp32 -p <port> --after hard_reset read_mac` (uses esptool's
  own tested reset logic — don't hand-roll DTR/RTS toggling, this board's wiring doesn't
  match the naive assumption and will land it in bootloader/download mode instead of
  normal boot), then read raw serial with a small pyserial script that does **not** touch
  `.dtr`/`.rts` itself.
- To pull a real crash log from a connected device instead of guessing at a crash cause:
  `xcrun devicectl device info files --device <id> --domain-type systemCrashLogs` lists
  them, `xcrun devicectl device copy from --device <id> --domain-type systemCrashLogs
  --source "<filename>.ips" --destination <local path>` retrieves one. It's a JSON-lines
  file (`json.loads(text.split('\n', 1)[1])`) — the crashed thread's frames are the fastest
  way to a real root cause, much faster than guessing.
- Swift 6 strict concurrency caused two real, subtle crashes this session unrelated to
  ratchet logic itself (in the liveness-check audio code) — both were closures that Swift
  inferred as `@MainActor`-isolated just from being written inside an `@MainActor` class,
  which crashed when a system framework (AVAudioEngine) called them from a different
  thread. If a similarly weird crash/hang shows up in new code, check for this pattern
  first (explicit `@Sendable` typing on the closure, defined as a free function rather than
  inline, is the fix) before assuming it's a logic bug.

## Session lifetime, admin audit log, and a Dockerfile outage (2026-08-04)

Closed out the last two items from the hardening pass above:

- **`sessionToken` lifetime: 24h → 1h.** It's never persisted client-side (in-memory only in `AuthViewModel`, lost on app restart), so shortening it has no real UX cost — it only shrinks the replay window if it's ever exfiltrated. Git access is unaffected; `git/git-credentials.js` has its own independent 24h expiry.
- **Persistent audit log for admin identity resets.** `DELETE /admin/identities/:deviceId` was only `console.log`'d before — lost on restart, unqueryable. Added an `admin_actions` SQLite table, `backend/audit/log.js`, and `GET /admin/audit-log` (admin-gated) so "who reset this deviceId, and when" has a durable, queryable answer.

**This caused a real (brief) production outage.** `backend/audit/log.js` was added and imported by `server.js`, tests passed locally (34/34), it was committed, pushed, and deployed — and the deployed container immediately crash-looped with `ERR_MODULE_NOT_FOUND: /app/audit/log.js`. Root cause: `Dockerfile` copies source directories by explicit name (`COPY auth ./auth`, `COPY git ./git`, etc.) rather than the whole build context, and the new `audit/` directory was never added to that list. `npm test` never catches this class of bug because it runs `server.js` directly via `node`, not through the Docker image — so a Dockerfile that's silently out of sync with the source tree looks completely fine right up until it's deployed.

Fixed in two parts:
1. Added `COPY audit ./audit` to the Dockerfile and redeployed — confirmed via `railway logs` (clean boot, no crash) and a live 401 (not 502) from `/admin/audit-log`.
2. Added a second CI job (`docker-build` in `.github/workflows/backend-tests.yml`) that actually builds `./backend`'s Docker image and boots a real container, failing the build if `/health` doesn't respond within 20s. This is the durable fix — it makes this exact class of bug (Dockerfile drift from the real source tree) fail in CI instead of in production. Verified: both `test` and `docker-build` jobs pass on the run that includes this fix.

Commits: `264b486` (session lifetime + audit log), `8d4e75f` (Dockerfile fix), `e3bfbff` (CI docker-build job).

## Backend security hardening (2026-08-04)

A pass over `server.js` looking for things that were fine for local dev but risky now that it's a real deployment with real phones/devices talking to it. Four fixes, all live in production:

1. **`SECRET_KEY` fail-loud check.** Previously, if `SECRET_KEY` wasn't set, the server silently fell back to a hardcoded `'dev-secret-key'` string — which means anyone could forge a valid JWT (session token, phone session token) just by knowing that string, if the env var was ever accidentally unset in production. Now the server checks `NODE_ENV === 'production'` on boot and calls `process.exit(1)` with a clear error if `SECRET_KEY` is missing, instead of starting up insecurely. Confirmed Railway's `SECRET_KEY` var is set before deploying this.
2. **Removed CORS middleware entirely.** The `cors` npm package and its `app.use(cors())` were left over from early scaffolding; there's no browser client — only the native iOS app and ESP32 firmware talk to this API — so CORS (a browser-only enforcement mechanism) does nothing useful here and was reflecting every origin by default. Removed the middleware, the import, and the `cors` dependency from `package.json`. (Note: `https://physicalkey-core-production.up.railway.app` still shows an `Access-Control-Allow-Origin: *` header on responses — confirmed via `curl -D -` that this is added by Railway's own edge proxy [`server: railway-hikari`], not by the app. Not something app code controls; harmless since there's no browser client to exploit it.)
3. **Dedicated auth rate limiting.** The existing general limiter (100 req/15min per IP) covers the whole API. Added a stricter, dedicated limiter (20 req/15min per IP) specifically on `/auth/phone/challenge`, `/auth/phone/verify`, and `/auth/device/verify` — the three endpoints an attacker would actually hit to brute-force or enumerate device/phone identities.
4. **JWT algorithm pinned.** Both `jwt.sign()` calls now pass `algorithm: 'HS256'` explicitly, and both `jwt.verify()` calls (`requireAuth`, `requirePhoneSession`) now pass `{ algorithms: ['HS256'] }`. Without this, a library/config change down the line could silently widen what algorithms are accepted (including `alg: none`, a classic JWT bypass).

Verified via the full 33-test suite (`npm test`, `NODE_ENV=test` bypasses the new stricter auth limiter so tests aren't rate-limited) before deploying, then confirmed live: `/health` returns 200, general rate-limit headers present (`x-ratelimit-remaining`), server didn't crash-loop on boot (SECRET_KEY check passed).

Commit: `435a28d`.

## Team accounts (2026-08-04)

The landing page has marketed a "Team" pricing tier ($149) since it was built, but the
backend only ever had single-device Solo identities — no account grouping, no
membership, no way to revoke one person's access without touching their device
directly. This adds the actual data model and API; **deliberately backend-only** —
no landing page checkout, no payments, no app UI. Those are separate, larger pieces of
work.

**The model** supports both shapes a team plausibly needs, as the same underlying
mechanism rather than two separate features:
- *Everyone has their own key* — each member's physical device gets one `device_access`
  grant (themselves only). Functionally like a bunch of independent Solo pairs, just
  grouped under one org for visibility and centralized revocation.
- *One shared key* (e.g. an office door) — one physical device, multiple `device_access`
  rows, one per member allowed to use it.

Four new tables in `lib/db.js`: `organizations`, `organization_members` (role:
owner/admin/member, status: active/revoked), `organization_devices` (a device belongs to
at most one org), `device_access` (per-member grants on a specific org device — this is
the table that actually decides who can use what). Owners/admins get implicit access to
every device in their own org without needing an explicit grant row; plain `member`-role
phones need one.

**A real authorization layer, not just bookkeeping.** Before this, `/auth/device/verify`
only checked that the phone and the device were each genuinely who they claimed to be
(authentication) — nothing stopped ANY successfully-authenticated phone from pairing
with ANY successfully-authenticated device (BLE physical proximity was the only real
gate). Now, once a device is claimed by an org, there's a second check: is *this specific
phone* authorized for *this specific device*? A personal (Solo, non-org) device is
completely unaffected — this is additive, not a behavior change for existing users.

**Org management works from just a phone, deliberately.** `/auth/phone/verify`'s
response now also includes a `phoneSessionToken` (1h expiry, `scope: 'phone_session'`)
— separate from the existing `sessionToken` from `/auth/device/verify` (`scope:
'full_access'`, needed for git credentials and the org-authorization-gated
`/api/profile`). Revoking a departing team member's access is exactly the kind of thing
someone needs to do from their phone alone, without their own physical key device on
hand — so org endpoints accept the lighter phone-only session, not the full one.

**API** (all except `POST /orgs` require an active membership in `:orgId`; mutations
require `owner`/`admin` role):
```
POST   /orgs                                    { name } -> org (caller becomes owner)
GET    /orgs/:orgId                              -> org + members + devices
POST   /orgs/:orgId/members                      { deviceId, role? } -> add/reactivate a member
DELETE /orgs/:orgId/members/:deviceId            -> revoke (soft) — cannot target the owner
POST   /orgs/:orgId/devices                      { deviceId } -> claim an already-registered device for this org
DELETE /orgs/:orgId/devices/:deviceId            -> release it back to unrestricted personal-device behavior
GET    /orgs/:orgId/devices/:deviceId/access     -> list who's been granted this device
POST   /orgs/:orgId/devices/:deviceId/access     { memberDeviceId } -> grant
DELETE /orgs/:orgId/devices/:deviceId/access/:memberDeviceId -> revoke one grant
```

13 new tests in `test/organizations.test.js` cover both access shapes (exclusive and
shared), role enforcement (member vs admin vs owner), the owner-can't-self-remove guard,
revoked-membership overriding a still-present device grant, device removal clearing its
grants, double-claim rejection, and confirming personal devices stay fully unrestricted.
All 33 backend tests (20 existing + 13 new) pass, including 3 repeated full runs to rule
out flakiness in the new server-restart-adjacent test setup.

**One infrastructure fix needed along the way**: the global rate limiter (100
requests/15min, protects against real abuse) was tripping on the org test file alone,
since a single test exercising a full org lifecycle (create, add several members, claim
a device, grant/revoke access, multiple auth flows) easily exceeds 100 requests within
one server instance's lifetime — nothing to do with what the limit actually protects
against. Skipped only when `NODE_ENV=test` (set exclusively by `test/helpers.js`);
production and normal local dev are unaffected.

## Automated test suite + CI (2026-08-04)

Until now, backend correctness was only ever checked by manually running the scripts in
`backend/scripts/` against a live server (usually production) and reading the console
output — no real assertions, no CI, easy to skip, and (as the trust-on-first-use section
below shows) sometimes accidentally exercised against whatever server happened to be
running on `localhost:3000`, including a stray leftover dev process from earlier in this
session.

**`backend/test/`** — a real `node:test` suite (Node's own built-in test runner, zero new
dependencies, matching how this project already prefers built-ins like `node:sqlite` over
adding libraries):
- `helpers.js` — spawns a *real* `node server.js` child process against an isolated,
  throwaway SQLite directory (`PK_DATA_DIR`, a small additive env-var override in
  `lib/db.js` — unset in normal dev/production, so a no-op there) on a random port. Never
  touches the real local dev database or production.
- `crypto-flow.test.js` — Ed25519 challenge/response, forged-signature rejection, replay
  rejection, trust-on-first-use hijack rejection.
- `git-forensics.test.js` — git credential issuance/validation, admin-only access control
  on `/admin/forensics` (403 non-admin, 401 no token), attacker technique data actually
  populates (regression check for a real bug fixed earlier this session where a `Set`
  wasn't serializing).
- `persistence.test.js` — a **real process kill + restart** against the same on-disk data
  directory (not an in-memory reset), confirming identities/git-credentials/honeypot
  events survive and a post-restart hijack attempt is still rejected.
- `admin-identities.test.js` — the `GET`/`DELETE /admin/identities/:deviceId` endpoints
  (added the same day, see the section below): full register → inspect → reset → confirm
  gone → re-register-with-a-different-key cycle, plus unauthenticated-request rejection.

Run locally: `cd backend && npm test` (20 tests, ~0.5s). **CI**:
`.github/workflows/backend-tests.yml` runs the same command on every push/PR that touches
`backend/**`, on Node 26 (matching the Dockerfile's `node:26-alpine`, not just the
`package.json` engines floor).

## Trust-on-first-use lockouts, and the fix (2026-08-04)

**The bug, as a user hit it:** after re-flashing 3 ESP32 boards to enable flash+NVS
encryption (see `hardware/README.md`) — which requires a full chip erase, regenerating
each board's Ed25519 identity — pairing got stuck in a loop: Face ID kept succeeding,
Bluetooth pairing kept succeeding, but the backend kept rejecting with "Device
verification failed" / "Phone verification failed" for no visible reason. Same root
cause hit a phone identity earlier for an unrelated reason (its local Keychain identity
ended up not matching what the backend had on file).

**Root cause:** trust-on-first-use (see the persistence section below) is deliberately
permanent — the whole point is that a restart or an attacker can't hijack an
already-registered `deviceId` by re-registering a different key. But that same property
means there was no way to distinguish "an attacker trying to steal this deviceId" from
"the real owner's key legitimately changed" (a re-flashed board, a recreated phone
identity) — both look identical to the backend: same `deviceId`, different key,
signature no longer matches. Confirmed directly, not guessed: added a temporary debug
log printing the exact registered key / challenge / signature bytes, redeployed,
reproduced the failure, and independently re-ran the same `crypto.verify()` call
locally — genuinely a non-matching signature, not a formatting/encoding bug.

**The fix — two parts:**
1. **Immediate**: reset the specific stale identities directly (initially via `railway
   ssh` + a one-off `node:sqlite` script against the production DB file, since no admin
   tooling existed yet for this).
2. **Proper**: added real admin endpoints so this never needs raw DB surgery again —
   `backend/auth/identity-admin.js` + two routes in `server.js`:
   - `GET /admin/identities/:deviceId` — inspect a registration (404 if none).
   - `DELETE /admin/identities/:deviceId` — reset it, so the *next* auth attempt
     re-registers fresh via trust-on-first-use. Still requires full admin auth
     (`requireAdmin`, same JWT-as-`ADMIN_DEVICE_ID` gate as `/admin/forensics`) — this
     is a deliberate, narrowly-scoped exception to the lock, not a bypass of it: you
     still need to know the exact `deviceId` and be authenticated as the admin device,
     and whoever registers next after a reset owns that identity from then on.

   Tested end-to-end against production with a real admin session (register a throwaway
   identity → admin GET finds it → admin DELETE resets it → GET now 404 → confirmed
   *without* a valid admin token both routes correctly 401).

**Example usage** (needs a valid admin `sessionToken` — see `scripts/test-crypto-flow.js`
for how to complete the phone+device auth flow, or reuse `keys/admin-device.key.pem` /
`keys/admin-phone.key.pem` if a session already exists for `demo-device-admin-001`):
```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://physicalkey-core-production.up.railway.app/admin/identities/physicalkey-device-680947e0684c

curl -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://physicalkey-core-production.up.railway.app/admin/identities/physicalkey-device-680947e0684c
```

**When you'll hit this again:** any time an ESP32 board's flash gets erased
(re-flashing alone doesn't erase NVS and is fine; `erase-flash` does), or a phone's
Keychain identity gets recreated — that deviceId's *old* registration needs resetting
via the endpoint above before it can pair again. Not automatic on purpose — an
automatic "any new key wins" policy would defeat the actual security property
trust-on-first-use exists for.

**Also set up along the way**: an SSH key (`~/.ssh/id_ed25519`) registered with Railway
(`railway ssh keys add`) for direct container access (`railway ssh -- <command>`) —
useful for exactly this kind of direct-DB diagnosis in the future, now that it exists.
This is also what the "not worth chasing" honeypot-cleanup note below was blocked on;
that's unblocked now too, if it's ever worth doing.


**Setup completed at:** 2026-08-03 11:32 UTC
**Status:** Backend running locally. Not everything in the original test list passed — see below.

**Location:** `~/physicalkey-core/backend` (this machine had no `/mnt/user-data/outputs/...` — that path belonged to a different, disconnected session, so the project was rebuilt here from scratch using the exact file contents you pasted).

**Prerequisite installed:** Node.js was not present on this Mac at all. Installed via `brew install node` (v26.5.1 / npm 11.17.0) after checking in with you.

**One code fix required:** `package.json` originally pinned `jsonwebtoken@^9.1.0`, which doesn't exist on npm (latest is `9.0.2`). Changed to `^9.0.2` so `npm install` would succeed.

## Deployment (2026-08-03 22:22 UTC)
Live at **https://physicalkey-core-production.up.railway.app** on Railway, with a persistent volume so this isn't just `localhost` anymore.

- **Dockerfile pinned to `node:26-alpine`** rather than trusting whatever Node version Railway's auto-detection (Nixpacks) would have picked — `node:sqlite` needs to actually be available and stable, so this removes that guesswork entirely.
- **Persistent volume** (`physicalkey-core-volume`, 5GB) mounted at `/app/data`, matching where `lib/db.js` resolves the SQLite file. Verified with the same kind of test as the local persistence check, but against a *real* Railway restart (`railway service restart`, confirmed same deployment ID before/after — not a rebuild): identities, git credentials, and honeypot logs all survived.
- **Real production secrets**: generated a proper random `SECRET_KEY` (`crypto.randomBytes(48)`) and set it as a Railway environment variable — not the `dev-secret-key-change-in-production` placeholder from `.env`, which never leaves this machine (still gitignored, and Railway's variables are separate from it).

**Two bugs only showed up once this was actually behind a real reverse proxy** — neither reproduces on `localhost`, which is exactly why deploying was worth doing rather than stopping at "works on my machine":

1. **Honeypot IP tracking was useless in production.** `req.ip` resolved to Railway's rotating internal proxy addresses instead of the real client IP — every request from the same test script looked like a different attacker (`uniqueIPs` inflating on every call). Root cause: no `trust proxy` setting at all initially, so Express used the raw socket peer (an internal `100.64.0.x` address), not `X-Forwarded-For`.
2. **First fix caused a full outage.** Setting `trust proxy: true` (trust the whole forwarded chain) seemed like the right fix, but `express-rate-limit` — mounted globally ahead of every route including `/health` — hard-rejects that as unsafe (`ERR_ERL_PERMISSIVE_TRUST_PROXY`, since an unbounded trust setting is spoofable for rate-limit bypass) and threw on every single request. Production was fully down (`/health` itself timed out) for a few minutes until this was caught via `railway logs` and fixed.

**Actual fix**: `trust proxy` stays a small bounded number (`1`) — safe for `express-rate-limit`, since that's what it's actually protecting. Honeypot logging uses a separate `getClientIp()` helper (in `honeypot/logger.js`, exported for reuse) that reads the real client IP directly from the leftmost `X-Forwarded-For` entry — decoupled from Express's trust-proxy hop-counting, and not used for any access-control decision, so it doesn't carry the same spoofing risk that matters for rate-limiting. Verified live: 21 consecutive test requests all correctly attributed to the one real client IP (`73.118.250.122`), not 12 different ones.

**Known cosmetic leftover, not fixed**: the honeypot log on production still has ~40 stale entries from before this fix, logged with the wrong (rotating internal) IPs. Attempted to clear them via `railway volume files delete`, but that subcommand needs an SSH key I haven't set up — not worth chasing for a cleanup with no real users affected. `totalAttempts`/`uniqueIPs` in `/admin/forensics` will look inflated until that data ages out or someone clears the volume manually.

**Two CLI bugs hit along the way** (Railway CLI v5.30.4, not this codebase): `railway volume add -s <service-name>` crashes with a Rust panic (`Option::unwrap() on a None value`) — works fine with explicit UUIDs (`-p <project-id> -e <env-id> -s <service-id>`) instead of names.

To redeploy after future changes: `cd ~/physicalkey-core/backend && railway up --detach -y`. To check status: `railway status`. To watch logs: `railway logs`.

## Persistence (2026-08-03 21:37 UTC)
All state now survives a server restart, backed by `node:sqlite` (built into Node 22+/26 — **zero new npm dependencies**). Database file: `backend/data/physicalkey.db` (gitignored, local runtime data, not source).

- **What's persisted**: registered phone/device identities (public keys + status), git credentials (hashed, see below), honeypot events (used to derive both the summary and attacker profiles — no separate table to drift out of sync).
- **What's still in-memory**: `activeChallenges` (the short-lived, 2-minute phone/device auth challenges in `server.js`). Deliberate — losing an in-flight challenge on restart just means the client re-requests one; no reason to persist something that expires in 2 minutes anyway.
- **Why this actually matters, not just as a formality**: before this, restarting the server silently wiped every registered device's public key. That meant an attacker who could trigger a restart (crash, deploy, etc.) could re-register an already-trusted `deviceId` under a *new* key — full impersonation via restart. Persisting registrations closes that. Verified directly: after a real process kill + restart, re-authenticating a previously-registered device with its original key succeeds, and attempting to hijack that same `deviceId` with a *different* key is correctly rejected.
- **Git password hashing added**: moving credentials from RAM to a file on disk changes the risk profile, so git passwords are no longer stored in plaintext — salted `scrypt` hash (`crypto.scryptSync` + `crypto.timingSafeEqual`, both built into `node:crypto`, no new dependency) with the plaintext returned to the caller only once, at issuance.

**Verified live** via `node scripts/test-persistence.js register`, then a real `kill -9` of the server process (not just an in-process reset) followed by `npm start`, then `node scripts/test-persistence.js verify`:
- Git credentials issued before the restart still validate against `/git/auth` afterward
- Re-authenticating the same `deviceId` with its original persisted key → succeeds
- Attempting to hijack that `deviceId` with a freshly generated, different key → 401 rejected
- Honeypot events logged before the restart are still visible in `/admin/forensics` afterward

New script: `scripts/test-persistence.js` (two-phase: `register` before restart, `verify` after). Also fixed both existing test scripts (`test-crypto-flow.js`'s admin path was unaffected; `test-git-forensics.js` needed a fix) to be idempotent against a persistent database — previously they unconditionally regenerated the admin device's keypair on every run, which is harmless against an in-memory store that resets anyway but breaks against a real database (the new key on disk no longer matches the one already bound in storage, which is correctly rejected). Confirmed `test-git-forensics.js` now passes when run twice in a row without a database reset in between.

## Cryptographic Auth Upgrade (2026-08-03 11:40 UTC)
Phone and device signature verification is now **real Ed25519 public-key challenge-response**, not string-presence checking.

- Server generates a genuine random 32-byte challenge (`crypto.randomBytes`, replacing the old `Math.random()`-based one) for both the phone and device stage.
- Client (phone/device) signs the challenge with an Ed25519 private key; server verifies the signature against a registered public key using `crypto.verify()`.
- First contact from a given `deviceId` (phone or IoT device) must include its public key (base64-encoded SPKI DER) — trust-on-first-use registration. After that, only a valid signature from the matching private key is accepted.
- Every challenge is now consumed on **every** code path (success or failure), fixing a replay gap where a failed phone-verify attempt used to leave the original challenge re-usable.
- **What this is not:** real Apple App Attest / Google Play Integrity. Those require an actual iOS/Android app plus server calls to Apple's/Google's attestation backends — not something testable from a laptop with curl. This gives genuine cryptographic proof-of-possession of a private key, which is the concrete, verifiable part of the "cryptographic" layer in the original spec.

**Verified live**, via `node scripts/test-crypto-flow.js` (full output captured, not just described):
- Forged phone signature → 401 `Phone verification failed` (correctly rejected)
- Valid phone signature → 200, issues `deviceChallengeId`
- Forged device signature → 401 `Device verification failed` (correctly rejected)
- **Replay**: reusing an already-consumed `deviceChallengeId`, even with a *valid* signature → 401 `Device challenge invalid` (correctly rejected — proves one-time-use)
- Full valid run → 200, issues `sessionToken` + `gitCredentials`; `/api/profile` with that token → `authenticated: true`
- Confirmed the **old** insecure bypass is gone: a plain string like `"demo-signature-123"` with no registered public key now gets 401, not 200 (previously this was silently accepted)

New helper scripts (no new npm dependencies — built on Node's `crypto`, `fs`, and global `fetch`):
- `scripts/keygen.js <name>` — generates an Ed25519 keypair, saves the private key to `keys/<name>.key.pem`, prints the public key
- `scripts/sign.js <name> <message>` — signs a message with a saved private key, prints the base64 signature
- `scripts/test-crypto-flow.js` — automated end-to-end proof (happy path + forged-signature + replay checks)

## Git + Forensics Endpoints Wired Up (2026-08-03 12:52 UTC)
Both were previously dead code (defined in `git/git-credentials.js` / `honeypot/logger.js` but no route ever called them). Now real:

- **`GET /git/auth`** — the callback a git server (e.g. Gitea) would hit with the client's Basic Auth credentials to decide whether to allow a clone/push. Validates against the `gitCredentials` issued by `/auth/device/verify` (real random 24-byte password via `crypto.randomBytes`, replacing the old 5-6 char `Math.random().toString(36)` password). Wrong password, missing credentials, and expired credentials are all rejected (401) and logged to the honeypot.
- **`GET /admin/forensics`** — requires a valid session token *and* that the authenticated `deviceId` matches `ADMIN_DEVICE_ID` from `.env`; non-admin devices get 403, no token gets 401. Returns the real honeypot summary, recent events, and attacker profiles.
- **Bug fixed along the way**: `attackerProfiles` tracked a `techniques` `Set` that was created but never populated, and would have silently serialized to `{}` in the forensics JSON response. Now `activateHoneypot()` actually adds each `reason` to it, and `suspicionLevel` is recalculated (`low`/`medium`/`high`) based on attempt count instead of being hardcoded to `'medium'` forever.
- **Response shape change**: `gitCredentials` from `/auth/device/verify` now returns `{username, password, scope, repositories, createdAt, expiresAt}` instead of the old `{username, password, expiresIn}` — more informative, but a breaking change if anything already depended on the old shape (nothing does yet).
- Removed the old `gitCredentialHandler` middleware (it accepted *any* non-empty `Authorization` header as valid — no actual check) since it's fully superseded by real credential validation.

**Verified live**, via `node scripts/test-git-forensics.js`:
- `/git/auth` with valid credentials → 200 `granted: true`
- `/git/auth` with wrong password → 401 (rejected)
- `/git/auth` with no credentials → 401 (rejected)
- `/admin/forensics` as a regular (non-admin) authenticated device → 403 (blocked)
- `/admin/forensics` with no token → 401
- `/admin/forensics` as the admin device (`demo-device-admin-001`) → 200, with a real attacker profile showing `techniques: [...]` actually populated (confirming the Set-serialization bug is fixed) and `suspicionLevel` computed from attempt count

## Backend Status
- Server: RUNNING on http://localhost:3000 (PID 24842, `node server.js` via `npm start`)
- Health Check (`GET /health`): PASS — 200, `{"status":"online",...}`
- Status Endpoint (`GET /status`): PASS — 200, `{"status":"operational",...}`
- Auth Requirements (`GET /auth/requirements`): PASS — 200

## Authentication Flow Tests
- Phone Challenge (`POST /auth/phone/challenge`): PASS — returned `challengeId` + `challenge`
- Phone Verification (`POST /auth/phone/verify`): PASS — returned `deviceChallengeId` + `deviceChallenge`
- Device Verification (`POST /auth/device/verify`): PASS — returned `sessionToken` + `gitCredentials`
- Session Token: ISSUED (JWT, 24h expiry)
- Git Credentials: ISSUED (`{username, password, expiresIn}`)
- Protected Endpoint with valid token (`GET /api/profile`): PASS — 200, `"authenticated": true`
- Protected Endpoint with no token: PASS (correctly rejected) — 401 `{"error":"Unauthorized"}`
- Protected Endpoint with garbage token: PASS (correctly rejected) — 401 `{"error":"Invalid token"}`

## Honeypot
- Failed-auth logging: PASS — every rejected `/api/profile` request triggers `activateHoneypot()` and logs `🎭 HONEYPOT ACTIVATED: ... from IP: ::1` to the server console/log with reason and IP.
- `GET /api/honeypot/fake-database`: **PASS (fixed 2026-08-03 11:35 UTC)** — added the missing route to `server.js`. Returns 200 with decoy data (`_decoy: true`, fake user records) and logs `🎭 HONEYPOT ACTIVATED: Honeypot endpoint accessed` with the requester's IP.
- Still unused/not wired into any route: `getHoneypotSummary()` (`honeypot/logger.js`), `gitCredentialHandler` (`git/git-credentials.js`), and everything in `access/device-access.js` — all defined but not called from anywhere. Not a bug, just dead code from the original spec; only worth touching if you want an `/admin/forensics`-style dashboard or real git-scope/tier enforcement.

## What Actually Got Built
```
~/physicalkey-core/backend/
├── server.js
├── package.json
├── .env
├── auth/phone-auth.js
├── auth/device-auth.js
├── honeypot/logger.js
├── git/git-credentials.js
└── access/device-access.js
```
Signature verification is now real Ed25519 crypto (see above). Everything else about this remains a **local demo**: no real Apple App Attest / Google Play Integrity, and all state (challenges, devices, honeypot logs, git tokens, registered public keys) lives in memory and resets on server restart. Fine for local testing; still not production-grade (no persistence, no rate-limit tuning, no TLS, no real IoT hardware).

## To Restart Server
```bash
cd ~/physicalkey-core/backend
npm start
```
Server runs on http://localhost:3000. (It's currently still running in the background from tonight's session — PID 23047 — so you likely don't need to restart it unless the Mac reboots or the process is killed.)

## Not Done Tonight (out of scope / not requested with real content)
- No IoT hardware, CAD files, firmware, mobile app code, marketing copy, or business plan was generated — none of that existed as actual files, only as descriptions in the docs you'd downloaded, and wasn't part of tonight's code request.
- No deployment (Railway/Vercel/Docker), no real Git server (Gitea), no database — everything above is in-memory and local-only.
