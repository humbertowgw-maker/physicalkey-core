# CHECKPOINT — where PhysicalKey actually stands

A short, current status board — not a log. `SETUP_COMPLETE.md` has the full history;
this file is just "what's true right now" so nothing gets re-litigated or re-run by
accident. Update this whenever status changes; keep old detail in `SETUP_COMPLETE.md`,
not here.

**Last updated:** 2026-08-14

**Priority call from Humberto (2026-08-12): Stripe/checkout is now the LAST step, not
the next one — focus on finishing the actual product first.** A DNS ENOTFOUND report
earlier the same day was never reproduced (Railway logs clean, both relevant domains
resolve fine) and Humberto confirmed it was just an "is anything wrong" check, not tied
to PK — dropped, don't chase it.

## ✅ Confirmed, don't re-verify

- **Phase 1 (Authentication): closed 2026-08-10.** 127/127 backend tests.
- **Secure Enclave P-256 + BLE MITM passkey pairing: proven end-to-end on real
  hardware (2026-08-12).** Board `...0684c`'s first-ever bonding — Face ID sign → BLE
  passkey pairing → device signs → backend-verified ratchet → `.authenticated` → real
  git credentials issued — confirmed live via on-device log screenshot. This closed the
  one open item from the 2026-08-07/09 session.
- **All 3 boards now confirmed on current firmware and paired (2026-08-13).** `...03c9c`
  and `...00800` were BOTH found running stale pre-security-fix firmware (`5ec8add`
  2026-08-06 and `8807b67` 2026-08-05 respectively — both before `42496c5` added BLE MITM
  passkey pairing on 2026-08-07). That's why no PIN was asked on first reconnect: plain
  Just-Works pairing, a real security gap on 2 of 3 real boards. Both reflashed with
  `idf.py encrypted-flash` (identities survived — NVS untouched), fresh passkeys
  generated, Humberto forgot the stale iOS bonds and re-paired. Both confirmed
  independently via backend data (`last_seen`/`access_count` moved at the exact retry
  moment, no signature-error events nearby), not just his reports.
  **`...00800`'s flash failed mid-write once first** ("chip stopped responding" — a
  transient connection issue, not a code problem) and boot-looped (`SW_RESET` repeating,
  no app ever starting) — recovered cleanly with a second `encrypted-flash` attempt. Same
  recoverable pattern as the documented `flash`-vs-`encrypted-flash` boot-loop, different
  cause; if a flash ever fails partway through, don't panic, just retry `encrypted-flash`
  after confirming the chip still responds to `esptool.py read_mac`.
  **Implication for the open-hardware/manufacturing plan: don't assume a board is running
  current firmware just because it boots and has an identity — check the boot log's `App
  version` against `git log` before trusting it, especially before shipping one to anyone.**
- **Landing page checkout fixed (2026-08-12).** `physicalkey-landing/index.html`'s
  `API_BASE` was a dead placeholder; now points at the real Railway backend. Committed,
  pushed, deployed, confirmed live.
- **Apple Developer Program: real, paid enrollment exists.** Team "humberto Zepeda",
  ID `9RYL8ZRC3U`, confirmed `isFreeProvisioningTeam: false`. (Earlier in this same
  session I wrongly implied this was missing — corrected after checking Xcode's account
  data directly. Don't re-raise this as a blocker.)

## 🔴 Blocked on Apple / Humberto

1. **Beta App Review is in progress for build 1.0 (1).** Submitted 2026-08-13/14 (see
   below for full detail). Status confirmed live in App Store Connect on 2026-08-14:
   **"Waiting for Review"**, expires in 90 days if untouched. Typical turnaround
   24–48h from submission for a first build, sometimes longer. Nothing actionable
   until Apple responds (approval, rejection, or a reviewer question) — don't
   re-check obsessively, just check back when there's a reason to (email
   notification, or after ~48h).
2. ~~Confirm the 2 "unconfirmed attacker" honeypot IPs~~ — **done 2026-08-14.** Humberto
   confirmed. `KNOWN_INTERNAL_IPS` on Railway is now
   `73.118.250.122,152.233.76.10,166.198.252.53`. Verified live: `/admin/forensics` now
   reports `internalIPs: 13` out of `13` unique IPs ever logged — zero external
   attackers currently, honestly. No open items remain from this session's pentest.

## ✅ Live penetration test of production + fixes, real results (2026-08-14)

Ran an authorized, read-only/non-destructive security assessment directly against
`physicalkey-core-production.up.railway.app` — live probing plus read-only prod DB/log
inspection via `railway ssh` (not code review alone). Full writeup with evidence is in
the two artifacts published this session (security assessment + market/competitive
report) — ask if the links are needed again, they're not duplicated here.

**One real finding, fixed and deployed same day:** `POST /auth/phone/challenge` only
checked `phoneAttestation` for truthiness — a bare string passed and still got a real
challenge minted into the in-memory `activeChallenges` map, which was previously *only*
cleaned up lazily (on a matching `/verify` call that garbage input will never trigger).
Fixed in `backend/server.js`: the endpoint now validates `phoneAttestation` is an object
with real `platform`/`deviceId` strings before storing anything, and a `setInterval`
sweep (every 60s) now actively prunes expired challenge entries regardless of whether
verify was ever called. Also fixed while in there: malformed JSON bodies now return 400
(`Invalid JSON body`) instead of a generic 500 — cosmetic, no info leak, but wrong status
code. **3 new tests added** (`backend/test/crypto-flow.test.js`), **132/132 passing**.
Deployed via `railway up`, confirmed live against production with real curl requests
(not just local tests) — both fixes verified working on the actual prod URL.

**Everything else tested came back clean, confirmed live not assumed:** Helmet security
headers, TLS 1.3, all 3 admin endpoints correctly reject unauthenticated calls, JWT
forgery (`alg:none`, garbage, empty bearer) all rejected, no exposed `.env`/`.git`/db
file over HTTP, honeypot git-http-backend path traversal is **not exploitable** (encoded
attempt reached the app and was cleanly rejected by git's own dispatch table — confirmed
via prod logs; raw attempt never reached the app at all, blocked at Railway's edge
layer), no permissive CORS, `npm audit` = 0 vulnerabilities, `/auth/repair/challenge`
properly requires real pre-existing paired identities (not exploitable the same way as
phone/challenge).

**Real end-to-end test results, all suites re-run live today (not carried forward from
memory):**
- Backend: 132/132 (129 + 3 new from the fixes above)
- iOS (`xcodebuild test` on iPhone 17 Pro Simulator): 20/20, zero failures
- Firmware host-tests (native compile, no board needed): all passed, including the
  X25519 ratchet derivation, continuity-across-sessions, and weak-key-rejection checks

**Honeypot forensics re-examined with real data (not the earlier "unconfirmed" framing):**
all 13 IPs ever logged reviewed directly against the prod DB via `railway ssh`. 11 were
already correctly internal (CGNAT + configured dev IP). The 2 previously-"unconfirmed"
IPs (`152.233.76.10`, `166.198.252.53`) are almost certainly Humberto's own test-script
traffic, not real attackers: every logged event for both is `statusCode: 200`
(successful, not failed/malicious), and one event for `152.233.76.10` carries
`deviceId: "git-test-device-2dj3st"` — the exact naming convention
`scripts/test-git-forensics.js` generates. **Net conclusion: zero confirmed real external
attacker traffic exists in the honeypot as of today.** Phase 2's "collect attacker
techniques / publish forensics" has nothing real to write up yet — that's an honest
status, not a gap to manufacture data for. Revisit once the honeypot logs something with
failed/malformed requests instead of clean 200s.

## ✅ TestFlight build submitted for Beta App Review (2026-08-13/14)

**Export compliance answered.** "Standard encryption algorithms instead of, or in
addition to, using or accessing the encryption within Apple's operating system" — correct
per the app's actual crypto (P-256 ECDSA via Secure Enclave, X25519 + HMAC-SHA512 ratchet
— all standard/published algorithms, not proprietary, and implemented beyond just calling
iOS's built-in HTTPS). France distribution question: Humberto answered directly in the
UI, not captured here — check App Store Connect if it matters later.

**Individual tester added → this became an External Testing / Beta App Review flow.**
Using "Add New Testers" (email-invite) rather than adding an org team member triggers
Apple's Beta App Review, not just internal-testing (which would've skipped review
entirely — worth remembering for future builds where a fast internal-only loop is
wanted: add testers as App Store Connect team members via Users and Access instead).

**Real blocker surfaced and solved: no username/password exists for PhysicalKey.** Auth
is Face ID + BLE pairing with a physical ESP32 key, not a traditional login, so the
review form's "Sign-in required" checkbox was unchecked and the Beta App Description
instead explains the hardware requirement and offers a live demo / loaner device via
contact info (Humberto Zepeda, `achilleszepeda@icloud.com`, phone on file in the
submission — not duplicated here). **If Apple's review bounces asking for sign-in
credentials or hardware access, that's the open question to resolve — offering a demo
call is the fallback, not yet tested against a real reviewer response.**

Submitted via the "Submit for Review" button in App Store Connect → TestFlight → iOS
Builds → 1.0 (1); confirmed via the "Remove from Review" button now showing in place of
"Submit for Review" plus a success banner.

## ✅ TestFlight build uploaded — first submission done (2026-08-13)

**App Store Connect app record created.** Humberto logged in (2FA), I filled the New App
form and he picked User Access: iOS, name "PhysicalKey", English (U.S.), bundle ID
`com.physicalkey.app` (was already registered from earlier archive attempts), SKU
`physicalkey-ios-001`, Full Access. This unblocked everything downstream.

**Archived, exported, and uploaded end-to-end, same session:**
```bash
xcodebuild -project PhysicalKey.xcodeproj -scheme PhysicalKey -sdk iphoneos \
  -configuration Release -destination "generic/platform=iOS" \
  -archivePath build/PhysicalKey.xcarchive -allowProvisioningUpdates archive
# ** ARCHIVE SUCCEEDED **

xcodebuild -exportArchive -archivePath build/PhysicalKey.xcarchive \
  -exportPath build/export -exportOptionsPlist ExportOptions.plist \
  -allowProvisioningUpdates
# Upload succeeded. Uploaded PhysicalKey. ** EXPORT SUCCEEDED **
```
`mobile/ios/ExportOptions.plist` now has `destination: upload` (added once the app
record existed — previously deliberately left out, see file's own comment history).
Archive signed automatically with team `9RYL8ZRC3U`'s development identity; export
re-signed with App Store distribution profile, all non-interactive via
`-allowProvisioningUpdates`. Nothing left to rediscover about this path — it's proven,
reusable for every future build: bump the version/build number in Xcode, re-run both
commands.

Apple's server-side processing typically takes 15–60 min after upload before the build
shows up under TestFlight and is assignable to testers.

## ⏸ Deprioritized to last, by explicit instruction (2026-08-12) — don't chase

- **Stripe/checkout activation** (test-mode credentials → wire into Railway → verify
  real checkout end-to-end). Code side is done and waiting; Humberto said this is the
  last step, after the product itself is finished.

## ✅ Landing page updated to match (2026-08-13)

`physicalkey-landing`'s roadmap section still said "the hardware is being assembled" —
stale as of yesterday's real end-to-end bonding confirmation and the MIT hardware
license. Now says the device flow is proven and links to `hardware/` as open source /
build-your-own. Deployed and confirmed live.

## ✅ Hardware/manufacturing path — decided (2026-08-13)

DIY: 3D-print enclosures + source parts from Alibaba (~$100 to start), open-source the
hardware design so the community can build/verify/improve it too, pre-order launch later
— *after* a small self-built batch is proven, not before. `hardware/README.md`'s "Building
it yourself" section is now a real guide for this (BOM callout still needs Humberto's
actual sourcing link — flagged as a TODO in the file itself). **Still open:** the exact
Alibaba listing/part number.

## ⚪ Not started — real scope, not a quick task

- **Phase 2 remainder:** honeypot is live and logging, but "collect attacker
  techniques" / "publish forensics" are still unchecked — see the note below, there's
  no real attacker data yet.
- **Phase 3 (Physical Access):** PKA-Lock, PKA-Safe. Zero code exists for this.
- **Phase 4 (Public Launch):** Product Hunt, technical write-ups. Depends on App Store
  approval landing first.
- **Third-party security audit** — roadmapped Oct 2026, nothing scheduled.

## ✅ Also confirmed, don't re-verify (added after the priority reset above)

- **License split done (2026-08-13).** `hardware/` (firmware, schematics, BOM) is MIT —
  fully open, build/sell your own boards, no restriction. Everything else (backend,
  mobile app) moved from plain MIT to Business Source License 1.1 — free to self-host
  for your own use, blocked from being resold as a competing hosted service, converts
  to Apache 2.0 on 2030-08-13. Pushed to `main`. **Not lawyer-reviewed** — this uses the
  standard, widely-adopted BUSL 1.1 template (same one Sentry/CockroachDB use) with one
  customized clause (the "Additional Use Grant"); fine for now, but worth a real lawyer's
  eyes before it matters for an actual dispute or funding round.

- **Honeypot forensics no longer reports our own traffic as attacker data (2026-08-13).**
  `/admin/forensics` now excludes known-internal IPs by default — our own dev IP
  (`KNOWN_INTERNAL_IPS` env var on Railway) and the CGNAT range `100.64.0.0/10`
  (structurally can't be a real internet attacker's source IP). `summary.internalIPs`
  shows the excluded count; `?includeInternal=true` still surfaces everything for
  debugging. Verified live on production: went from 13 "attacker" IPs to 2 real
  unconfirmed ones (`152.233.76.10`, `166.198.252.53` — left in, not confident enough
  they're also us to hardcode them out). 2 new tests, 129/129 passing. **Note:** getting
  this live required `railway up` from `backend/`, not just `railway variables --set` —
  the latter only restarts the existing image with new env vars, it does NOT rebuild
  from the latest git push. Remember this next time a code change needs to reach
  production.

## Known, deliberately deferred (not gaps — don't re-propose these)

KMS/HSM-backed signing key, quantum-resistant crypto, and hardware tamper detection are
all explicitly 2027/PKA-Ultra-tier roadmap items per `SECURITY.md`. Factory device
attestation needs a real manufacturing relationship. None of these are things to "just
go implement."
