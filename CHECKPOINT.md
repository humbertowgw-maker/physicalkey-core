# CHECKPOINT — where PhysicalKey actually stands

A short, current status board — not a log. `SETUP_COMPLETE.md` has the full history;
this file is just "what's true right now" so nothing gets re-litigated or re-run by
accident. Update this whenever status changes; keep old detail in `SETUP_COMPLETE.md`,
not here.

**Last updated:** 2026-08-12

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
- **Landing page checkout fixed (2026-08-12).** `physicalkey-landing/index.html`'s
  `API_BASE` was a dead placeholder; now points at the real Railway backend. Committed,
  pushed, deployed, confirmed live.
- **Apple Developer Program: real, paid enrollment exists.** Team "humberto Zepeda",
  ID `9RYL8ZRC3U`, confirmed `isFreeProvisioningTeam: false`. (Earlier in this same
  session I wrongly implied this was missing — corrected after checking Xcode's account
  data directly. Don't re-raise this as a blocker.)

## 🔴 Blocked on Humberto — can't proceed without this

1. **Confirm PhysicalKey's actual App Store Connect / TestFlight status.** This Mac has
   *zero* local evidence PhysicalKey was ever archived or uploaded — no
   `~/Library/Developer/Xcode/Archives` folder at all, Xcode Cloud's local DB is
   completely empty, and no provisioning profile here is scoped to `com.physicalkey.app`
   (only a generic wildcard dev profile). If this happened, it was from a different
   Mac — need Humberto to check App Store Connect directly (I can't log into his Apple
   ID) and report back. This is the real blocker to "finish PK" right now.

## 🟡 Ready to execute the moment the above unblocks

- Archive + upload to TestFlight — steps already written in `mobile/ios/TESTFLIGHT.md`
  — *pending* the App Store Connect status check above (don't start this until that's
  answered, to avoid duplicating an app record that already exists).

## ⏸ Deprioritized to last, by explicit instruction (2026-08-12) — don't chase

- **Stripe/checkout activation** (test-mode credentials → wire into Railway → verify
  real checkout end-to-end). Code side is done and waiting; Humberto said this is the
  last step, after the product itself is finished.

## ✅ Hardware/manufacturing path — decided (2026-08-13)

DIY: 3D-print enclosures + source parts from Alibaba (~$100 to start), open-source the
hardware design so the community can build/verify/improve it too, pre-order launch later
— *after* a small self-built batch is proven, not before. `hardware/README.md`'s "Building
it yourself" section is now a real guide for this (BOM callout still needs Humberto's
actual sourcing link — flagged as a TODO in the file itself). **Still open:** the exact
Alibaba listing/part number, and re-confirming the other 2 boards (`...03c9c`, `...00800`)
are actually re-paired since the encryption migration — don't assume either without
checking.

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
