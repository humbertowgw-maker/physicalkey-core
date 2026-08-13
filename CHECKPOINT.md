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
- **Hardware/manufacturing decision** — no enclosure, no fulfillment path, only 3 bare
  ESP32 dev boards exist. Selling a physical unit needs this, but it's part of the same
  "later" bucket as Stripe.

## ⚪ Not started — real scope, not a quick task

- **Phase 2 remainder:** honeypot is live and logging, but "collect attacker
  techniques" / "publish forensics" are still unchecked — see the note below, there's
  no real attacker data yet.
- **Phase 3 (Physical Access):** PKA-Lock, PKA-Safe. Zero code exists for this.
- **Phase 4 (Public Launch):** Product Hunt, technical write-ups. Depends on App Store
  approval landing first.
- **Third-party security audit** — roadmapped Oct 2026, nothing scheduled.

## 🔵 No dependency, pick up anytime

- Honeypot forensics data (372 attempts, 13 "attacker" IPs as of 2026-08-12) is
  overwhelmingly our own dev/CI traffic, confirmed by matching IPs to this machine's own
  public IP and to CGNAT/internal ranges. Real external attacker data essentially
  doesn't exist yet. Could tag known dev IPs now so future reports are trustworthy the
  moment real traffic shows up — doesn't block anything else.

## Known, deliberately deferred (not gaps — don't re-propose these)

KMS/HSM-backed signing key, quantum-resistant crypto, and hardware tamper detection are
all explicitly 2027/PKA-Ultra-tier roadmap items per `SECURITY.md`. Factory device
attestation needs a real manufacturing relationship. None of these are things to "just
go implement."
