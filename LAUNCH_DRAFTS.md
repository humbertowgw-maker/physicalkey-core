# Launch drafts

Copy-paste-ready drafts for the first wave of free GTM moves, per the market/competitive
report from 2026-08-14. Nothing here has been posted yet — these go out under Humberto's
identity, so posting/submitting is manual. Update this file's status line as each one
goes out; don't let it silently drift stale.

**Status:** none posted yet, as of 2026-08-14.

---

## Show HN

**Title:** Show HN: PhysicalKey – open-hardware key pairing your phone's Secure Enclave to an ESP32

**Body:**

Hi HN — I built PhysicalKey: a physical authentication device where your iPhone's
Secure Enclave (Face ID-gated P-256 key) pairs over BLE with an ESP32 board, and a
backend verifies both signatures plus a per-session X25519+HMAC-SHA512 ratchet to
detect cloned devices.

Right now it issues real git credentials as the access grant — that's the "prove the
whole crypto chain works end-to-end" use case. The roadmap is toward physical access
control: door locks, safes.

What's real, not vaporware: 3 hand-built boards, 132 backend tests + 20 iOS tests +
firmware ratchet tests all passing, and I just ran a live penetration test against my
own production backend — one real finding (weak input validation on a
challenge-minting endpoint), fixed and deployed same day.

Licensing is split on purpose: firmware/schematics/BOM are MIT (build your own board,
no restriction), backend/app are BSL 1.1 (free to self-host, can't resell as a
competing hosted service, converts to Apache 2.0 in 2030).

Repo: https://github.com/humbertowgw-maker/physicalkey-core

Would love feedback, especially from anyone who's built BLE access control before —
what did I miss?

---

## Hackaday.io project page

**Title:** PhysicalKey — Secure Enclave phone identity meets an open-hardware BLE key

**Summary (one-liner):** An ESP32 hardware key that only unlocks for a phone whose
Secure Enclave key it's cryptographically bonded to — open hardware, self-hostable
backend.

**Details:**

Combines a Face ID-gated Secure Enclave P-256 identity on iOS with an ESP32 device
over BLE Secure Connections passkey pairing, verified server-side via an
X25519+HMAC-SHA512 continuity ratchet that catches cloned device identities.
MIT-licensed firmware/schematics/BOM — build your own board from the repo. Currently
issuing git credentials as a real-world proof of the auth chain; physical lock/safe
control is next on the roadmap.

---

## r/selfhosted

**Title:** I built a self-hostable, open-hardware auth key (Secure Enclave + ESP32 + BLE) — MIT hardware, BSL backend

**Body:**

Been building PhysicalKey: an ESP32-based hardware key that only authenticates for a
phone whose Secure Enclave-resident P-256 key it's cryptographically bonded to over
BLE. Backend verifies everything server-side with an anti-clone ratchet (X25519 +
HMAC-SHA512).

Relevant to this sub specifically: the backend/app is Business Source License 1.1 —
you can self-host it for your own use, full source available, just can't resell it as
a competing hosted service. Docs at `backend/SELF_HOSTING.md`. Hardware
(firmware/schematics/BOM) is plain MIT — build your own board from the repo, no
restriction at all.

It's a Node/Express + SQLite backend, single process, no external dependencies beyond
what's in the repo. Currently used to gate git credential issuance as a
proof-of-concept; I'm honest in the docs that this is single-instance with no
HA/replica yet — backups exist, redundancy doesn't.

Repo: https://github.com/humbertowgw-maker/physicalkey-core — feedback on the
self-host path especially welcome, that's the part I've tested least against
real-world deployment variety.

---

## r/homeautomation — deliberately not drafted yet

Decided 2026-08-14 to skip this one until Phase 3 (PKA-Lock) actually has working code.
Posting a lock-control pitch to a community that cares specifically about working
hardware, before any lock control exists, risks reading as vaporware. Revisit once
there's a real demo.

---

## OSHWA self-certification — info to have ready

Needs Humberto's own account at certification.oshwa.org — not something to submit on
his behalf. What's needed when he does:

- **Project name:** PhysicalKey (hardware only — firmware/schematics/BOM in `hardware/`)
- **Responsible party:** Humberto's name + email
- **Project URL:** the GitHub repo, or a link straight to `hardware/`
- **Category:** likely "Electronics" or "IoT/Embedded"
- **Compliance confirmation:** documentation is public and license-compliant — already
  true (MIT, `hardware/LICENSE`, `hardware/README.md`)
