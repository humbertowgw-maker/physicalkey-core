# PhysicalKey Local Backend Setup — Results

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
