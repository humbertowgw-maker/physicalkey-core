# The real-access-gate demo

This is a real git server. The only thing gating it is a live call to the production
PhysicalKey backend's `GET /git/auth` — the same endpoint the security audit and
competitive brief have both been describing for days as "designed, but nothing actually
calls it." This closes that gap: `git clone`/`git push` against it genuinely succeed or
fail based on whether you're holding a still-valid PhysicalKey session issued a moment
earlier by real phone + Face ID + physical ESP32 authentication.

No mock, no shortcut, no bypass flag.

## Run it

```bash
node demo/git-gate-server.js
```

First run creates a real bare repo at `demo/vault.git` (gitignored — it's runtime data,
not source) seeded with one commit. Listens on `:7420` by default; point it at a
different backend with `PK_BACKEND_URL` (defaults to the live Railway production
backend).

## Demo it

```bash
# Locked — no credentials, real rejection from git itself
git clone http://localhost:7420/vault.git /tmp/locked-out

# Do a real PhysicalKey auth in the app: phone unlock → Face ID → BLE → board signs →
# backend verifies → git credentials issued. Then, unlocked:
git clone http://<deviceId>:<password>@localhost:7420/vault.git /tmp/lets-in
cat /tmp/lets-in/ACCESS_GRANTED.md
```

Credentials expire in 24h (same TTL the backend already enforces) and can be revoked
early via the admin identity-reset endpoint — try cloning again after either and watch
it fail the same real way it did the first time.

## What this proves, and what it doesn't

Proves: the whole chain — phone biometric, physical key signature, backend verification,
credential issuance, and a real git server actually consuming those credentials to
gate a real clone/push — works end to end, live, against production. Verified twice
before handing this to a live demo: once confirming the deny path rejects real requests
against the live backend, once confirming the full grant→clone→push path lands real
files using genuinely backend-issued credentials against a local test backend (a fresh
device registration against production is correctly blocked by the enforced allow-list
— proving *that* works too, just meaning it can't be scripted end-to-end against prod).

Doesn't prove: this is still Tier C in the competitive audit's terms — a single Railway
process gates this the same way it gates everything else. That's a separate, known,
still-open gap, not something this demo changes.
