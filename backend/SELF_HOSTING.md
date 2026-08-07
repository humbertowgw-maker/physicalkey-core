# Self-hosting PhysicalKey

The default deployment is a single instance on a single volume — whether that's the
PK-run Railway instance or one you run yourself with the steps below, it's the same
architecture, and it has the same limit: if that one process or its one database file is
unreachable, `/git/auth` and `/auth/device/verify` fail for everyone pointed at it. There
is currently no multi-region or replicated deployment path.

What self-hosting buys you instead is **not depending on PK's shared instance** — your
own outage, your own maintenance windows, your own data, on infrastructure you control.
It does not, by itself, give you high availability. See "If you need real HA" below if
that's what you're after.

## Running it

```bash
cp .env.example .env   # fill in SECRET_KEY and ADMIN_DEVICE_ID
docker compose up -d
```

Required environment variables (see `docker-compose.yml`):

- `SECRET_KEY` — signs every session token this backend issues. Generate one with
  `openssl rand -hex 32`. Losing or rotating this invalidates every outstanding session.
- `ADMIN_DEVICE_ID` — the one deviceId allowed to hit `/admin/*` routes. This is a
  deployer-set value, not something registered through the normal device-pairing flow.

Optional:

- `ENFORCE_DEVICE_ALLOWLIST` — off by default. Turn on once you've populated
  `device_allowlist` if you want to gate which physical boards may register at all,
  rather than trust-on-first-use for any deviceId.
- `PK_BACKUP_RETAIN` — how many scheduled snapshots to keep (default 14).

Point your git server's HTTP auth callback (e.g. Gitea's) at
`http://<your-host>:3000/git/auth`, and your iOS app / firmware at
`http://<your-host>:3000` instead of the PK-hosted URL.

## Backups

The server writes a snapshot to `data/backups/` on an interval
(`PK_BACKUP_INTERVAL_MS`, default 6 hours) automatically — no separate cron needed. Pull
one out of the container, or trigger one on demand:

```bash
# on demand, as the admin device
curl -X POST http://localhost:3000/admin/backups \
  -H "Authorization: Bearer <admin session token>"

# copy the current data volume's backups out
docker compose cp physicalkey:/app/data/backups ./backups
```

To restore, stop the container, then:

```bash
docker compose run --rm physicalkey node scripts/restore.js /app/data/backups/<snapshot>.db
docker compose up -d
```

The existing database is copied aside (`physicalkey.db.pre-restore-<timestamp>`) before
being overwritten, so a bad restore is itself recoverable.

**These snapshots live on the same volume as the live database.** Losing the volume
loses both. For real disaster recovery, copy backups off the host on a schedule (a cron
job running the `docker compose cp` command above into off-box storage is enough — there
is nothing PhysicalKey-specific about that step).

## If you need real HA

This deployment is a single container against a single SQLite file — adequate for one
org's own git access, not for a multi-region or zero-downtime-deploy requirement. Getting
real high availability means migrating off `node:sqlite` to a server-based database
(Postgres) with a replica, and running multiple backend instances behind a load balancer.
That's a real migration, not a config change, and isn't done in this codebase today.
