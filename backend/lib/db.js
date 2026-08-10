import { DatabaseSync } from 'node:sqlite';
import path from 'path';
import { dataDir } from './data-dir.js';

const db = new DatabaseSync(path.join(dataDir, 'physicalkey.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS identities (
    device_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('phone', 'device')),
    public_key TEXT NOT NULL,
    platform TEXT,
    registered_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    access_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    recovery_policy TEXT NOT NULL DEFAULT 'self-service'
  );

  CREATE TABLE IF NOT EXISTS git_credentials (
    device_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    scope TEXT NOT NULL,
    repositories TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS honeypot_events (
    id TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    reason TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}',
    level TEXT NOT NULL DEFAULT 'warning',
    timestamp TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_honeypot_events_ip ON honeypot_events(ip);

  -- Team accounts. An org is owned by a phone identity (deviceId), has members (other
  -- phone identities), and can claim physical key devices — either exclusively (one
  -- member's device_access row) or shared (multiple members' rows for the same device).
  CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner_device_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended'))
  );

  -- A phone identity's membership in an org. 'owner'/'admin' can manage members and
  -- device access; 'member' can only use devices they've been explicitly granted access
  -- to. Revoking membership (status='revoked') cuts off ALL of that member's access
  -- within this org, regardless of any individual device_access grants below.
  CREATE TABLE IF NOT EXISTS organization_members (
    org_id TEXT NOT NULL REFERENCES organizations(id),
    device_id TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
    added_at INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    PRIMARY KEY (org_id, device_id)
  );

  -- Which org a physical key device belongs to. A device belongs to at most one org; a
  -- device with no row here is a personal (Solo) device, unaffected by any of this.
  CREATE TABLE IF NOT EXISTS organization_devices (
    device_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id),
    added_at INTEGER NOT NULL
  );

  -- Per-member grants for a specific org device. A device used by exactly one member
  -- (the common "Team" case: everyone has their own key) has exactly one row here; a
  -- shared device (e.g. one office door) has one row per member who can unlock it.
  -- Owners/admins get implicit access to every device in their org without needing a
  -- row here — this table is specifically for 'member'-role grants.
  CREATE TABLE IF NOT EXISTS device_access (
    org_id TEXT NOT NULL REFERENCES organizations(id),
    device_id TEXT NOT NULL,
    member_device_id TEXT NOT NULL,
    granted_at INTEGER NOT NULL,
    PRIMARY KEY (org_id, device_id, member_device_id)
  );

  CREATE INDEX IF NOT EXISTS idx_org_members_device ON organization_members(device_id);
  CREATE INDEX IF NOT EXISTS idx_device_access_device ON device_access(org_id, device_id);

  -- Durable record of sensitive admin actions (identity resets, and now org membership /
  -- device-access changes too — see auth/organizations.js). Previously only console.log'd,
  -- which is lost on restart and unqueryable — this survives both, so "who did what, and
  -- when" is always answerable later. org_id is nullable: identity resets and other
  -- global admin actions aren't scoped to any one org.
  CREATE TABLE IF NOT EXISTS admin_actions (
    id TEXT PRIMARY KEY,
    admin_device_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_device_id TEXT,
    org_id TEXT,
    details TEXT NOT NULL DEFAULT '{}',
    timestamp TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_admin_actions_timestamp ON admin_actions(timestamp);

  -- A revocation cutoff for a given identity's already-issued session tokens. Not a
  -- blacklist of individual tokens — a single timestamp is enough, since every JWT this
  -- backend issues already embeds its own issuedAt: any token minted at or before this
  -- cutoff is rejected outright by requireAuth/requirePhoneSession, even if it hasn't
  -- naturally expired yet. Set by the identity-reset escape hatch (see
  -- auth/identity-admin.js) so that action revokes not just future re-registration but any
  -- session already in someone's hands.
  CREATE TABLE IF NOT EXISTS session_revocations (
    device_id TEXT PRIMARY KEY,
    revoked_at INTEGER NOT NULL
  );

  -- Interim device provenance control (see hardware/README.md's audit gap notes): trust-
  -- on-first-use alone means "has a keypair" and "is a real physical ESP32 board" are the
  -- same claim, which they aren't — anyone can register a plausible-looking deviceId as a
  -- new "device". This is a cheap stopgap until real factory-provisioned certs exist: an
  -- admin-managed allow-list of known-real deviceIds (their eFuse-MAC-derived IDs), checked
  -- only when ENFORCE_DEVICE_ALLOWLIST=true (off by default — unset in dev/test, so this
  -- never affects the existing test suite's dynamically-created device identities; set only
  -- on the real production deployment once populated). Only gates NEW device registration —
  -- already-registered devices and all phone identities are unaffected either way.
  CREATE TABLE IF NOT EXISTS device_allowlist (
    device_id TEXT PRIMARY KEY,
    note TEXT,
    added_at INTEGER NOT NULL
  );

  -- Session-ratchet continuity state (see the security-layers plan) for a device that's
  -- reported a ratchet result at least once. Absence of a row here is NOT a signal — it just
  -- means bootstrap (first session, or state was legitimately lost to a re-flash/reinstall).
  -- 'mismatch' is the only value worth acting on: both sides had prior state and it disagreed.
  -- v1 is warn-not-block by design — see identity-admin.js's clearRatchetState for the escape
  -- hatch when a mismatch turns out to be a false positive rather than a real clone.
  -- 'next_proof' is the backend's own mirrored copy of the HMAC chain, needed so the backend
  -- computes the verdict itself (see auth/ratchet.js's verifyAndRecordRatchetAttestation)
  -- instead of trusting a client-reported string. 'unverifiable' covers a device that claims
  -- continuation but has no next_proof on file yet — e.g. its first session after this
  -- column was introduced — which is a migration gap, not a real mismatch.
  CREATE TABLE IF NOT EXISTS ratchet_state (
    device_id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('bootstrap', 'verified', 'mismatch', 'unverifiable')),
    next_proof TEXT,
    verified_by TEXT NOT NULL DEFAULT 'server',
    updated_at INTEGER NOT NULL
  );

  -- Real phone<->board pairing history, for personal (non-org) devices — nothing else
  -- tracks this today (org devices have explicit device_access grants, but a Solo
  -- device's "who has actually used this" was previously implicit and unrecorded).
  -- Written on every successful /auth/device/verify. This is what self-service repair
  -- (auth/repair.js) checks before letting a board vouch for resetting a phone identity —
  -- without it, ANY registered board could free up ANY phone's identity, not just one it
  -- has a real history with.
  CREATE TABLE IF NOT EXISTS device_phone_pairings (
    device_id TEXT NOT NULL,
    phone_device_id TEXT NOT NULL,
    first_paired_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    PRIMARY KEY (device_id, phone_device_id)
  );

  -- One row per Stripe subscription, kept in sync via the /billing/webhook handler (see
  -- payments/stripe.js) so the backend has a fast local answer to "is this customer paid"
  -- without calling out to Stripe on every request. Keyed by Stripe's own subscription id,
  -- not email — an email can move between subscriptions (cancel, resubscribe) and this
  -- keeps each of those as its own row rather than clobbering history.
  CREATE TABLE IF NOT EXISTS subscriptions (
    stripe_subscription_id TEXT PRIMARY KEY,
    stripe_customer_id TEXT NOT NULL,
    email TEXT,
    plan TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_subscriptions_customer ON subscriptions(stripe_customer_id);
`);

// Migration for a database created before next_proof/verified_by/'unverifiable' existed
// (CREATE TABLE IF NOT EXISTS above is a no-op against an already-existing table, so this
// covers upgrading it in place). SQLite can't ALTER a CHECK constraint, so this rebuilds the
// table — safe and cheap at this table's size (one row per physical device, single digits).
const ratchetStateColumns = db.prepare("PRAGMA table_info(ratchet_state)").all().map((c) => c.name);
if (!ratchetStateColumns.includes('next_proof')) {
  db.exec(`
    ALTER TABLE ratchet_state RENAME TO ratchet_state_old;
    CREATE TABLE ratchet_state (
      device_id TEXT PRIMARY KEY,
      status TEXT NOT NULL CHECK (status IN ('bootstrap', 'verified', 'mismatch', 'unverifiable')),
      next_proof TEXT,
      verified_by TEXT NOT NULL DEFAULT 'server',
      updated_at INTEGER NOT NULL
    );
    INSERT INTO ratchet_state (device_id, status, next_proof, verified_by, updated_at)
      SELECT device_id, status, NULL, 'server', updated_at FROM ratchet_state_old;
    DROP TABLE ratchet_state_old;
  `);
}

// Migration for a database created before admin_actions had org_id — a plain nullable
// column with no constraint, so unlike ratchet_state above this doesn't need a table
// rebuild, just an ADD COLUMN.
const adminActionsColumns = db.prepare("PRAGMA table_info(admin_actions)").all().map((c) => c.name);
if (!adminActionsColumns.includes('org_id')) {
  db.exec('ALTER TABLE admin_actions ADD COLUMN org_id TEXT');
}

// Migration for a database created before identities had recovery_policy. SQLite applies
// a column's DEFAULT to every existing row on ADD COLUMN, so every already-registered
// identity gets 'self-service' — today's actual behavior — with no behavior change.
const identitiesColumns = db.prepare("PRAGMA table_info(identities)").all().map((c) => c.name);
if (!identitiesColumns.includes('recovery_policy')) {
  db.exec("ALTER TABLE identities ADD COLUMN recovery_policy TEXT NOT NULL DEFAULT 'self-service'");
}

// Migration for a database created before admin_actions was hash-chained (see
// audit/log.js) — plain nullable columns, no rebuild needed. Rows written before this
// migration have NULL hash/prev_hash and are treated as outside the verifiable chain
// (verifyAuditChain starts from the first row that has a hash), not as a broken chain.
if (!adminActionsColumns.includes('hash')) {
  db.exec('ALTER TABLE admin_actions ADD COLUMN prev_hash TEXT');
  db.exec('ALTER TABLE admin_actions ADD COLUMN hash TEXT');
}
// Only safe to create once org_id is guaranteed to exist — on a fresh database this is a
// no-op right after CREATE TABLE; on an existing one, only after the migration above.
db.exec('CREATE INDEX IF NOT EXISTS idx_admin_actions_org ON admin_actions(org_id)');

export default db;
