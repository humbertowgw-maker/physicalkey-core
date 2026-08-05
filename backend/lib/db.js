import { DatabaseSync } from 'node:sqlite';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Overridable so the test suite can point at an isolated, throwaway directory instead of
// the real local/production data — unset in normal running (dev or Railway), so this is
// a no-op there.
const dataDir = process.env.PK_DATA_DIR || path.join(__dirname, '..', 'data');
fs.mkdirSync(dataDir, { recursive: true });

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
    status TEXT NOT NULL DEFAULT 'active'
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

  -- Durable record of sensitive admin actions (currently: identity resets via
  -- auth/identity-admin.js). Previously only console.log'd, which is lost on restart and
  -- unqueryable — this survives both, so "who reset this deviceId, and when" is always
  -- answerable later.
  CREATE TABLE IF NOT EXISTS admin_actions (
    id TEXT PRIMARY KEY,
    admin_device_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_device_id TEXT,
    details TEXT NOT NULL DEFAULT '{}',
    timestamp TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_admin_actions_timestamp ON admin_actions(timestamp);

  -- Session-ratchet continuity state (see the security-layers plan) for a device that's
  -- reported a ratchet result at least once. Absence of a row here is NOT a signal — it just
  -- means bootstrap (first session, or state was legitimately lost to a re-flash/reinstall).
  -- 'mismatch' is the only value worth acting on: both sides had prior state and it disagreed.
  -- v1 is warn-not-block by design — see identity-admin.js's clearRatchetState for the escape
  -- hatch when a mismatch turns out to be a false positive rather than a real clone.
  CREATE TABLE IF NOT EXISTS ratchet_state (
    device_id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('bootstrap', 'verified', 'mismatch')),
    updated_at INTEGER NOT NULL
  );
`);

export default db;
