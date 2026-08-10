import crypto from 'crypto';
import db from '../lib/db.js';

const insertStmt = db.prepare('INSERT INTO admin_actions (id, admin_device_id, action, target_device_id, org_id, details, timestamp, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
const recentStmt = db.prepare('SELECT * FROM admin_actions ORDER BY rowid DESC LIMIT ?');
const recentForOrgStmt = db.prepare('SELECT * FROM admin_actions WHERE org_id = ? ORDER BY rowid DESC LIMIT ?');
const lastHashStmt = db.prepare('SELECT hash FROM admin_actions ORDER BY rowid DESC LIMIT 1');
const allChainedStmt = db.prepare("SELECT * FROM admin_actions WHERE hash IS NOT NULL ORDER BY rowid ASC");

function rowToEntry(row) {
  return {
    id: row.id,
    adminDeviceId: row.admin_device_id,
    action: row.action,
    targetDeviceId: row.target_device_id,
    orgId: row.org_id,
    details: JSON.parse(row.details),
    timestamp: row.timestamp
  };
}

// Genesis value for the very first hash-chained row — distinguishable from a real SHA-256
// hex digest by construction (all zeros), never produced by computeHash below.
const GENESIS_HASH = '0'.repeat(64);

// Binds a row to its exact field values and to whatever came immediately before it, so
// editing any field in any row — or deleting a row outright — changes the hash the *next*
// row committed to at write time, making both detectable by verifyAuditChain(). This is
// tamper-evident, not tamper-proof: someone with full write access to this SQLite file
// could recompute the entire chain from scratch. Closing that requires signing with a key
// this backend doesn't hold (HSM/KMS) or mirroring the chain tip somewhere external — both
// real infrastructure decisions, not a code-only fix, and deliberately left open rather
// than half-solved here.
function computeHash(prevHash, entry) {
  return crypto.createHash('sha256')
    .update(prevHash)
    .update(entry.id)
    .update(entry.adminDeviceId)
    .update(entry.action)
    .update(entry.targetDeviceId ?? '')
    .update(entry.orgId ?? '')
    .update(JSON.stringify(entry.details))
    .update(entry.timestamp)
    .digest('hex');
}

// `orgId` is null for global admin actions (identity resets) and set for org-scoped ones
// (membership/device-access changes — see server.js's /orgs/... handlers), so the same
// table and function serve both the global /admin/audit-log and the per-org
// /orgs/:orgId/audit-log without needing two separate logging paths.
export function logAdminAction(adminDeviceId, action, targetDeviceId, details = {}, orgId = null) {
  const entry = {
    id: crypto.randomUUID(),
    adminDeviceId,
    action,
    targetDeviceId: targetDeviceId ?? null,
    orgId,
    details,
    timestamp: new Date().toISOString()
  };
  const prevHash = lastHashStmt.get()?.hash ?? GENESIS_HASH;
  const hash = computeHash(prevHash, entry);
  insertStmt.run(entry.id, entry.adminDeviceId, entry.action, entry.targetDeviceId, entry.orgId, JSON.stringify(entry.details), entry.timestamp, prevHash, hash);
  return entry;
}

// Walks every hash-chained row in write order and recomputes each hash from its own
// fields plus the previous row's hash, so it catches both an edited field (that row's own
// hash stops matching) and a deleted row (the next row's prev_hash stops matching anything
// recomputable). Rows written before the hash-chain migration have a NULL hash and are
// skipped — they predate this guarantee entirely, not a break in it.
//
// Critically, expectedPrev always starts at GENESIS_HASH, never at whatever the first row
// *encountered* happens to claim — logAdminAction guarantees the true first chained row
// (migrated DB or not) was written with prev_hash === GENESIS_HASH, so trusting anything
// else as the starting point would silently accept a deleted first row, or a whole prefix
// of deleted rows, as a legitimate new chain start.
export function verifyAuditChain() {
  const rows = allChainedStmt.all();
  let expectedPrev = GENESIS_HASH;
  for (const row of rows) {
    const entry = rowToEntry(row);
    if (row.prev_hash !== expectedPrev) {
      return { intact: false, brokenAt: row.id, reason: 'prev_hash does not match the preceding row — a row was likely deleted or reordered', checked: rows.length };
    }
    const recomputed = computeHash(row.prev_hash, entry);
    if (recomputed !== row.hash) {
      return { intact: false, brokenAt: row.id, reason: 'stored hash does not match its own fields — this row was edited after being written', checked: rows.length };
    }
    expectedPrev = row.hash;
  }
  return { intact: true, brokenAt: null, reason: null, checked: rows.length };
}

export function getAdminActionLog(limit = 200) {
  return recentStmt.all(limit).map(rowToEntry);
}

// Scoped to one org — used by GET /orgs/:orgId/audit-log so an org's own owner/admin can
// see their org's history without needing the global admin device's credentials, which
// today is the only thing that can see anything here at all.
export function getOrgActionLog(orgId, limit = 200) {
  return recentForOrgStmt.all(orgId, limit).map(rowToEntry);
}
