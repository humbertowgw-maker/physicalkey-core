import crypto from 'crypto';
import db from '../lib/db.js';

const insertStmt = db.prepare('INSERT INTO admin_actions (id, admin_device_id, action, target_device_id, org_id, details, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)');
const recentStmt = db.prepare('SELECT * FROM admin_actions ORDER BY rowid DESC LIMIT ?');
const recentForOrgStmt = db.prepare('SELECT * FROM admin_actions WHERE org_id = ? ORDER BY rowid DESC LIMIT ?');

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
  insertStmt.run(entry.id, entry.adminDeviceId, entry.action, entry.targetDeviceId, entry.orgId, JSON.stringify(entry.details), entry.timestamp);
  return entry;
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
