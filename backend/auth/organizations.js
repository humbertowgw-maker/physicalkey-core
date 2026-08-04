import crypto from 'crypto';
import db from '../lib/db.js';

// Team accounts. Deliberately supports two shapes of the same underlying model rather
// than picking one:
//   - "everyone has their own key": one device_access row per (device, member) pair,
//     one member each — functionally identical to a bunch of independent Solo pairs,
//     just grouped under an org for visibility/admin.
//   - "one shared key" (e.g. an office door): one device row, multiple device_access
//     rows, one per member allowed to use it.
// Both are just rows in the same device_access table; nothing in this module needs to
// know which shape a given org is using.

const insertOrgStmt = db.prepare(`INSERT INTO organizations (id, name, owner_device_id, created_at) VALUES (?, ?, ?, ?)`);
const getOrgStmt = db.prepare(`SELECT * FROM organizations WHERE id = ?`);

const upsertMemberStmt = db.prepare(`
  INSERT INTO organization_members (org_id, device_id, role, added_at, status)
  VALUES (?, ?, ?, ?, 'active')
  ON CONFLICT (org_id, device_id) DO UPDATE SET role = excluded.role, status = 'active'
`);
const getMemberStmt = db.prepare(`SELECT * FROM organization_members WHERE org_id = ? AND device_id = ?`);
const listMembersStmt = db.prepare(`SELECT device_id, role, added_at, status FROM organization_members WHERE org_id = ? ORDER BY added_at`);
const revokeMemberStmt = db.prepare(`UPDATE organization_members SET status = 'revoked' WHERE org_id = ? AND device_id = ?`);

const insertOrgDeviceStmt = db.prepare(`INSERT INTO organization_devices (device_id, org_id, added_at) VALUES (?, ?, ?)`);
const getOrgDeviceStmt = db.prepare(`SELECT * FROM organization_devices WHERE device_id = ?`);
const listOrgDevicesStmt = db.prepare(`SELECT device_id, added_at FROM organization_devices WHERE org_id = ? ORDER BY added_at`);
const deleteOrgDeviceStmt = db.prepare(`DELETE FROM organization_devices WHERE device_id = ?`);

const grantAccessStmt = db.prepare(`
  INSERT INTO device_access (org_id, device_id, member_device_id, granted_at)
  VALUES (?, ?, ?, ?)
  ON CONFLICT (org_id, device_id, member_device_id) DO NOTHING
`);
const revokeAccessStmt = db.prepare(`DELETE FROM device_access WHERE org_id = ? AND device_id = ? AND member_device_id = ?`);
const listDeviceAccessStmt = db.prepare(`SELECT member_device_id, granted_at FROM device_access WHERE org_id = ? AND device_id = ?`);
const deleteAllAccessForDeviceStmt = db.prepare(`DELETE FROM device_access WHERE device_id = ?`);
const hasAccessStmt = db.prepare(`SELECT 1 FROM device_access WHERE org_id = ? AND device_id = ? AND member_device_id = ?`);

export function createOrganization(name, ownerDeviceId) {
  const id = crypto.randomUUID();
  const now = Date.now();
  insertOrgStmt.run(id, name, ownerDeviceId, now);
  upsertMemberStmt.run(id, ownerDeviceId, 'owner', now);
  return getOrgStmt.get(id);
}

export function getOrganization(orgId) {
  return getOrgStmt.get(orgId) ?? null;
}

export function getMembership(orgId, deviceId) {
  return getMemberStmt.get(orgId, deviceId) ?? null;
}

export function listMembers(orgId) {
  return listMembersStmt.all(orgId);
}

/** Adds a member, or reactivates one that was previously removed. */
export function addMember(orgId, deviceId, role = 'member') {
  upsertMemberStmt.run(orgId, deviceId, role, Date.now());
  return getMembership(orgId, deviceId);
}

/**
 * Soft-revokes a member (status='revoked', not deleted — keeps history, matches the
 * same revoke-not-delete pattern device-auth.js already uses for devices). Revoking
 * membership cuts off ALL of that member's device access in this org immediately,
 * regardless of any individual device_access grants — those checks all also verify
 * active membership, so a revoked member fails even with a still-present grant row.
 */
export function removeMember(orgId, deviceId) {
  const existing = getMembership(orgId, deviceId);
  if (!existing) return null;
  revokeMemberStmt.run(orgId, deviceId);
  return getMembership(orgId, deviceId);
}

export function getDeviceOrg(deviceId) {
  return getOrgDeviceStmt.get(deviceId) ?? null;
}

export function listOrgDevices(orgId) {
  return listOrgDevicesStmt.all(orgId);
}

/** Associates a physical key device with an org. A device can belong to at most one org. */
export function addDeviceToOrg(orgId, deviceId) {
  const existing = getDeviceOrg(deviceId);
  if (existing) {
    throw new Error(existing.org_id === orgId ? 'Device already belongs to this org' : 'Device already belongs to a different org');
  }
  insertOrgDeviceStmt.run(deviceId, orgId, Date.now());
  return getDeviceOrg(deviceId);
}

/** Removes a device from its org entirely, along with every member's access grant for it. */
export function removeDeviceFromOrg(deviceId) {
  const existing = getDeviceOrg(deviceId);
  if (!existing) return null;
  deleteAllAccessForDeviceStmt.run(deviceId);
  deleteOrgDeviceStmt.run(deviceId);
  return existing;
}

export function listDeviceAccess(orgId, deviceId) {
  return listDeviceAccessStmt.all(orgId, deviceId);
}

/** Grants an org member access to a specific org device. Member must be active in the org. */
export function grantDeviceAccess(orgId, deviceId, memberDeviceId) {
  const membership = getMembership(orgId, memberDeviceId);
  if (!membership || membership.status !== 'active') {
    throw new Error('Cannot grant device access to a non-member or revoked member');
  }
  const device = getDeviceOrg(deviceId);
  if (!device || device.org_id !== orgId) {
    throw new Error('Device does not belong to this org');
  }
  grantAccessStmt.run(orgId, deviceId, memberDeviceId, Date.now());
}

export function revokeDeviceAccess(orgId, deviceId, memberDeviceId) {
  revokeAccessStmt.run(orgId, deviceId, memberDeviceId);
}

/**
 * The actual enforcement check, called from /auth/device/verify. A device with no org
 * association is a personal (Solo) device — always authorized, unchanged from today's
 * behavior. An org device requires the phone to be an ACTIVE member; owners/admins get
 * implicit access to every device in their own org, 'member'-role phones need an
 * explicit device_access grant.
 */
export function isAuthorizedForDevice(deviceId, phoneDeviceId) {
  const orgDevice = getDeviceOrg(deviceId);
  if (!orgDevice) return true; // personal device, not part of any org

  const membership = getMembership(orgDevice.org_id, phoneDeviceId);
  if (!membership || membership.status !== 'active') return false;
  if (membership.role === 'owner' || membership.role === 'admin') return true;

  return Boolean(hasAccessStmt.get(orgDevice.org_id, deviceId, phoneDeviceId));
}
