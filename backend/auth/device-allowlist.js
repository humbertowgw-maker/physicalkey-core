import db from '../lib/db.js';

// Interim device-provenance control — see device_allowlist's schema comment in
// backend/lib/db.js for the full reasoning. Enforcement is opt-in via
// ENFORCE_DEVICE_ALLOWLIST=true, checked by the caller (device-auth.js), not this module —
// this module only manages the list itself.
const insertStmt = db.prepare(`
  INSERT INTO device_allowlist (device_id, note, added_at) VALUES (?, ?, ?)
  ON CONFLICT(device_id) DO UPDATE SET note = excluded.note
`);
const deleteStmt = db.prepare('DELETE FROM device_allowlist WHERE device_id = ?');
const getStmt = db.prepare('SELECT device_id, note, added_at FROM device_allowlist WHERE device_id = ?');
const listStmt = db.prepare('SELECT device_id, note, added_at FROM device_allowlist ORDER BY added_at');

export function isEnforced() {
  return process.env.ENFORCE_DEVICE_ALLOWLIST === 'true';
}

export function isDeviceAllowed(deviceId) {
  return Boolean(getStmt.get(deviceId));
}

export function addToAllowlist(deviceId, note = null) {
  insertStmt.run(deviceId, note, Date.now());
  return getStmt.get(deviceId);
}

/** Returns the removed row, or null if the deviceId wasn't on the list. */
export function removeFromAllowlist(deviceId) {
  const existing = getStmt.get(deviceId);
  if (!existing) return null;
  deleteStmt.run(deviceId);
  return existing;
}

export function listAllowlist() {
  return listStmt.all();
}
