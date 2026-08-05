import db from '../lib/db.js';

// Backend half of the session-ratchet continuity check (see the security-layers plan). The
// actual X25519 exchange and HKDF/HMAC chaining happen peer-to-peer between phone and device
// over BLE — the backend never sees the secret, only the per-session result the device
// attested to (folded into its existing Ed25519-signed challenge response). This module just
// records that result and provides the escape hatch for clearing it.
const upsertStmt = db.prepare(`
  INSERT INTO ratchet_state (device_id, status, updated_at) VALUES (?, ?, ?)
  ON CONFLICT(device_id) DO UPDATE SET status = excluded.status, updated_at = excluded.updated_at
`);
const getStmt = db.prepare('SELECT device_id, status, updated_at FROM ratchet_state WHERE device_id = ?');
const deleteStmt = db.prepare('DELETE FROM ratchet_state WHERE device_id = ?');

const VALID_STATUSES = new Set(['bootstrap', 'verified', 'mismatch']);

export function isValidRatchetStatus(status) {
  return VALID_STATUSES.has(status);
}

export function recordRatchetStatus(deviceId, status) {
  upsertStmt.run(deviceId, status, Date.now());
}

export function getRatchetState(deviceId) {
  return getStmt.get(deviceId) ?? null;
}

export function clearRatchetState(deviceId) {
  const existing = getStmt.get(deviceId);
  deleteStmt.run(deviceId);
  return existing;
}
