import db from '../lib/db.js';

// Admin tooling for the trust-on-first-use identity model: once a deviceId's public key
// is registered (phone-auth.js / device-auth.js), it's locked in permanently — a real,
// intentional security property (a restart or a network attacker can't hijack an
// already-trusted deviceId by re-registering a different key). But it means any
// legitimate key change — a phone's Keychain identity being recreated, an ESP32 board's
// flash being erased and regenerating its Ed25519 identity — permanently and silently
// locks that deviceId out, since the old key never matches again and there's no
// self-service recovery. This module is the deliberate escape hatch: reset one specific,
// already-known-broken deviceId back to "never registered" so it can go through
// trust-on-first-use again, without touching anything else in the system.
const getIdentityStmt = db.prepare('SELECT device_id, kind, public_key, platform, registered_at, last_seen, access_count, status FROM identities WHERE device_id = ?');
const deleteIdentityStmt = db.prepare('DELETE FROM identities WHERE device_id = ?');

export function getIdentity(deviceId) {
  return getIdentityStmt.get(deviceId) ?? null;
}

export function resetIdentity(deviceId) {
  const existing = getIdentityStmt.get(deviceId);
  if (!existing) return null;
  deleteIdentityStmt.run(deviceId);
  return existing;
}
