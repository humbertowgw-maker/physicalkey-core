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
const getIdentityStmt = db.prepare('SELECT device_id, kind, public_key, platform, registered_at, last_seen, access_count, status, recovery_policy FROM identities WHERE device_id = ?');
const deleteIdentityStmt = db.prepare('DELETE FROM identities WHERE device_id = ?');
const setRecoveryPolicyStmt = db.prepare('UPDATE identities SET recovery_policy = ? WHERE device_id = ?');
// Deliberately omits public_key — this is for auditing which deviceIds exist (e.g. before
// populating the device allow-list), not inspecting one's registration in detail. The
// existing single-deviceId lookup above still returns the full record including the key.
const listIdentitiesStmt = db.prepare('SELECT device_id, kind, platform, registered_at, last_seen, access_count, status, recovery_policy FROM identities ORDER BY registered_at ASC');

export function getIdentity(deviceId) {
  return getIdentityStmt.get(deviceId) ?? null;
}

export function listIdentities() {
  return listIdentitiesStmt.all();
}

// Thrown instead of returning a value, so callers can't accidentally treat a locked
// identity as "not found" (404) or silently succeed — it's a distinct, deliberate outcome
// that server.js maps to its own 403. This is the enforcement half of the recovery_policy
// promise: a 'permanent' identity is not resettable by this code path at all, full stop —
// no admin flag, no override argument, nothing to bypass it with. If that's ever wrong for
// a specific identity, the only way back is the one-way-locked-out ratchet in
// setRecoveryPolicy below, and even that refuses once an identity is already 'permanent'.
export class RecoveryPolicyLockedError extends Error {
  constructor(deviceId) {
    super(`${deviceId} has recovery_policy='permanent' — this identity cannot be reset`);
    this.name = 'RecoveryPolicyLockedError';
  }
}

export function resetIdentity(deviceId) {
  const existing = getIdentityStmt.get(deviceId);
  if (!existing) return null;
  if (existing.recovery_policy === 'permanent') {
    throw new RecoveryPolicyLockedError(deviceId);
  }
  deleteIdentityStmt.run(deviceId);
  return existing;
}

const VALID_RECOVERY_POLICIES = new Set(['permanent', 'self-service']);

// One-way ratchet: 'self-service' -> 'permanent' is allowed; anything starting FROM
// 'permanent' is refused, including setting it to 'permanent' again or back to
// 'self-service'. Without this, "permanent" would just mean "permanent until an admin
// changes the flag first" — a real backdoor around the whole point of the feature.
export function setRecoveryPolicy(deviceId, policy) {
  if (!VALID_RECOVERY_POLICIES.has(policy)) {
    throw new Error(`Invalid recovery_policy: ${policy}`);
  }
  const existing = getIdentityStmt.get(deviceId);
  if (!existing) return null;
  if (existing.recovery_policy === 'permanent') {
    throw new RecoveryPolicyLockedError(deviceId);
  }
  setRecoveryPolicyStmt.run(policy, deviceId);
  return getIdentityStmt.get(deviceId);
}

// A revocation cutoff for a deviceId's already-issued session tokens (see
// session_revocations in lib/db.js). Not a token blacklist — every JWT this backend issues
// already embeds its own `issuedAt`, so a single stored cutoff lets requireAuth/
// requirePhoneSession reject any token minted at or before it, even one that hasn't
// naturally expired. Wired into the identity-reset escape hatch below, so resetting a
// deviceId's trust also immediately kills any session already in someone's hands, not just
// future re-registration.
const upsertRevocationStmt = db.prepare(`
  INSERT INTO session_revocations (device_id, revoked_at) VALUES (?, ?)
  ON CONFLICT(device_id) DO UPDATE SET revoked_at = excluded.revoked_at
`);
const getRevocationStmt = db.prepare('SELECT revoked_at FROM session_revocations WHERE device_id = ?');

export function revokeSessionsIssuedBefore(deviceId, cutoff = Date.now()) {
  upsertRevocationStmt.run(deviceId, cutoff);
  return cutoff;
}

export function isSessionRevoked(deviceId, issuedAt) {
  if (!deviceId || typeof issuedAt !== 'number') return false;
  const row = getRevocationStmt.get(deviceId);
  return Boolean(row) && issuedAt <= row.revoked_at;
}
