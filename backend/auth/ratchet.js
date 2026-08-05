import crypto from 'crypto';
import db from '../lib/db.js';

// Backend half of the session-ratchet continuity check (see the security-layers plan). The
// actual X25519 exchange and HKDF/HMAC chaining happen peer-to-peer between phone and device
// over BLE — the backend never sees the raw shared secret, only a one-way HMAC-SHA512
// derivative of it ("next_proof"), signed by the device's existing Ed25519 identity key so
// the backend can verify — not just record — the continuity claim itself, rather than
// trusting a bare string self-reported by the phone app.
const upsertStmt = db.prepare(`
  INSERT INTO ratchet_state (device_id, status, next_proof, verified_by, updated_at) VALUES (?, ?, ?, ?, ?)
  ON CONFLICT(device_id) DO UPDATE SET
    status = excluded.status, next_proof = excluded.next_proof,
    verified_by = excluded.verified_by, updated_at = excluded.updated_at
`);
const getStmt = db.prepare('SELECT device_id, status, next_proof, verified_by, updated_at FROM ratchet_state WHERE device_id = ?');
const deleteStmt = db.prepare('DELETE FROM ratchet_state WHERE device_id = ?');
const getDeviceKeyStmt = db.prepare("SELECT public_key FROM identities WHERE device_id = ? AND kind = 'device'");

const LEGACY_STATUSES = new Set(['bootstrap', 'verified', 'mismatch']);
const ATTEST_CONTEXT = Buffer.from('physicalkey-ratchet-attest-v1', 'utf8');

export function isValidRatchetStatus(status) {
  return LEGACY_STATUSES.has(status);
}

// Legacy: records a bare, client-reported status string with no cryptographic verification
// at all. Kept only as telemetry during the rollout window (a phone/board not yet upgraded
// to the signed-attestation flow) — deliberately does not overwrite next_proof (so it can
// never desync a real backend-verified chain), and callers must never treat this as
// trustworthy for anything security-relevant (no honeypot trigger, no "verified" claim).
export function recordRatchetStatus(deviceId, status) {
  const existing = getStmt.get(deviceId);
  upsertStmt.run(deviceId, status, existing?.next_proof ?? null, 'client-reported', Date.now());
}

export function getRatchetState(deviceId) {
  return getStmt.get(deviceId) ?? null;
}

export function clearRatchetState(deviceId) {
  const existing = getStmt.get(deviceId);
  deleteStmt.run(deviceId);
  return existing;
}

/**
 * Independently verifies a device-signed ratchet attestation and computes the continuity
 * verdict server-side, instead of trusting a client-reported string.
 *
 * `challenge` must be the same raw challenge bytes (utf8) already used to verify this
 * session's primary deviceSignature — binding the attestation to it means a captured
 * attestation from one session can't be replayed to claim continuity in another.
 *
 * `attestation` fields (all base64 except `status`, a 0/1 number) mirror the 209-byte BLE
 * wire payload the firmware signs: devicePublicKey(32) || rc(16) || deviceProof(64) ||
 * nextProof(32) || status(1) || signature(64, Ed25519 over the rest via the device's
 * existing identity key).
 *
 * Returns { ok: false, reason } on any failure (unregistered device, malformed fields, bad
 * signature) or { ok: true, verdict } where verdict is 'bootstrap' | 'verified' | 'mismatch'
 * | 'unverifiable' (a continuation claim from a device the backend has no next_proof on file
 * for yet — e.g. its first session since this verification was introduced; a migration gap,
 * not a real mismatch).
 */
export function verifyAndRecordRatchetAttestation(deviceId, challenge, attestation) {
  const { devicePublicKey: devicePublicKeyB64, rc: rcB64, deviceProof: deviceProofB64, nextProof: nextProofB64, status, signature: signatureB64 } = attestation ?? {};

  if (status !== 0 && status !== 1) {
    return { ok: false, reason: 'malformed_status' };
  }
  if ([devicePublicKeyB64, rcB64, deviceProofB64, nextProofB64, signatureB64].some((f) => typeof f !== 'string')) {
    return { ok: false, reason: 'malformed_encoding' };
  }

  const devicePublicKey = Buffer.from(devicePublicKeyB64, 'base64');
  const rc = Buffer.from(rcB64, 'base64');
  const deviceProof = Buffer.from(deviceProofB64, 'base64');
  const nextProof = Buffer.from(nextProofB64, 'base64');
  const signature = Buffer.from(signatureB64, 'base64');
  if (devicePublicKey.length !== 32 || rc.length !== 16 || deviceProof.length !== 64 || nextProof.length !== 32 || signature.length !== 64) {
    return { ok: false, reason: 'malformed_length' };
  }

  const deviceIdentity = getDeviceKeyStmt.get(deviceId);
  if (!deviceIdentity) {
    return { ok: false, reason: 'device_not_registered' };
  }

  const msg = Buffer.concat([
    ATTEST_CONTEXT,
    crypto.createHash('sha256').update(Buffer.from(challenge, 'utf8')).digest(),
    devicePublicKey, rc, deviceProof, nextProof, Buffer.from([status])
  ]);

  const publicKeyObj = crypto.createPublicKey({
    key: Buffer.from(deviceIdentity.public_key, 'base64'),
    format: 'der',
    type: 'spki'
  });

  if (!crypto.verify(null, msg, publicKeyObj, signature)) {
    return { ok: false, reason: 'bad_signature' };
  }

  const existing = getStmt.get(deviceId);
  let verdict;
  if (status === 0) {
    verdict = 'bootstrap';
  } else if (existing?.next_proof) {
    const priorProof = Buffer.from(existing.next_proof, 'base64');
    const expectedProof = crypto.createHmac('sha512', priorProof).update(rc).digest();
    verdict = crypto.timingSafeEqual(expectedProof, deviceProof) ? 'verified' : 'mismatch';
  } else {
    verdict = 'unverifiable';
  }

  upsertStmt.run(deviceId, verdict, nextProof.toString('base64'), 'server', Date.now());
  return { ok: true, verdict };
}
