import crypto from 'crypto';
import db from '../lib/db.js';

// Self-service identity repair: lets a phone's stuck/lost identity be reset by proving
// physical possession of a board it has a genuine pairing history with — no admin needed.
// Reuses the board's existing generic challenge-signing capability (the same
// Challenge/Signature GATT characteristics every normal login already writes to and reads
// from) rather than adding new firmware. The REPAIR_CONTEXT prefix is what keeps a
// signature obtained here from ever being confused with, or replayed as, a normal
// device-verify signature (a plain 32 random bytes with no prefix) — same domain-
// separation idea as RATCHET_ATTEST_CONTEXT elsewhere in this codebase.
const REPAIR_CONTEXT = 'PHYSICALKEY-REPAIR-AUTH-V1:';
const CHALLENGE_TTL_MS = 120000;

const recordPairingStmt = db.prepare(`
  INSERT INTO device_phone_pairings (device_id, phone_device_id, first_paired_at, last_seen_at)
  VALUES (?, ?, ?, ?)
  ON CONFLICT(device_id, phone_device_id) DO UPDATE SET last_seen_at = excluded.last_seen_at
`);
const hasEverPairedStmt = db.prepare('SELECT 1 FROM device_phone_pairings WHERE device_id = ? AND phone_device_id = ?');

export function recordPairing(deviceId, phoneDeviceId) {
  const now = Date.now();
  recordPairingStmt.run(deviceId, phoneDeviceId, now, now);
}

export function hasEverPaired(deviceId, phoneDeviceId) {
  return Boolean(hasEverPairedStmt.get(deviceId, phoneDeviceId));
}

// In-memory, like the main auth flow's activeChallenges in server.js — losing an
// in-flight repair challenge on a restart just means the client re-requests one, and
// these are short-lived (2 min) by design anyway.
const repairChallenges = new Map();

export function createRepairChallenge(boardDeviceId, targetPhoneDeviceId) {
  const nonce = crypto.randomBytes(16).toString('base64');
  // The challenge bytes themselves commit to exactly which phone identity this proof is
  // for — not just a bare nonce — so a signature obtained for one target can't be reused
  // to authorize resetting a different one.
  const challenge = `${REPAIR_CONTEXT}${targetPhoneDeviceId}:${nonce}`;
  const challengeId = crypto.randomUUID();
  repairChallenges.set(challengeId, {
    boardDeviceId,
    targetPhoneDeviceId,
    challenge,
    createdAt: Date.now(),
    expiresAt: Date.now() + CHALLENGE_TTL_MS
  });
  return { challengeId, challenge };
}

// One-time use: consumed regardless of outcome, same pattern as every other challenge in
// this codebase, so a captured challengeId can't be replayed even against a fresh attempt.
export function consumeRepairChallenge(challengeId) {
  const stored = repairChallenges.get(challengeId);
  repairChallenges.delete(challengeId);
  if (!stored) return null;
  if (Date.now() > stored.expiresAt) return null;
  return stored;
}

export function verifyBoardSignature(challenge, signatureB64, boardPublicKeyB64) {
  try {
    const publicKeyObj = crypto.createPublicKey({
      key: Buffer.from(boardPublicKeyB64, 'base64'),
      format: 'der',
      type: 'spki'
    });
    return crypto.verify(
      null,
      Buffer.from(challenge, 'utf8'),
      publicKeyObj,
      Buffer.from(signatureB64, 'base64')
    );
  } catch {
    return false;
  }
}
