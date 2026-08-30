import crypto from 'node:crypto';
import db from '../lib/db.js';

// Avoids visually ambiguous characters (0/O, 1/I/L) since this code is read off a web
// page and typed into a phone keyboard by hand.
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

function randomSegment(length) {
  let out = '';
  for (let i = 0; i < length; i++) {
    out += ALPHABET[crypto.randomInt(ALPHABET.length)];
  }
  return out;
}

function generateCode() {
  return `${randomSegment(4)}-${randomSegment(4)}-${randomSegment(4)}`;
}

const insertStmt = db.prepare(`
  INSERT INTO license_codes (code, stripe_subscription_id, stripe_customer_id, created_at)
  VALUES (?, ?, ?, ?)
`);
const getByCodeStmt = db.prepare('SELECT * FROM license_codes WHERE code = ?');
const getBySubscriptionStmt = db.prepare(
  'SELECT * FROM license_codes WHERE stripe_subscription_id = ? ORDER BY created_at DESC LIMIT 1',
);
const redeemStmt = db.prepare(
  "UPDATE license_codes SET org_id = ?, redeemed_at = ? WHERE code = ? AND redeemed_at IS NULL",
);

/** Called from the checkout.session.completed webhook — one code per completed Team checkout. */
export function createLicenseCode({ stripeSubscriptionId, stripeCustomerId }) {
  const code = generateCode();
  insertStmt.run(code, stripeSubscriptionId, stripeCustomerId, Date.now());
  return code;
}

/** Polled by the landing page's success screen — the webhook may not have landed yet. */
export function getLicenseCodeBySubscription(stripeSubscriptionId) {
  return getBySubscriptionStmt.get(stripeSubscriptionId) ?? null;
}

/**
 * Redeems a code onto an org. Returns the redeemed row, or null if the code doesn't exist
 * or was already redeemed (the UPDATE's WHERE clause makes double-redemption impossible
 * even under a race — only one call can ever match redeemed_at IS NULL for a given code).
 */
export function redeemLicenseCode(code, orgId) {
  const normalized = code.trim().toUpperCase();
  const result = redeemStmt.run(orgId, Date.now(), normalized);
  if (result.changes === 0) return null;
  return getByCodeStmt.get(normalized);
}
