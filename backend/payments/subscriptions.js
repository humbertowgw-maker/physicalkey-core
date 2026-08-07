import db from '../lib/db.js';

// email is deliberately excluded from the UPDATE clause: a subscription.updated webhook
// carries no reliable email field, and re-running this with email=null must never wipe
// out the real address a prior checkout.session.completed already recorded.
const upsertStmt = db.prepare(`
  INSERT INTO subscriptions (stripe_subscription_id, stripe_customer_id, email, plan, status, created_at, updated_at)
  VALUES (?, ?, ?, ?, ?, ?, ?)
  ON CONFLICT(stripe_subscription_id) DO UPDATE SET
    status = excluded.status,
    plan = excluded.plan,
    updated_at = excluded.updated_at
`);
const getBySubscriptionStmt = db.prepare('SELECT * FROM subscriptions WHERE stripe_subscription_id = ?');
const getByCustomerStmt = db.prepare('SELECT * FROM subscriptions WHERE stripe_customer_id = ? ORDER BY updated_at DESC LIMIT 1');
const listActiveStmt = db.prepare("SELECT * FROM subscriptions WHERE status = 'active' ORDER BY updated_at DESC");
const listAllStmt = db.prepare('SELECT * FROM subscriptions ORDER BY updated_at DESC');

function rowToEntry(row) {
  if (!row) return null;
  return {
    stripeSubscriptionId: row.stripe_subscription_id,
    stripeCustomerId: row.stripe_customer_id,
    email: row.email,
    plan: row.plan,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

/** Insert-or-update a subscription record from a Stripe webhook event. */
export function recordSubscription({ stripeSubscriptionId, stripeCustomerId, email = null, plan, status }, now = Date.now()) {
  upsertStmt.run(stripeSubscriptionId, stripeCustomerId, email, plan, status, now, now);
  return rowToEntry(getBySubscriptionStmt.get(stripeSubscriptionId));
}

export function getSubscription(stripeSubscriptionId) {
  return rowToEntry(getBySubscriptionStmt.get(stripeSubscriptionId));
}

export function getSubscriptionByCustomer(stripeCustomerId) {
  return rowToEntry(getByCustomerStmt.get(stripeCustomerId));
}

export function listActiveSubscriptions() {
  return listActiveStmt.all().map(rowToEntry);
}

export function listAllSubscriptions() {
  return listAllStmt.all().map(rowToEntry);
}
