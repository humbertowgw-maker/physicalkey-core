import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Dynamic import, after PK_DATA_DIR is set, and deliberately not via the spawned-child-
// process pattern the rest of the suite uses: lib/db.js reads PK_DATA_DIR once at module
// evaluation time, and static imports are hoisted above any top-level code in this file —
// so a plain `import` here would run before we ever get to set the env var, and would
// silently open the real dev database instead of a throwaway one.
let recordSubscription, getSubscription, getSubscriptionByCustomer, listActiveSubscriptions, listAllSubscriptions;
let dataDir;

before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'physicalkey-subscriptions-test-'));
  process.env.PK_DATA_DIR = dataDir;
  ({ recordSubscription, getSubscription, getSubscriptionByCustomer, listActiveSubscriptions, listAllSubscriptions } =
    await import('../payments/subscriptions.js'));
});

after(() => {
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('recordSubscription inserts a new row for an unseen subscription id', () => {
  const result = recordSubscription({
    stripeSubscriptionId: 'sub_test_1',
    stripeCustomerId: 'cus_test_1',
    email: 'a@example.com',
    plan: 'team',
    status: 'active'
  }, 1_700_000_000_000);

  assert.equal(result.stripeSubscriptionId, 'sub_test_1');
  assert.equal(result.email, 'a@example.com');
  assert.equal(result.status, 'active');
});

test('recordSubscription updates status/plan on conflict but never overwrites a known email with null', () => {
  recordSubscription({
    stripeSubscriptionId: 'sub_test_2',
    stripeCustomerId: 'cus_test_2',
    email: 'b@example.com',
    plan: 'team',
    status: 'active'
  }, 1_700_000_000_000);

  // A subscription.updated event carries no email — this is the realistic shape of that
  // webhook, not a contrived edge case.
  const updated = recordSubscription({
    stripeSubscriptionId: 'sub_test_2',
    stripeCustomerId: 'cus_test_2',
    plan: 'team',
    status: 'canceled'
  }, 1_700_000_100_000);

  assert.equal(updated.status, 'canceled');
  assert.equal(updated.email, 'b@example.com', 'email from the original checkout must survive an update with no email');
});

test('getSubscription returns null for an unknown id', () => {
  assert.equal(getSubscription('sub_never_seen'), null);
});

test('getSubscriptionByCustomer returns the most recently updated subscription for that customer', () => {
  recordSubscription({ stripeSubscriptionId: 'sub_c1', stripeCustomerId: 'cus_multi', plan: 'team', status: 'active' }, 1_700_000_000_000);
  recordSubscription({ stripeSubscriptionId: 'sub_c2', stripeCustomerId: 'cus_multi', plan: 'team', status: 'active' }, 1_700_000_500_000);

  const latest = getSubscriptionByCustomer('cus_multi');
  assert.equal(latest.stripeSubscriptionId, 'sub_c2');
});

test('listActiveSubscriptions excludes canceled subscriptions', () => {
  recordSubscription({ stripeSubscriptionId: 'sub_active_1', stripeCustomerId: 'cus_active', plan: 'team', status: 'active' }, 1_700_000_000_000);
  recordSubscription({ stripeSubscriptionId: 'sub_canceled_1', stripeCustomerId: 'cus_canceled', plan: 'team', status: 'canceled' }, 1_700_000_000_000);

  const active = listActiveSubscriptions();
  const ids = active.map((s) => s.stripeSubscriptionId);
  assert.ok(ids.includes('sub_active_1'));
  assert.ok(!ids.includes('sub_canceled_1'));
});

test('listAllSubscriptions includes every status', () => {
  const all = listAllSubscriptions();
  const statuses = new Set(all.map((s) => s.status));
  assert.ok(statuses.has('active'));
  assert.ok(statuses.has('canceled'));
});
