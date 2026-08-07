import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import Stripe from 'stripe';
import { startServer, keypair, fullAuth } from './helpers.js';

const WEBHOOK_SECRET = 'whsec_test_secret_for_billing_tests';
// Real key format matters to the Stripe SDK's own constructor validation, but this never
// makes a network call in these tests — generateTestHeaderString and constructEvent are
// both pure local HMAC operations.
const stripeTestClient = new Stripe('sk_test_dummy_key_for_signing_only');

function signedCheckoutPayload({ subscriptionId, customerId, email }) {
  const payload = JSON.stringify({
    id: 'evt_test_checkout',
    object: 'event',
    type: 'checkout.session.completed',
    data: {
      object: {
        customer: customerId,
        subscription: subscriptionId,
        customer_details: { email }
      }
    }
  });
  const header = stripeTestClient.webhooks.generateTestHeaderString({ payload, secret: WEBHOOK_SECRET });
  return { payload, header };
}

let unconfigured;
let configured;
let configuredAdminToken;

before(async () => {
  unconfigured = await startServer();

  configured = await startServer({
    env: {
      STRIPE_SECRET_KEY: 'sk_test_dummy',
      STRIPE_PRICE_ID_TEAM: 'price_dummy',
      STRIPE_WEBHOOK_SECRET: WEBHOOK_SECRET
    }
  });
  const adminSession = await fullAuth(configured.baseUrl, 'billing-admin-phone', keypair(), configured.adminDeviceId, keypair());
  configuredAdminToken = adminSession.sessionToken;
});

after(async () => {
  await unconfigured.stop();
  await configured.stop();
});

test('POST /billing/checkout returns 503 when Stripe env vars are unset', async () => {
  const res = await fetch(`${unconfigured.baseUrl}/billing/checkout`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'someone@example.com' })
  });
  assert.equal(res.status, 503);
});

test('OPTIONS /billing/checkout answers the CORS preflight for the landing page origin', async () => {
  const res = await fetch(`${configured.baseUrl}/billing/checkout`, { method: 'OPTIONS' });
  assert.equal(res.status, 204);
  assert.equal(res.headers.get('access-control-allow-origin'), 'https://physicalkey.whitegwireless.com');
  assert.equal(res.headers.get('access-control-allow-methods'), 'POST');
});

test('POST /billing/checkout rejects a missing or invalid email before ever calling Stripe', async () => {
  const missing = await fetch(`${configured.baseUrl}/billing/checkout`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({})
  });
  assert.equal(missing.status, 400);

  const invalid = await fetch(`${configured.baseUrl}/billing/checkout`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'not-an-email' })
  });
  assert.equal(invalid.status, 400);
});

test('POST /billing/checkout sets the scoped CORS header on the actual response, not just preflight', async () => {
  const res = await fetch(`${configured.baseUrl}/billing/checkout`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({})
  });
  assert.equal(res.headers.get('access-control-allow-origin'), 'https://physicalkey.whitegwireless.com');
});

test('POST /billing/webhook returns 503 when Stripe env vars are unset', async () => {
  const res = await fetch(`${unconfigured.baseUrl}/billing/webhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{}'
  });
  assert.equal(res.status, 503);
});

test('POST /billing/webhook rejects a payload with an invalid signature', async () => {
  const { payload } = signedCheckoutPayload({
    subscriptionId: 'sub_bad_sig', customerId: 'cus_bad_sig', email: 'x@example.com'
  });
  const res = await fetch(`${configured.baseUrl}/billing/webhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'stripe-signature': 't=1,v1=not_a_real_signature' },
    body: payload
  });
  assert.equal(res.status, 400);
});

test('POST /billing/webhook with a genuinely Stripe-signed checkout.session.completed records the subscription', async () => {
  const { payload, header } = signedCheckoutPayload({
    subscriptionId: 'sub_from_webhook', customerId: 'cus_from_webhook', email: 'webhook-test@example.com'
  });

  const res = await fetch(`${configured.baseUrl}/billing/webhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'stripe-signature': header },
    body: payload
  });
  assert.equal(res.status, 200);

  const admin = await fetch(`${configured.baseUrl}/admin/subscriptions`, {
    headers: { Authorization: `Bearer ${configuredAdminToken}` }
  });
  const { subscriptions } = await admin.json();
  const recorded = subscriptions.find((s) => s.stripeSubscriptionId === 'sub_from_webhook');
  assert.ok(recorded, 'the webhook-recorded subscription should show up in /admin/subscriptions');
  assert.equal(recorded.status, 'active');
  assert.equal(recorded.email, 'webhook-test@example.com');
});

test('GET /admin/subscriptions requires an admin token', async () => {
  const res = await fetch(`${configured.baseUrl}/admin/subscriptions`);
  assert.equal(res.status, 401);
});
