import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import Stripe from 'stripe';
import { startServer, keypair, phoneAuth, fullAuth } from './helpers.js';

const WEBHOOK_SECRET = 'whsec_test_secret_for_licensing_tests';
const stripeTestClient = new Stripe('sk_test_dummy_key_for_signing_only');

let server;
let adminToken;

before(async () => {
  server = await startServer({
    env: {
      STRIPE_SECRET_KEY: 'sk_test_dummy',
      STRIPE_PRICE_ID_TEAM: 'price_dummy',
      STRIPE_WEBHOOK_SECRET: WEBHOOK_SECRET
    }
  });
  const adminSession = await fullAuth(server.baseUrl, 'licensing-admin-phone', keypair(), server.adminDeviceId, keypair());
  adminToken = adminSession.sessionToken;
});

after(async () => { await server.stop(); });

function authHeader(token) {
  return { Authorization: `Bearer ${token}` };
}

function orgHeaders(token) {
  return { 'Content-Type': 'application/json', ...authHeader(token) };
}

async function phoneSession(deviceId) {
  const keys = keypair();
  const { phoneSessionToken } = await phoneAuth(server.baseUrl, deviceId, keys);
  return { deviceId, keys, phoneSessionToken };
}

async function createOrg(ownerSession, name) {
  const res = await fetch(`${server.baseUrl}/orgs`, {
    method: 'POST', headers: orgHeaders(ownerSession.phoneSessionToken),
    body: JSON.stringify({ name })
  });
  return res.json();
}

async function claimDevice(orgId, ownerSession, deviceId) {
  return fetch(`${server.baseUrl}/orgs/${orgId}/devices`, {
    method: 'POST', headers: orgHeaders(ownerSession.phoneSessionToken),
    body: JSON.stringify({ deviceId })
  });
}

/** Runs a real webhook through the server to generate a genuine, redeemable code. */
async function generateLicenseCode(subscriptionId) {
  const payload = JSON.stringify({
    id: `evt_${subscriptionId}`,
    object: 'event',
    type: 'checkout.session.completed',
    data: { object: { customer: `cus_${subscriptionId}`, subscription: subscriptionId } }
  });
  const header = stripeTestClient.webhooks.generateTestHeaderString({ payload, secret: WEBHOOK_SECRET });
  const res = await fetch(`${server.baseUrl}/billing/webhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'stripe-signature': header },
    body: payload
  });
  assert.equal(res.status, 200);

  const codeRes = await fetch(`${server.baseUrl}/admin/license-codes/${subscriptionId}`, {
    headers: authHeader(adminToken)
  });
  const record = await codeRes.json();
  return record.code;
}

test('a second device on the same org is blocked without a redeemed license — the free shape is exactly one device', async () => {
  const owner = await phoneSession('license-owner-1');
  const org = await createOrg(owner, 'Single Device Org');

  const deviceAKeys = keypair();
  await fullAuth(server.baseUrl, 'license-bootstrap-1a', keypair(), 'license-device-1a', deviceAKeys);
  const first = await claimDevice(org.id, owner, 'license-device-1a');
  assert.equal(first.status, 201, 'the first device on a fresh org is free');

  const deviceBKeys = keypair();
  await fullAuth(server.baseUrl, 'license-bootstrap-1b', keypair(), 'license-device-1b', deviceBKeys);
  const second = await claimDevice(org.id, owner, 'license-device-1b');
  assert.equal(second.status, 402, 'a second device without an active Team plan should be rejected as payment-required');
});

test('redeeming a valid code unlocks a second device on that org', async () => {
  const owner = await phoneSession('license-owner-2');
  const org = await createOrg(owner, 'Redemption Org');

  const deviceAKeys = keypair();
  await fullAuth(server.baseUrl, 'license-bootstrap-2a', keypair(), 'license-device-2a', deviceAKeys);
  await claimDevice(org.id, owner, 'license-device-2a');

  const code = await generateLicenseCode('sub_redeem_test_2');
  const redeemRes = await fetch(`${server.baseUrl}/orgs/${org.id}/redeem-license`, {
    method: 'POST', headers: orgHeaders(owner.phoneSessionToken),
    body: JSON.stringify({ code })
  });
  assert.equal(redeemRes.status, 200);
  assert.equal((await redeemRes.json()).status, 'active');

  const deviceBKeys = keypair();
  await fullAuth(server.baseUrl, 'license-bootstrap-2b', keypair(), 'license-device-2b', deviceBKeys);
  const second = await claimDevice(org.id, owner, 'license-device-2b');
  assert.equal(second.status, 201, 'a second device should now succeed after redeeming a valid code');
});

test('a code cannot be redeemed twice', async () => {
  const owner1 = await phoneSession('license-owner-3a');
  const owner2 = await phoneSession('license-owner-3b');
  const org1 = await createOrg(owner1, 'First Redeemer Org');
  const org2 = await createOrg(owner2, 'Second Redeemer Org');

  const code = await generateLicenseCode('sub_redeem_test_3');

  const first = await fetch(`${server.baseUrl}/orgs/${org1.id}/redeem-license`, {
    method: 'POST', headers: orgHeaders(owner1.phoneSessionToken),
    body: JSON.stringify({ code })
  });
  assert.equal(first.status, 200);

  const second = await fetch(`${server.baseUrl}/orgs/${org2.id}/redeem-license`, {
    method: 'POST', headers: orgHeaders(owner2.phoneSessionToken),
    body: JSON.stringify({ code })
  });
  assert.equal(second.status, 404, 'an already-redeemed code must not work for a different org');
});

test('an invalid code, and a non-admin caller, are both rejected', async () => {
  const owner = await phoneSession('license-owner-4');
  const member = await phoneSession('license-member-4');
  const org = await createOrg(owner, 'Bad Code Org');
  await fetch(`${server.baseUrl}/orgs/${org.id}/members`, {
    method: 'POST', headers: orgHeaders(owner.phoneSessionToken),
    body: JSON.stringify({ deviceId: member.deviceId })
  });

  const bogus = await fetch(`${server.baseUrl}/orgs/${org.id}/redeem-license`, {
    method: 'POST', headers: orgHeaders(owner.phoneSessionToken),
    body: JSON.stringify({ code: 'NOPE-NOPE-NOPE' })
  });
  assert.equal(bogus.status, 404);

  const code = await generateLicenseCode('sub_redeem_test_4');
  const asMember = await fetch(`${server.baseUrl}/orgs/${org.id}/redeem-license`, {
    method: 'POST', headers: orgHeaders(member.phoneSessionToken),
    body: JSON.stringify({ code })
  });
  assert.equal(asMember.status, 403, 'a plain member, not just owners/admins, cannot redeem a license for the org');
});
