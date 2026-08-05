import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, keypair, phoneAuth, fullAuth } from './helpers.js';

let server;
let adminToken;

before(async () => {
  server = await startServer();
  const adminSession = await fullAuth(server.baseUrl, 'revoke-admin-phone', keypair(), server.adminDeviceId, keypair());
  adminToken = adminSession.sessionToken;
});
after(async () => { await server.stop(); });

async function resetIdentity(deviceId) {
  const res = await fetch(`${server.baseUrl}/admin/identities/${deviceId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  return { status: res.status, body: await res.json() };
}

test('resetting a device identity revokes an already-issued full_access session for it, before natural expiry', async () => {
  const deviceId = 'revoke-target-device-1';
  const session = await fullAuth(server.baseUrl, 'revoke-phone-1', keypair(), deviceId, keypair());

  let res = await fetch(`${server.baseUrl}/api/profile`, { headers: { Authorization: `Bearer ${session.sessionToken}` } });
  assert.equal(res.status, 200, 'sanity check: the session works before the reset');

  const reset = await resetIdentity(deviceId);
  assert.equal(reset.status, 200);
  assert.ok(typeof reset.body.revokedSessionsAt === 'number', 'the reset response should confirm a revocation cutoff was set');

  res = await fetch(`${server.baseUrl}/api/profile`, { headers: { Authorization: `Bearer ${session.sessionToken}` } });
  assert.equal(res.status, 401, 'the same still-unexpired token must be rejected immediately after the reset');
});

test('resetting the PHONE identity behind a full_access session also revokes that session', async () => {
  // The stolen "device + phone both" scenario: an admin resetting the phone (because it
  // was the thing stolen) must not leave an already-issued full_access session — which
  // embeds the phone's identity too — still usable.
  const phoneDeviceId = 'revoke-phone-2';
  const deviceId = 'revoke-target-device-2';
  const session = await fullAuth(server.baseUrl, phoneDeviceId, keypair(), deviceId, keypair());

  let res = await fetch(`${server.baseUrl}/api/profile`, { headers: { Authorization: `Bearer ${session.sessionToken}` } });
  assert.equal(res.status, 200);

  await resetIdentity(phoneDeviceId);

  res = await fetch(`${server.baseUrl}/api/profile`, { headers: { Authorization: `Bearer ${session.sessionToken}` } });
  assert.equal(res.status, 401, 'resetting the phone side must also kill a full_access session it helped authorize');
});

test('resetting a phone identity revokes its phone_session tokens too', async () => {
  const phoneDeviceId = 'revoke-phone-3';
  const { phoneSessionToken } = await phoneAuth(server.baseUrl, phoneDeviceId, keypair());

  let res = await fetch(`${server.baseUrl}/orgs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${phoneSessionToken}` },
    body: JSON.stringify({ name: 'pre-reset org' })
  });
  assert.equal(res.status, 201, 'sanity check: the phone session works before the reset');

  await resetIdentity(phoneDeviceId);

  res = await fetch(`${server.baseUrl}/orgs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${phoneSessionToken}` },
    body: JSON.stringify({ name: 'post-reset org' })
  });
  assert.equal(res.status, 401, 'the same phone_session token must be rejected after its identity is reset');
});

test('a session minted AFTER the reset (re-registration) is unaffected', async () => {
  const deviceId = 'revoke-target-device-4';
  const phoneKeys1 = keypair();
  await fullAuth(server.baseUrl, 'revoke-phone-4a', phoneKeys1, deviceId, keypair());

  await resetIdentity(deviceId);

  // Re-registers deviceId fresh, after the reset — a later issuedAt than the revocation
  // cutoff, so this new session must NOT be treated as revoked.
  const newSession = await fullAuth(server.baseUrl, 'revoke-phone-4b', keypair(), deviceId, keypair());
  const res = await fetch(`${server.baseUrl}/api/profile`, { headers: { Authorization: `Bearer ${newSession.sessionToken}` } });
  assert.equal(res.status, 200, 'a session issued after the reset must work normally');
});

test('resetting one deviceId does not revoke an unrelated deviceId\'s session', async () => {
  const bystander = await fullAuth(server.baseUrl, 'revoke-bystander-phone', keypair(), 'revoke-bystander-device', keypair());
  await fullAuth(server.baseUrl, 'revoke-phone-5', keypair(), 'revoke-target-device-5', keypair());
  await resetIdentity('revoke-target-device-5');

  const res = await fetch(`${server.baseUrl}/api/profile`, { headers: { Authorization: `Bearer ${bystander.sessionToken}` } });
  assert.equal(res.status, 200, 'an unrelated device\'s session must be unaffected by someone else\'s reset');
});

test('a revoked token used against a protected endpoint is honeypotted', async () => {
  const deviceId = 'revoke-target-device-6';
  const session = await fullAuth(server.baseUrl, 'revoke-phone-6', keypair(), deviceId, keypair());
  await resetIdentity(deviceId);

  await fetch(`${server.baseUrl}/api/profile`, { headers: { Authorization: `Bearer ${session.sessionToken}` } });

  const res = await fetch(`${server.baseUrl}/admin/forensics`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const body = await res.json();
  const found = body.events.some((e) => e.reason === 'Revoked session token used' && e.details.deviceId === deviceId);
  assert.ok(found, 'a revoked token being used should show up in forensics, distinct from an invalid/expired one');
});
