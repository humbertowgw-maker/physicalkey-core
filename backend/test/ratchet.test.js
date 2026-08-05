import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, keypair, fullAuth } from './helpers.js';

let server;
let adminToken;

before(async () => {
  server = await startServer();
  const adminSession = await fullAuth(server.baseUrl, 'ratchet-admin-phone', keypair(), server.adminDeviceId, keypair());
  adminToken = adminSession.sessionToken;
});
after(async () => { await server.stop(); });

test('device verify with no ratchetStatus field behaves exactly as before (backward compatible)', async () => {
  const result = await fullAuth(server.baseUrl, 'ratchet-phone-1', keypair(), 'ratchet-device-1', keypair());
  assert.ok(result.sessionToken);

  const res = await fetch(`${server.baseUrl}/admin/identities/ratchet-device-1`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const body = await res.json();
  assert.equal(body.ratchet, null, 'no ratchet row should exist when the phone never reported a status');
});

test('a valid ratchetStatus is recorded and does not block authentication, even mismatch', async () => {
  const result = await fullAuth(
    server.baseUrl, 'ratchet-phone-2', keypair(), 'ratchet-device-2', keypair(),
    { ratchetStatus: 'mismatch' }
  );
  assert.ok(result.sessionToken, 'a ratchet mismatch is warn-not-block: auth must still succeed');

  const res = await fetch(`${server.baseUrl}/admin/identities/ratchet-device-2`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const body = await res.json();
  assert.equal(body.ratchet.status, 'mismatch');
});

test('a mismatch is logged to forensics as a warning, not silently dropped', async () => {
  await fullAuth(
    server.baseUrl, 'ratchet-phone-3', keypair(), 'ratchet-device-3', keypair(),
    { ratchetStatus: 'mismatch' }
  );

  const res = await fetch(`${server.baseUrl}/admin/forensics`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const body = await res.json();
  const found = body.events.some(e => e.reason.includes('Ratchet continuity mismatch') && e.details.deviceId === 'ratchet-device-3');
  assert.ok(found, 'the mismatch should show up in the forensics event log');
});

test('an invalid ratchetStatus value is rejected as malformed but still does not block auth', async () => {
  const result = await fullAuth(
    server.baseUrl, 'ratchet-phone-4', keypair(), 'ratchet-device-4', keypair(),
    { ratchetStatus: 'not-a-real-status' }
  );
  assert.ok(result.sessionToken);

  const res = await fetch(`${server.baseUrl}/admin/identities/ratchet-device-4`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const body = await res.json();
  assert.equal(body.ratchet, null, 'a malformed status should never be stored');
});

test('admin identity reset also clears ratchet state — the escape hatch', async () => {
  await fullAuth(
    server.baseUrl, 'ratchet-phone-5', keypair(), 'ratchet-device-5', keypair(),
    { ratchetStatus: 'mismatch' }
  );

  let res = await fetch(`${server.baseUrl}/admin/identities/ratchet-device-5`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  let body = await res.json();
  assert.equal(body.ratchet.status, 'mismatch', 'sanity check: the mismatch is there before reset');

  res = await fetch(`${server.baseUrl}/admin/identities/ratchet-device-5`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.clearedRatchetStatus, 'mismatch', 'the reset response should report what ratchet status it cleared');

  res = await fetch(`${server.baseUrl}/admin/identities/ratchet-device-5`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert.equal(res.status, 404, 'the identity itself is gone after reset, same as before this change');
});

test('resetting an identity with no ratchet state reports clearedRatchetStatus as null', async () => {
  await fullAuth(server.baseUrl, 'ratchet-phone-6', keypair(), 'ratchet-device-6', keypair());

  const res = await fetch(`${server.baseUrl}/admin/identities/ratchet-device-6`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.clearedRatchetStatus, null);
});
