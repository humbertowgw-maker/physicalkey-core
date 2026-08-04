import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, keypair, fullAuth } from './helpers.js';

let server;
let adminToken;

before(async () => {
  server = await startServer();
  const adminSession = await fullAuth(server.baseUrl, 'admin-session-phone', keypair(), server.adminDeviceId, keypair());
  adminToken = adminSession.sessionToken;
});
after(async () => { await server.stop(); });

test('GET/DELETE /admin/identities reject requests with no admin token', async () => {
  let res = await fetch(`${server.baseUrl}/admin/identities/nonexistent`);
  assert.equal(res.status, 401);

  res = await fetch(`${server.baseUrl}/admin/identities/nonexistent`, { method: 'DELETE' });
  assert.equal(res.status, 401);
});

test('GET /admin/identities/:deviceId 404s for an unregistered deviceId', async () => {
  const res = await fetch(`${server.baseUrl}/admin/identities/never-registered`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert.equal(res.status, 404);
});

test('reset flow: register -> admin can inspect it -> admin resets it -> it is gone -> re-registers fresh', async () => {
  const targetDeviceId = 'admin-reset-target';
  const originalKeys = keypair();

  const registered = await fullAuth(server.baseUrl, 'target-phone', keypair(), targetDeviceId, originalKeys);
  assert.ok(registered.sessionToken, 'target identity should register successfully the first time');

  let res = await fetch(`${server.baseUrl}/admin/identities/${targetDeviceId}`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  let body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.device_id, targetDeviceId);
  assert.equal(body.public_key, originalKeys.publicKeyB64);

  res = await fetch(`${server.baseUrl}/admin/identities/${targetDeviceId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.status, 'reset');

  res = await fetch(`${server.baseUrl}/admin/identities/${targetDeviceId}`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert.equal(res.status, 404, 'identity should be gone immediately after reset');

  // The actual point of the reset: the SAME deviceId can now register a DIFFERENT key —
  // exactly what a re-flashed ESP32 board or a recreated phone Keychain identity needs.
  const newKeys = keypair();
  const reregistered = await fullAuth(server.baseUrl, 'target-phone-2', keypair(), targetDeviceId, newKeys);
  assert.ok(reregistered.sessionToken, 'deviceId should be able to re-register with a new key after an admin reset');

  res = await fetch(`${server.baseUrl}/admin/identities/${targetDeviceId}`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  body = await res.json();
  assert.equal(body.public_key, newKeys.publicKeyB64, 'the newly re-registered key should now be on file');
});

test('DELETE /admin/identities/:deviceId 404s for an unregistered deviceId', async () => {
  const res = await fetch(`${server.baseUrl}/admin/identities/still-never-registered`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert.equal(res.status, 404);
});
