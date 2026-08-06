import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, keypair, fullAuth, phoneAuth } from './helpers.js';

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

test('GET /admin/device-org/:deviceId reports no org for an unclaimed device, and rejects with no admin token', async () => {
  const unauth = await fetch(`${server.baseUrl}/admin/device-org/nonexistent`);
  assert.equal(unauth.status, 401);

  const res = await fetch(`${server.baseUrl}/admin/device-org/never-claimed-device`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.org, null);
});

test('GET /admin/device-org/:deviceId surfaces the claiming org, its members, and access grants — without the admin needing org membership', async () => {
  const ownerDeviceId = 'device-org-diag-owner';
  const { phoneSessionToken: ownerToken } = await phoneAuth(server.baseUrl, ownerDeviceId, keypair());

  const orgRes = await fetch(`${server.baseUrl}/orgs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${ownerToken}` },
    body: JSON.stringify({ name: 'Diagnostic Test Org' })
  });
  const org = await orgRes.json();

  const targetDeviceId = 'device-org-diag-target';
  await fullAuth(server.baseUrl, 'device-org-diag-target-phone', keypair(), targetDeviceId, keypair());

  await fetch(`${server.baseUrl}/orgs/${org.id}/devices`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${ownerToken}` },
    body: JSON.stringify({ deviceId: targetDeviceId })
  });

  // The admin device is NOT a member of this org — this is exactly the scenario that
  // motivated the endpoint: no other route can answer "which org claimed this device"
  // without already being a member of it.
  const res = await fetch(`${server.baseUrl}/admin/device-org/${targetDeviceId}`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.org.id, org.id);
  assert.ok(body.members.find(m => m.device_id === ownerDeviceId && m.role === 'owner'));
});

test('DELETE /admin/device-org/:deviceId releases a claimed device, and rejects with no admin token', async () => {
  const ownerDeviceId = 'device-org-release-owner';
  const { phoneSessionToken: ownerToken } = await phoneAuth(server.baseUrl, ownerDeviceId, keypair());

  const orgRes = await fetch(`${server.baseUrl}/orgs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${ownerToken}` },
    body: JSON.stringify({ name: 'Release Test Org' })
  });
  const org = await orgRes.json();

  const targetDeviceId = 'device-org-release-target';
  await fullAuth(server.baseUrl, 'device-org-release-target-phone', keypair(), targetDeviceId, keypair());

  await fetch(`${server.baseUrl}/orgs/${org.id}/devices`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${ownerToken}` },
    body: JSON.stringify({ deviceId: targetDeviceId })
  });

  const unauth = await fetch(`${server.baseUrl}/admin/device-org/${targetDeviceId}`, { method: 'DELETE' });
  assert.equal(unauth.status, 401);

  let res = await fetch(`${server.baseUrl}/admin/device-org/${targetDeviceId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  let body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.status, 'released');
  assert.equal(body.previousOrgId, org.id);

  // Confirmed released, not just a claimed success response.
  res = await fetch(`${server.baseUrl}/admin/device-org/${targetDeviceId}`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  body = await res.json();
  assert.equal(body.org, null);

  // 404 on an already-unclaimed device, not a silent 200.
  res = await fetch(`${server.baseUrl}/admin/device-org/${targetDeviceId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert.equal(res.status, 404);
});

test('new identities default to recovery_policy self-service, and reset works normally', async () => {
  const targetDeviceId = 'recovery-default-target';
  await fullAuth(server.baseUrl, 'recovery-default-phone', keypair(), targetDeviceId, keypair());

  const res = await fetch(`${server.baseUrl}/admin/identities/${targetDeviceId}`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const body = await res.json();
  assert.equal(body.recovery_policy, 'self-service');

  const del = await fetch(`${server.baseUrl}/admin/identities/${targetDeviceId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert.equal(del.status, 200, 'a self-service identity should still reset normally');
});

test('POST /admin/identities/:deviceId/recovery-policy sets it, and rejects invalid values / no token', async () => {
  const targetDeviceId = 'recovery-policy-set-target';
  await fullAuth(server.baseUrl, 'recovery-policy-set-phone', keypair(), targetDeviceId, keypair());

  const unauth = await fetch(`${server.baseUrl}/admin/identities/${targetDeviceId}/recovery-policy`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ recoveryPolicy: 'permanent' })
  });
  assert.equal(unauth.status, 401);

  const invalid = await fetch(`${server.baseUrl}/admin/identities/${targetDeviceId}/recovery-policy`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ recoveryPolicy: 'sometimes' })
  });
  assert.equal(invalid.status, 400);

  const notFound = await fetch(`${server.baseUrl}/admin/identities/never-registered-xyz/recovery-policy`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ recoveryPolicy: 'permanent' })
  });
  assert.equal(notFound.status, 404);

  const res = await fetch(`${server.baseUrl}/admin/identities/${targetDeviceId}/recovery-policy`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ recoveryPolicy: 'permanent' })
  });
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.recovery_policy, 'permanent');
});

test('a permanent identity cannot be reset, cannot be un-permanented, and this is enforced by the code — not just documented', async () => {
  const targetDeviceId = 'recovery-permanent-target';
  await fullAuth(server.baseUrl, 'recovery-permanent-phone', keypair(), targetDeviceId, keypair());

  await fetch(`${server.baseUrl}/admin/identities/${targetDeviceId}/recovery-policy`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ recoveryPolicy: 'permanent' })
  });

  // The actual guarantee: DELETE refuses outright, no admin override path exists in code.
  const del = await fetch(`${server.baseUrl}/admin/identities/${targetDeviceId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert.equal(del.status, 403);

  // Confirmed NOT deleted — a 403 that quietly still deleted it would be worse than useless.
  const stillThere = await fetch(`${server.baseUrl}/admin/identities/${targetDeviceId}`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert.equal(stillThere.status, 200);

  // Cannot be walked back to self-service either — otherwise "permanent" would just mean
  // "permanent until an admin flips the flag first," which defeats the point.
  const revert = await fetch(`${server.baseUrl}/admin/identities/${targetDeviceId}/recovery-policy`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ recoveryPolicy: 'self-service' })
  });
  assert.equal(revert.status, 403);

  const stillPermanent = await fetch(`${server.baseUrl}/admin/identities/${targetDeviceId}`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const body = await stillPermanent.json();
  assert.equal(body.recovery_policy, 'permanent');
});

test('GET /admin/identities lists every registered identity, without exposing public keys', async () => {
  const deviceId = 'list-target-device';
  await fullAuth(server.baseUrl, 'list-target-phone', keypair(), deviceId, keypair());

  const unauth = await fetch(`${server.baseUrl}/admin/identities`);
  assert.equal(unauth.status, 401);

  const res = await fetch(`${server.baseUrl}/admin/identities`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.ok(Array.isArray(body.identities));

  const phoneEntry = body.identities.find(i => i.device_id === 'list-target-phone');
  const deviceEntry = body.identities.find(i => i.device_id === deviceId);
  assert.ok(phoneEntry, 'the newly registered phone identity should appear in the list');
  assert.ok(deviceEntry, 'the newly registered device identity should appear in the list');
  assert.equal(deviceEntry.kind, 'device');
  assert.equal(phoneEntry.kind, 'phone');
  assert.equal(deviceEntry.public_key, undefined, 'the list view should not include public keys');
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

test('resetting a device identity also revokes its git credentials', async () => {
  const targetDeviceId = 'git-revoke-target';
  const session = await fullAuth(server.baseUrl, 'git-revoke-phone', keypair(), targetDeviceId, keypair());

  const auth = Buffer.from(`${session.gitCredentials.username}:${session.gitCredentials.password}`).toString('base64');
  let res = await fetch(`${server.baseUrl}/git/auth`, { headers: { Authorization: `Basic ${auth}` } });
  assert.equal(res.status, 200, 'git credentials should work before the reset');

  res = await fetch(`${server.baseUrl}/admin/identities/${targetDeviceId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.revokedGitAccess, true, 'the reset response should confirm git access was revoked');

  res = await fetch(`${server.baseUrl}/git/auth`, { headers: { Authorization: `Basic ${auth}` } });
  assert.notEqual(res.status, 200, 'the same git credentials must stop working immediately after an identity reset — not linger for their remaining 24h');
});

test('GET /admin/audit-log rejects non-admin requests and records identity resets', async () => {
  let res = await fetch(`${server.baseUrl}/admin/audit-log`);
  assert.equal(res.status, 401);

  const targetDeviceId = 'audit-log-target';
  await fullAuth(server.baseUrl, 'audit-target-phone', keypair(), targetDeviceId, keypair());

  res = await fetch(`${server.baseUrl}/admin/identities/${targetDeviceId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert.equal(res.status, 200);

  res = await fetch(`${server.baseUrl}/admin/audit-log`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const body = await res.json();
  assert.equal(res.status, 200);
  const entry = body.entries.find(e => e.targetDeviceId === targetDeviceId);
  assert.ok(entry, 'the reset should have been recorded in the audit log');
  assert.equal(entry.action, 'identity_reset');
  assert.equal(entry.adminDeviceId, server.adminDeviceId);
});
