import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, keypair, fullAuth } from './helpers.js';

let unenforced;
let enforced;
let enforcedAdminToken;

before(async () => {
  unenforced = await startServer();
  enforced = await startServer({ env: { ENFORCE_DEVICE_ALLOWLIST: 'true' } });
  const adminSession = await fullAuth(enforced.baseUrl, 'allowlist-admin-phone', keypair(), enforced.adminDeviceId, keypair());
  enforcedAdminToken = adminSession.sessionToken;
});
after(async () => {
  await unenforced.stop();
  await enforced.stop();
});

test('allow-list is off by default — a brand-new device registers exactly as before', async () => {
  const result = await fullAuth(unenforced.baseUrl, 'unenforced-phone-1', keypair(), 'unenforced-device-1', keypair());
  assert.ok(result.sessionToken, 'with ENFORCE_DEVICE_ALLOWLIST unset, TOFU registration is unaffected');
});

test('with enforcement on, a new device NOT on the allow-list is rejected', async () => {
  await assert.rejects(
    fullAuth(enforced.baseUrl, 'enforced-phone-1', keypair(), 'enforced-device-not-listed', keypair()),
    /device verify failed/,
    'a deviceId never added to the allow-list must not be able to TOFU-register when enforcement is on'
  );
});

test('with enforcement on, a device that IS on the allow-list registers normally', async () => {
  const deviceId = 'enforced-device-listed';
  let res = await fetch(`${enforced.baseUrl}/admin/device-allowlist`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${enforcedAdminToken}` },
    body: JSON.stringify({ deviceId, note: 'test board' })
  });
  assert.equal(res.status, 201);

  const result = await fullAuth(enforced.baseUrl, 'enforced-phone-2', keypair(), deviceId, keypair());
  assert.ok(result.sessionToken, 'a pre-approved deviceId should register normally once enforcement is on');
});

test('an already-registered device keeps working under enforcement, even though it was never added to the list', async () => {
  // Registered on the UNENFORCED server above ("unenforced-device-1") — but the point here
  // is the ONLY gate is at first-ever registration. Simulate by registering fresh on the
  // enforced server first via the allow-list, then confirm re-auth doesn't re-check the list.
  const deviceId = 'enforced-device-reauth';
  const deviceKeys = keypair();
  let res = await fetch(`${enforced.baseUrl}/admin/device-allowlist`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${enforcedAdminToken}` },
    body: JSON.stringify({ deviceId })
  });
  assert.equal(res.status, 201);
  await fullAuth(enforced.baseUrl, 'enforced-phone-3a', keypair(), deviceId, deviceKeys);

  // Remove it from the allow-list — if re-registration checked the list again, this would
  // now fail; it must not, since the device already has a trusted key on file.
  await fetch(`${enforced.baseUrl}/admin/device-allowlist/${deviceId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${enforcedAdminToken}` }
  });

  const result = await fullAuth(enforced.baseUrl, 'enforced-phone-3b', keypair(), deviceId, deviceKeys);
  assert.ok(result.sessionToken, 'an already-registered device must keep working even after being removed from the allow-list');
});

test('phone identities are never gated by the device allow-list', async () => {
  // Phones TOFU-register too, but the allow-list only ever checks kind='device' — a phone
  // with a never-listed deviceId must still be able to complete the phone-only steps.
  const res = await fetch(`${enforced.baseUrl}/auth/phone/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ phoneAttestation: { platform: 'iOS', deviceId: 'never-listed-phone', publicKey: keypair().publicKeyB64 } })
  });
  assert.equal(res.status, 200, 'phone registration must be unaffected by the device allow-list');
});

test('GET /admin/device-allowlist reports enforcement state and current entries, admin-only', async () => {
  let res = await fetch(`${enforced.baseUrl}/admin/device-allowlist`);
  assert.equal(res.status, 401, 'must require admin auth');

  res = await fetch(`${enforced.baseUrl}/admin/device-allowlist`, { headers: { Authorization: `Bearer ${enforcedAdminToken}` } });
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.enforced, true);
  assert.ok(Array.isArray(body.entries));
});

test('DELETE /admin/device-allowlist/:deviceId 404s for a deviceId never added', async () => {
  const res = await fetch(`${enforced.baseUrl}/admin/device-allowlist/never-added-at-all`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${enforcedAdminToken}` }
  });
  assert.equal(res.status, 404);
});

test('allow-list changes are recorded in the global admin audit log', async () => {
  const deviceId = 'enforced-device-audited';
  await fetch(`${enforced.baseUrl}/admin/device-allowlist`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${enforcedAdminToken}` },
    body: JSON.stringify({ deviceId })
  });

  const res = await fetch(`${enforced.baseUrl}/admin/audit-log`, { headers: { Authorization: `Bearer ${enforcedAdminToken}` } });
  const body = await res.json();
  const entry = body.entries.find((e) => e.action === 'device_allowlist_added' && e.targetDeviceId === deviceId);
  assert.ok(entry, 'adding a deviceId to the allow-list should be recorded in the audit log');
});
