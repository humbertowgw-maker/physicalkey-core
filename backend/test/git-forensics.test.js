import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, keypair, fullAuth } from './helpers.js';

let server;
let session;

before(async () => {
  server = await startServer();
  session = await fullAuth(
    server.baseUrl,
    'git-test-phone', keypair(),
    'git-test-device', keypair()
  );
});
after(async () => { await server.stop(); });

test('/git/auth accepts valid credentials', async () => {
  const auth = Buffer.from(`${session.gitCredentials.username}:${session.gitCredentials.password}`).toString('base64');
  const res = await fetch(`${server.baseUrl}/git/auth`, { headers: { Authorization: `Basic ${auth}` } });
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.granted, true);
});

test('/git/auth rejects a wrong password', async () => {
  const auth = Buffer.from(`${session.gitCredentials.username}:wrong-password`).toString('base64');
  const res = await fetch(`${server.baseUrl}/git/auth`, { headers: { Authorization: `Basic ${auth}` } });
  assert.notEqual(res.status, 200, 'a wrong password must not be granted access');
});

test('/git/auth rejects missing credentials', async () => {
  const res = await fetch(`${server.baseUrl}/git/auth`);
  assert.notEqual(res.status, 200, 'missing credentials must not be granted access');
});

test('/admin/forensics rejects a non-admin device with an otherwise-valid session', async () => {
  const res = await fetch(`${server.baseUrl}/admin/forensics`, {
    headers: { Authorization: `Bearer ${session.sessionToken}` }
  });
  assert.equal(res.status, 403);
});

test('/admin/forensics rejects requests with no token at all', async () => {
  const res = await fetch(`${server.baseUrl}/admin/forensics`);
  assert.equal(res.status, 401);
});

test('/admin/forensics returns real attacker data (with populated techniques) for the admin device', async () => {
  // Trip the honeypot with some bad requests first, so there's something for the report
  // to actually contain.
  await fetch(`${server.baseUrl}/git/auth`); // missing creds
  await fetch(`${server.baseUrl}/api/honeypot/fake-database`);

  const adminSession = await fullAuth(
    server.baseUrl,
    'admin-test-phone', keypair(),
    server.adminDeviceId, keypair()
  );

  const res = await fetch(`${server.baseUrl}/admin/forensics`, {
    headers: { Authorization: `Bearer ${adminSession.sessionToken}` }
  });
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.ok(Array.isArray(body.attackers) && body.attackers.length > 0, 'expected at least one attacker profile');
  const withTechniques = body.attackers.find((a) => Array.isArray(a.techniques) && a.techniques.length > 0);
  assert.ok(withTechniques, 'attacker techniques must be populated (regression check: a Set that fails to serialize would show up as an empty array here)');
});

test('honeypot decoy endpoint returns decoy data, not anything real', async () => {
  const res = await fetch(`${server.baseUrl}/api/honeypot/fake-database`);
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body._decoy, true);
  assert.ok(Array.isArray(body.users));
});
