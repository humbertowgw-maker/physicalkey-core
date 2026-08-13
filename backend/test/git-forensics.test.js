import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { startServer, keypair, fullAuth } from './helpers.js';

let server;
let session;
const adminKeys = keypair();

async function adminAuth() {
  const adminSession = await fullAuth(server.baseUrl, `admin-test-phone-${crypto.randomUUID()}`, keypair(), server.adminDeviceId, adminKeys);
  return adminSession.sessionToken;
}

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

  const adminToken = await adminAuth();

  const res = await fetch(`${server.baseUrl}/admin/forensics`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.ok(Array.isArray(body.attackers) && body.attackers.length > 0, 'expected at least one attacker profile');
  const withTechniques = body.attackers.find((a) => Array.isArray(a.techniques) && a.techniques.length > 0);
  assert.ok(withTechniques, 'attacker techniques must be populated (regression check: a Set that fails to serialize would show up as an empty array here)');
});

test('a normal successful auth flow is never logged as a honeypot event', async () => {
  // honeypotLogger is applied only to the three pre-auth endpoints, none of which ever
  // legitimately carries an Authorization header — logging on "no auth header" as well as
  // on failure meant every ordinary successful auth attempt got recorded as an "event"
  // indistinguishable from an attack. A real failure still logs (details.statusCode >= 400,
  // via this same middleware, independent of any explicit activateHoneypot() call); a
  // success must not, ever.
  await fullAuth(server.baseUrl, 'quiet-phone', keypair(), 'quiet-device', keypair());

  const adminToken = await adminAuth();
  const res = await fetch(`${server.baseUrl}/admin/forensics`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const body = await res.json();
  assert.equal(res.status, 200);

  const successfulEventsLogged = body.events.filter((e) => e.details?.statusCode === 200);
  assert.equal(successfulEventsLogged.length, 0, 'no honeypot event should ever carry a 200 status code — that middleware only fires on real failures now');
});

test('honeypot decoy endpoint returns decoy data, not anything real', async () => {
  const res = await fetch(`${server.baseUrl}/api/honeypot/fake-database`);
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body._decoy, true);
  assert.ok(Array.isArray(body.users));
});

test('/admin/forensics excludes CGNAT-range IPs (100.64.0.0/10) from attackers by default, includes them with includeInternal=true', async () => {
  await fetch(`${server.baseUrl}/git/auth`, { headers: { 'X-Forwarded-For': '100.64.5.5' } });

  const adminToken = await adminAuth();
  const defaultRes = await fetch(`${server.baseUrl}/admin/forensics`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const defaultBody = await defaultRes.json();
  assert.ok(!defaultBody.attackers.some((a) => a.ip === '100.64.5.5'), 'a CGNAT-range IP is not a real internet attacker source and must not appear by default');
  assert.ok(defaultBody.summary.internalIPs >= 1, 'summary must report how many IPs were excluded, not hide it silently');

  const includeRes = await fetch(`${server.baseUrl}/admin/forensics?includeInternal=true`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const includeBody = await includeRes.json();
  const tagged = includeBody.attackers.find((a) => a.ip === '100.64.5.5');
  assert.ok(tagged, 'includeInternal=true must still surface the IP for debugging');
  assert.equal(tagged.internal, true);
});

test('/admin/forensics excludes IPs listed in KNOWN_INTERNAL_IPS from attackers by default', async () => {
  const taggedServer = await startServer({ env: { KNOWN_INTERNAL_IPS: '203.0.113.9,203.0.113.10' } });
  try {
    await fetch(`${taggedServer.baseUrl}/git/auth`, { headers: { 'X-Forwarded-For': '203.0.113.9' } });
    await fetch(`${taggedServer.baseUrl}/git/auth`, { headers: { 'X-Forwarded-For': '203.0.113.55' } }); // NOT on the list

    const adminSession = await fullAuth(taggedServer.baseUrl, `admin-phone-${crypto.randomUUID()}`, keypair(), taggedServer.adminDeviceId, keypair());
    const res = await fetch(`${taggedServer.baseUrl}/admin/forensics`, {
      headers: { Authorization: `Bearer ${adminSession.sessionToken}` }
    });
    const body = await res.json();
    assert.ok(!body.attackers.some((a) => a.ip === '203.0.113.9'), 'IP on KNOWN_INTERNAL_IPS must be excluded by default');
    assert.ok(body.attackers.some((a) => a.ip === '203.0.113.55'), 'an IP NOT on the list must still show up as a real external caller');
  } finally {
    await taggedServer.stop();
  }
});
