import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, keypair, fullAuth } from './helpers.js';

let server;
let adminToken;

before(async () => {
  server = await startServer();
  const adminSession = await fullAuth(server.baseUrl, 'resilience-admin-phone', keypair(), server.adminDeviceId, keypair());
  adminToken = adminSession.sessionToken;
});
after(async () => { await server.stop(); });

test('GET /health reports database status, not just process liveness', async () => {
  const res = await fetch(`${server.baseUrl}/health`);
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.status, 'online');
  assert.equal(body.database, 'ok');
});

test('POST /admin/backups requires an admin token', async () => {
  const res = await fetch(`${server.baseUrl}/admin/backups`, { method: 'POST' });
  assert.equal(res.status, 401);
});

test('POST /admin/backups writes a snapshot, and GET /admin/backups lists it', async () => {
  const before = await (await fetch(`${server.baseUrl}/admin/backups`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  })).json();
  assert.deepEqual(before.backups, []);

  const created = await fetch(`${server.baseUrl}/admin/backups`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert.equal(created.status, 201);
  const { backup } = await created.json();
  assert.match(backup, /^physicalkey-.*\.db$/);

  const after = await (await fetch(`${server.baseUrl}/admin/backups`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  })).json();
  assert.deepEqual(after.backups, [backup]);
});

test('GET /admin/backups/latest downloads the most recent snapshot file', async () => {
  await fetch(`${server.baseUrl}/admin/backups`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${adminToken}` }
  });

  const res = await fetch(`${server.baseUrl}/admin/backups/latest`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert.equal(res.status, 200);
  const bytes = await res.arrayBuffer();
  // A real SQLite file starts with this 16-byte magic header.
  const header = Buffer.from(bytes.slice(0, 16)).toString('utf8');
  assert.equal(header, 'SQLite format 3\0');
});

test('GET /admin/backups/latest 404s when no backup exists yet', async () => {
  const fresh = await startServer();
  const adminSession = await fullAuth(fresh.baseUrl, 'resilience-admin-phone-2', keypair(), fresh.adminDeviceId, keypair());
  const res = await fetch(`${fresh.baseUrl}/admin/backups/latest`, {
    headers: { Authorization: `Bearer ${adminSession.sessionToken}` }
  });
  assert.equal(res.status, 404);
  await fresh.stop();
});
