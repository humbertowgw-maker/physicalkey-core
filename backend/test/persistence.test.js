import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnServerAt, keypair, sign, fullAuth } from './helpers.js';

// A real process kill + restart against the same on-disk data directory — the actual
// thing that matters here (an in-process "reset a variable" test would prove nothing
// about the SQLite persistence this is meant to verify).
let dataDir;
let port;
let adminDeviceId;
let server;

let phoneId, deviceId, phoneKeys, deviceKeys, gitCredentials;

before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'physicalkey-persist-test-'));
  port = 4000 + Math.floor(Math.random() * 5000);
  adminDeviceId = `test-admin-device-${Math.random().toString(36).slice(2, 8)}`;
  server = await spawnServerAt(dataDir, { port, adminDeviceId });

  phoneId = 'persist-phone-1';
  deviceId = 'persist-device-1';
  phoneKeys = keypair();
  deviceKeys = keypair();

  const session = await fullAuth(server.baseUrl, phoneId, phoneKeys, deviceId, deviceKeys);
  gitCredentials = session.gitCredentials;

  // Trip the honeypot once before restarting, so there's something to verify survived.
  await fetch(`${server.baseUrl}/git/auth`); // missing credentials

  await server.kill();
  server = await spawnServerAt(dataDir, { port, adminDeviceId }); // real restart, same data dir
});

after(async () => {
  await server.kill();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('git credentials issued before a restart still validate after it', async () => {
  const auth = Buffer.from(`${gitCredentials.username}:${gitCredentials.password}`).toString('base64');
  const res = await fetch(`${server.baseUrl}/git/auth`, { headers: { Authorization: `Basic ${auth}` } });
  assert.equal(res.status, 200);
});

test('re-authenticating the same deviceId with its original key succeeds after a restart', async () => {
  const session = await fullAuth(server.baseUrl, phoneId, phoneKeys, deviceId, deviceKeys);
  assert.ok(session.sessionToken);
});

test('hijacking a persisted deviceId with a different key is still rejected after a restart', async () => {
  const hijackKeys = keypair();
  await assert.rejects(
    fullAuth(server.baseUrl, phoneId, phoneKeys, deviceId, hijackKeys),
    /device verify failed/,
    'a restart must not let a deviceId be re-registered under a different key'
  );
});

test('honeypot events logged before a restart are still visible via /admin/forensics', async () => {
  const adminSession = await fullAuth(server.baseUrl, 'persist-admin-phone', keypair(), adminDeviceId, keypair());
  const res = await fetch(`${server.baseUrl}/admin/forensics`, {
    headers: { Authorization: `Bearer ${adminSession.sessionToken}` }
  });
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.ok(body.summary.totalAttempts >= 1, 'expected at least the pre-restart honeypot trip to still be recorded');
});
