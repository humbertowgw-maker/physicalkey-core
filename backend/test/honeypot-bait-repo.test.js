import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execSync } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import { startServer, keypair, fullAuth } from './helpers.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let server;
let adminToken;

before(async () => {
  server = await startServer();
  const adminSession = await fullAuth(server.baseUrl, 'bait-admin-phone', keypair(), server.adminDeviceId, keypair());
  adminToken = adminSession.sessionToken;
});
after(async () => { await server.stop(); });

async function forensics() {
  const res = await fetch(`${server.baseUrl}/admin/forensics`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert.equal(res.status, 200);
  return res.json();
}

test('GET /backup.git/info/refs?service=git-upload-pack succeeds with no credentials at all', async () => {
  const res = await fetch(`${server.baseUrl}/backup.git/info/refs?service=git-upload-pack`);
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.match(body, /git-upload-pack/);
});

test('a real git clone against the bait repo succeeds and returns the decoy content', async () => {
  const dest = path.join(__dirname, '..', '..', '.tmp-bait-clone-test');
  execSync(`rm -rf "${dest}"`);
  execSync(`git clone -q "${server.baseUrl}/backup.git" "${dest}"`);
  const readme = execSync('cat README.md', { cwd: dest }).toString();
  assert.match(readme, /Internal deploy credentials backup/);
  const creds = execSync('cat deploy-credentials.json', { cwd: dest }).toString();
  assert.match(creds, /fake-key-do-not-use-/);
  execSync(`rm -rf "${dest}"`);
});

test('every hit — even a bare GET with no auth — is logged to the honeypot, not just failures', async () => {
  const before = await forensics();
  const beforeCount = before.summary.totalAttempts;

  await fetch(`${server.baseUrl}/backup.git/info/refs?service=git-upload-pack`);

  const after = await forensics();
  assert.ok(after.summary.totalAttempts > beforeCount, 'expected a new honeypot event from the bare hit');
  const latest = after.events[after.events.length - 1];
  assert.equal(latest.reason, 'Honeypot git repo accessed');
});

test('an attempted username/password is captured in the logged details, not just the fact of a hit', async () => {
  await fetch(`${server.baseUrl}/backup.git/info/refs?service=git-upload-pack`, {
    headers: { Authorization: `Basic ${Buffer.from('root:hunter2').toString('base64')}` }
  });

  const report = await forensics();
  const match = report.events.slice().reverse().find(
    (e) => e.reason === 'Honeypot git repo accessed' && e.details.attemptedUsername === 'root'
  );
  assert.ok(match, 'expected an event capturing the attempted username "root"');
});

test('GET /admin/forensics rejects requests with no admin token', async () => {
  const res = await fetch(`${server.baseUrl}/admin/forensics`);
  assert.equal(res.status, 401);
});
