import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'path';
import { DatabaseSync } from 'node:sqlite';
import { startServer, keypair, fullAuth, phoneAuth } from './helpers.js';

let server;
let adminToken;
let ownerToken;

before(async () => {
  server = await startServer();
  const adminSession = await fullAuth(server.baseUrl, 'audit-chain-admin-phone', keypair(), server.adminDeviceId, keypair());
  adminToken = adminSession.sessionToken;
  // Org endpoints need a phone-session token, not the admin's full-access one — a
  // separate, ordinary phone identity plays the org owner, same as org-audit.test.js.
  ({ phoneSessionToken: ownerToken } = await phoneAuth(server.baseUrl, 'audit-chain-org-owner', keypair()));
});
after(async () => { await server.stop(); });

function orgHeaders(token) {
  return { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` };
}

async function verify(baseUrl, token) {
  const res = await fetch(`${baseUrl}/admin/audit-log/verify`, { headers: { Authorization: `Bearer ${token}` } });
  assert.equal(res.status, 200);
  return res.json();
}

test('GET /admin/audit-log/verify rejects requests with no admin token', async () => {
  const res = await fetch(`${server.baseUrl}/admin/audit-log/verify`);
  assert.equal(res.status, 401);
});

test('chain reports intact with no admin actions yet', async () => {
  const result = await verify(server.baseUrl, adminToken);
  assert.equal(result.intact, true);
  assert.equal(result.brokenAt, null);
});

test('chain stays intact across real admin actions', async () => {
  const orgRes = await fetch(`${server.baseUrl}/orgs`, {
    method: 'POST', headers: orgHeaders(ownerToken), body: JSON.stringify({ name: 'Audit Chain Test Org' })
  });
  const org = await orgRes.json();

  await fetch(`${server.baseUrl}/orgs/${org.id}/members`, {
    method: 'POST', headers: orgHeaders(ownerToken), body: JSON.stringify({ deviceId: 'audit-chain-member-1' })
  });
  await fetch(`${server.baseUrl}/orgs/${org.id}/members`, {
    method: 'POST', headers: orgHeaders(ownerToken), body: JSON.stringify({ deviceId: 'audit-chain-member-2' })
  });

  const result = await verify(server.baseUrl, adminToken);
  assert.equal(result.intact, true);
  assert.ok(result.checked >= 2, `expected at least 2 chained rows, got ${result.checked}`);
});

// Each tamper scenario gets its own fresh server + DB, so one test's corruption can't
// bleed into the next and mask which specific reason verifyAuditChain reports.
async function tamperTestServer() {
  const s = await startServer();
  const admin = await fullAuth(s.baseUrl, 'tamper-admin-phone', keypair(), s.adminDeviceId, keypair());
  const { phoneSessionToken: owner } = await phoneAuth(s.baseUrl, 'tamper-org-owner', keypair());
  return { server: s, adminToken: admin.sessionToken, ownerToken: owner };
}

test('editing a row after the fact is detected', async () => {
  const t = await tamperTestServer();
  try {
    const orgRes = await fetch(`${t.server.baseUrl}/orgs`, {
      method: 'POST', headers: orgHeaders(t.ownerToken), body: JSON.stringify({ name: 'Tamper Edit Test Org' })
    });
    const org = await orgRes.json();
    await fetch(`${t.server.baseUrl}/orgs/${org.id}/members`, {
      method: 'POST', headers: orgHeaders(t.ownerToken), body: JSON.stringify({ deviceId: 'audit-chain-tamper-target' })
    });

    const before = await verify(t.server.baseUrl, t.adminToken);
    assert.equal(before.intact, true);

    // Open the exact same SQLite file the running server just wrote to and edit a row
    // directly, simulating an attacker with raw DB write access rather than going through
    // the app's own API — the scenario this feature exists to catch.
    const dbPath = path.join(t.server.dataDir, 'physicalkey.db');
    const rawDb = new DatabaseSync(dbPath);
    rawDb.exec(`UPDATE admin_actions SET target_device_id = 'audit-chain-tamper-target-EDITED' WHERE target_device_id = 'audit-chain-tamper-target'`);
    rawDb.close();

    const after = await verify(t.server.baseUrl, t.adminToken);
    assert.equal(after.intact, false);
    assert.match(after.reason, /edited after being written/);
  } finally {
    await t.server.stop();
  }
});

test('deleting a row is detected via the next row\'s broken prev_hash link', async () => {
  const t = await tamperTestServer();
  try {
    const orgRes = await fetch(`${t.server.baseUrl}/orgs`, {
      method: 'POST', headers: orgHeaders(t.ownerToken), body: JSON.stringify({ name: 'Tamper Delete Test Org' })
    });
    const org = await orgRes.json();
    await fetch(`${t.server.baseUrl}/orgs/${org.id}/members`, {
      method: 'POST', headers: orgHeaders(t.ownerToken), body: JSON.stringify({ deviceId: 'audit-chain-delete-victim' })
    });
    await fetch(`${t.server.baseUrl}/orgs/${org.id}/members`, {
      method: 'POST', headers: orgHeaders(t.ownerToken), body: JSON.stringify({ deviceId: 'audit-chain-delete-witness' })
    });

    const dbPath = path.join(t.server.dataDir, 'physicalkey.db');
    const rawDb = new DatabaseSync(dbPath);
    rawDb.exec(`DELETE FROM admin_actions WHERE target_device_id = 'audit-chain-delete-victim'`);
    rawDb.close();

    const result = await verify(t.server.baseUrl, t.adminToken);
    assert.equal(result.intact, false);
    assert.match(result.reason, /prev_hash/);
  } finally {
    await t.server.stop();
  }
});
