import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, keypair, phoneAuth, fullAuth } from './helpers.js';

let server;

before(async () => { server = await startServer(); });
after(async () => { await server.stop(); });

async function phoneSession(deviceId) {
  const keys = keypair();
  const { phoneSessionToken } = await phoneAuth(server.baseUrl, deviceId, keys);
  return { deviceId, keys, phoneSessionToken };
}

function authHeader(token) {
  return { Authorization: `Bearer ${token}` };
}

function orgHeaders(token) {
  return { 'Content-Type': 'application/json', ...authHeader(token) };
}

async function createOrg(ownerSession, name) {
  const res = await fetch(`${server.baseUrl}/orgs`, {
    method: 'POST', headers: orgHeaders(ownerSession.phoneSessionToken),
    body: JSON.stringify({ name })
  });
  return res.json();
}

async function addMember(orgId, ownerSession, memberDeviceId, role) {
  return fetch(`${server.baseUrl}/orgs/${orgId}/members`, {
    method: 'POST', headers: orgHeaders(ownerSession.phoneSessionToken),
    body: JSON.stringify({ deviceId: memberDeviceId, ...(role ? { role } : {}) })
  });
}

async function auditLog(orgId, session) {
  const res = await fetch(`${server.baseUrl}/orgs/${orgId}/audit-log`, { headers: authHeader(session.phoneSessionToken) });
  return { status: res.status, body: await res.json() };
}

test('an org owner sees member-added entries scoped to their own org', async () => {
  const owner = await phoneSession('audit-owner-1');
  const org = await createOrg(owner, 'Audit Co');
  const res = await addMember(org.id, owner, 'audit-member-1', 'member');
  assert.equal(res.status, 201);

  const { status, body } = await auditLog(org.id, owner);
  assert.equal(status, 200);
  const entry = body.entries.find((e) => e.action === 'member_added' && e.targetDeviceId === 'audit-member-1');
  assert.ok(entry, 'the member-added action should be recorded and visible to the org owner');
  assert.equal(entry.orgId, org.id);
  assert.equal(entry.adminDeviceId, owner.deviceId);
});

test('a plain member cannot read the org audit log', async () => {
  const owner = await phoneSession('audit-owner-2');
  const org = await createOrg(owner, 'Audit Co 2');
  const memberDeviceId = 'audit-member-2';
  await addMember(org.id, owner, memberDeviceId, 'member');
  const member = await phoneSession(memberDeviceId);

  const { status } = await auditLog(org.id, member);
  assert.equal(status, 403, 'reading the audit log requires owner/admin, same as other org-admin operations');
});

test('one org cannot see another org\'s audit entries', async () => {
  const ownerA = await phoneSession('audit-owner-3a');
  const orgA = await createOrg(ownerA, 'Org A');
  await addMember(orgA.id, ownerA, 'audit-member-3a', 'member');

  const ownerB = await phoneSession('audit-owner-3b');
  const orgB = await createOrg(ownerB, 'Org B');
  await addMember(orgB.id, ownerB, 'audit-member-3b', 'member');

  const { body: bodyA } = await auditLog(orgA.id, ownerA);
  assert.ok(!bodyA.entries.some((e) => e.targetDeviceId === 'audit-member-3b'), 'org A must not see org B\'s member-added entry');

  const { body: bodyB } = await auditLog(orgB.id, ownerB);
  assert.ok(!bodyB.entries.some((e) => e.targetDeviceId === 'audit-member-3a'), 'org B must not see org A\'s member-added entry');
});

test('the global /admin/audit-log still sees everything, org-scoped and not', async () => {
  const owner = await phoneSession('audit-owner-4');
  const org = await createOrg(owner, 'Audit Co 4');
  await addMember(org.id, owner, 'audit-member-4', 'member');

  const adminSession = await fullAuth(server.baseUrl, 'audit-admin-phone', keypair(), server.adminDeviceId, keypair());
  const res = await fetch(`${server.baseUrl}/admin/audit-log`, { headers: authHeader(adminSession.sessionToken) });
  const body = await res.json();
  assert.equal(res.status, 200);
  const entry = body.entries.find((e) => e.action === 'member_added' && e.targetDeviceId === 'audit-member-4');
  assert.ok(entry, 'the global admin log must still see org-scoped actions too, unchanged');
  assert.equal(entry.orgId, org.id);
});

test('member removal, device claim, and access grant/revoke are all recorded', async () => {
  const owner = await phoneSession('audit-owner-5');
  const org = await createOrg(owner, 'Audit Co 5');

  const memberDeviceId = 'audit-member-5';
  await addMember(org.id, owner, memberDeviceId, 'member');
  await fetch(`${server.baseUrl}/orgs/${org.id}/members/${memberDeviceId}`, { method: 'DELETE', headers: authHeader(owner.phoneSessionToken) });

  // Register a real device identity first — claiming requires it to already exist.
  const keyDeviceId = 'audit-device-5';
  await fullAuth(server.baseUrl, 'audit-device-5-phone', keypair(), keyDeviceId, keypair());
  await fetch(`${server.baseUrl}/orgs/${org.id}/devices`, {
    method: 'POST', headers: orgHeaders(owner.phoneSessionToken), body: JSON.stringify({ deviceId: keyDeviceId })
  });

  const grantMemberId = 'audit-grant-member-5';
  await addMember(org.id, owner, grantMemberId, 'member');
  await fetch(`${server.baseUrl}/orgs/${org.id}/devices/${keyDeviceId}/access`, {
    method: 'POST', headers: orgHeaders(owner.phoneSessionToken), body: JSON.stringify({ memberDeviceId: grantMemberId })
  });
  await fetch(`${server.baseUrl}/orgs/${org.id}/devices/${keyDeviceId}/access/${grantMemberId}`, {
    method: 'DELETE', headers: authHeader(owner.phoneSessionToken)
  });

  const { body } = await auditLog(org.id, owner);
  const actions = body.entries.map((e) => e.action);
  for (const expected of ['member_added', 'member_removed', 'device_added_to_org', 'device_access_granted', 'device_access_revoked']) {
    assert.ok(actions.includes(expected), `expected "${expected}" to be recorded in the org audit log`);
  }
});
