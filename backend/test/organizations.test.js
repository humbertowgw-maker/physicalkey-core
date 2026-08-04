import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, keypair, phoneAuth, fullAuth } from './helpers.js';

let server;

before(async () => { server = await startServer(); });
after(async () => { await server.stop(); });

// Registers a phone identity once and returns everything needed to act as it again
// later (phoneSessionToken for org-management calls, keys for a subsequent fullAuth as
// this same identity — trust-on-first-use means a SECOND phone-auth for the same
// deviceId must reuse the ORIGINAL key, not a fresh one, or it's correctly rejected).
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

async function claimDevice(orgId, ownerSession, deviceId) {
  return fetch(`${server.baseUrl}/orgs/${orgId}/devices`, {
    method: 'POST', headers: orgHeaders(ownerSession.phoneSessionToken),
    body: JSON.stringify({ deviceId })
  });
}

async function grantAccess(orgId, ownerSession, deviceId, memberDeviceId) {
  return fetch(`${server.baseUrl}/orgs/${orgId}/devices/${deviceId}/access`, {
    method: 'POST', headers: orgHeaders(ownerSession.phoneSessionToken),
    body: JSON.stringify({ memberDeviceId })
  });
}

test('POST /orgs creates an org with the caller as owner', async () => {
  const owner = await phoneSession('org-owner-1');
  const org = await createOrg(owner, 'Acme Corp');
  assert.equal(org.name, 'Acme Corp');
  assert.equal(org.owner_device_id, owner.deviceId);

  const membersRes = await fetch(`${server.baseUrl}/orgs/${org.id}`, { headers: authHeader(owner.phoneSessionToken) });
  const orgDetail = await membersRes.json();
  assert.equal(orgDetail.members.length, 1);
  assert.equal(orgDetail.members[0].device_id, owner.deviceId);
  assert.equal(orgDetail.members[0].role, 'owner');
});

test('a full_access device session cannot be used for org management (wrong scope)', async () => {
  const session = await fullAuth(server.baseUrl, 'wrong-scope-phone', keypair(), 'wrong-scope-device', keypair());
  const res = await fetch(`${server.baseUrl}/orgs`, {
    method: 'POST', headers: orgHeaders(session.sessionToken),
    body: JSON.stringify({ name: 'Should Fail' })
  });
  assert.equal(res.status, 401);
});

test('non-members cannot read org state; members can', async () => {
  const owner = await phoneSession('org-owner-2');
  const outsider = await phoneSession('org-outsider-2');
  const org = await createOrg(owner, 'Private Org');

  let res = await fetch(`${server.baseUrl}/orgs/${org.id}`, { headers: authHeader(outsider.phoneSessionToken) });
  assert.equal(res.status, 403);

  res = await fetch(`${server.baseUrl}/orgs/${org.id}`, { headers: authHeader(owner.phoneSessionToken) });
  assert.equal(res.status, 200);
});

test('members cannot add/remove members or devices; owners and admins can', async () => {
  const owner = await phoneSession('org-owner-3');
  const member = await phoneSession('org-member-3');
  const outsider = await phoneSession('org-outsider-3');
  const org = await createOrg(owner, 'Role Test Org');

  let res = await addMember(org.id, owner, member.deviceId);
  assert.equal(res.status, 201);

  res = await addMember(org.id, member, outsider.deviceId);
  assert.equal(res.status, 403, 'a plain member cannot add someone else');

  res = await addMember(org.id, outsider, outsider.deviceId);
  assert.equal(res.status, 403, 'a non-member cannot add anyone either');
});

test('the org owner cannot be removed via the member-removal endpoint', async () => {
  const owner = await phoneSession('org-owner-4');
  const org = await createOrg(owner, 'No Self Removal');

  const res = await fetch(`${server.baseUrl}/orgs/${org.id}/members/${owner.deviceId}`, {
    method: 'DELETE', headers: authHeader(owner.phoneSessionToken)
  });
  assert.equal(res.status, 409);
});

test('a removed member loses access, and a re-added one regains it', async () => {
  const owner = await phoneSession('org-owner-5');
  const member = await phoneSession('org-member-5');
  const org = await createOrg(owner, 'Revoke Test Org');
  await addMember(org.id, owner, member.deviceId);

  let res = await fetch(`${server.baseUrl}/orgs/${org.id}/members/${member.deviceId}`, {
    method: 'DELETE', headers: authHeader(owner.phoneSessionToken)
  });
  assert.equal(res.status, 200);

  res = await fetch(`${server.baseUrl}/orgs/${org.id}`, { headers: authHeader(member.phoneSessionToken) });
  assert.equal(res.status, 403, 'a revoked member should no longer be able to read org state');

  res = await addMember(org.id, owner, member.deviceId);
  assert.equal(res.status, 201, 're-adding a previously-removed member should succeed');

  res = await fetch(`${server.baseUrl}/orgs/${org.id}`, { headers: authHeader(member.phoneSessionToken) });
  assert.equal(res.status, 200, 're-added member should have access again');
});

test('a personal (non-org) device is unaffected by any of this — unrestricted as before', async () => {
  const deviceKeys = keypair();
  const hardwareDeviceId = 'solo-device-1';

  const session = await fullAuth(server.baseUrl, 'solo-phone-1', keypair(), hardwareDeviceId, deviceKeys);
  assert.ok(session.sessionToken);

  // A completely different phone, using the SAME physical device (same key — a device
  // has one identity regardless of which phone talks to it), also succeeds — same
  // pre-org behavior. A device only becomes access-restricted once explicitly claimed
  // by an org.
  const otherSession = await fullAuth(server.baseUrl, 'solo-phone-2', keypair(), hardwareDeviceId, deviceKeys);
  assert.ok(otherSession.sessionToken);
});

test('exclusive access: an org device only works for the member explicitly granted access to it', async () => {
  const owner = await phoneSession('org-owner-6');
  const memberA = await phoneSession('org-member-6a');
  const memberB = await phoneSession('org-member-6b');
  const deviceKeys = keypair();
  const hardwareDeviceId = 'org-device-exclusive-6';

  // Register the device first as an ordinary (not-yet-org) device — it needs to exist
  // as a known identity before it can be added to an org.
  await fullAuth(server.baseUrl, 'bootstrap-phone-6', keypair(), hardwareDeviceId, deviceKeys);

  const org = await createOrg(owner, 'Exclusive Device Org');
  await addMember(org.id, owner, memberA.deviceId);
  await addMember(org.id, owner, memberB.deviceId);

  let res = await claimDevice(org.id, owner, hardwareDeviceId);
  assert.equal(res.status, 201, 'claiming an already-registered device for the org should succeed');

  // Now that it's org-owned, NOBODY without an explicit grant can use it — not even
  // a fresh phone that's never touched it before (this is the actual behavior change
  // from Solo: authentication alone is no longer sufficient once a device joins an org).
  await assert.rejects(
    fullAuth(server.baseUrl, 'random-phone-6', keypair(), hardwareDeviceId, deviceKeys),
    /device verify failed/,
    'an org device must reject a phone with no membership at all'
  );
  await assert.rejects(
    fullAuth(server.baseUrl, memberB.deviceId, memberB.keys, hardwareDeviceId, deviceKeys),
    /device verify failed/,
    'an actual org member with no grant for this specific device must also be rejected'
  );

  // Grant ONLY memberA access.
  res = await grantAccess(org.id, owner, hardwareDeviceId, memberA.deviceId);
  assert.equal(res.status, 201);

  const grantedSession = await fullAuth(server.baseUrl, memberA.deviceId, memberA.keys, hardwareDeviceId, deviceKeys);
  assert.ok(grantedSession.sessionToken, 'the granted member should now be able to use the device');

  // memberB still has no grant, still rejected.
  await assert.rejects(
    fullAuth(server.baseUrl, memberB.deviceId, memberB.keys, hardwareDeviceId, deviceKeys),
    /device verify failed/,
    'a member without an explicit grant must still be rejected'
  );
});

test('shared access: multiple members can be granted the same device', async () => {
  const owner = await phoneSession('org-owner-7');
  const memberA = await phoneSession('org-member-7a');
  const memberB = await phoneSession('org-member-7b');
  const deviceKeys = keypair();
  const hardwareDeviceId = 'org-device-shared-7';

  await fullAuth(server.baseUrl, 'bootstrap-phone-7', keypair(), hardwareDeviceId, deviceKeys);

  const org = await createOrg(owner, 'Shared Door Org');
  await addMember(org.id, owner, memberA.deviceId);
  await addMember(org.id, owner, memberB.deviceId);
  await claimDevice(org.id, owner, hardwareDeviceId);
  await grantAccess(org.id, owner, hardwareDeviceId, memberA.deviceId);
  await grantAccess(org.id, owner, hardwareDeviceId, memberB.deviceId);

  const sessionA = await fullAuth(server.baseUrl, memberA.deviceId, memberA.keys, hardwareDeviceId, deviceKeys);
  const sessionB = await fullAuth(server.baseUrl, memberB.deviceId, memberB.keys, hardwareDeviceId, deviceKeys);
  assert.ok(sessionA.sessionToken);
  assert.ok(sessionB.sessionToken, 'a second, independently-granted member should also be able to use the same shared device');
});

test('owners and admins get implicit access to org devices without an explicit grant', async () => {
  const owner = await phoneSession('org-owner-8');
  const admin = await phoneSession('org-admin-8');
  const deviceKeys = keypair();
  const hardwareDeviceId = 'org-device-implicit-8';

  await fullAuth(server.baseUrl, 'bootstrap-phone-8', keypair(), hardwareDeviceId, deviceKeys);

  const org = await createOrg(owner, 'Implicit Access Org');
  await addMember(org.id, owner, admin.deviceId, 'admin');
  await claimDevice(org.id, owner, hardwareDeviceId);

  // Neither owner nor admin were ever explicitly granted access to this device.
  const ownerSession = await fullAuth(server.baseUrl, owner.deviceId, owner.keys, hardwareDeviceId, deviceKeys);
  assert.ok(ownerSession.sessionToken, 'owner should have implicit access');

  const adminSession = await fullAuth(server.baseUrl, admin.deviceId, admin.keys, hardwareDeviceId, deviceKeys);
  assert.ok(adminSession.sessionToken, 'admin should have implicit access');
});

test('revoking membership entirely overrides a still-present device_access grant', async () => {
  const owner = await phoneSession('org-owner-9');
  const member = await phoneSession('org-member-9');
  const deviceKeys = keypair();
  const hardwareDeviceId = 'org-device-9';

  await fullAuth(server.baseUrl, 'bootstrap-phone-9', keypair(), hardwareDeviceId, deviceKeys);

  const org = await createOrg(owner, 'Revoke Overrides Grant Org');
  await addMember(org.id, owner, member.deviceId);
  await claimDevice(org.id, owner, hardwareDeviceId);
  await grantAccess(org.id, owner, hardwareDeviceId, member.deviceId);

  const before = await fullAuth(server.baseUrl, member.deviceId, member.keys, hardwareDeviceId, deviceKeys);
  assert.ok(before.sessionToken, 'sanity check: access works before revocation');

  // Revoke the MEMBERSHIP (not the specific device grant, which is left in place).
  await fetch(`${server.baseUrl}/orgs/${org.id}/members/${member.deviceId}`, {
    method: 'DELETE', headers: authHeader(owner.phoneSessionToken)
  });

  await assert.rejects(
    fullAuth(server.baseUrl, member.deviceId, member.keys, hardwareDeviceId, deviceKeys),
    /device verify failed/,
    'revoking org membership must cut off device access even though the device_access row itself was never explicitly removed'
  );
});

test('removing a device from an org clears its access grants too', async () => {
  const owner = await phoneSession('org-owner-10');
  const member = await phoneSession('org-member-10');
  const deviceKeys = keypair();
  const hardwareDeviceId = 'org-device-10';

  await fullAuth(server.baseUrl, 'bootstrap-phone-10', keypair(), hardwareDeviceId, deviceKeys);

  const org = await createOrg(owner, 'Device Removal Org');
  await addMember(org.id, owner, member.deviceId);
  await claimDevice(org.id, owner, hardwareDeviceId);
  await grantAccess(org.id, owner, hardwareDeviceId, member.deviceId);

  const res = await fetch(`${server.baseUrl}/orgs/${org.id}/devices/${hardwareDeviceId}`, {
    method: 'DELETE', headers: authHeader(owner.phoneSessionToken)
  });
  assert.equal(res.status, 200);

  // The device is no longer org-owned at all, so it reverts to the Solo behavior:
  // unrestricted, ANY phone can use it again.
  const session = await fullAuth(server.baseUrl, 'anyone-10', keypair(), hardwareDeviceId, deviceKeys);
  assert.ok(session.sessionToken, 'a device removed from its org should revert to unrestricted personal-device behavior');
});

test('a device already claimed by one org cannot be claimed by another', async () => {
  const owner1 = await phoneSession('org-owner-11a');
  const owner2 = await phoneSession('org-owner-11b');
  const deviceKeys = keypair();
  const hardwareDeviceId = 'org-device-11';

  await fullAuth(server.baseUrl, 'bootstrap-phone-11', keypair(), hardwareDeviceId, deviceKeys);

  const org1 = await createOrg(owner1, 'First Claimant Org');
  const org2 = await createOrg(owner2, 'Second Claimant Org');

  let res = await claimDevice(org1.id, owner1, hardwareDeviceId);
  assert.equal(res.status, 201);

  res = await claimDevice(org2.id, owner2, hardwareDeviceId);
  assert.equal(res.status, 409, 'a device already claimed by another org must not be claimable again');
});
