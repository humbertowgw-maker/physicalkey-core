import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, keypair, fullAuth, sign } from './helpers.js';

let server;
let adminToken;

before(async () => {
  server = await startServer();
  const adminSession = await fullAuth(server.baseUrl, 'repair-admin-phone', keypair(), server.adminDeviceId, keypair());
  adminToken = adminSession.sessionToken;
});
after(async () => { await server.stop(); });

test('full happy path: a board with real pairing history can repair-authorize resetting its paired phone', async () => {
  const boardDeviceId = 'repair-board-happy';
  const phoneDeviceId = 'repair-phone-happy';
  const boardKeys = keypair();
  const oldPhoneKeys = keypair();

  // Establishes real pairing history via a normal auth flow — this is what
  // hasEverPaired() checks before issuing a repair challenge.
  const original = await fullAuth(server.baseUrl, phoneDeviceId, oldPhoneKeys, boardDeviceId, boardKeys);
  assert.ok(original.sessionToken);

  const gitAuthHeader = Buffer.from(`${original.gitCredentials.username}:${original.gitCredentials.password}`).toString('base64');
  let gitCheck = await fetch(`${server.baseUrl}/git/auth`, { headers: { Authorization: `Basic ${gitAuthHeader}` } });
  assert.equal(gitCheck.status, 200, 'git credentials should work before the repair');

  let res = await fetch(`${server.baseUrl}/auth/repair/challenge`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ boardDeviceId, targetPhoneDeviceId: phoneDeviceId })
  });
  let body = await res.json();
  assert.equal(res.status, 200);
  assert.ok(body.challengeId);
  assert.ok(body.challenge.startsWith('PHYSICALKEY-REPAIR-AUTH-V1:'));
  assert.ok(body.challenge.includes(phoneDeviceId), 'the challenge should bind to the exact target identity');

  const boardSignature = sign(boardKeys.privateKey, body.challenge);
  res = await fetch(`${server.baseUrl}/auth/repair/verify`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId: body.challengeId, boardSignature })
  });
  body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.status, 'reset');
  assert.equal(body.deviceId, phoneDeviceId);
  // Git credentials are granted per DEVICE (the board), not per phone — resetting the
  // phone identity correctly leaves them untouched, since the board's own identity was
  // never touched by this at all.
  assert.equal(body.revokedGitAccess, false);

  gitCheck = await fetch(`${server.baseUrl}/git/auth`, { headers: { Authorization: `Basic ${gitAuthHeader}` } });
  assert.equal(gitCheck.status, 200, 'git credentials issued to the board should still work — only the phone identity was reset');

  res = await fetch(`${server.baseUrl}/api/profile`, { headers: { Authorization: `Bearer ${original.sessionToken}` } });
  assert.equal(res.status, 401, 'the old sessionToken must be revoked, not just the identity reset for next time');

  // The actual point: the SAME deviceId can now register a DIFFERENT key, exactly like a
  // replacement phone would need to.
  const newPhoneKeys = keypair();
  const reregistered = await fullAuth(server.baseUrl, phoneDeviceId, newPhoneKeys, boardDeviceId, boardKeys);
  assert.ok(reregistered.sessionToken, 'the repaired identity should register fresh with a new key via the ordinary auth flow');
});

test('repair challenge is rejected for a board with no real pairing history to the target phone', async () => {
  const boardDeviceId = 'repair-board-nohistory';
  const phoneDeviceId = 'repair-phone-nohistory';
  // Register both identities independently (never paired with EACH OTHER).
  await fullAuth(server.baseUrl, phoneDeviceId, keypair(), 'repair-board-nohistory-unrelated', keypair());
  await fullAuth(server.baseUrl, 'repair-phone-nohistory-unrelated', keypair(), boardDeviceId, keypair());

  const res = await fetch(`${server.baseUrl}/auth/repair/challenge`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ boardDeviceId, targetPhoneDeviceId: phoneDeviceId })
  });
  assert.equal(res.status, 403);
});

test('repair challenge is rejected for an unknown board or non-phone/unknown target', async () => {
  const phoneDeviceId = 'repair-phone-badtarget';
  const boardDeviceId = 'repair-board-badtarget';
  await fullAuth(server.baseUrl, phoneDeviceId, keypair(), boardDeviceId, keypair());

  let res = await fetch(`${server.baseUrl}/auth/repair/challenge`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ boardDeviceId: 'never-registered-board', targetPhoneDeviceId: phoneDeviceId })
  });
  assert.equal(res.status, 404);

  res = await fetch(`${server.baseUrl}/auth/repair/challenge`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ boardDeviceId, targetPhoneDeviceId: 'never-registered-phone' })
  });
  assert.equal(res.status, 404);

  // The board itself is a 'device' kind identity — can't be the repair TARGET.
  res = await fetch(`${server.baseUrl}/auth/repair/challenge`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ boardDeviceId, targetPhoneDeviceId: boardDeviceId })
  });
  assert.equal(res.status, 404);
});

test('a permanent identity cannot be repaired, self-service or otherwise', async () => {
  const boardDeviceId = 'repair-board-permanent';
  const phoneDeviceId = 'repair-phone-permanent';
  const boardKeys = keypair();
  await fullAuth(server.baseUrl, phoneDeviceId, keypair(), boardDeviceId, boardKeys);

  await fetch(`${server.baseUrl}/admin/identities/${phoneDeviceId}/recovery-policy`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ recoveryPolicy: 'permanent' })
  });

  const res = await fetch(`${server.baseUrl}/auth/repair/challenge`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ boardDeviceId, targetPhoneDeviceId: phoneDeviceId })
  });
  assert.equal(res.status, 403);
});

test('a forged board signature is rejected, and does NOT reset the target identity', async () => {
  const boardDeviceId = 'repair-board-forged';
  const phoneDeviceId = 'repair-phone-forged';
  await fullAuth(server.baseUrl, phoneDeviceId, keypair(), boardDeviceId, keypair());

  const res1 = await fetch(`${server.baseUrl}/auth/repair/challenge`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ boardDeviceId, targetPhoneDeviceId: phoneDeviceId })
  });
  const { challengeId, challenge } = await res1.json();

  const wrongKeys = keypair(); // NOT the real board's key
  const forgedSignature = sign(wrongKeys.privateKey, challenge);

  const res2 = await fetch(`${server.baseUrl}/auth/repair/verify`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId, boardSignature: forgedSignature })
  });
  assert.equal(res2.status, 401);

  // Confirm the identity genuinely wasn't touched — a forged proof must never have a
  // side effect, not even a partial one.
  const check = await fetch(`${server.baseUrl}/admin/identities/${phoneDeviceId}`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert.equal(check.status, 200, 'the identity should still exist, untouched, after a forged repair attempt');
});

test('a repair challenge is single-use — replaying challengeId fails even with a valid signature', async () => {
  const boardDeviceId = 'repair-board-replay';
  const phoneDeviceId = 'repair-phone-replay';
  const boardKeys = keypair();
  await fullAuth(server.baseUrl, phoneDeviceId, keypair(), boardDeviceId, boardKeys);

  const res1 = await fetch(`${server.baseUrl}/auth/repair/challenge`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ boardDeviceId, targetPhoneDeviceId: phoneDeviceId })
  });
  const { challengeId, challenge } = await res1.json();
  const boardSignature = sign(boardKeys.privateKey, challenge);

  const first = await fetch(`${server.baseUrl}/auth/repair/verify`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId, boardSignature })
  });
  assert.equal(first.status, 200);

  const replay = await fetch(`${server.baseUrl}/auth/repair/verify`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId, boardSignature })
  });
  assert.equal(replay.status, 401, 'a consumed challengeId must be rejected even with a genuinely valid signature');
});
