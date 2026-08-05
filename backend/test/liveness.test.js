import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, keypair, sign, fullAuth } from './helpers.js';

let server;
let adminToken;

before(async () => {
  server = await startServer();
  const adminSession = await fullAuth(server.baseUrl, 'liveness-admin-phone', keypair(), server.adminDeviceId, keypair());
  adminToken = adminSession.sessionToken;
});
after(async () => { await server.stop(); });

async function phoneVerify(deviceId, livenessResult) {
  const phone = keypair();
  let res = await fetch(`${server.baseUrl}/auth/phone/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ phoneAttestation: { platform: 'iOS', deviceId, publicKey: phone.publicKeyB64 } })
  });
  const { challengeId, challenge } = await res.json();
  const phoneSignature = sign(phone.privateKey, challenge);

  res = await fetch(`${server.baseUrl}/auth/phone/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId, phoneSignature, ...(livenessResult !== undefined ? { livenessResult } : {}) })
  });
  return res;
}

test('phone verify with no livenessResult field behaves exactly as before (backward compatible)', async () => {
  const res = await phoneVerify('liveness-phone-1', undefined);
  assert.equal(res.status, 200);
});

test('a passing livenessResult does not affect the response', async () => {
  const res = await phoneVerify('liveness-phone-2', {
    audioDetected: true, audioSnr: 2283.2, hapticMatched: 3, hapticTotal: 3
  });
  assert.equal(res.status, 200);
});

test('a failed audio check is warn-not-block: auth still succeeds', async () => {
  const res = await phoneVerify('liveness-phone-3', {
    audioDetected: false, audioSnr: 1.1, hapticMatched: 3, hapticTotal: 3
  });
  assert.equal(res.status, 200, 'a failed liveness check must never block a valid signature');
});

test('a failed haptic check (partial match) is also warn-not-block', async () => {
  const res = await phoneVerify('liveness-phone-4', {
    audioDetected: true, audioSnr: 500, hapticMatched: 1, hapticTotal: 3
  });
  assert.equal(res.status, 200);
});

test('a failed liveness check actually shows up in /admin/forensics, a passing one does not', async () => {
  const res = await phoneVerify('liveness-phone-5-flagged', {
    audioDetected: false, audioSnr: 0.9, hapticMatched: 0, hapticTotal: 3
  });
  assert.equal(res.status, 200);

  const forensics = await fetch(`${server.baseUrl}/admin/forensics`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const body = await forensics.json();
  const flagged = body.events.find(e => e.reason === 'Liveness check failed' && e.details.deviceId === 'liveness-phone-5-flagged');
  assert.ok(flagged, 'the failed check should be logged to forensics');
  assert.equal(flagged.details.livenessResult.audioDetected, false);

  const notFlagged = body.events.find(e => e.reason === 'Liveness check failed' && e.details.deviceId === 'liveness-phone-2');
  assert.equal(notFlagged, undefined, 'a passing check from an earlier test should never have been logged');
});

test('a malformed livenessResult (not an object) is ignored without erroring', async () => {
  const res = await phoneVerify('liveness-phone-6', 'not-an-object');
  assert.equal(res.status, 200, 'a garbage livenessResult must not break the whole verify request');
});
