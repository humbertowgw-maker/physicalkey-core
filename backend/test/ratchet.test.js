import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { startServer, keypair, sign, phoneAuth } from './helpers.js';

// Re-exported so this file can still call the plain phone+device flow the same way the
// rest of the suite does, without pulling in a second copy of fullAuth from helpers.js.
async function fullAuth(baseUrl, phoneDeviceId, phoneKeys, hardwareDeviceId, deviceKeys, extra = {}) {
  const { deviceChallengeId, deviceChallenge } = await phoneAuth(baseUrl, phoneDeviceId, phoneKeys);
  const deviceSignature = sign(deviceKeys.privateKey, deviceChallenge);
  const res = await fetch(`${baseUrl}/auth/device/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceChallengeId, deviceSignature, deviceId: hardwareDeviceId, publicKey: deviceKeys.publicKeyB64, ...extra })
  });
  const body = await res.json();
  if (!res.ok) throw new Error(`device verify failed: ${res.status} ${JSON.stringify(body)}`);
  return body;
}

const ATTEST_CONTEXT = Buffer.from('physicalkey-ratchet-attest-v1', 'utf8');

/**
 * Builds a real, correctly-signed ratchetAttestation object exactly the way the firmware
 * will — same message layout, same key/message order in the HMAC, same Ed25519 signing key
 * — so these tests exercise the actual verification contract, not a simplified stand-in.
 * The X25519 exchange itself is irrelevant to what the backend checks (it never recomputes
 * the shared secret), so devicePublicKey/rc/nextProof can be arbitrary random bytes; only
 * deviceProof (when claiming continuation) needs to be a real HMAC over the prior next_proof
 * for a 'verified' outcome, and the signature must be real for anything to be accepted at all.
 */
function buildAttestation({ deviceEd25519PrivateKey, challenge, status, priorNextProofB64, wrongDeviceProof = false }) {
  const devicePublicKey = crypto.randomBytes(32);
  const rc = crypto.randomBytes(16);
  const nextProof = crypto.randomBytes(32);
  let deviceProof;
  if (status === 0) {
    deviceProof = Buffer.alloc(64);
  } else if (wrongDeviceProof) {
    deviceProof = crypto.randomBytes(64);
  } else {
    const priorProof = Buffer.from(priorNextProofB64, 'base64');
    deviceProof = crypto.createHmac('sha512', priorProof).update(rc).digest();
  }

  const msg = Buffer.concat([
    ATTEST_CONTEXT,
    crypto.createHash('sha256').update(Buffer.from(challenge, 'utf8')).digest(),
    devicePublicKey, rc, deviceProof, nextProof, Buffer.from([status])
  ]);
  const signature = crypto.sign(null, msg, deviceEd25519PrivateKey);

  return {
    devicePublicKey: devicePublicKey.toString('base64'),
    rc: rc.toString('base64'),
    deviceProof: deviceProof.toString('base64'),
    nextProof: nextProof.toString('base64'),
    status,
    signature: signature.toString('base64'),
    _nextProofB64: nextProof.toString('base64') // test-only convenience, stripped before sending
  };
}

async function deviceVerifyWithAttestation(baseUrl, phoneDeviceId, phoneKeys, hardwareDeviceId, deviceKeys, attestation) {
  const { deviceChallengeId, deviceChallenge } = await phoneAuth(baseUrl, phoneDeviceId, phoneKeys);
  const deviceSignature = sign(deviceKeys.privateKey, deviceChallenge);
  const { _nextProofB64, ...ratchetAttestation } = attestation(deviceChallenge);
  const res = await fetch(`${baseUrl}/auth/device/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceChallengeId, deviceSignature, deviceId: hardwareDeviceId, publicKey: deviceKeys.publicKeyB64, ratchetAttestation })
  });
  const body = await res.json();
  return { status: res.status, body, nextProofB64: _nextProofB64 };
}

let server;
let adminToken;

before(async () => {
  server = await startServer();
  const adminSession = await fullAuth(server.baseUrl, 'ratchet-admin-phone', keypair(), server.adminDeviceId, keypair());
  adminToken = adminSession.sessionToken;
});
after(async () => { await server.stop(); });

test('device verify with no ratchetStatus field behaves exactly as before (backward compatible)', async () => {
  const result = await fullAuth(server.baseUrl, 'ratchet-phone-1', keypair(), 'ratchet-device-1', keypair());
  assert.ok(result.sessionToken);

  const res = await fetch(`${server.baseUrl}/admin/identities/ratchet-device-1`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const body = await res.json();
  assert.equal(body.ratchet, null, 'no ratchet row should exist when the phone never reported a status');
});

test('a valid ratchetStatus is recorded and does not block authentication, even mismatch', async () => {
  const result = await fullAuth(
    server.baseUrl, 'ratchet-phone-2', keypair(), 'ratchet-device-2', keypair(),
    { ratchetStatus: 'mismatch' }
  );
  assert.ok(result.sessionToken, 'a ratchet mismatch is warn-not-block: auth must still succeed');

  const res = await fetch(`${server.baseUrl}/admin/identities/ratchet-device-2`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const body = await res.json();
  assert.equal(body.ratchet.status, 'mismatch');
});

test('a legacy unsigned mismatch claim is recorded but does not trigger the honeypot — it is not trustworthy evidence', async () => {
  // A real, server-verified mismatch (see the signed-attestation tests below) DOES trigger
  // the honeypot. This bare, unsigned string doesn't — anyone could send it, so treating it
  // as an attack signal would make the honeypot trivially triggerable by a normal client
  // that's simply lying, which defeats the point of a signal meant to indicate a real clone.
  await fullAuth(
    server.baseUrl, 'ratchet-phone-3', keypair(), 'ratchet-device-3', keypair(),
    { ratchetStatus: 'mismatch' }
  );

  const identityRes = await fetch(`${server.baseUrl}/admin/identities/ratchet-device-3`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const identity = await identityRes.json();
  assert.equal(identity.ratchet.status, 'mismatch', 'the claim is still recorded, just not as a verified one');
  assert.equal(identity.ratchet.verified_by, 'client-reported');

  const res = await fetch(`${server.baseUrl}/admin/forensics`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const body = await res.json();
  const found = body.events.some(e => e.reason.includes('Ratchet continuity mismatch') && e.details.deviceId === 'ratchet-device-3');
  assert.equal(found, false, 'an unsigned, unverified mismatch claim must not by itself trigger the honeypot');
});

test('an invalid ratchetStatus value is rejected as malformed but still does not block auth', async () => {
  const result = await fullAuth(
    server.baseUrl, 'ratchet-phone-4', keypair(), 'ratchet-device-4', keypair(),
    { ratchetStatus: 'not-a-real-status' }
  );
  assert.ok(result.sessionToken);

  const res = await fetch(`${server.baseUrl}/admin/identities/ratchet-device-4`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const body = await res.json();
  assert.equal(body.ratchet, null, 'a malformed status should never be stored');
});

test('admin identity reset also clears ratchet state — the escape hatch', async () => {
  await fullAuth(
    server.baseUrl, 'ratchet-phone-5', keypair(), 'ratchet-device-5', keypair(),
    { ratchetStatus: 'mismatch' }
  );

  let res = await fetch(`${server.baseUrl}/admin/identities/ratchet-device-5`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  let body = await res.json();
  assert.equal(body.ratchet.status, 'mismatch', 'sanity check: the mismatch is there before reset');

  res = await fetch(`${server.baseUrl}/admin/identities/ratchet-device-5`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.clearedRatchetStatus, 'mismatch', 'the reset response should report what ratchet status it cleared');

  res = await fetch(`${server.baseUrl}/admin/identities/ratchet-device-5`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert.equal(res.status, 404, 'the identity itself is gone after reset, same as before this change');
});

test('resetting an identity with no ratchet state reports clearedRatchetStatus as null', async () => {
  await fullAuth(server.baseUrl, 'ratchet-phone-6', keypair(), 'ratchet-device-6', keypair());

  const res = await fetch(`${server.baseUrl}/admin/identities/ratchet-device-6`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.clearedRatchetStatus, null);
});

// --- Signed attestation (verifyAndRecordRatchetAttestation) — the actual fix ---

test('a real signed bootstrap attestation is verified server-side and recorded as bootstrap', async () => {
  const deviceKeys = keypair();
  const { status, body } = await deviceVerifyWithAttestation(
    server.baseUrl, 'attest-phone-1', keypair(), 'attest-device-1', deviceKeys,
    (challenge) => buildAttestation({ deviceEd25519PrivateKey: deviceKeys.privateKey, challenge, status: 0 })
  );
  assert.equal(status, 200);
  assert.ok(body.sessionToken);

  const res = await fetch(`${server.baseUrl}/admin/identities/attest-device-1`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const identity = await res.json();
  assert.equal(identity.ratchet.status, 'bootstrap');
  assert.equal(identity.ratchet.verified_by, 'server', 'a real signed attestation must be recorded as server-verified, not client-reported');
});

test('a second session with a correct HMAC proof over the stored next_proof verifies server-side', async () => {
  const deviceKeys = keypair();
  const phoneDeviceId = 'attest-phone-2';
  const phoneKeys = keypair();
  const hardwareDeviceId = 'attest-device-2';

  const first = await deviceVerifyWithAttestation(
    server.baseUrl, phoneDeviceId, phoneKeys, hardwareDeviceId, deviceKeys,
    (challenge) => buildAttestation({ deviceEd25519PrivateKey: deviceKeys.privateKey, challenge, status: 0 })
  );
  assert.equal(first.status, 200);

  const second = await deviceVerifyWithAttestation(
    server.baseUrl, phoneDeviceId, phoneKeys, hardwareDeviceId, deviceKeys,
    (challenge) => buildAttestation({ deviceEd25519PrivateKey: deviceKeys.privateKey, challenge, status: 1, priorNextProofB64: first.nextProofB64 })
  );
  assert.equal(second.status, 200);

  const res = await fetch(`${server.baseUrl}/admin/identities/${hardwareDeviceId}`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const identity = await res.json();
  assert.equal(identity.ratchet.status, 'verified', 'a correctly-chained HMAC proof, independently recomputed by the backend, must verify');
});

test('a continuation claim with a wrong HMAC proof is recorded as a server-detected mismatch and honeypotted', async () => {
  const deviceKeys = keypair();
  const phoneDeviceId = 'attest-phone-3';
  const phoneKeys = keypair();
  const hardwareDeviceId = 'attest-device-3';

  const first = await deviceVerifyWithAttestation(
    server.baseUrl, phoneDeviceId, phoneKeys, hardwareDeviceId, deviceKeys,
    (challenge) => buildAttestation({ deviceEd25519PrivateKey: deviceKeys.privateKey, challenge, status: 0 })
  );
  assert.equal(first.status, 200);

  const second = await deviceVerifyWithAttestation(
    server.baseUrl, phoneDeviceId, phoneKeys, hardwareDeviceId, deviceKeys,
    (challenge) => buildAttestation({ deviceEd25519PrivateKey: deviceKeys.privateKey, challenge, status: 1, priorNextProofB64: first.nextProofB64, wrongDeviceProof: true })
  );
  assert.equal(second.status, 200, 'still warn-not-block: a mismatch must not fail authentication');

  const res = await fetch(`${server.baseUrl}/admin/identities/${hardwareDeviceId}`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const identity = await res.json();
  assert.equal(identity.ratchet.status, 'mismatch');

  const forensics = await (await fetch(`${server.baseUrl}/admin/forensics`, { headers: { Authorization: `Bearer ${adminToken}` } })).json();
  const found = forensics.events.some((e) => e.reason.includes('Ratchet continuity mismatch') && e.details.deviceId === hardwareDeviceId);
  assert.ok(found, 'a real, backend-detected mismatch must still show up in forensics');
});

test('a continuation claim with no prior next_proof on file is unverifiable, not a false mismatch', async () => {
  // Simulates the migration case: a device whose real NVS ratchet state predates this
  // backend upgrade claims continuation, but the backend has nothing to compare against yet.
  const deviceKeys = keypair();
  const { status, body } = await deviceVerifyWithAttestation(
    server.baseUrl, 'attest-phone-4', keypair(), 'attest-device-4', deviceKeys,
    (challenge) => buildAttestation({ deviceEd25519PrivateKey: deviceKeys.privateKey, challenge, status: 1, priorNextProofB64: crypto.randomBytes(32).toString('base64') })
  );
  assert.equal(status, 200);
  assert.ok(body.sessionToken);

  const res = await fetch(`${server.baseUrl}/admin/identities/attest-device-4`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const identity = await res.json();
  assert.equal(identity.ratchet.status, 'unverifiable', 'no stored next_proof yet must never be conflated with a real mismatch');
});

test('an attestation signed by the wrong key is rejected and honeypotted, and does not overwrite real state', async () => {
  const deviceKeys = keypair();
  const impostorKeys = keypair();
  const hardwareDeviceId = 'attest-device-5';

  const legit = await deviceVerifyWithAttestation(
    server.baseUrl, 'attest-phone-5', keypair(), hardwareDeviceId, deviceKeys,
    (challenge) => buildAttestation({ deviceEd25519PrivateKey: deviceKeys.privateKey, challenge, status: 0 })
  );
  assert.equal(legit.status, 200);

  const forged = await deviceVerifyWithAttestation(
    server.baseUrl, 'attest-phone-5b', keypair(), hardwareDeviceId, deviceKeys,
    // signed with a DIFFERENT key than the one registered for this deviceId
    (challenge) => buildAttestation({ deviceEd25519PrivateKey: impostorKeys.privateKey, challenge, status: 1, priorNextProofB64: legit.nextProofB64 })
  );
  assert.equal(forged.status, 200, 'the primary deviceSignature is still real and valid, so auth itself succeeds — only the ratchet claim is rejected');

  const res = await fetch(`${server.baseUrl}/admin/identities/${hardwareDeviceId}`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const identity = await res.json();
  assert.equal(identity.ratchet.status, 'bootstrap', 'the forged attestation must not overwrite the real prior state');

  const forensics = await (await fetch(`${server.baseUrl}/admin/forensics`, { headers: { Authorization: `Bearer ${adminToken}` } })).json();
  const found = forensics.events.some((e) => e.reason.includes('Ratchet attestation invalid: bad_signature') && e.details.deviceId === hardwareDeviceId);
  assert.ok(found, 'a signature that does not match the registered device key must be flagged, not silently ignored');
});

test('a legacy unsigned ratchetStatus still works for backward compatibility but is marked client-reported, not server-verified', async () => {
  const result = await fullAuth(
    server.baseUrl, 'attest-phone-6', keypair(), 'attest-device-6', keypair(),
    { ratchetStatus: 'verified' }
  );
  assert.ok(result.sessionToken);

  const res = await fetch(`${server.baseUrl}/admin/identities/attest-device-6`, { headers: { Authorization: `Bearer ${adminToken}` } });
  const identity = await res.json();
  assert.equal(identity.ratchet.status, 'verified');
  assert.equal(identity.ratchet.verified_by, 'client-reported', 'an unsigned legacy claim must never be indistinguishable from a real server-verified one');
});
