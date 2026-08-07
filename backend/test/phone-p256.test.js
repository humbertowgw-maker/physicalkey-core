import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { startServer, keypair, p256Keypair, sign, phoneAuth, fullAuth } from './helpers.js';

let server;

before(async () => { server = await startServer(); });
after(async () => { await server.stop(); });

test('a P-256 phone (what real iOS now generates via SecureEnclave.P256) registers and authenticates end to end', async () => {
  const phoneKeys = p256Keypair();
  const deviceKeys = keypair(); // the board stays Ed25519 — unaffected by this migration
  const result = await fullAuth(server.baseUrl, 'p256-phone-1', phoneKeys, 'p256-phone-1-device', deviceKeys);
  assert.ok(result.sessionToken, 'a P-256 phone identity should authenticate successfully');
});

test('a legacy Ed25519 phone identity still authenticates — the migration does not force re-pairing', async () => {
  const phoneKeys = keypair(); // Ed25519, the pre-migration shape
  const deviceKeys = keypair();
  const result = await fullAuth(server.baseUrl, 'legacy-ed25519-phone-1', phoneKeys, 'legacy-ed25519-phone-1-device', deviceKeys);
  assert.ok(result.sessionToken, 'an already-registered Ed25519 phone must keep working');
});

test('a P-256 phone signature does not validate against a different P-256 phone\'s registered key', async () => {
  const phoneKeys = p256Keypair();
  const impostorKeys = p256Keypair();

  let res = await fetch(`${server.baseUrl}/auth/phone/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      phoneAttestation: { platform: 'iOS', deviceId: 'p256-phone-impersonation', publicKey: phoneKeys.publicKeyB64 }
    })
  });
  const challengeBody = await res.json();

  const forgedSignature = sign(impostorKeys.privateKey, challengeBody.challenge);
  res = await fetch(`${server.baseUrl}/auth/phone/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId: challengeBody.challengeId, phoneSignature: forgedSignature })
  });
  assert.equal(res.status, 401);
});

test('an unsupported key type (e.g. RSA) is rejected outright rather than throwing', async () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicKeyB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

  let res = await fetch(`${server.baseUrl}/auth/phone/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      phoneAttestation: { platform: 'iOS', deviceId: 'rsa-phone-unsupported', publicKey: publicKeyB64 }
    })
  });
  const challengeBody = await res.json();

  const rsaSignature = crypto.sign('sha256', Buffer.from(challengeBody.challenge), privateKey).toString('base64');
  res = await fetch(`${server.baseUrl}/auth/phone/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId: challengeBody.challengeId, phoneSignature: rsaSignature })
  });
  assert.equal(res.status, 401, 'an RSA key is neither ed25519 nor ec — verifySignature should return false, not throw');
});

test('P-256 phone -> device -> git credentials issuance works through the full stack, not just phone verify', async () => {
  const phoneKeys = p256Keypair();
  const deviceKeys = keypair();
  const result = await fullAuth(server.baseUrl, 'p256-phone-full-stack', phoneKeys, 'p256-phone-full-stack-device', deviceKeys);

  assert.ok(result.gitCredentials, 'git credentials should be issued exactly as for a legacy Ed25519 phone');
  const auth = Buffer.from(`${result.gitCredentials.username}:${result.gitCredentials.password}`).toString('base64');
  const gitRes = await fetch(`${server.baseUrl}/git/auth`, { headers: { Authorization: `Basic ${auth}` } });
  assert.equal(gitRes.status, 200);
});
