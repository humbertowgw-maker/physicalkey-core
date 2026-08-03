import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BASE = process.env.PK_BASE_URL || 'http://localhost:3000';

function keygen(name) {
  execFileSync('node', [path.join(__dirname, 'keygen.js'), name], { stdio: 'inherit' });
  return fs.readFileSync(path.join(__dirname, '..', 'keys', `${name}.pub.b64`), 'utf8').trim();
}

function sign(name, message) {
  return execFileSync('node', [path.join(__dirname, 'sign.js'), name, message]).toString().trim();
}

async function main() {
  console.log('\n=== Generating fresh Ed25519 keypairs ===');
  const suffix = Math.random().toString(36).slice(2, 8);
  const phoneId = `crypto-test-phone-${suffix}`;
  const deviceId = `crypto-test-device-${suffix}`;
  const phonePub = keygen('test-phone');
  const devicePub = keygen('test-device');

  console.log('\n=== Phone challenge ===');
  let res = await fetch(`${BASE}/auth/phone/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      phoneAttestation: {
        platform: 'iOS',
        deviceId: phoneId,
        imei: '352657092923456',
        bundleId: 'com.physicalkey.app',
        publicKey: phonePub
      }
    })
  });
  let body = await res.json();
  console.log(res.status, body);
  const { challengeId, challenge } = body;

  console.log('\n=== Phone verify with a FORGED signature (garbage bytes) — MUST be rejected ===');
  res = await fetch(`${BASE}/auth/phone/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId, phoneSignature: Buffer.from('not-a-real-signature').toString('base64') })
  });
  body = await res.json();
  console.log(res.status, body);
  if (res.status === 200) throw new Error('SECURITY BUG: phone verify accepted a forged signature');

  console.log('\n=== Fresh phone challenge (previous one was consumed by the failed attempt) ===');
  res = await fetch(`${BASE}/auth/phone/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      phoneAttestation: { platform: 'iOS', deviceId: phoneId, imei: '352657092923456', bundleId: 'com.physicalkey.app' }
    })
  });
  body = await res.json();
  console.log(res.status, body);
  const challengeId2 = body.challengeId;
  const challenge2 = body.challenge;

  console.log('\n=== Phone verify with a VALID signature ===');
  const phoneSig = sign('test-phone', challenge2);
  res = await fetch(`${BASE}/auth/phone/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId: challengeId2, phoneSignature: phoneSig })
  });
  body = await res.json();
  console.log(res.status, body);
  if (res.status !== 200) throw new Error('Phone verify with a VALID signature was rejected — crypto is broken');
  const { deviceChallengeId, deviceChallenge } = body;

  console.log('\n=== Device verify with a FORGED signature — MUST be rejected ===');
  res = await fetch(`${BASE}/auth/device/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      deviceChallengeId,
      deviceSignature: Buffer.from('not-a-real-signature').toString('base64'),
      deviceId,
      publicKey: devicePub
    })
  });
  body = await res.json();
  console.log(res.status, body);
  if (res.status === 200) throw new Error('SECURITY BUG: device verify accepted a forged signature');

  console.log('\n=== Replay check: reusing the now-consumed deviceChallengeId, even with a VALID signature — MUST be rejected ===');
  const replaySig = sign('test-device', deviceChallenge);
  res = await fetch(`${BASE}/auth/device/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceChallengeId, deviceSignature: replaySig, deviceId, publicKey: devicePub })
  });
  body = await res.json();
  console.log(res.status, body);
  if (res.status === 200) throw new Error('SECURITY BUG: a consumed/replayed challenge was accepted');

  console.log('\n=== Full clean run: phone challenge -> verify -> device verify, all with VALID signatures ===');
  res = await fetch(`${BASE}/auth/phone/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      phoneAttestation: { platform: 'iOS', deviceId: phoneId, imei: '352657092923456', bundleId: 'com.physicalkey.app' }
    })
  });
  body = await res.json();
  const phoneSig2 = sign('test-phone', body.challenge);
  res = await fetch(`${BASE}/auth/phone/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId: body.challengeId, phoneSignature: phoneSig2 })
  });
  body = await res.json();
  const deviceSig = sign('test-device', body.deviceChallenge);
  res = await fetch(`${BASE}/auth/device/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceChallengeId: body.deviceChallengeId, deviceSignature: deviceSig, deviceId })
  });
  body = await res.json();
  console.log(res.status, body);
  if (res.status !== 200) throw new Error('Device verify with a VALID signature was rejected — crypto is broken');

  console.log('\n=== Protected endpoint with the issued sessionToken ===');
  res = await fetch(`${BASE}/api/profile`, { headers: { Authorization: `Bearer ${body.sessionToken}` } });
  const profile = await res.json();
  console.log(res.status, profile);
  if (res.status !== 200 || profile.authenticated !== true) throw new Error('Protected endpoint did not authenticate a valid session');

  console.log('\nAll cryptographic auth tests passed: valid signatures accepted, forged signature rejected, replayed challenge rejected.');
}

main().catch(err => {
  console.error('\nTEST FAILED:', err.message);
  process.exit(1);
});
