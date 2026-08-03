import { execFileSync } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

// Proves the ESP32 firmware's actual Ed25519 library (Rhys Weatherley's arduinolibs
// Crypto, the same library main.cpp/firmware.ino use) produces keys and signatures the
// PhysicalKey backend accepts — run against the live production backend, not a mock.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BASE = process.env.PK_BASE_URL || 'https://physicalkey-core-production.up.railway.app';
const BIN = path.join(__dirname, 'firmware-crypto-poc');

function genkey() {
  const output = execFileSync(BIN, ['genkey']).toString();
  const privateHex = output.match(/PRIVATE_HEX=([0-9a-f]+)/)[1];
  const publicB64 = output.match(/PUBLIC_SPKI_B64=(\S+)/)[1];
  return { privateHex, publicB64 };
}

function sign(privateHex, message) {
  const output = execFileSync(BIN, ['sign', privateHex, message]).toString();
  return output.match(/SIGNATURE_B64=(\S+)/)[1];
}

async function main() {
  const suffix = Math.random().toString(36).slice(2, 8);
  const phone = genkey();
  const device = genkey();

  console.log('\n=== Phone challenge ===');
  let res = await fetch(`${BASE}/auth/phone/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      phoneAttestation: {
        platform: 'iOS',
        deviceId: `firmware-poc-phone-${suffix}`,
        imei: '352657092923456',
        bundleId: 'com.physicalkey.app',
        publicKey: phone.publicB64
      }
    })
  });
  let body = await res.json();
  console.log(res.status, body);
  if (res.status !== 200) throw new Error('phone challenge failed');

  console.log('\n=== Phone verify (signed by the ESP32 firmware\'s Ed25519 library) ===');
  const phoneSig = sign(phone.privateHex, body.challenge);
  res = await fetch(`${BASE}/auth/phone/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId: body.challengeId, phoneSignature: phoneSig })
  });
  body = await res.json();
  console.log(res.status, body);
  if (res.status !== 200) throw new Error('phone verify rejected a firmware-library signature — crypto is NOT compatible');

  console.log('\n=== Device verify (signed by the SAME firmware Ed25519 library — this is the actual key-fob code path) ===');
  const deviceSig = sign(device.privateHex, body.deviceChallenge);
  res = await fetch(`${BASE}/auth/device/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      deviceChallengeId: body.deviceChallengeId,
      deviceSignature: deviceSig,
      deviceId: `firmware-poc-device-${suffix}`,
      publicKey: device.publicB64
    })
  });
  body = await res.json();
  console.log(res.status, body);
  if (res.status !== 200) throw new Error('device verify rejected a firmware-library signature — crypto is NOT compatible');

  console.log('\n=== Forged signature (garbage bytes, still base64) — MUST be rejected ===');
  res = await fetch(`${BASE}/auth/phone/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      phoneAttestation: {
        platform: 'iOS',
        deviceId: `firmware-poc-forge-${suffix}`,
        imei: '352657092923456',
        bundleId: 'com.physicalkey.app',
        publicKey: phone.publicB64
      }
    })
  });
  body = await res.json();
  res = await fetch(`${BASE}/auth/phone/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId: body.challengeId, phoneSignature: Buffer.from('not-a-real-signature').toString('base64') })
  });
  body = await res.json();
  console.log(res.status, body);
  if (res.status === 200) throw new Error('SECURITY BUG: a forged signature was accepted');

  console.log('\nESP32 firmware Ed25519 library IS compatible with the PhysicalKey backend: real phone + device signatures accepted end-to-end, forged signature rejected.');
}

main().catch(err => {
  console.error('\nTEST FAILED:', err.message);
  process.exit(1);
});
