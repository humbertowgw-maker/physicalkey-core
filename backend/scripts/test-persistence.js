import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BASE = process.env.PK_BASE_URL || 'http://localhost:3000';
const STATE_FILE = path.join(__dirname, '..', 'data', '.persistence-test-state.json');
const keysDir = path.join(__dirname, '..', 'keys');

function keygen(name) {
  execFileSync('node', [path.join(__dirname, 'keygen.js'), name], { stdio: 'inherit' });
}

function readPub(name) {
  return fs.readFileSync(path.join(keysDir, `${name}.pub.b64`), 'utf8').trim();
}

function sign(name, message) {
  return execFileSync('node', [path.join(__dirname, 'sign.js'), name, message]).toString().trim();
}

async function fullAuth({ phoneId, deviceId, phoneKeyName, deviceKeyName, sendPhonePublicKey, sendDevicePublicKey }) {
  let res = await fetch(`${BASE}/auth/phone/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      phoneAttestation: {
        platform: 'iOS',
        deviceId: phoneId,
        imei: '352657092923456',
        bundleId: 'com.physicalkey.app',
        ...(sendPhonePublicKey ? { publicKey: readPub(phoneKeyName) } : {})
      }
    })
  });
  let body = await res.json();
  if (res.status !== 200) return { status: res.status, body, stage: 'phone_challenge' };

  const phoneSig = sign(phoneKeyName, body.challenge);
  res = await fetch(`${BASE}/auth/phone/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId: body.challengeId, phoneSignature: phoneSig })
  });
  body = await res.json();
  if (res.status !== 200) return { status: res.status, body, stage: 'phone_verify' };

  const deviceSig = sign(deviceKeyName, body.deviceChallenge);
  res = await fetch(`${BASE}/auth/device/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      deviceChallengeId: body.deviceChallengeId,
      deviceSignature: deviceSig,
      deviceId,
      ...(sendDevicePublicKey ? { publicKey: readPub(deviceKeyName) } : {})
    })
  });
  body = await res.json();
  return { status: res.status, body, stage: 'device_verify' };
}

const mode = process.argv[2];
if (!['register', 'verify'].includes(mode)) {
  console.error('Usage: node scripts/test-persistence.js <register|verify>');
  process.exit(1);
}

async function main() {
  if (mode === 'register') {
    const suffix = Math.random().toString(36).slice(2, 8);
    const phoneId = `persist-phone-${suffix}`;
    const deviceId = `persist-device-${suffix}`;

    keygen('persist-phone');
    keygen('persist-device');

    console.log('\n=== [register] Registering phone+device with fresh keys, before restart ===');
    const result = await fullAuth({
      phoneId, deviceId,
      phoneKeyName: 'persist-phone', deviceKeyName: 'persist-device',
      sendPhonePublicKey: true, sendDevicePublicKey: true
    });
    console.log(result.status, result.body);
    if (result.status !== 200) throw new Error('Initial registration failed — cannot proceed');

    fs.mkdirSync(path.dirname(STATE_FILE), { recursive: true });
    fs.writeFileSync(STATE_FILE, JSON.stringify({ phoneId, deviceId, gitCredentials: result.body.gitCredentials }, null, 2));
    console.log(`\nState saved. Now RESTART the server process, then run:\n  node scripts/test-persistence.js verify`);
    return;
  }

  // mode === 'verify'
  if (!fs.existsSync(STATE_FILE)) {
    throw new Error('No state file found — run "register", restart the server, then run "verify"');
  }
  const { phoneId, deviceId, gitCredentials } = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));

  console.log('\n=== [verify] Git credentials issued BEFORE the restart still validate (checked first, before any new auth rotates them) ===');
  let res = await fetch(`${BASE}/git/auth`, {
    headers: { Authorization: 'Basic ' + Buffer.from(`${gitCredentials.username}:${gitCredentials.password}`).toString('base64') }
  });
  let body = await res.json();
  console.log(res.status, body);
  if (res.status !== 200) throw new Error('Git credentials issued before the restart no longer validate — persistence is broken');

  console.log('\n=== [verify] Re-authenticating the SAME deviceId using the ORIGINAL persisted key (no publicKey resent) — MUST succeed ===');
  console.log('(note: this reissues fresh git credentials for the device, which is expected — the OLD ones were already confirmed valid above)');
  const same = await fullAuth({
    phoneId, deviceId,
    phoneKeyName: 'persist-phone', deviceKeyName: 'persist-device',
    sendPhonePublicKey: false, sendDevicePublicKey: false
  });
  console.log(same.status, same.body);
  if (same.status !== 200) throw new Error('Auth with the original persisted key failed after restart — persistence is broken');

  console.log('\n=== [verify] Attempting to HIJACK the same deviceId with a DIFFERENT new key — MUST be rejected ===');
  keygen('persist-device-hijack');
  const hijack = await fullAuth({
    phoneId, deviceId,
    phoneKeyName: 'persist-phone', deviceKeyName: 'persist-device-hijack',
    sendPhonePublicKey: false, sendDevicePublicKey: false
  });
  console.log(hijack.status, hijack.body);
  if (hijack.status === 200) throw new Error('SECURITY BUG: a deviceId was re-registered/hijacked with a different key after restart');

  console.log('\n=== [verify] Honeypot events logged BEFORE the restart are still visible via /admin/forensics ===');
  // The phone side is fine to always register fresh (random phoneId each run). But
  // demo-device-admin-001 is a FIXED deviceId that may already be registered from an
  // earlier test run, so don't regenerate that key (it would no longer match what's
  // stored server-side) — only generate it if it doesn't exist yet. The publicKey is
  // always sent regardless; the server only uses it for first-time registration and
  // ignores it otherwise, so this is safe either way.
  const adminSuffix = Math.random().toString(36).slice(2, 8);
  keygen(`persist-admin-phone-${adminSuffix}`);
  if (!fs.existsSync(path.join(keysDir, 'admin-device.key.pem'))) keygen('admin-device');

  const admin = await fullAuth({
    phoneId: `persist-admin-phone-${adminSuffix}`,
    deviceId: 'demo-device-admin-001',
    phoneKeyName: `persist-admin-phone-${adminSuffix}`, deviceKeyName: 'admin-device',
    sendPhonePublicKey: true, sendDevicePublicKey: true
  });
  if (admin.status !== 200) throw new Error(`Could not authenticate as admin device: ${JSON.stringify(admin.body)}`);

  res = await fetch(`${BASE}/admin/forensics`, { headers: { Authorization: `Bearer ${admin.body.sessionToken}` } });
  body = await res.json();
  console.log(res.status, JSON.stringify(body.summary));
  if (res.status !== 200) throw new Error('Admin forensics call failed');
  if (body.summary.totalAttempts < 1) throw new Error('Forensics report is empty after restart — honeypot log did not persist');

  console.log('\nAll persistence tests passed: registered identities, git credentials, and honeypot logs all survived a real server restart, and hijacking an already-registered deviceId with a new key was correctly rejected.');
}

main().catch(err => {
  console.error('\nTEST FAILED:', err.message);
  process.exit(1);
});
