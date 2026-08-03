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

async function fullAuth(phoneId, deviceId, phoneKeyName, deviceKeyName) {
  const phonePub = keygen(phoneKeyName);
  const devicePub = keygen(deviceKeyName);

  let res = await fetch(`${BASE}/auth/phone/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      phoneAttestation: { platform: 'iOS', deviceId: phoneId, imei: '352657092923456', bundleId: 'com.physicalkey.app', publicKey: phonePub }
    })
  });
  let body = await res.json();

  const phoneSig = sign(phoneKeyName, body.challenge);
  res = await fetch(`${BASE}/auth/phone/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId: body.challengeId, phoneSignature: phoneSig })
  });
  body = await res.json();

  const deviceSig = sign(deviceKeyName, body.deviceChallenge);
  res = await fetch(`${BASE}/auth/device/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceChallengeId: body.deviceChallengeId, deviceSignature: deviceSig, deviceId, publicKey: devicePub })
  });
  return res.json();
}

async function main() {
  const suffix = Math.random().toString(36).slice(2, 8);

  console.log('\n=== Full auth as a REGULAR (non-admin) device ===');
  const regular = await fullAuth(`git-test-phone-${suffix}`, `git-test-device-${suffix}`, 'git-test-phone', 'git-test-device');
  console.log(regular);

  console.log('\n=== /git/auth with VALID git credentials ===');
  let res = await fetch(`${BASE}/git/auth`, {
    headers: { Authorization: 'Basic ' + Buffer.from(`${regular.gitCredentials.username}:${regular.gitCredentials.password}`).toString('base64') }
  });
  let body = await res.json();
  console.log(res.status, body);
  if (res.status !== 200 || body.granted !== true) throw new Error('/git/auth rejected valid credentials');

  console.log('\n=== /git/auth with WRONG password — MUST be rejected ===');
  res = await fetch(`${BASE}/git/auth`, {
    headers: { Authorization: 'Basic ' + Buffer.from(`${regular.gitCredentials.username}:wrong-password`).toString('base64') }
  });
  body = await res.json();
  console.log(res.status, body);
  if (res.status === 200) throw new Error('SECURITY BUG: /git/auth accepted a wrong password');

  console.log('\n=== /git/auth with no credentials — MUST be rejected ===');
  res = await fetch(`${BASE}/git/auth`);
  body = await res.json();
  console.log(res.status, body);
  if (res.status === 200) throw new Error('SECURITY BUG: /git/auth accepted no credentials');

  console.log('\n=== /admin/forensics as REGULAR device (has valid session, not admin) — MUST be 403 ===');
  res = await fetch(`${BASE}/admin/forensics`, { headers: { Authorization: `Bearer ${regular.sessionToken}` } });
  body = await res.json();
  console.log(res.status, body);
  if (res.status !== 403) throw new Error('SECURITY BUG: non-admin device was not blocked from /admin/forensics');

  console.log('\n=== /admin/forensics with no token — MUST be 401 ===');
  res = await fetch(`${BASE}/admin/forensics`);
  body = await res.json();
  console.log(res.status, body);
  if (res.status !== 401) throw new Error('/admin/forensics did not require auth');

  console.log('\n=== Full auth as the ADMIN device (deviceId = demo-device-admin-001) ===');
  const admin = await fullAuth(`admin-phone-${suffix}`, 'demo-device-admin-001', 'admin-phone', 'admin-device');
  console.log(admin);

  console.log('\n=== /admin/forensics as ADMIN device — should be 200 with real data ===');
  res = await fetch(`${BASE}/admin/forensics`, { headers: { Authorization: `Bearer ${admin.sessionToken}` } });
  body = await res.json();
  console.log(res.status, JSON.stringify(body, null, 2));
  if (res.status !== 200) throw new Error('Admin device was rejected from /admin/forensics');
  if (!Array.isArray(body.attackers) || body.attackers.length === 0) throw new Error('Forensics report has no attacker data (expected some from the failed attempts above)');
  const withTechniques = body.attackers.find(a => a.techniques && a.techniques.length > 0);
  if (!withTechniques) throw new Error('BUG STILL PRESENT: attacker techniques are empty (Set not serializing)');

  console.log('\nAll git + forensics tests passed: valid/invalid git credentials handled correctly, non-admin blocked from forensics, admin sees real attacker data with populated techniques.');
}

main().catch(err => {
  console.error('\nTEST FAILED:', err.message);
  process.exit(1);
});
