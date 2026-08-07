import { spawn } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVER_PATH = path.join(__dirname, '..', 'server.js');

// Ed25519 SubjectPublicKeyInfo DER has no algorithm parameters, so this 12-byte prefix is
// fixed and identical for every Ed25519 key — same constant the firmware/backend both
// independently derive from Node's own `publicKey.export({type:'spki',format:'der'})`.
// Used for BOARD/DEVICE identities everywhere (device-auth.js is Ed25519-only, unchanged
// by the phone-side Secure Enclave migration) and for legacy-phone backward-compat tests.
export function keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  return { publicKey, privateKey, publicKeyB64 };
}

// P-256, matching what iOS's KeyManager.swift now generates via
// SecureEnclave.P256.Signing.PrivateKey — this is what a real phone registers today.
// Node's own SPKI DER export needs no hand-rolled prefix (unlike Ed25519 above): EC SPKI
// carries its curve OID in the DER itself, and CryptoKit's P256.Signing.PublicKey produces
// the exact same RFC 5480 encoding independently.
export function p256Keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const publicKeyB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  return { publicKey, privateKey, publicKeyB64 };
}

// Dispatches on the private key's own type, so existing Ed25519 callers (the whole
// existing test suite — device keys, and legacy-phone tests) are unaffected; a P-256
// key from p256Keypair() above signs with the same call.
export function sign(privateKey, message) {
  const algorithm = privateKey.asymmetricKeyType === 'ec' ? 'sha256' : null;
  return crypto.sign(algorithm, Buffer.from(message, 'utf8'), privateKey).toString('base64');
}

/**
 * Spawns a real `node server.js` pointed at a specific data directory and port — the
 * low-level primitive. Used directly by persistence tests that need to kill and restart
 * a server against the SAME data directory (to prove data survives a real process
 * restart, not just stay in memory); `startServer()` below is the convenience wrapper
 * for everything else, which allocates a fresh throwaway directory and cleans it up.
 */
export async function spawnServerAt(dataDir, { port, adminDeviceId, env = {} } = {}) {
  port ??= 4000 + Math.floor(Math.random() * 5000);
  adminDeviceId ??= `test-admin-device-${crypto.randomBytes(4).toString('hex')}`;

  const child = spawn('node', [SERVER_PATH], {
    env: {
      ...process.env,
      PORT: String(port),
      PK_DATA_DIR: dataDir,
      SECRET_KEY: 'test-secret-key-not-for-production',
      ADMIN_DEVICE_ID: adminDeviceId,
      NODE_ENV: 'test',
      ...env
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  let output = '';
  child.stdout.on('data', (d) => { output += d.toString(); });
  child.stderr.on('data', (d) => { output += d.toString(); });

  const baseUrl = `http://localhost:${port}`;
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${baseUrl}/health`);
      if (res.ok) break;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 100));
  }

  return {
    baseUrl,
    adminDeviceId,
    port,
    dataDir,
    getOutput: () => output,
    async kill() {
      child.kill('SIGTERM');
      await new Promise((resolve) => child.once('exit', resolve));
    }
  };
}

/**
 * Spawns a real `node server.js` against an isolated, throwaway SQLite data directory —
 * not the real dev database and never production. Each test file gets its own instance
 * (own port, own data dir) so files can run in parallel without interfering.
 */
export async function startServer(options = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'physicalkey-test-'));
  const instance = await spawnServerAt(dataDir, options);
  return {
    ...instance,
    async stop() {
      await instance.kill();
      fs.rmSync(dataDir, { recursive: true, force: true });
    }
  };
}

/** Runs a full phone challenge/verify against a running test server. Registers on first use. */
export async function phoneAuth(baseUrl, deviceId, phoneKeys) {
  let res = await fetch(`${baseUrl}/auth/phone/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      phoneAttestation: { platform: 'iOS', deviceId, publicKey: phoneKeys.publicKeyB64 }
    })
  });
  const challengeBody = await res.json();
  if (!res.ok) throw new Error(`phone challenge failed: ${res.status} ${JSON.stringify(challengeBody)}`);

  const phoneSignature = sign(phoneKeys.privateKey, challengeBody.challenge);
  res = await fetch(`${baseUrl}/auth/phone/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId: challengeBody.challengeId, phoneSignature })
  });
  const verifyBody = await res.json();
  if (!res.ok) throw new Error(`phone verify failed: ${res.status} ${JSON.stringify(verifyBody)}`);
  return verifyBody; // { deviceChallengeId, deviceChallenge }
}

/**
 * Runs a full phone+device auth flow, returning the resulting session token.
 * `extra` merges additional fields into the /auth/device/verify body — e.g. { ratchetStatus }.
 */
export async function fullAuth(baseUrl, phoneDeviceId, phoneKeys, hardwareDeviceId, deviceKeys, extra = {}) {
  const { deviceChallengeId, deviceChallenge } = await phoneAuth(baseUrl, phoneDeviceId, phoneKeys);

  const deviceSignature = sign(deviceKeys.privateKey, deviceChallenge);
  const res = await fetch(`${baseUrl}/auth/device/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      deviceChallengeId,
      deviceSignature,
      deviceId: hardwareDeviceId,
      publicKey: deviceKeys.publicKeyB64,
      ...extra
    })
  });
  const body = await res.json();
  if (!res.ok) throw new Error(`device verify failed: ${res.status} ${JSON.stringify(body)}`);
  return body; // { sessionToken, gitCredentials, ... }
}
