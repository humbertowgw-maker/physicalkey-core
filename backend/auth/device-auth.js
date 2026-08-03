import crypto from 'crypto';
import db from '../lib/db.js';

const getDeviceStmt = db.prepare('SELECT * FROM identities WHERE device_id = ? AND kind = ?');
const insertDeviceStmt = db.prepare(`
  INSERT INTO identities (device_id, kind, public_key, registered_at, last_seen, access_count, status)
  VALUES (?, 'device', ?, ?, ?, 0, 'active')
`);
const touchDeviceStmt = db.prepare('UPDATE identities SET last_seen = ?, access_count = access_count + 1 WHERE device_id = ? AND kind = ?');
const revokeDeviceStmt = db.prepare("UPDATE identities SET status = 'revoked' WHERE device_id = ? AND kind = ?");

export function registerDevice(deviceId, publicKeyB64) {
  try {
    const now = Date.now();
    insertDeviceStmt.run(deviceId, publicKeyB64, now, now);
    console.log(`✓ Device registered: ${deviceId}`);
    return getDeviceStmt.get(deviceId, 'device');
  } catch (error) {
    console.error('Device registration error:', error);
    return null;
  }
}

export async function validateDeviceSignature(challenge, deviceSignatureB64, deviceId, publicKeyB64) {
  try {
    console.log(`🔑 Validating device signature for: ${deviceId}`);

    let device = getDeviceStmt.get(deviceId, 'device');
    if (!device) {
      // Trust-on-first-use: an unknown device must supply its public key to register.
      // Once registered, this is persisted — a restart cannot be used to re-register
      // (hijack) a deviceId that already has a trusted key on file.
      if (!publicKeyB64) {
        console.error(`Unknown device ${deviceId} did not supply a publicKey for registration`);
        return false;
      }
      device = registerDevice(deviceId, publicKeyB64);
    }

    if (device.status !== 'active') {
      console.error(`Device ${deviceId} is not active (status=${device.status})`);
      return false;
    }

    if (!deviceSignatureB64) {
      console.error(`No deviceSignature provided for ${deviceId}`);
      return false;
    }

    const publicKeyObj = crypto.createPublicKey({
      key: Buffer.from(device.public_key, 'base64'),
      format: 'der',
      type: 'spki'
    });

    const isValid = crypto.verify(
      null,
      Buffer.from(challenge, 'utf8'),
      publicKeyObj,
      Buffer.from(deviceSignatureB64, 'base64')
    );

    if (!isValid) {
      console.error(`✗ Invalid device signature: ${deviceId}`);
      return false;
    }

    touchDeviceStmt.run(Date.now(), deviceId, 'device');

    console.log(`✓ Device signature cryptographically verified: ${deviceId}`);
    return true;
  } catch (error) {
    console.error('Device signature validation error:', error.message);
    return false;
  }
}

export function getDeviceInfo(deviceId) {
  const device = getDeviceStmt.get(deviceId, 'device');
  if (!device) return null;

  return {
    deviceId: device.device_id,
    registeredAt: device.registered_at,
    lastSeen: device.last_seen,
    accessCount: device.access_count,
    status: device.status
  };
}

export function revokeDevice(deviceId) {
  revokeDeviceStmt.run(deviceId, 'device');
  return getDeviceStmt.get(deviceId, 'device');
}
