import crypto from 'crypto';

const registeredDevices = new Map(); // deviceId -> { publicKey (base64 SPKI DER), registeredAt, lastSeen, accessCount, status }

export function registerDevice(deviceId, publicKeyB64) {
  try {
    const registration = {
      deviceId,
      publicKey: publicKeyB64,
      registeredAt: Date.now(),
      lastSeen: Date.now(),
      accessCount: 0,
      status: 'active'
    };

    registeredDevices.set(deviceId, registration);
    console.log(`✓ Device registered: ${deviceId}`);
    return registration;
  } catch (error) {
    console.error('Device registration error:', error);
    return null;
  }
}

export async function validateDeviceSignature(challenge, deviceSignatureB64, deviceId, publicKeyB64) {
  try {
    console.log(`🔑 Validating device signature for: ${deviceId}`);

    let device = registeredDevices.get(deviceId);
    if (!device) {
      // Trust-on-first-use: an unknown device must supply its public key to register.
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
      key: Buffer.from(device.publicKey, 'base64'),
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

    device.lastSeen = Date.now();
    device.accessCount++;

    console.log(`✓ Device signature cryptographically verified: ${deviceId}`);
    return true;
  } catch (error) {
    console.error('Device signature validation error:', error.message);
    return false;
  }
}

export function getDeviceInfo(deviceId) {
  const device = registeredDevices.get(deviceId);
  if (!device) return null;

  return {
    deviceId: device.deviceId,
    registeredAt: device.registeredAt,
    lastSeen: device.lastSeen,
    accessCount: device.accessCount,
    status: device.status
  };
}

export function revokeDevice(deviceId) {
  const device = registeredDevices.get(deviceId);
  if (device) device.status = 'revoked';
  return device;
}
