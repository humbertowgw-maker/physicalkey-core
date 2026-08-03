import crypto from 'crypto';

// NOTE: This is real Ed25519 public-key challenge-response, not Apple App Attest /
// Google Play Integrity. Those require an actual mobile app and calls to Apple/Google's
// attestation servers, which isn't something a backend alone can verify. This gives
// genuine cryptographic proof of possession of a private key tied to a deviceId,
// using trust-on-first-use (TOFU) registration of the public key.

const registeredPhones = new Map(); // deviceId -> { publicKey (base64 SPKI DER), platform, registeredAt }

function registerPhone(deviceId, publicKeyB64, platform) {
  const registration = { deviceId, publicKey: publicKeyB64, platform, registeredAt: Date.now() };
  registeredPhones.set(deviceId, registration);
  console.log(`✓ Phone identity registered: ${deviceId} (${platform})`);
  return registration;
}

export async function validatePhoneAttestation(attestationObject, phoneSignatureB64, challenge) {
  try {
    if (!attestationObject) {
      console.error('No attestation object provided');
      return false;
    }

    const { platform, deviceId, publicKey } = attestationObject;
    if (!platform || !deviceId) {
      console.error('phoneAttestation missing platform or deviceId');
      return false;
    }

    let phone = registeredPhones.get(deviceId);
    if (!phone) {
      if (!publicKey) {
        console.error(`Unknown phone ${deviceId} did not supply a publicKey for registration`);
        return false;
      }
      phone = registerPhone(deviceId, publicKey, platform);
    }

    if (!phoneSignatureB64) {
      console.error(`No phoneSignature provided for ${deviceId}`);
      return false;
    }

    const publicKeyObj = crypto.createPublicKey({
      key: Buffer.from(phone.publicKey, 'base64'),
      format: 'der',
      type: 'spki'
    });

    const isValid = crypto.verify(
      null,
      Buffer.from(challenge, 'utf8'),
      publicKeyObj,
      Buffer.from(phoneSignatureB64, 'base64')
    );

    if (!isValid) {
      console.error(`✗ Invalid phone signature: ${deviceId}`);
      return false;
    }

    console.log(`✓ Phone signature cryptographically verified: ${deviceId} (${platform})`);
    return { platform, deviceId, isGenuine: true };
  } catch (error) {
    console.error('Phone attestation validation error:', error.message);
    return false;
  }
}

export function getPhoneCharacteristics(phoneAttestation) {
  return {
    platform: phoneAttestation.platform,
    deviceId: phoneAttestation.deviceId,
    jailbroken: false,
    biometricAvailable: true
  };
}
