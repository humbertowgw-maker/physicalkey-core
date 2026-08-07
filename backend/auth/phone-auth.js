import crypto from 'crypto';
import db from '../lib/db.js';

// NOTE: This is real public-key challenge-response, not Apple App Attest / Google Play
// Integrity. Those require an actual mobile app and calls to Apple/Google's attestation
// servers, which isn't something a backend alone can verify. This gives genuine
// cryptographic proof of possession of a private key tied to a deviceId, using
// trust-on-first-use (TOFU) registration of the public key. Registrations are persisted
// to SQLite so a server restart can't be used to re-register (hijack) a deviceId that
// already has a trusted key on file.
//
// Phones register EITHER a P-256 key (current: iOS's KeyManager.swift generates these
// Secure-Enclave-resident, via SecureEnclave.P256.Signing.PrivateKey) or a legacy Ed25519
// key (software-only Keychain storage — how every phone identity was registered before
// the Secure Enclave migration). Both remain valid indefinitely: an already-registered
// Ed25519 phone has no reason to be forced through re-pairing just because new
// registrations use a different curve now. The device/board identity (device-auth.js) is
// unaffected by any of this and stays Ed25519-only — ESP32 has no Secure Enclave
// equivalent to gain from switching.
function verifySignature(publicKeyObj, message, signatureBuf) {
  if (publicKeyObj.asymmetricKeyType === 'ed25519') {
    return crypto.verify(null, message, publicKeyObj, signatureBuf);
  }
  if (publicKeyObj.asymmetricKeyType === 'ec') {
    // 'der' is Node's default dsaEncoding for EC verify, matching both Node's own
    // crypto.sign() default and CryptoKit's ECDSASignature.derRepresentation — no format
    // negotiation needed on either side.
    return crypto.verify('sha256', message, publicKeyObj, signatureBuf);
  }
  return false;
}

const getPhoneStmt = db.prepare('SELECT * FROM identities WHERE device_id = ? AND kind = ?');
const insertPhoneStmt = db.prepare(`
  INSERT INTO identities (device_id, kind, public_key, platform, registered_at, last_seen, access_count, status)
  VALUES (?, 'phone', ?, ?, ?, ?, 0, 'active')
`);

function registerPhone(deviceId, publicKeyB64, platform) {
  const now = Date.now();
  insertPhoneStmt.run(deviceId, publicKeyB64, platform, now, now);
  console.log(`✓ Phone identity registered: ${deviceId} (${platform})`);
  return getPhoneStmt.get(deviceId, 'phone');
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

    let phone = getPhoneStmt.get(deviceId, 'phone');
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
      key: Buffer.from(phone.public_key, 'base64'),
      format: 'der',
      type: 'spki'
    });

    const isValid = verifySignature(
      publicKeyObj,
      Buffer.from(challenge, 'utf8'),
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
