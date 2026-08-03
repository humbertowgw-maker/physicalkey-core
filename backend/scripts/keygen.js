import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const keysDir = path.join(__dirname, '..', 'keys');

const name = process.argv[2];
if (!name) {
  console.error('Usage: node scripts/keygen.js <name>');
  process.exit(1);
}

fs.mkdirSync(keysDir, { recursive: true });

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

const publicKeyB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });

fs.writeFileSync(path.join(keysDir, `${name}.key.pem`), privateKeyPem, { mode: 0o600 });
fs.writeFileSync(path.join(keysDir, `${name}.pub.b64`), publicKeyB64);

console.log(`Generated Ed25519 keypair for "${name}"`);
console.log(`  Private key: keys/${name}.key.pem (keep secret, never send to the server)`);
console.log(`  Public key (base64 SPKI, send to server on first registration):`);
console.log(publicKeyB64);
