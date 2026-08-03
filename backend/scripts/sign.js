import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const keysDir = path.join(__dirname, '..', 'keys');

const [name, message] = process.argv.slice(2);
if (!name || message === undefined) {
  console.error('Usage: node scripts/sign.js <name> <message>');
  process.exit(1);
}

const privateKeyPem = fs.readFileSync(path.join(keysDir, `${name}.key.pem`), 'utf8');
const privateKey = crypto.createPrivateKey(privateKeyPem);

const signature = crypto.sign(null, Buffer.from(message, 'utf8'), privateKey);
console.log(signature.toString('base64'));
