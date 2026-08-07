import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Overridable so the test suite (and CLI scripts that must not open a second connection
// against the live database file, e.g. restore.js) can point at an isolated directory
// instead of real local/production data — unset in normal running (dev or Railway).
export const dataDir = process.env.PK_DATA_DIR || path.join(__dirname, '..', 'data');
fs.mkdirSync(dataDir, { recursive: true });
