// Deliberately does NOT import lib/db.js — that would open a second DatabaseSync
// connection against the very file this script is about to overwrite. Resolves the data
// directory independently instead.
import fs from 'fs';
import path from 'path';
import { dataDir } from '../lib/data-dir.js';

const source = process.argv[2];
if (!source) {
  console.error('Usage: node scripts/restore.js <path-to-backup-file>');
  console.error('List available backups with: ls data/backups/');
  process.exit(1);
}
if (!fs.existsSync(source)) {
  console.error(`Backup file not found: ${source}`);
  process.exit(1);
}

console.error('Stop the server before restoring — this replaces the live database file');
console.error('while it may still be open by a running process.');

const target = path.join(dataDir, 'physicalkey.db');
if (fs.existsSync(target)) {
  const safety = `${target}.pre-restore-${Date.now()}`;
  fs.copyFileSync(target, safety);
  console.log(`Existing database saved to ${safety} before overwrite`);
}

fs.copyFileSync(source, target);
console.log(`Restored ${source} -> ${target}`);
console.log('Start the server for the restored database to take effect.');
