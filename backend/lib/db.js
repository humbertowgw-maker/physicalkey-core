import { DatabaseSync } from 'node:sqlite';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Overridable so the test suite can point at an isolated, throwaway directory instead of
// the real local/production data — unset in normal running (dev or Railway), so this is
// a no-op there.
const dataDir = process.env.PK_DATA_DIR || path.join(__dirname, '..', 'data');
fs.mkdirSync(dataDir, { recursive: true });

const db = new DatabaseSync(path.join(dataDir, 'physicalkey.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS identities (
    device_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('phone', 'device')),
    public_key TEXT NOT NULL,
    platform TEXT,
    registered_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    access_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active'
  );

  CREATE TABLE IF NOT EXISTS git_credentials (
    device_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    scope TEXT NOT NULL,
    repositories TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS honeypot_events (
    id TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    reason TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}',
    level TEXT NOT NULL DEFAULT 'warning',
    timestamp TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_honeypot_events_ip ON honeypot_events(ip);
`);

export default db;
