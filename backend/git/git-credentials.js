import crypto from 'crypto';
import db from '../lib/db.js';

const upsertStmt = db.prepare(`
  INSERT INTO git_credentials (device_id, username, password_hash, scope, repositories, created_at, expires_at)
  VALUES (?, ?, ?, ?, ?, ?, ?)
  ON CONFLICT(device_id) DO UPDATE SET
    username = excluded.username,
    password_hash = excluded.password_hash,
    scope = excluded.scope,
    repositories = excluded.repositories,
    created_at = excluded.created_at,
    expires_at = excluded.expires_at
`);
const getStmt = db.prepare('SELECT * FROM git_credentials WHERE device_id = ?');
const deleteStmt = db.prepare('DELETE FROM git_credentials WHERE device_id = ?');

// Credentials now persist to disk, so the password is stored as a salted scrypt hash
// rather than plaintext — only the caller who was just issued the password (once,
// at grant time) ever sees it.
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hashHex] = stored.split(':');
  const candidate = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(hashHex, 'hex');
  if (candidate.length !== expected.length) return false;
  return crypto.timingSafeEqual(candidate, expected);
}

export function grantGitAccess(deviceId, scope = 'read_write') {
  const now = Date.now();
  const plaintextPassword = crypto.randomBytes(18).toString('base64url');
  const repositories = ['physicalkey-core'];
  const expiresAt = now + (24 * 60 * 60 * 1000);

  upsertStmt.run(deviceId, deviceId, hashPassword(plaintextPassword), scope, JSON.stringify(repositories), now, expiresAt);
  console.log(`✓ Git credentials granted: ${deviceId}`);

  return {
    username: deviceId,
    password: plaintextPassword,
    scope,
    repositories,
    createdAt: now,
    expiresAt
  };
}

export function parseBasicAuth(req) {
  const header = req.get('authorization') || '';
  if (!header.startsWith('Basic ')) return null;

  const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
  const separatorIndex = decoded.indexOf(':');
  if (separatorIndex === -1) return null;

  return {
    username: decoded.slice(0, separatorIndex),
    password: decoded.slice(separatorIndex + 1)
  };
}

export function validateGitCredentials(username, password) {
  const row = getStmt.get(username);
  if (!row) return { granted: false, reason: 'unknown_username' };
  if (!verifyPassword(password, row.password_hash)) return { granted: false, reason: 'invalid_password' };

  if (Date.now() > row.expires_at) {
    deleteStmt.run(username);
    return { granted: false, reason: 'expired' };
  }

  return {
    granted: true,
    record: {
      username: row.username,
      scope: row.scope,
      repositories: JSON.parse(row.repositories),
      createdAt: row.created_at,
      expiresAt: row.expires_at
    }
  };
}

export function revokeGitAccess(deviceId) {
  const result = deleteStmt.run(deviceId);
  return result.changes > 0;
}
