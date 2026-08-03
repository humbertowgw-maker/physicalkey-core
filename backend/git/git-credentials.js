import crypto from 'crypto';

const gitTokens = new Map(); // deviceId -> { username, password, scope, repositories, createdAt, expiresAt }

export function grantGitAccess(deviceId, scope = 'read_write') {
  const credentials = {
    username: deviceId,
    password: crypto.randomBytes(18).toString('base64url'),
    scope,
    repositories: ['physicalkey-core'],
    createdAt: Date.now(),
    expiresAt: Date.now() + (24 * 60 * 60 * 1000)
  };
  gitTokens.set(deviceId, credentials);
  console.log(`✓ Git credentials granted: ${deviceId}`);
  return credentials;
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
  const record = gitTokens.get(username);
  if (!record) return { granted: false, reason: 'unknown_username' };
  if (record.password !== password) return { granted: false, reason: 'invalid_password' };

  if (Date.now() > record.expiresAt) {
    gitTokens.delete(username);
    return { granted: false, reason: 'expired' };
  }

  return { granted: true, record };
}

export function revokeGitAccess(deviceId) {
  return gitTokens.delete(deviceId);
}
