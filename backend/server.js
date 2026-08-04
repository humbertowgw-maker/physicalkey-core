import crypto from 'crypto';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { v4 as uuid } from 'uuid';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { validatePhoneAttestation } from './auth/phone-auth.js';
import { validateDeviceSignature, registerDevice } from './auth/device-auth.js';
import { grantGitAccess, parseBasicAuth, validateGitCredentials } from './git/git-credentials.js';
import { honeypotLogger, activateHoneypot, getForensicsReport, getClientIp } from './honeypot/logger.js';
import { getIdentity, resetIdentity } from './auth/identity-admin.js';
import {
  createOrganization, getOrganization, getMembership, listMembers, addMember, removeMember,
  getDeviceOrg, listOrgDevices, addDeviceToOrg, removeDeviceFromOrg,
  listDeviceAccess, grantDeviceAccess, revokeDeviceAccess, isAuthorizedForDevice
} from './auth/organizations.js';

dotenv.config();

const app = express();
const SECRET_KEY = process.env.SECRET_KEY || 'dev-secret-key';
const ADMIN_DEVICE_ID = process.env.ADMIN_DEVICE_ID;
const activeChallenges = new Map();

// Trust proxy is deliberately a small bounded number here, NOT `true` — express-rate-limit
// hard-rejects (throws on every request) an unbounded "trust the whole chain" setting,
// since that would let a client bypass per-IP rate limiting by prepending fake
// X-Forwarded-For entries. This value only feeds rate-limiting's IP key; see
// getClientIp() below for how the honeypot gets a real client IP for forensic logging.
app.set('trust proxy', 1);

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
// Skipped only when NODE_ENV=test — a single test file exercising a full org (create,
// add several members, claim a device, grant/revoke access, multiple auth flows) easily
// exceeds this within one server instance's lifetime, which has nothing to do with what
// the limit is actually protecting against. NODE_ENV=test is set only by the test
// harness (see test/helpers.js); production and normal dev runs are unaffected.
if (process.env.NODE_ENV !== 'test') {
  app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
}

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'online', timestamp: new Date().toISOString() });
});

// Status
app.get('/status', (req, res) => {
  res.json({
    system: 'PhysicalKey Core',
    status: 'operational',
    components: {
      phoneAuth: 'active',
      deviceAuth: 'active',
      gitServer: 'active',
      honeypot: 'monitoring'
    },
    timestamp: new Date().toISOString()
  });
});

// Auth requirements
app.get('/auth/requirements', (req, res) => {
  res.json({
    requirements: {
      phone: 'Apple App Attest or Google Play Integrity',
      device: 'IoT device with Bluetooth LE + NFC',
      biometric: 'Face ID or Fingerprint'
    },
    status: 'Ready to authenticate'
  });
});

// Phone challenge
app.post('/auth/phone/challenge', honeypotLogger, (req, res) => {
  try {
    const { phoneAttestation } = req.body;
    if (!phoneAttestation) {
      activateHoneypot(getClientIp(req), 'No phone attestation provided');
      return res.status(400).json({ error: 'Phone attestation required' });
    }

    const challenge = crypto.randomBytes(32).toString('base64');
    const challengeId = uuid();

    activeChallenges.set(challengeId, {
      phoneAttestation,
      challenge,
      createdAt: Date.now(),
      expiresAt: Date.now() + 120000
    });

    res.json({ challengeId, challenge, expiresIn: 120 });
  } catch (error) {
    console.error('Phone challenge error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Phone verify
app.post('/auth/phone/verify', honeypotLogger, async (req, res) => {
  try {
    const { challengeId, phoneSignature } = req.body;
    const stored = activeChallenges.get(challengeId);

    if (!stored) {
      activateHoneypot(getClientIp(req), 'Challenge not found');
      return res.status(401).json({ error: 'Challenge expired' });
    }

    if (Date.now() > stored.expiresAt) {
      activeChallenges.delete(challengeId);
      return res.status(401).json({ error: 'Challenge expired' });
    }

    const phoneValid = await validatePhoneAttestation(stored.phoneAttestation, phoneSignature, stored.challenge);
    activeChallenges.delete(challengeId); // one-time use: consume regardless of outcome

    if (!phoneValid) {
      activateHoneypot(getClientIp(req), 'Invalid phone attestation');
      return res.status(401).json({ error: 'Phone verification failed' });
    }

    const deviceChallenge = crypto.randomBytes(32).toString('base64');
    const deviceChallengeId = uuid();

    activeChallenges.set(deviceChallengeId, {
      phoneAttestation: stored.phoneAttestation,
      challenge: deviceChallenge,
      stage: 'device_verification',
      createdAt: Date.now(),
      expiresAt: Date.now() + 120000
    });

    // A lighter session, scoped only to org/team management — deliberately NOT
    // 'full_access' (no git credentials, no device-authorized session). The point is
    // that managing your team (adding a member, revoking someone who left) shouldn't
    // require having your physical key device on hand, since that's a real-world
    // action people need to take from just their phone.
    const phoneSessionToken = jwt.sign({
      phoneDeviceId: stored.phoneAttestation.deviceId,
      scope: 'phone_session',
      issuedAt: Date.now()
    }, SECRET_KEY, { expiresIn: '1h' });

    res.json({ status: 'phone_verified', deviceChallengeId, deviceChallenge, expiresIn: 120, phoneSessionToken });
  } catch (error) {
    console.error('Phone verify error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Device verify
app.post('/auth/device/verify', honeypotLogger, async (req, res) => {
  try {
    const { deviceChallengeId, deviceSignature, deviceId, publicKey } = req.body;
    const stored = activeChallenges.get(deviceChallengeId);

    if (!stored || stored.stage !== 'device_verification') {
      return res.status(401).json({ error: 'Device challenge invalid' });
    }

    if (Date.now() > stored.expiresAt) {
      activeChallenges.delete(deviceChallengeId);
      return res.status(401).json({ error: 'Challenge expired' });
    }

    const deviceValid = await validateDeviceSignature(stored.challenge, deviceSignature, deviceId, publicKey);
    activeChallenges.delete(deviceChallengeId); // one-time use: consume regardless of outcome

    if (!deviceValid) {
      activateHoneypot(getClientIp(req), 'Invalid device signature');
      return res.status(401).json({ error: 'Device verification failed' });
    }

    // Authentication (the signature checks above) proves this phone and this device are
    // each who they claim to be. This is a SEPARATE authorization check: is this
    // specific phone allowed to use this specific device at all? A personal (Solo)
    // device with no org association is unaffected (matches all prior behavior); an
    // org-owned device requires active membership, with owners/admins implicitly
    // authorized for every device in their own org.
    if (!isAuthorizedForDevice(deviceId, stored.phoneAttestation.deviceId)) {
      activateHoneypot(getClientIp(req), 'Phone not authorized for this org device', { deviceId, phoneDeviceId: stored.phoneAttestation.deviceId });
      return res.status(403).json({ error: 'This phone is not authorized to use this device' });
    }

    const sessionToken = jwt.sign({
      deviceId,
      phoneAttestation: stored.phoneAttestation,
      scope: 'full_access',
      issuedAt: Date.now()
    }, SECRET_KEY, { expiresIn: '24h' });

    const gitCredentials = grantGitAccess(deviceId);

    res.json({
      status: 'authenticated',
      sessionToken,
      gitCredentials,
      message: 'Phone + Device verified. Full access granted.'
    });
  } catch (error) {
    console.error('Device verify error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Protected endpoint
const requireAuth = (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    activateHoneypot(getClientIp(req), 'Missing authorization token');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.deviceId = decoded.deviceId;
    next();
  } catch (error) {
    activateHoneypot(getClientIp(req), 'Invalid token');
    res.status(401).json({ error: 'Invalid token' });
  }
};

app.get('/api/profile', requireAuth, (req, res) => {
  res.json({
    deviceId: req.deviceId,
    authenticated: true,
    access: 'full',
    timestamp: new Date().toISOString()
  });
});

// --- Organizations (Team accounts) ---
// Phone-only session (see /auth/phone/verify) — org management doesn't require having
// a physical key device on hand, since revoking a departing team member's access is
// exactly the kind of thing someone needs to do from just their phone.
const requirePhoneSession = (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    activateHoneypot(getClientIp(req), 'Missing authorization token');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    if (decoded.scope !== 'phone_session') {
      return res.status(401).json({ error: 'Invalid session for this operation' });
    }
    req.phoneDeviceId = decoded.phoneDeviceId;
    next();
  } catch (error) {
    activateHoneypot(getClientIp(req), 'Invalid token');
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Any active member (any role) may read org state.
const requireOrgMember = (req, res, next) => {
  const membership = getMembership(req.params.orgId, req.phoneDeviceId);
  if (!membership || membership.status !== 'active') {
    return res.status(403).json({ error: 'Not a member of this org' });
  }
  req.orgMembership = membership;
  next();
};

// Only 'owner'/'admin' may manage membership or device access.
const requireOrgAdmin = (req, res, next) => {
  const membership = getMembership(req.params.orgId, req.phoneDeviceId);
  if (!membership || membership.status !== 'active' || !['owner', 'admin'].includes(membership.role)) {
    activateHoneypot(getClientIp(req), 'Org admin access denied', { orgId: req.params.orgId, phoneDeviceId: req.phoneDeviceId });
    return res.status(403).json({ error: 'Owner or admin role required' });
  }
  req.orgMembership = membership;
  next();
};

app.post('/orgs', requirePhoneSession, (req, res) => {
  const { name } = req.body;
  if (!name || typeof name !== 'string' || !name.trim()) {
    return res.status(400).json({ error: 'Org name is required' });
  }
  const org = createOrganization(name.trim(), req.phoneDeviceId);
  res.status(201).json(org);
});

app.get('/orgs/:orgId', requirePhoneSession, requireOrgMember, (req, res) => {
  const org = getOrganization(req.params.orgId);
  if (!org) return res.status(404).json({ error: 'Org not found' });
  res.json({
    ...org,
    members: listMembers(req.params.orgId),
    devices: listOrgDevices(req.params.orgId)
  });
});

app.post('/orgs/:orgId/members', requirePhoneSession, requireOrgAdmin, (req, res) => {
  const { deviceId, role } = req.body;
  if (!deviceId) return res.status(400).json({ error: 'deviceId is required' });
  if (role && !['admin', 'member'].includes(role)) {
    return res.status(400).json({ error: "role must be 'admin' or 'member'" });
  }
  const member = addMember(req.params.orgId, deviceId, role || 'member');
  res.status(201).json(member);
});

app.delete('/orgs/:orgId/members/:deviceId', requirePhoneSession, requireOrgAdmin, (req, res) => {
  const membership = getMembership(req.params.orgId, req.params.deviceId);
  if (!membership) return res.status(404).json({ error: 'Not a member of this org' });
  if (membership.role === 'owner') {
    return res.status(409).json({ error: 'Cannot remove the org owner — there is no ownership-transfer flow yet' });
  }
  const result = removeMember(req.params.orgId, req.params.deviceId);
  res.json(result);
});

app.post('/orgs/:orgId/devices', requirePhoneSession, requireOrgAdmin, (req, res) => {
  const { deviceId } = req.body;
  if (!deviceId) return res.status(400).json({ error: 'deviceId is required' });
  const identity = getIdentity(deviceId);
  if (!identity || identity.kind !== 'device') {
    return res.status(404).json({ error: 'No registered key device with that deviceId' });
  }
  try {
    const orgDevice = addDeviceToOrg(req.params.orgId, deviceId);
    res.status(201).json(orgDevice);
  } catch (error) {
    res.status(409).json({ error: error.message });
  }
});

app.delete('/orgs/:orgId/devices/:deviceId', requirePhoneSession, requireOrgAdmin, (req, res) => {
  const orgDevice = getDeviceOrg(req.params.deviceId);
  if (!orgDevice || orgDevice.org_id !== req.params.orgId) {
    return res.status(404).json({ error: 'This device does not belong to this org' });
  }
  const result = removeDeviceFromOrg(req.params.deviceId);
  res.json(result);
});

app.get('/orgs/:orgId/devices/:deviceId/access', requirePhoneSession, requireOrgMember, (req, res) => {
  const orgDevice = getDeviceOrg(req.params.deviceId);
  if (!orgDevice || orgDevice.org_id !== req.params.orgId) {
    return res.status(404).json({ error: 'This device does not belong to this org' });
  }
  res.json(listDeviceAccess(req.params.orgId, req.params.deviceId));
});

app.post('/orgs/:orgId/devices/:deviceId/access', requirePhoneSession, requireOrgAdmin, (req, res) => {
  const { memberDeviceId } = req.body;
  if (!memberDeviceId) return res.status(400).json({ error: 'memberDeviceId is required' });
  try {
    grantDeviceAccess(req.params.orgId, req.params.deviceId, memberDeviceId);
    res.status(201).json({ status: 'granted' });
  } catch (error) {
    res.status(409).json({ error: error.message });
  }
});

app.delete('/orgs/:orgId/devices/:deviceId/access/:memberDeviceId', requirePhoneSession, requireOrgAdmin, (req, res) => {
  revokeDeviceAccess(req.params.orgId, req.params.deviceId, req.params.memberDeviceId);
  res.json({ status: 'revoked' });
});

// Git access validation — callback endpoint a git server (e.g. Gitea) hits with the
// client's Basic Auth credentials (the gitCredentials issued by /auth/device/verify)
// to decide whether to allow a clone/push.
app.get('/git/auth', (req, res) => {
  const creds = parseBasicAuth(req);
  if (!creds) {
    activateHoneypot(getClientIp(req), 'Git auth missing credentials');
    res.set('WWW-Authenticate', 'Basic realm="physicalkey-git"');
    return res.status(401).json({ granted: false, error: 'Basic auth credentials required' });
  }

  const result = validateGitCredentials(creds.username, creds.password);
  if (!result.granted) {
    activateHoneypot(getClientIp(req), `Git auth failed: ${result.reason}`, { username: creds.username });
    return res.status(401).json({ granted: false, error: 'Invalid or expired git credentials' });
  }

  res.json({
    granted: true,
    username: result.record.username,
    repositories: result.record.repositories,
    scope: result.record.scope,
    expiresAt: new Date(result.record.expiresAt).toISOString()
  });
});

// Admin-only forensic dashboard
const requireAdmin = (req, res, next) => {
  requireAuth(req, res, () => {
    if (!ADMIN_DEVICE_ID || req.deviceId !== ADMIN_DEVICE_ID) {
      activateHoneypot(getClientIp(req), 'Forensics access denied: non-admin device', { deviceId: req.deviceId });
      return res.status(403).json({ error: 'Forbidden: admin access required' });
    }
    next();
  });
};

app.get('/admin/forensics', requireAdmin, (req, res) => {
  res.json(getForensicsReport());
});

// Inspect one identity's trust-on-first-use registration (phone or device). Read-only —
// safe to call to check current state before deciding whether a reset is actually needed.
app.get('/admin/identities/:deviceId', requireAdmin, (req, res) => {
  const identity = getIdentity(req.params.deviceId);
  if (!identity) {
    return res.status(404).json({ error: 'No identity registered for this deviceId' });
  }
  res.json(identity);
});

// Resets one deviceId's trust-on-first-use registration, so its NEXT auth attempt
// registers fresh with whatever key it currently presents. Needed whenever a deviceId's
// underlying key legitimately changes — a phone's Keychain identity recreated, an ESP32
// board's flash erased and its Ed25519 identity regenerated — since trust-on-first-use
// otherwise locks that deviceId out permanently with no self-service recovery. This is a
// deliberate, narrowly-scoped exception to that lock, not a bypass of it: it still
// requires knowing the exact deviceId and full admin auth, and the NEXT registration is
// itself still subject to trust-on-first-use (whoever registers next owns it).
app.delete('/admin/identities/:deviceId', requireAdmin, (req, res) => {
  const removed = resetIdentity(req.params.deviceId);
  if (!removed) {
    return res.status(404).json({ error: 'No identity registered for this deviceId' });
  }
  console.log(`⚠ Admin reset identity: ${req.params.deviceId} (was kind=${removed.kind}, registered_at=${removed.registered_at})`);
  res.json({ status: 'reset', deviceId: req.params.deviceId, previousKind: removed.kind });
});

// Honeypot decoy endpoint
app.get('/api/honeypot/fake-database', (req, res) => {
  const entry = activateHoneypot(getClientIp(req), 'Honeypot endpoint accessed', {
    path: req.path,
    userAgent: req.get('user-agent')
  });

  res.json({
    _decoy: true,
    loggedEventId: entry?.id,
    users: [
      { id: 1, email: 'admin@physicalkey.demo', apiKey: 'fake-key-do-not-use-aaaa1111' },
      { id: 2, email: 'support@physicalkey.demo', apiKey: 'fake-key-do-not-use-bbbb2222' }
    ]
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 PhysicalKey Server running on http://localhost:${PORT}`);
  console.log(`📱 Authentication: POST http://localhost:${PORT}/auth/phone/challenge`);
  console.log(`🔒 Health: http://localhost:${PORT}/health`);
  console.log(`🎯 Status: http://localhost:${PORT}/status\n`);
});
