import crypto from 'crypto';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { v4 as uuid } from 'uuid';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { validatePhoneAttestation } from './auth/phone-auth.js';
import { validateDeviceSignature, registerDevice } from './auth/device-auth.js';
import { grantGitAccess, parseBasicAuth, validateGitCredentials, revokeGitAccess } from './git/git-credentials.js';
import { honeypotLogger, activateHoneypot, getForensicsReport, getClientIp } from './honeypot/logger.js';
import { getIdentity, listIdentities, resetIdentity, revokeSessionsIssuedBefore, isSessionRevoked } from './auth/identity-admin.js';
import { logAdminAction, getAdminActionLog, getOrgActionLog } from './audit/log.js';
import { isValidRatchetStatus, recordRatchetStatus, getRatchetState, clearRatchetState, verifyAndRecordRatchetAttestation } from './auth/ratchet.js';
import {
  createOrganization, getOrganization, getMembership, listMembers, addMember, removeMember,
  getDeviceOrg, listOrgDevices, addDeviceToOrg, removeDeviceFromOrg,
  listDeviceAccess, grantDeviceAccess, revokeDeviceAccess, isAuthorizedForDevice
} from './auth/organizations.js';
import { isEnforced as isAllowlistEnforced, addToAllowlist, removeFromAllowlist, listAllowlist } from './auth/device-allowlist.js';

dotenv.config();

const app = express();

// If SECRET_KEY is ever unset in production (a botched deploy, a cleared env var), the
// old behavior silently fell back to a hardcoded placeholder string — every session
// token in the system would become forgeable by anyone who's ever read this file.
// Refusing to start is the correct failure mode: a loud, immediate crash beats a silent
// security downgrade. The fallback is kept for local dev/test convenience, where
// NODE_ENV is never 'production' (unset for `npm start`, 'test' for the test suite —
// see test/helpers.js; only the Dockerfile sets NODE_ENV=production).
if (!process.env.SECRET_KEY && process.env.NODE_ENV === 'production') {
  console.error('FATAL: SECRET_KEY environment variable must be set in production.');
  process.exit(1);
}
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
// No CORS middleware: every real client here is a native iOS app or ESP32 firmware,
// neither of which is subject to (or benefits from) CORS — it's a browser-only
// enforcement mechanism. `cors()` previously reflected every origin by default, which
// was pure unnecessary exposure with no actual client that needed it. If a browser-based
// admin panel or web client is ever added, reintroduce it scoped to that origin
// specifically, not wide open.
app.use(express.json({ limit: '10mb' }));
// Skipped only when NODE_ENV=test — a single test file exercising a full org (create,
// add several members, claim a device, grant/revoke access, multiple auth flows) easily
// exceeds this within one server instance's lifetime, which has nothing to do with what
// the limit is actually protecting against. NODE_ENV=test is set only by the test
// harness (see test/helpers.js); production and normal dev runs are unaffected.
if (process.env.NODE_ENV !== 'test') {
  app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
}

// A tighter limit specifically on the auth handshake endpoints, on top of the general
// one above. Trust-on-first-use means whoever registers a deviceId first (with a valid
// signature over the challenge) owns it permanently — there's no separate secret gating
// that first registration beyond knowing the deviceId string itself. A legitimate client
// calls these a handful of times per session; this doesn't touch that, but it meaningfully
// raises the cost of automated guessing/racing against not-yet-registered deviceIds from
// a single source. Doesn't eliminate the risk (a patient, distributed attacker isn't
// slowed by a per-IP limit) — a full fix would need a different bootstrapping mechanism
// for first registration, which is a bigger architectural change than this pass covers.
const authRateLimit = process.env.NODE_ENV === 'test'
  ? (req, res, next) => next()
  : rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });

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
app.post('/auth/phone/challenge', authRateLimit, honeypotLogger, (req, res) => {
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
app.post('/auth/phone/verify', authRateLimit, honeypotLogger, async (req, res) => {
  try {
    const { challengeId, phoneSignature, livenessResult } = req.body;
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

    // Liveness result (see the security-layers plan) — proves a real physical phone with
    // working speaker/mic/haptics executed this session live, not an automated client
    // replaying an extracted key. Memoryless (nothing persisted; each auth attempt is judged
    // on its own), phone-reported only (no App Attest yet — same honest limitation as the
    // session ratchet), and warn-not-block: a failed check is logged, never rejected, since
    // it can fail legitimately (loud room, phone in a case) with no bearing on whether the
    // underlying Ed25519 signature — the actual authentication — is valid.
    if (livenessResult && typeof livenessResult === 'object') {
      const audioFailed = livenessResult.audioDetected === false;
      const hapticFailed = typeof livenessResult.hapticMatched === 'number' &&
        typeof livenessResult.hapticTotal === 'number' &&
        livenessResult.hapticMatched < livenessResult.hapticTotal;
      if (audioFailed || hapticFailed) {
        activateHoneypot(getClientIp(req), 'Liveness check failed', {
          deviceId: stored.phoneAttestation.deviceId,
          livenessResult
        });
      }
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
    }, SECRET_KEY, { algorithm: 'HS256', expiresIn: '1h' });

    res.json({ status: 'phone_verified', deviceChallengeId, deviceChallenge, expiresIn: 120, phoneSessionToken });
  } catch (error) {
    console.error('Phone verify error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Device verify
app.post('/auth/device/verify', authRateLimit, honeypotLogger, async (req, res) => {
  try {
    const { deviceChallengeId, deviceSignature, deviceId, publicKey, ratchetStatus, ratchetAttestation } = req.body;
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

    // Session-ratchet continuity result (see the security-layers plan). The device signs
    // the exchange output with its existing Ed25519 identity key, bound to this session's
    // challenge — the backend verifies that signature and computes the verdict itself
    // (verifyAndRecordRatchetAttestation), rather than trusting a client-reported string.
    // Still deliberately warn-not-block: a mismatch is logged, not rejected, given how
    // costly false lockouts from state desync have already been this project (identity
    // TOFU, BLE bonds) — that policy is unchanged, only the trustworthiness of the signal
    // driving it.
    if (ratchetAttestation && typeof ratchetAttestation === 'object') {
      const result = verifyAndRecordRatchetAttestation(deviceId, stored.challenge, ratchetAttestation);
      if (!result.ok) {
        activateHoneypot(getClientIp(req), `Ratchet attestation invalid: ${result.reason}`, { deviceId });
      } else if (result.verdict === 'mismatch') {
        activateHoneypot(getClientIp(req), 'Ratchet continuity mismatch — possible cloned device identity', { deviceId });
      }
    } else if (ratchetStatus !== undefined) {
      // Legacy path: a bare, unsigned status string with no cryptographic verification —
      // kept only for the transition window while firmware/app on some boards may not be
      // upgraded yet. Never drives the honeypot and is never treated as a verified claim;
      // see recordRatchetStatus's own doc comment.
      if (isValidRatchetStatus(ratchetStatus)) {
        recordRatchetStatus(deviceId, ratchetStatus);
      } else {
        activateHoneypot(getClientIp(req), 'Malformed ratchetStatus value', { deviceId, ratchetStatus });
      }
    }

    // Short-lived deliberately: this token isn't persisted client-side (AuthViewModel
    // keeps it only in memory, lost on app restart), and it's what gates the admin
    // endpoints (/admin/forensics, /admin/identities) for the admin device — so there's
    // no UX cost to a tight expiry, only a smaller replay window if it's ever exfiltrated.
    // Git access has its own independent 24h expiry (git/git-credentials.js) unaffected
    // by this.
    const sessionToken = jwt.sign({
      deviceId,
      phoneAttestation: stored.phoneAttestation,
      scope: 'full_access',
      issuedAt: Date.now()
    }, SECRET_KEY, { algorithm: 'HS256', expiresIn: '1h' });

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
    const decoded = jwt.verify(token, SECRET_KEY, { algorithms: ['HS256'] });
    // A full_access token embeds both the key device's identity and the phone's — an admin
    // reset of EITHER one (e.g. a stolen phone, or a device whose key was cloned) must kill
    // any session already minted with it, not just block future re-registration.
    if (isSessionRevoked(decoded.deviceId, decoded.issuedAt) || isSessionRevoked(decoded.phoneAttestation?.deviceId, decoded.issuedAt)) {
      activateHoneypot(getClientIp(req), 'Revoked session token used', { deviceId: decoded.deviceId });
      return res.status(401).json({ error: 'Session revoked' });
    }
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
    const decoded = jwt.verify(token, SECRET_KEY, { algorithms: ['HS256'] });
    if (decoded.scope !== 'phone_session') {
      return res.status(401).json({ error: 'Invalid session for this operation' });
    }
    if (isSessionRevoked(decoded.phoneDeviceId, decoded.issuedAt)) {
      activateHoneypot(getClientIp(req), 'Revoked session token used', { phoneDeviceId: decoded.phoneDeviceId });
      return res.status(401).json({ error: 'Session revoked' });
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
  logAdminAction(req.phoneDeviceId, 'member_added', deviceId, { role: role || 'member' }, req.params.orgId);
  res.status(201).json(member);
});

app.delete('/orgs/:orgId/members/:deviceId', requirePhoneSession, requireOrgAdmin, (req, res) => {
  const membership = getMembership(req.params.orgId, req.params.deviceId);
  if (!membership) return res.status(404).json({ error: 'Not a member of this org' });
  if (membership.role === 'owner') {
    return res.status(409).json({ error: 'Cannot remove the org owner — there is no ownership-transfer flow yet' });
  }
  const result = removeMember(req.params.orgId, req.params.deviceId);
  logAdminAction(req.phoneDeviceId, 'member_removed', req.params.deviceId, { previousRole: membership.role }, req.params.orgId);
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
    logAdminAction(req.phoneDeviceId, 'device_added_to_org', deviceId, {}, req.params.orgId);
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
  logAdminAction(req.phoneDeviceId, 'device_removed_from_org', req.params.deviceId, {}, req.params.orgId);
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
    logAdminAction(req.phoneDeviceId, 'device_access_granted', req.params.deviceId, { memberDeviceId }, req.params.orgId);
    res.status(201).json({ status: 'granted' });
  } catch (error) {
    res.status(409).json({ error: error.message });
  }
});

app.delete('/orgs/:orgId/devices/:deviceId/access/:memberDeviceId', requirePhoneSession, requireOrgAdmin, (req, res) => {
  revokeDeviceAccess(req.params.orgId, req.params.deviceId, req.params.memberDeviceId);
  logAdminAction(req.phoneDeviceId, 'device_access_revoked', req.params.deviceId, { memberDeviceId: req.params.memberDeviceId }, req.params.orgId);
  res.json({ status: 'revoked' });
});

// Org-scoped view of the same admin_actions log /admin/audit-log exposes globally — lets
// an org's own owner/admin see their org's membership/device-access history without
// needing the single global admin device's credentials, which is otherwise the only thing
// that can see any of this today.
app.get('/orgs/:orgId/audit-log', requirePhoneSession, requireOrgAdmin, (req, res) => {
  res.json({ entries: getOrgActionLog(req.params.orgId) });
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

// List every currently-registered identity (phone or device), lightest shape (no public
// key). Read-only, admin-gated. Previously the only way to check what's registered was a
// single-deviceId lookup — no way to audit the full set without already knowing every
// deviceId to ask about. Needed to safely populate the device allow-list without guessing.
app.get('/admin/identities', requireAdmin, (req, res) => {
  res.json({ identities: listIdentities() });
});

// Diagnose a device's org claim and access grants without needing to already be a member
// of whatever org claimed it — every /orgs/:orgId/* route requires org membership, which
// is a real chicken-and-egg problem for an admin trying to figure out why a specific real
// phone got "not authorized to use this device" and there's no other way to find out which
// org is even responsible. Read-only.
app.get('/admin/device-org/:deviceId', requireAdmin, (req, res) => {
  const org = getDeviceOrg(req.params.deviceId);
  if (!org) {
    return res.json({ deviceId: req.params.deviceId, org: null });
  }
  res.json({
    deviceId: req.params.deviceId,
    org: getOrganization(org.org_id),
    claimedAt: org.added_at,
    members: listMembers(org.org_id),
    deviceAccess: listDeviceAccess(org.org_id, req.params.deviceId)
  });
});

// Inspect one identity's trust-on-first-use registration (phone or device). Read-only —
// safe to call to check current state before deciding whether a reset is actually needed.
app.get('/admin/identities/:deviceId', requireAdmin, (req, res) => {
  const identity = getIdentity(req.params.deviceId);
  if (!identity) {
    return res.status(404).json({ error: 'No identity registered for this deviceId' });
  }
  res.json({ ...identity, ratchet: getRatchetState(req.params.deviceId) });
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
  // Also clears session-ratchet continuity state, if any — the escape hatch called for in
  // the security-layers plan. A ratchet mismatch that turns out to be a false positive (or a
  // deliberate re-pair) shouldn't need a second, different admin operation to clear; it's
  // the same "this deviceId starts fresh" action as an identity reset already is.
  const clearedRatchet = clearRatchetState(req.params.deviceId);
  // And revokes any git credentials already issued for this deviceId — otherwise a stolen
  // device+phone pair keeps working git access for up to 24h after the identity that
  // authorized it has been reset, which defeats the point of an incident-response action.
  const revokedGitAccess = revokeGitAccess(req.params.deviceId);
  // And kills any session token already minted for this deviceId, not just future
  // re-registration — a JWT that hasn't naturally expired yet would otherwise keep working
  // for up to its full 1h lifetime after the identity backing it was just reset.
  const revokedSessionsAt = revokeSessionsIssuedBefore(req.params.deviceId);
  console.log(`⚠ Admin reset identity: ${req.params.deviceId} (was kind=${removed.kind}, registered_at=${removed.registered_at})`);
  logAdminAction(req.deviceId, 'identity_reset', req.params.deviceId, {
    kind: removed.kind,
    registeredAt: removed.registered_at,
    clearedRatchetStatus: clearedRatchet?.status ?? null,
    revokedGitAccess,
    revokedSessionsAt
  });
  res.json({ status: 'reset', deviceId: req.params.deviceId, previousKind: removed.kind, clearedRatchetStatus: clearedRatchet?.status ?? null, revokedGitAccess, revokedSessionsAt });
});

// Durable log of admin actions (currently: identity resets) — who did what, to which
// deviceId, and when. Read-only; entries are written by the actions themselves.
app.get('/admin/audit-log', requireAdmin, (req, res) => {
  res.json({ entries: getAdminActionLog() });
});

// Interim device-provenance allow-list (see auth/device-allowlist.js). Enforcement itself
// is controlled by the ENFORCE_DEVICE_ALLOWLIST env var, checked in device-auth.js — these
// endpoints just manage the list, and work the same whether or not enforcement is on, so
// the list can be populated ahead of flipping enforcement on.
app.get('/admin/device-allowlist', requireAdmin, (req, res) => {
  res.json({ enforced: isAllowlistEnforced(), entries: listAllowlist() });
});

app.post('/admin/device-allowlist', requireAdmin, (req, res) => {
  const { deviceId, note } = req.body;
  if (!deviceId || typeof deviceId !== 'string') {
    return res.status(400).json({ error: 'deviceId is required' });
  }
  const entry = addToAllowlist(deviceId, note ?? null);
  logAdminAction(req.deviceId, 'device_allowlist_added', deviceId, { note: note ?? null });
  res.status(201).json(entry);
});

app.delete('/admin/device-allowlist/:deviceId', requireAdmin, (req, res) => {
  const removed = removeFromAllowlist(req.params.deviceId);
  if (!removed) {
    return res.status(404).json({ error: 'deviceId is not on the allow-list' });
  }
  logAdminAction(req.deviceId, 'device_allowlist_removed', req.params.deviceId, {});
  res.json({ status: 'removed', deviceId: req.params.deviceId });
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
