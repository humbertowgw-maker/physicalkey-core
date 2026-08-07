import crypto from 'crypto';
import path from 'path';
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
import { getIdentity, listIdentities, resetIdentity, setRecoveryPolicy, RecoveryPolicyLockedError, revokeSessionsIssuedBefore, isSessionRevoked } from './auth/identity-admin.js';
import { logAdminAction, getAdminActionLog, getOrgActionLog } from './audit/log.js';
import { isValidRatchetStatus, recordRatchetStatus, getRatchetState, clearRatchetState, verifyAndRecordRatchetAttestation } from './auth/ratchet.js';
import {
  createOrganization, getOrganization, getMembership, listMembers, addMember, removeMember,
  getDeviceOrg, listOrgDevices, addDeviceToOrg, removeDeviceFromOrg,
  listDeviceAccess, grantDeviceAccess, revokeDeviceAccess, isAuthorizedForDevice
} from './auth/organizations.js';
import { isEnforced as isAllowlistEnforced, addToAllowlist, removeFromAllowlist, listAllowlist } from './auth/device-allowlist.js';
import { recordPairing, hasEverPaired, createRepairChallenge, consumeRepairChallenge, verifyBoardSignature } from './auth/repair.js';
import db from './lib/db.js';
import { dataDir } from './lib/data-dir.js';
import { runBackup, pruneBackups, listBackups, backupsDir } from './lib/backup.js';
import { isConfigured as isBillingConfigured, createCheckoutSession, handleWebhookEvent } from './payments/stripe.js';
import { listAllSubscriptions } from './payments/subscriptions.js';

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
// No general CORS middleware: every OTHER real client here is a native iOS app or ESP32
// firmware, neither of which is subject to (or benefits from) CORS. /billing/checkout is
// the one deliberate exception — see the scoped Access-Control-Allow-Origin set directly
// on that route below, limited to the landing page's own origin, not wide open.
app.use(express.json({
  limit: '10mb',
  // Stripe webhook signature verification needs the exact raw bytes Stripe signed —
  // parsing and re-serializing (what express.json() does to req.body) would produce
  // different bytes and always fail verification. Stashing the raw buffer here, only for
  // that one route, avoids reordering this middleware relative to everything else that
  // already depends on req.body being parsed JSON.
  verify: (req, res, buf) => {
    if (req.originalUrl === '/billing/webhook') req.rawBody = buf;
  }
}));
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

// Health check — actually touches the database rather than just confirming the process
// is alive. A process that's up but whose SQLite file has gone missing, corrupted, or
// unwritable (a bad volume mount, a full disk) previously reported "online" and kept
// getting traffic; Railway (or any platform watching this endpoint) can now restart it
// instead of silently serving errors.
app.get('/health', (req, res) => {
  try {
    db.prepare('SELECT 1').get();
    res.json({ status: 'online', database: 'ok', timestamp: new Date().toISOString() });
  } catch (error) {
    console.error('Health check: database unreachable:', error.message);
    res.status(503).json({ status: 'degraded', database: 'error', timestamp: new Date().toISOString() });
  }
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

// Billing — the only routes in this file a browser calls directly (from the landing
// page), rather than the iOS app or firmware. Scoped CORS, not the blanket kind.
const LANDING_ORIGIN = process.env.LANDING_ORIGIN || 'https://physicalkey.whitegwireless.com';

app.options('/billing/checkout', (req, res) => {
  res.set('Access-Control-Allow-Origin', LANDING_ORIGIN);
  res.set('Access-Control-Allow-Methods', 'POST');
  res.set('Access-Control-Allow-Headers', 'Content-Type');
  res.status(204).end();
});

app.post('/billing/checkout', async (req, res) => {
  res.set('Access-Control-Allow-Origin', LANDING_ORIGIN);

  if (!isBillingConfigured()) {
    return res.status(503).json({ error: 'Billing is not configured yet' });
  }

  const email = typeof req.body?.email === 'string' ? req.body.email.trim() : '';
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'A valid email is required' });
  }

  try {
    const origin = req.get('origin') || LANDING_ORIGIN;
    const session = await createCheckoutSession(email, {
      successUrl: `${origin}/?checkout=success`,
      cancelUrl: `${origin}/?checkout=cancelled`
    });
    res.json({ url: session.url });
  } catch (error) {
    console.error('Checkout session creation failed:', error.message);
    res.status(500).json({ error: 'Could not start checkout' });
  }
});

// Called by Stripe's servers directly, never a browser — no CORS needed. Relies on
// req.rawBody, stashed by express.json()'s verify hook above specifically for this route,
// since signature verification needs the exact bytes Stripe signed.
app.post('/billing/webhook', (req, res) => {
  if (!isBillingConfigured()) return res.status(503).end();

  try {
    handleWebhookEvent(req.rawBody, req.get('stripe-signature'));
    res.status(200).json({ received: true });
  } catch (error) {
    console.error('Webhook verification failed:', error.message);
    res.status(400).json({ error: 'Invalid signature' });
  }
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

    // Real pairing history, for self-service repair (auth/repair.js) to check before
    // letting a board vouch for resetting a phone's identity — without this, any
    // registered board could free up any phone identity, not just one it's actually
    // been used with.
    recordPairing(deviceId, stored.phoneAttestation.deviceId);

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

// Self-service identity repair (see auth/repair.js): step 1 of 2. Requests a
// domain-separated challenge for the phone to relay to the board over BLE — written to
// the board's existing Challenge characteristic (the same one every normal login already
// uses), signed with its Ed25519 identity key, read back from Signature. No new firmware
// needed. Public — proof of physical possession of a board with real pairing history to
// this exact phone identity IS the authorization, same trust model as the admin escape
// hatch just without needing an admin.
app.post('/auth/repair/challenge', authRateLimit, honeypotLogger, (req, res) => {
  const { boardDeviceId, targetPhoneDeviceId } = req.body;
  if (!boardDeviceId || !targetPhoneDeviceId) {
    return res.status(400).json({ error: 'boardDeviceId and targetPhoneDeviceId are required' });
  }

  const board = getIdentity(boardDeviceId);
  if (!board || board.kind !== 'device' || board.status !== 'active') {
    activateHoneypot(getClientIp(req), 'Repair challenge requested for an unknown/invalid board', { boardDeviceId });
    return res.status(404).json({ error: 'Unknown board' });
  }

  const target = getIdentity(targetPhoneDeviceId);
  if (!target || target.kind !== 'phone') {
    return res.status(404).json({ error: 'No phone identity registered for this deviceId' });
  }
  if (target.recovery_policy === 'permanent') {
    return res.status(403).json({ error: `${targetPhoneDeviceId} has recovery_policy='permanent' — this identity cannot be repaired, self-service or otherwise` });
  }

  if (!hasEverPaired(boardDeviceId, targetPhoneDeviceId)) {
    activateHoneypot(getClientIp(req), 'Repair challenge requested for a board with no real pairing history to this phone identity', { boardDeviceId, targetPhoneDeviceId });
    return res.status(403).json({ error: 'This board has no recorded pairing history with this phone identity' });
  }

  const { challengeId, challenge } = createRepairChallenge(boardDeviceId, targetPhoneDeviceId);
  res.json({ challengeId, challenge, expiresIn: 120 });
});

// Self-service identity repair, step 2 of 2. Verifies the board's signature over the
// exact challenge issued above, then — if valid — resets the target phone identity via
// the same resetIdentity() the admin escape hatch uses, with the same side effects
// (clears ratchet state, revokes git access, revokes any live session). The phone then
// just goes through the completely ordinary /auth/phone + /auth/device flow next; nothing
// about registering the new key is special-cased here.
app.post('/auth/repair/verify', authRateLimit, honeypotLogger, (req, res) => {
  const { challengeId, boardSignature } = req.body;
  const stored = consumeRepairChallenge(challengeId);
  if (!stored) {
    return res.status(401).json({ error: 'Repair challenge expired or not found' });
  }

  const board = getIdentity(stored.boardDeviceId);
  if (!board) {
    return res.status(404).json({ error: 'Board no longer registered' });
  }

  if (!boardSignature || !verifyBoardSignature(stored.challenge, boardSignature, board.public_key)) {
    activateHoneypot(getClientIp(req), 'Repair authorization signature invalid — possible forged board proof', {
      boardDeviceId: stored.boardDeviceId,
      targetPhoneDeviceId: stored.targetPhoneDeviceId
    });
    return res.status(401).json({ error: 'Invalid board signature' });
  }

  let removed;
  try {
    removed = resetIdentity(stored.targetPhoneDeviceId);
  } catch (err) {
    if (err instanceof RecoveryPolicyLockedError) {
      return res.status(403).json({ error: err.message });
    }
    throw err;
  }
  if (!removed) {
    return res.status(404).json({ error: 'No identity registered for this deviceId' });
  }

  const clearedRatchet = clearRatchetState(stored.targetPhoneDeviceId);
  const revokedGitAccess = revokeGitAccess(stored.targetPhoneDeviceId);
  const revokedSessionsAt = revokeSessionsIssuedBefore(stored.targetPhoneDeviceId);
  console.log(`⚠ Self-service repair: ${stored.targetPhoneDeviceId} reset via board ${stored.boardDeviceId}`);
  logAdminAction(stored.boardDeviceId, 'self_service_repair', stored.targetPhoneDeviceId, {
    authorizedByBoard: stored.boardDeviceId,
    clearedRatchetStatus: clearedRatchet?.status ?? null,
    revokedGitAccess,
    revokedSessionsAt
  });

  res.json({
    status: 'reset',
    deviceId: stored.targetPhoneDeviceId,
    authorizedByBoard: stored.boardDeviceId,
    clearedRatchetStatus: clearedRatchet?.status ?? null,
    revokedGitAccess,
    revokedSessionsAt
  });
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

// Resilience: the database lives on a single Railway volume with no replica, so these
// exist to make disaster recovery actually possible — list what's on disk, and let an
// admin pull the latest snapshot off the box periodically (e.g. into their own storage)
// rather than the only copy being wherever Railway's volume happens to be.
app.get('/admin/subscriptions', requireAdmin, (req, res) => {
  res.json({ subscriptions: listAllSubscriptions() });
});

app.get('/admin/backups', requireAdmin, (req, res) => {
  res.json({ backups: listBackups(dataDir) });
});

// Lets an admin force a snapshot right now (e.g. immediately before a risky manual
// change), independent of the scheduled interval.
app.post('/admin/backups', requireAdmin, (req, res) => {
  try {
    const dest = runBackup(db, dataDir);
    logAdminAction(req.deviceId, 'backup_triggered', null, { path: dest });
    res.status(201).json({ backup: path.basename(dest) });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/admin/backups/latest', requireAdmin, (req, res) => {
  const files = listBackups(dataDir);
  if (!files.length) return res.status(404).json({ error: 'No backups yet' });
  res.download(path.join(backupsDir(dataDir), files[files.length - 1]));
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

// Admin escape hatch: release a device from its org without needing to authenticate as
// that org's own owner/admin — same shape as the identity-reset and allow-list admin
// overrides elsewhere in this file. Needed for exactly the case that motivated the GET
// above: a device got claimed by an org (deliberately, during real feature testing) and
// the claim was never released, silently blocking the device's actual intended owner.
// Does NOT bypass org isolation for normal use — a regular member/owner still can't do
// this for an org they don't belong to; this is the same narrowly-scoped, fully-audited
// admin-only exception the rest of this file already uses for "the lock is correct in
// general, but a specific case needs a deliberate, logged override."
app.delete('/admin/device-org/:deviceId', requireAdmin, (req, res) => {
  const removed = removeDeviceFromOrg(req.params.deviceId);
  if (!removed) {
    return res.status(404).json({ error: 'This device is not currently claimed by any org' });
  }
  logAdminAction(req.deviceId, 'admin_device_org_released', req.params.deviceId, { previousOrgId: removed.org_id });
  res.json({ status: 'released', deviceId: req.params.deviceId, previousOrgId: removed.org_id });
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

// Sets an identity's recovery_policy. 'self-service' (the default for everything today)
// means the admin reset above works as it always has. 'permanent' means the opposite: this
// identity becomes genuinely unresettable by this codebase, not just discouraged — the
// literal code-level backing for a "cannot be recovered, not even by us" product claim.
// This is a ONE-WAY setting: setRecoveryPolicy refuses any change once an identity is
// already 'permanent', including setting it to 'permanent' again — otherwise "permanent"
// would just mean "permanent until someone flips the flag back first," which defeats the
// entire point. There is deliberately no undo endpoint and no admin override for that.
app.post('/admin/identities/:deviceId/recovery-policy', requireAdmin, (req, res) => {
  const { recoveryPolicy } = req.body;
  if (recoveryPolicy !== 'permanent' && recoveryPolicy !== 'self-service') {
    return res.status(400).json({ error: "recoveryPolicy must be 'permanent' or 'self-service'" });
  }
  let updated;
  try {
    updated = setRecoveryPolicy(req.params.deviceId, recoveryPolicy);
  } catch (err) {
    if (err instanceof RecoveryPolicyLockedError) {
      return res.status(403).json({ error: err.message });
    }
    throw err;
  }
  if (!updated) {
    return res.status(404).json({ error: 'No identity registered for this deviceId' });
  }
  logAdminAction(req.deviceId, 'recovery_policy_set', req.params.deviceId, { recoveryPolicy });
  res.json(updated);
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
  let removed;
  try {
    removed = resetIdentity(req.params.deviceId);
  } catch (err) {
    if (err instanceof RecoveryPolicyLockedError) {
      return res.status(403).json({ error: err.message });
    }
    throw err;
  }
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

// In-process scheduled backups: VACUUM INTO a timestamped snapshot on an interval, then
// prune old ones. This is the pragmatic half of closing the single-point-of-failure gap —
// it doesn't add a second instance or a replica, but it means a corrupted or accidentally
// truncated database file isn't a total-loss event, and /admin/backups/latest gives a way
// to pull a copy off the box without shell access. Disabled during tests: the test suite
// spawns many short-lived server processes and doesn't need backup files accumulating in
// each throwaway data dir.
const BACKUP_INTERVAL_MS = Number(process.env.PK_BACKUP_INTERVAL_MS || 6 * 60 * 60 * 1000);
const BACKUP_RETAIN = Number(process.env.PK_BACKUP_RETAIN || 14);
let backupTimer = null;
if (process.env.NODE_ENV !== 'test') {
  const scheduledBackup = () => {
    try {
      const dest = runBackup(db, dataDir);
      const pruned = pruneBackups(dataDir, BACKUP_RETAIN);
      console.log(`✓ Scheduled backup written: ${dest}${pruned.length ? ` (pruned ${pruned.length} old)` : ''}`);
    } catch (error) {
      // A failed backup should never take the server down — log loudly and try again
      // next interval rather than crashing a healthy server over a backup hiccup.
      console.error('✗ Scheduled backup failed:', error.message);
    }
  };
  backupTimer = setInterval(scheduledBackup, BACKUP_INTERVAL_MS);
  backupTimer.unref();
  scheduledBackup();
}

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 PhysicalKey Server running on http://localhost:${PORT}`);
  console.log(`📱 Authentication: POST http://localhost:${PORT}/auth/phone/challenge`);
  console.log(`🔒 Health: http://localhost:${PORT}/health`);
  console.log(`🎯 Status: http://localhost:${PORT}/status\n`);
});
