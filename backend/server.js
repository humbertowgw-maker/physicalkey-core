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
import { honeypotLogger, activateHoneypot, getForensicsReport } from './honeypot/logger.js';

dotenv.config();

const app = express();
const SECRET_KEY = process.env.SECRET_KEY || 'dev-secret-key';
const ADMIN_DEVICE_ID = process.env.ADMIN_DEVICE_ID;
const activeChallenges = new Map();

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

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
      activateHoneypot(req.ip, 'No phone attestation provided');
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
      activateHoneypot(req.ip, 'Challenge not found');
      return res.status(401).json({ error: 'Challenge expired' });
    }

    if (Date.now() > stored.expiresAt) {
      activeChallenges.delete(challengeId);
      return res.status(401).json({ error: 'Challenge expired' });
    }

    const phoneValid = await validatePhoneAttestation(stored.phoneAttestation, phoneSignature, stored.challenge);
    activeChallenges.delete(challengeId); // one-time use: consume regardless of outcome

    if (!phoneValid) {
      activateHoneypot(req.ip, 'Invalid phone attestation');
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

    res.json({ status: 'phone_verified', deviceChallengeId, deviceChallenge, expiresIn: 120 });
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
      activateHoneypot(req.ip, 'Invalid device signature');
      return res.status(401).json({ error: 'Device verification failed' });
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
    activateHoneypot(req.ip, 'Missing authorization token');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.deviceId = decoded.deviceId;
    next();
  } catch (error) {
    activateHoneypot(req.ip, 'Invalid token');
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

// Git access validation — callback endpoint a git server (e.g. Gitea) hits with the
// client's Basic Auth credentials (the gitCredentials issued by /auth/device/verify)
// to decide whether to allow a clone/push.
app.get('/git/auth', (req, res) => {
  const creds = parseBasicAuth(req);
  if (!creds) {
    activateHoneypot(req.ip, 'Git auth missing credentials');
    res.set('WWW-Authenticate', 'Basic realm="physicalkey-git"');
    return res.status(401).json({ granted: false, error: 'Basic auth credentials required' });
  }

  const result = validateGitCredentials(creds.username, creds.password);
  if (!result.granted) {
    activateHoneypot(req.ip, `Git auth failed: ${result.reason}`, { username: creds.username });
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
      activateHoneypot(req.ip, 'Forensics access denied: non-admin device', { deviceId: req.deviceId });
      return res.status(403).json({ error: 'Forbidden: admin access required' });
    }
    next();
  });
};

app.get('/admin/forensics', requireAdmin, (req, res) => {
  res.json(getForensicsReport());
});

// Honeypot decoy endpoint
app.get('/api/honeypot/fake-database', (req, res) => {
  const entry = activateHoneypot(req.ip, 'Honeypot endpoint accessed', {
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
