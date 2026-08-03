import crypto from 'crypto';
import db from '../lib/db.js';

const insertStmt = db.prepare('INSERT INTO honeypot_events (id, ip, reason, details, level, timestamp) VALUES (?, ?, ?, ?, ?, ?)');
const recentStmt = db.prepare('SELECT * FROM honeypot_events ORDER BY rowid DESC LIMIT ?');
const summaryStmt = db.prepare('SELECT COUNT(*) as totalAttempts, COUNT(DISTINCT ip) as uniqueIPs FROM honeypot_events');
const attackersStmt = db.prepare(`
  SELECT ip, MIN(timestamp) as firstSeen, MAX(timestamp) as lastSeen, COUNT(*) as totalAttempts
  FROM honeypot_events GROUP BY ip
`);
const techniquesForIpStmt = db.prepare('SELECT DISTINCT reason FROM honeypot_events WHERE ip = ?');

function suspicionLevelFor(attemptCount) {
  if (attemptCount >= 7) return 'high';
  if (attemptCount >= 3) return 'medium';
  return 'low';
}

// Best-effort real client IP for forensic logging, independent of Express's trust-proxy
// hop counting (which is deliberately kept small/bounded for rate-limiting safety — see
// server.js). The leftmost X-Forwarded-For entry is the original client regardless of how
// many internal hops a platform's routing adds after it. This is only used for readability
// in the honeypot log, not for any access-control decision.
export function getClientIp(req) {
  const forwardedFor = req.headers['x-forwarded-for'];
  if (forwardedFor) return forwardedFor.split(',')[0].trim();
  return req.ip;
}

export function activateHoneypot(ip, reason, details = {}) {
  try {
    const entry = {
      id: crypto.randomUUID(),
      ip,
      reason,
      details,
      timestamp: new Date().toISOString(),
      level: 'warning'
    };

    insertStmt.run(entry.id, entry.ip, entry.reason, JSON.stringify(entry.details), entry.level, entry.timestamp);
    console.log(`🎭 HONEYPOT ACTIVATED: ${reason} from IP: ${ip}`);

    return entry;
  } catch (error) {
    console.error('Honeypot activation error:', error);
  }
}

export function honeypotLogger(req, res, next) {
  const originalSend = res.send;
  res.send = function(data) {
    if (res.statusCode >= 400 || !req.get('authorization')) {
      insertStmt.run(
        crypto.randomUUID(),
        getClientIp(req),
        `${req.method} ${req.path}`,
        JSON.stringify({ statusCode: res.statusCode }),
        'info',
        new Date().toISOString()
      );
    }
    return originalSend.call(this, data);
  };
  next();
}

export function getHoneypotSummary() {
  const row = summaryStmt.get();
  return {
    totalAttempts: row.totalAttempts,
    uniqueIPs: row.uniqueIPs,
    timestamp: new Date().toISOString()
  };
}

export function getForensicsReport() {
  const events = recentStmt.all(200).reverse().map(row => ({
    id: row.id,
    ip: row.ip,
    reason: row.reason,
    details: JSON.parse(row.details),
    level: row.level,
    timestamp: row.timestamp
  }));

  const attackers = attackersStmt.all().map(row => ({
    ip: row.ip,
    firstSeen: row.firstSeen,
    lastSeen: row.lastSeen,
    totalAttempts: row.totalAttempts,
    techniques: techniquesForIpStmt.all(row.ip).map(r => r.reason),
    suspicionLevel: suspicionLevelFor(row.totalAttempts)
  }));

  return { summary: getHoneypotSummary(), events, attackers };
}
