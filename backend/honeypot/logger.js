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

// As of 2026-08-12, a real /admin/forensics pull against production showed 372 attempts
// across 13 "attacker" IPs — and every single one turned out to be us: our own dev
// machine's public IP (running test scripts and real-device debugging), or CGNAT/
// internal-range addresses that could never be a genuine external caller's real source IP
// in the first place. Publishing that as "attacker forensics" would have been publishing
// our own traffic. This tags known-non-attacker IPs so the report stays honest once real
// external traffic does show up, without deleting anything from the underlying log.
function stripV4MappedPrefix(ip) {
  return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}

// RFC 6598 shared address space (100.64.0.0/10) — Carrier-Grade NAT. Not globally
// routable; an ISP's own NAT boundary strips it before a packet ever reaches the public
// internet. Any request whose apparent IP is in this range did not originate from a real
// remote attacker over the open internet — it's platform-internal traffic (health checks,
// internal routing) by definition, not a judgment call.
function isCgnatRange(ip) {
  const match = ip.match(/^100\.(\d{1,3})\./);
  if (!match) return false;
  const second = Number(match[1]);
  return second >= 64 && second <= 127;
}

// Our own known dev/CI IPs — these DO change over time and aren't structurally
// guaranteed like the CGNAT range above, so they're configured, not hardcoded. Set
// KNOWN_INTERNAL_IPS on Railway as a comma-separated list (see CHECKPOINT.md).
function isConfiguredInternalIp(ip) {
  const configured = (process.env.KNOWN_INTERNAL_IPS || '').split(',').map((s) => s.trim()).filter(Boolean);
  return configured.includes(ip);
}

export function isKnownInternalIp(rawIp) {
  const ip = stripV4MappedPrefix(rawIp);
  return isCgnatRange(ip) || isConfiguredInternalIp(ip);
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
    // Only >= 400 is actually informative here: this middleware is applied exclusively to
    // the pre-auth endpoints (challenge/verify), which by definition never carry an
    // Authorization header on a legitimate call — logging on that condition too meant every
    // normal successful auth attempt was indistinguishable from an attack in
    // getForensicsReport()'s attacker/suspicion-level aggregation.
    if (res.statusCode >= 400) {
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

// `includeInternal: true` returns every IP, each tagged `internal: true/false`, for
// debugging what got classified and why. The default (false) is the honest "is this
// actually attacker data" view: known-internal IPs are excluded from `attackers` (never
// from the raw `events` log, which stays complete) and `summary.internalIPs` reports how
// many were excluded, so filtering is visible, not silent.
export function getForensicsReport({ includeInternal = false } = {}) {
  const events = recentStmt.all(200).reverse().map(row => ({
    id: row.id,
    ip: row.ip,
    reason: row.reason,
    details: JSON.parse(row.details),
    level: row.level,
    timestamp: row.timestamp
  }));

  const allAttackers = attackersStmt.all().map(row => ({
    ip: row.ip,
    firstSeen: row.firstSeen,
    lastSeen: row.lastSeen,
    totalAttempts: row.totalAttempts,
    techniques: techniquesForIpStmt.all(row.ip).map(r => r.reason),
    suspicionLevel: suspicionLevelFor(row.totalAttempts),
    internal: isKnownInternalIp(row.ip)
  }));

  const internalIPs = allAttackers.filter(a => a.internal).length;
  const attackers = includeInternal ? allAttackers : allAttackers.filter(a => !a.internal);

  return {
    summary: { ...getHoneypotSummary(), internalIPs },
    events,
    attackers
  };
}
