const honeypotLog = [];
const attackerProfiles = new Map();

function suspicionLevelFor(attemptCount) {
  if (attemptCount >= 7) return 'high';
  if (attemptCount >= 3) return 'medium';
  return 'low';
}

export function activateHoneypot(ip, reason, details = {}) {
  try {
    const logEntry = {
      id: Math.random().toString(36).substring(7),
      ip,
      reason,
      details,
      timestamp: new Date().toISOString(),
      level: 'warning'
    };

    honeypotLog.push(logEntry);
    console.log(`🎭 HONEYPOT ACTIVATED: ${reason} from IP: ${ip}`);

    if (!attackerProfiles.has(ip)) {
      attackerProfiles.set(ip, {
        ip,
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        attempts: [],
        techniques: new Set(),
        suspicionLevel: 'low'
      });
    }

    const profile = attackerProfiles.get(ip);
    profile.lastSeen = Date.now();
    profile.attempts.push({ reason, timestamp: Date.now() });
    profile.techniques.add(reason);
    profile.suspicionLevel = suspicionLevelFor(profile.attempts.length);

    return logEntry;
  } catch (error) {
    console.error('Honeypot activation error:', error);
  }
}

export function honeypotLogger(req, res, next) {
  const originalSend = res.send;
  res.send = function(data) {
    if (res.statusCode >= 400 || !req.get('authorization')) {
      honeypotLog.push({
        method: req.method,
        path: req.path,
        ip: req.ip,
        statusCode: res.statusCode,
        timestamp: new Date().toISOString()
      });
    }
    return originalSend.call(this, data);
  };
  next();
}

export function getHoneypotSummary() {
  return {
    totalAttempts: honeypotLog.length,
    uniqueIPs: new Set(honeypotLog.map(log => log.ip)).size,
    timestamp: new Date().toISOString()
  };
}

export function getForensicsReport() {
  return {
    summary: getHoneypotSummary(),
    events: honeypotLog.slice(-200),
    attackers: Array.from(attackerProfiles.values()).map(profile => ({
      ip: profile.ip,
      firstSeen: new Date(profile.firstSeen).toISOString(),
      lastSeen: new Date(profile.lastSeen).toISOString(),
      totalAttempts: profile.attempts.length,
      techniques: Array.from(profile.techniques),
      suspicionLevel: profile.suspicionLevel
    }))
  };
}

export { honeypotLog, attackerProfiles };
