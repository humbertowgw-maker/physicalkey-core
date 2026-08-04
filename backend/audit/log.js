import crypto from 'crypto';
import db from '../lib/db.js';

const insertStmt = db.prepare('INSERT INTO admin_actions (id, admin_device_id, action, target_device_id, details, timestamp) VALUES (?, ?, ?, ?, ?, ?)');
const recentStmt = db.prepare('SELECT * FROM admin_actions ORDER BY rowid DESC LIMIT ?');

export function logAdminAction(adminDeviceId, action, targetDeviceId, details = {}) {
  const entry = {
    id: crypto.randomUUID(),
    adminDeviceId,
    action,
    targetDeviceId: targetDeviceId ?? null,
    details,
    timestamp: new Date().toISOString()
  };
  insertStmt.run(entry.id, entry.adminDeviceId, entry.action, entry.targetDeviceId, JSON.stringify(entry.details), entry.timestamp);
  return entry;
}

export function getAdminActionLog(limit = 200) {
  return recentStmt.all(limit).map(row => ({
    id: row.id,
    adminDeviceId: row.admin_device_id,
    action: row.action,
    targetDeviceId: row.target_device_id,
    details: JSON.parse(row.details),
    timestamp: row.timestamp
  }));
}
