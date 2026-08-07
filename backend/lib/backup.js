import fs from 'fs';
import path from 'path';

const PREFIX = 'physicalkey-';
const SUFFIX = '.db';

export function backupsDir(dataDir) {
  return path.join(dataDir, 'backups');
}

/**
 * Writes a consistent point-in-time snapshot of the live database using SQLite's own
 * VACUUM INTO — reads through the existing connection, so it doesn't block or interrupt
 * requests the server is handling, and doesn't need the process (or a second connection)
 * stopped first. `db` must be an already-open DatabaseSync on the live database.
 */
export function runBackup(db, dataDir, now = Date.now()) {
  const dir = backupsDir(dataDir);
  fs.mkdirSync(dir, { recursive: true });
  const stamp = new Date(now).toISOString().replace(/[:.]/g, '-');
  const dest = path.join(dir, `${PREFIX}${stamp}${SUFFIX}`);
  // VACUUM INTO refuses to overwrite an existing file, and the ISO-timestamped name
  // already makes collisions practically impossible within one process.
  db.exec(`VACUUM INTO '${dest.replace(/'/g, "''")}'`);
  return dest;
}

/** Filenames sort chronologically because the timestamp in each name is ISO-8601. */
export function listBackups(dataDir) {
  const dir = backupsDir(dataDir);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter((f) => f.startsWith(PREFIX) && f.endsWith(SUFFIX))
    .sort();
}

/** Deletes all but the `keep` most recent backups. Returns the filenames it removed. */
export function pruneBackups(dataDir, keep) {
  const files = listBackups(dataDir);
  const toDelete = files.slice(0, Math.max(0, files.length - keep));
  for (const f of toDelete) {
    fs.unlinkSync(path.join(backupsDir(dataDir), f));
  }
  return toDelete;
}

export function latestBackup(dataDir) {
  const files = listBackups(dataDir);
  return files.length ? path.join(backupsDir(dataDir), files[files.length - 1]) : null;
}
