import db from '../lib/db.js';
import { dataDir } from '../lib/data-dir.js';
import { runBackup, pruneBackups } from '../lib/backup.js';

const keep = Number(process.env.PK_BACKUP_RETAIN || 14);

const dest = runBackup(db, dataDir);
console.log(`Backup written: ${dest}`);

const pruned = pruneBackups(dataDir, keep);
if (pruned.length) {
  console.log(`Pruned ${pruned.length} old backup(s): ${pruned.join(', ')}`);
}
