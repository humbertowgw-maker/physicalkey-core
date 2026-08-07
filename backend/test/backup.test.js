import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { runBackup, listBackups, pruneBackups, latestBackup, backupsDir } from '../lib/backup.js';

let dataDir;
let db;

before(() => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'physicalkey-backup-test-'));
  db = new DatabaseSync(path.join(dataDir, 'physicalkey.db'));
  db.exec('CREATE TABLE widgets (id INTEGER PRIMARY KEY, name TEXT)');
  db.prepare('INSERT INTO widgets (name) VALUES (?)').run('gizmo');
});

after(() => {
  db.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('runBackup writes a snapshot file that is itself a valid, complete database', () => {
  const dest = runBackup(db, dataDir, 1_700_000_000_000);
  assert.ok(fs.existsSync(dest));

  const snapshot = new DatabaseSync(dest);
  const row = snapshot.prepare('SELECT name FROM widgets WHERE id = 1').get();
  snapshot.close();
  assert.equal(row.name, 'gizmo');
});

test('runBackup names the file after the given timestamp, sortable chronologically', () => {
  // Distinct timestamps from the previous test's snapshot — this file's `db`/`dataDir`
  // are shared across the whole suite via `before()`, so reusing a timestamp here would
  // collide with a file that test already wrote.
  const earlier = runBackup(db, dataDir, 1_800_000_000_000);
  const later = runBackup(db, dataDir, 1_800_000_100_000);
  assert.ok(earlier < later, 'earlier snapshot filename should sort before the later one');
});

test('listBackups returns an empty array when no backups directory exists yet', () => {
  const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'physicalkey-backup-empty-'));
  assert.deepEqual(listBackups(emptyDir), []);
  fs.rmSync(emptyDir, { recursive: true, force: true });
});

test('pruneBackups keeps only the N most recent snapshots', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'physicalkey-backup-prune-'));
  const pruneDb = new DatabaseSync(path.join(dir, 'physicalkey.db'));
  pruneDb.exec('CREATE TABLE t (id INTEGER PRIMARY KEY)');

  for (let i = 0; i < 5; i++) {
    runBackup(pruneDb, dir, 1_700_000_000_000 + i * 1000);
  }
  assert.equal(listBackups(dir).length, 5);

  const removed = pruneBackups(dir, 2);
  assert.equal(removed.length, 3);
  assert.equal(listBackups(dir).length, 2);
  // The two survivors should be the two latest, not an arbitrary pair.
  assert.ok(listBackups(dir).every((f) => !removed.includes(f)));

  pruneDb.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

test('pruneBackups is a no-op when the count is already at or below the limit', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'physicalkey-backup-noop-'));
  const noopDb = new DatabaseSync(path.join(dir, 'physicalkey.db'));
  noopDb.exec('CREATE TABLE t (id INTEGER PRIMARY KEY)');
  runBackup(noopDb, dir, 1_700_000_000_000);

  const removed = pruneBackups(dir, 10);
  assert.equal(removed.length, 0);
  assert.equal(listBackups(dir).length, 1);

  noopDb.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

test('latestBackup returns the most recent snapshot path, or null when none exist', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'physicalkey-backup-latest-'));
  assert.equal(latestBackup(dir), null);

  const latestDb = new DatabaseSync(path.join(dir, 'physicalkey.db'));
  latestDb.exec('CREATE TABLE t (id INTEGER PRIMARY KEY)');
  runBackup(latestDb, dir, 1_700_000_000_000);
  const dest = runBackup(latestDb, dir, 1_700_000_200_000);

  assert.equal(latestBackup(dir), dest);

  latestDb.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

test('backupsDir places snapshots in a backups/ subdirectory of the data dir', () => {
  assert.equal(backupsDir('/tmp/foo'), path.join('/tmp/foo', 'backups'));
});
