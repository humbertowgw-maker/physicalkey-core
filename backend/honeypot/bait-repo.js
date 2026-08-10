import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { dataDir } from '../lib/data-dir.js';

// The actual "deploy a honeypot git repository" roadmap item (Phase 2) — everything else
// it needs (activateHoneypot, getForensicsReport, suspicionLevelFor) already shipped as
// part of Phase 1 and sat unused. This is the bait content itself: a bare repo that looks
// like an internal credentials backup, served unconditionally to anyone who finds it —
// same "always let them in, log what they did" shape as the existing
// GET /api/honeypot/fake-database decoy, just for a git client instead of a browser.
// Named to match the public route it's served at (server.js's /backup.git/*) — GIT_PROJECT_ROOT
// resolves a repo by matching PATH_INFO's leading segment against a directory name under it,
// so the two have to agree.
export const baitRepoDir = path.join(dataDir, 'backup.git');

// Deliberately NOT real-looking AWS/Stripe/etc key formats (no "AKIA…", no "sk_live_…")
// — a string in that exact shape can trip GitHub's or a cloud provider's own automated
// leak-response scanning even when it's fake, which would just be noise for a solo
// founder to triage. Same "fake-key-do-not-use-…" convention already live in
// server.js's /api/honeypot/fake-database, kept consistent rather than inventing a
// second style.
const README = `# physicalkey-infra

Internal deploy credentials backup. DO NOT share this URL or commit it to a public repo.

Contact ops@physicalkey.internal if you believe you've reached this in error.
`;

const DEPLOY_CREDENTIALS = JSON.stringify({
  _comment: 'rotated quarterly — last rotation 2026-07-01',
  railway_deploy_token: 'fake-key-do-not-use-9f3a7c21e8',
  stripe_restricted_key: 'fake-key-do-not-use-b71c4de902',
  admin_recovery_phrase: 'fake-key-do-not-use-3d81ff02a6'
}, null, 2);

export function ensureBaitRepo() {
  if (fs.existsSync(baitRepoDir)) return;

  fs.mkdirSync(baitRepoDir, { recursive: true });
  execSync('git init --bare -q', { cwd: baitRepoDir });

  const seedDir = path.join(dataDir, '.honeypot-bait-seed-tmp');
  fs.rmSync(seedDir, { recursive: true, force: true });
  execSync(`git clone -q "${baitRepoDir}" "${seedDir}"`);
  fs.writeFileSync(path.join(seedDir, 'README.md'), README);
  fs.writeFileSync(path.join(seedDir, 'deploy-credentials.json'), DEPLOY_CREDENTIALS);
  execSync('git add README.md deploy-credentials.json', { cwd: seedDir });
  execSync(
    'git -c user.email="ops@physicalkey.internal" -c user.name="ops" commit -q -m "Rotate deploy credentials"',
    { cwd: seedDir }
  );
  execSync(`git push -q "${baitRepoDir}" HEAD:main`, { cwd: seedDir });
  fs.rmSync(seedDir, { recursive: true, force: true });
}
