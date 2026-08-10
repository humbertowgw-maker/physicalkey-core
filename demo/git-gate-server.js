// A real git-over-HTTP server whose ONLY access check is a live call to the production
// PhysicalKey backend's GET /git/auth — the exact endpoint the security audit and
// competitive brief have been describing for days as "designed but nothing actually
// calls it." This makes it real: `git clone` against this server genuinely succeeds or
// fails based on whether the Basic Auth credentials it receives are, at that moment, a
// still-valid set issued by a real phone+Face ID+ESP32 authentication a moment earlier.
//
// No mocking, no shortcuts: unauthorized requests get a real 401 from git's own client,
// the same as a real GitHub/Gitea rejection. Authorized ones spawn the real
// `git http-backend` CGI and hand it the exact repo on disk, so a successful clone lands
// real files, and a successful push genuinely updates the repo.
import { spawn, execSync } from 'child_process';
import http from 'http';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_NAME = 'vault.git';
const REPO_DIR = path.join(__dirname, REPO_NAME);
const PORT = process.env.GATE_PORT || 7420;
const BACKEND_URL = process.env.PK_BACKEND_URL || 'https://physicalkey-core-production.up.railway.app';
const GIT_HTTP_BACKEND = execSync('git --exec-path').toString().trim() + '/git-http-backend';

function ensureVault() {
  if (fs.existsSync(REPO_DIR)) return;
  console.log(`[gate] no vault found — creating a real bare repo at ${REPO_DIR}`);
  fs.mkdirSync(REPO_DIR, { recursive: true });
  execSync('git init --bare', { cwd: REPO_DIR });

  // Seed it with one real commit via a throwaway working clone, so `git clone` against
  // the gate has something genuine to hand back the moment it succeeds.
  const seedDir = path.join(__dirname, '.seed-tmp');
  fs.rmSync(seedDir, { recursive: true, force: true });
  execSync(`git clone "${REPO_DIR}" "${seedDir}"`);
  fs.writeFileSync(
    path.join(seedDir, 'ACCESS_GRANTED.md'),
    `# You're in.\n\nThis file only reached your disk because a real phone + Face ID + physical ` +
    `ESP32 key completed a live PhysicalKey authentication a moment ago, and the backend at\n` +
    `${BACKEND_URL}\nindependently verified it before this server would let \`git http-backend\` ` +
    `serve you anything.\n\nNo mock, no bypass — try cloning again without valid credentials and ` +
    `watch it fail the same way.\n`
  );
  execSync('git add ACCESS_GRANTED.md', { cwd: seedDir });
  execSync('git -c user.email="demo@physicalkey.local" -c user.name="PhysicalKey Demo" commit -m "Seed vault"', { cwd: seedDir });
  execSync(`git push "${REPO_DIR}" HEAD:main`, { cwd: seedDir });
  fs.rmSync(seedDir, { recursive: true, force: true });
  console.log('[gate] vault seeded with one real commit');
}

// Forwards the client's exact Authorization header to the real backend's /git/auth —
// the same validation function backend/git/git-credentials.js already exercises in
// tests, now actually being called by something a `git clone` can hit.
async function checkGate(authHeader) {
  const res = await fetch(`${BACKEND_URL}/git/auth`, {
    headers: authHeader ? { Authorization: authHeader } : {}
  });
  const body = await res.json();
  return { ok: res.ok && body.granted === true, body };
}

function runGitHttpBackend(req, res, remoteUser) {
  const url = new URL(req.url, 'http://localhost');
  const env = {
    ...process.env,
    GIT_PROJECT_ROOT: __dirname,
    GIT_HTTP_EXPORT_ALL: '1',
    PATH_INFO: url.pathname,
    QUERY_STRING: url.search.replace(/^\?/, ''),
    REQUEST_METHOD: req.method,
    CONTENT_TYPE: req.headers['content-type'] || '',
    CONTENT_LENGTH: req.headers['content-length'] || '0',
    REMOTE_USER: remoteUser,
    REMOTE_ADDR: req.socket.remoteAddress || '',
    GATEWAY_INTERFACE: 'CGI/1.1',
    SERVER_PROTOCOL: 'HTTP/1.1',
    SERVER_SOFTWARE: 'physicalkey-git-gate'
  };

  const child = spawn(GIT_HTTP_BACKEND, [], { env, cwd: __dirname });
  req.pipe(child.stdin);

  let headerBuf = Buffer.alloc(0);
  let headersSent = false;

  child.stdout.on('data', (chunk) => {
    if (headersSent) { res.write(chunk); return; }
    headerBuf = Buffer.concat([headerBuf, chunk]);
    const crlfIdx = headerBuf.indexOf('\r\n\r\n');
    const lfIdx = headerBuf.indexOf('\n\n');
    const candidates = [crlfIdx, lfIdx].filter((i) => i !== -1);
    if (candidates.length === 0) return; // wait for more data — header block not complete yet
    const idx = Math.min(...candidates);
    const sepLen = idx === crlfIdx ? 4 : 2;

    const headerText = headerBuf.slice(0, idx).toString('latin1');
    const rest = headerBuf.slice(idx + sepLen);
    const headers = {};
    for (const line of headerText.split(/\r?\n/)) {
      const colon = line.indexOf(':');
      if (colon === -1) continue;
      headers[line.slice(0, colon).trim()] = line.slice(colon + 1).trim();
    }
    const status = headers['Status'] ? parseInt(headers['Status'], 10) : 200;
    delete headers['Status'];
    res.writeHead(status, headers);
    if (rest.length) res.write(rest);
    headersSent = true;
  });

  child.stderr.on('data', (d) => console.error('[git-http-backend]', d.toString().trim()));
  child.on('close', () => { if (!res.writableEnded) res.end(); });
  child.on('error', (err) => {
    console.error('[gate] failed to spawn git-http-backend:', err.message);
    if (!headersSent) res.writeHead(500).end('git-http-backend failed to start');
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (!url.pathname.startsWith(`/${REPO_NAME}`)) {
    res.writeHead(404).end('not found — try /vault.git\n');
    return;
  }

  const authHeader = req.headers.authorization;
  const attemptedUser = authHeader?.startsWith('Basic ')
    ? Buffer.from(authHeader.slice(6), 'base64').toString('utf8').split(':')[0]
    : '(none)';

  const { ok, body } = await checkGate(authHeader);

  if (!ok) {
    console.log(`[gate] ✗ DENIED — user="${attemptedUser}" reason="${body?.error || 'no credentials'}"`);
    res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="physicalkey-vault"' });
    res.end('Access denied — not a valid, current PhysicalKey session\n');
    return;
  }

  console.log(`[gate] ✓ GRANTED — user="${body.username}" scope="${body.scope}" expires="${body.expiresAt}"`);
  runGitHttpBackend(req, res, body.username);
});

ensureVault();
server.listen(PORT, () => {
  console.log(`\n🔐 PhysicalKey git gate listening on http://localhost:${PORT}/${REPO_NAME}`);
  console.log(`   Every request is live-checked against ${BACKEND_URL}/git/auth — no mock.\n`);
  console.log(`   Try it locked:   git clone http://localhost:${PORT}/${REPO_NAME} /tmp/should-fail`);
  console.log(`   Then unlock it with real PhysicalKey credentials (phone + Face ID + board):`);
  console.log(`      git clone http://<deviceId>:<password>@localhost:${PORT}/${REPO_NAME} /tmp/should-work\n`);
});
