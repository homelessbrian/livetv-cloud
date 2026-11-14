// Live TV cloud sync: keeps one copy of a person's Live TV setup per Nuvio account.
//
// Who is calling is decided by Nuvio's own sign-in: the app sends the Nuvio access token it
// already has, and this Worker asks Nuvio's sign-in server whose token it is. The token is only
// checked here. It is never stored, logged or refreshed (refreshing it on a server would sign
// the TV out). Nothing is written to Nuvio's servers.
//
//   GET    /v1/setup           the saved copy                      200 | 404
//   PUT    /v1/setup           save a copy (see below)             200 | 409 | 413 | 429
//   DELETE /v1/setup           delete the saved copy               200
//   GET    /v1/setup/previous  the copy from before the last save  200 | 404
//   GET    /v1/health          is the service up                   200
//
// Our own apps use the same routes under /v2/ (/v2/setup, /v2/setup/previous), which also need
// the app key (see "App key" below). The /v1/ setup routes are the old open door: they keep
// working for apps that haven't updated yet, until the date in OLD_DOOR_CLOSES_AT.
//
//   GET    /v2/data/<file>     a sports data file (app key only)   200 | 304 | 404
//
// Every 5 minutes (the cron in wrangler.toml) it asks ESPN for the scores itself and saves them to
// the R2 bucket (see "ESPN scores" below), then asks GitHub to run nuvio-data's "ESPN shared
// schedule cache" job, which makes the ready-made files from them (GitHub's own schedule for it is
// often skipped for hours). Starting the job needs the secret ESPN_TRIGGER_TOKEN (a GitHub token
// that may only run Actions in nuvio-data).
//
// Private test builds (people with the tester key only; see the "Test builds" part below):
//   GET    /v1/updates/test/latest        what the newest test build is        200 | 404
//   GET    /v1/updates/test/apk/<code>    that test build's APK                200 | 404
//   GET    /v1/updates/test/download      the newest APK (first install)       200 | 404
//   The same three exist under /v1/updates/mobile-test/ for the phone app's test builds, and under
//   /v1/updates/release-check/ for a TV release build checked privately before it goes to users.
//
// The saved setup (it holds IPTV logins and the parental PIN) is encrypted before it goes into the
// database: AES-256-GCM, with a separate key per Nuvio account made from the secret
// SYNC_ENCRYPTION_KEY (set in the Cloudflare dashboard, never in the code). Without that secret a
// save is refused, so nothing readable is ever written. A copy saved before this was added is
// still read fine and is encrypted the next time it is touched.
//
// A save carries the revision it was based on. If someone else saved in between, it is refused
// with 409 and the current revision, so a TV that was offline can never overwrite newer work.

const MAX_BODY_BYTES = 5 * 1024 * 1024;
// A saved copy (squeezed, then encrypted) must fit in one database row, which can be 2 MB. The
// copy from before the last save has its own row (setup_previous), so each copy gets the full room.
const MAX_STORED_CHARS = 1_900_000;
const SAVES_PER_DAY = 500;
const TOKEN_CACHE_MS = 5 * 60 * 1000;
const NUVIO_TIMEOUT_MS = 8000;
const DEFAULT_NUVIO_API = 'https://api.nuvio.tv';

const SCHEMA = `CREATE TABLE IF NOT EXISTS setups (
  user_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL,
  data TEXT NOT NULL,
  saved_at INTEGER NOT NULL,
  device TEXT NOT NULL DEFAULT '',
  device_id TEXT NOT NULL DEFAULT '',
  prev_revision INTEGER,
  prev_data TEXT,
  prev_saved_at INTEGER,
  saves_day TEXT NOT NULL DEFAULT '',
  saves_count INTEGER NOT NULL DEFAULT 0
)`;

// The copy from before the last save. Older rows may still hold it in setups.prev_*; it is read
// from there until the next save moves it here.
const SCHEMA_PREVIOUS = `CREATE TABLE IF NOT EXISTS setup_previous (
  user_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL,
  data TEXT NOT NULL,
  saved_at INTEGER NOT NULL
)`;

const ENC_PREFIX = 'enc1:'; // encrypted
const ENC2_PREFIX = 'enc2:'; // squeezed (gzip), then encrypted
const MIN_SECRET_LENGTH = 32;

function toB64(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 8192) out += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(out);
}
const fromB64 = (text) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));

/** This account's own key, made from the secret. Throws 503 if the secret is missing or too short. */
async function accountKey(env, userId) {
  const secret = typeof env.SYNC_ENCRYPTION_KEY === 'string' ? env.SYNC_ENCRYPTION_KEY.trim() : '';
  if (secret.length < MIN_SECRET_LENGTH) throw new HttpError(503, 'encryption_not_set');
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey('raw', enc.encode(secret), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('livetv-cloud-v1'), info: enc.encode(`setup:${userId}`) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function squeeze(bytes) {
  const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function unsqueeze(bytes) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Text -> "enc2:<iv>:<encrypted>" (squeezed first). The account id is bound in, so a row can't be moved to another account. */
async function encryptText(env, userId, plain) {
  const key = await accountKey(env, userId);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(userId) },
    key,
    await squeeze(new TextEncoder().encode(plain))
  );
  return `${ENC2_PREFIX}${toB64(iv)}:${toB64(new Uint8Array(sealed))}`;
}

const isEncrypted = (stored) => typeof stored === 'string' && (stored.startsWith(ENC_PREFIX) || stored.startsWith(ENC2_PREFIX));

/** Back to text. A copy saved before encryption existed is returned as it is. */
async function decryptText(env, userId, stored) {
  if (!isEncrypted(stored)) return stored;
  const key = await accountKey(env, userId);
  try {
    const squeezed = stored.startsWith(ENC2_PREFIX);
    const [iv, sealed] = stored.slice(ENC_PREFIX.length).split(':');
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(iv), additionalData: new TextEncoder().encode(userId) },
      key,
      fromB64(sealed)
    );
    return new TextDecoder().decode(squeezed ? await unsqueeze(new Uint8Array(plain)) : plain);
  } catch {
    throw new HttpError(503, 'cannot_decrypt');
  }
}

/** Encrypts any older readable copy in place. Changes no revision; failing here changes nothing. */
async function upgradeRow(env, userId, row) {
  if (isEncrypted(row.data) && (!row.prev_data || isEncrypted(row.prev_data))) return;
  try {
    const data = isEncrypted(row.data) ? row.data : await encryptText(env, userId, row.data);
    const prev = !row.prev_data || isEncrypted(row.prev_data) ? row.prev_data : await encryptText(env, userId, row.prev_data);
    await env.DB.prepare('UPDATE setups SET data = ?, prev_data = ? WHERE user_id = ? AND revision = ?')
      .bind(data, prev ?? null, userId, row.revision).run();
  } catch {
    // Secret not set yet, or somebody saved in between: try again on the next read.
  }
}

/** Checked tokens for a few minutes, so the Nuvio sign-in server is not asked on every request. */
const checked = new Map(); // sha256(token) -> { userId, until }
let schemaReady = null;

class HttpError extends Error {
  constructor(status, code, extra = {}) {
    super(code);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

function reply(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers },
  });
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** The expiry (ms) written inside a token, or null if it can't be read. */
function tokenExpiry(token) {
  try {
    const part = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const payload = JSON.parse(atob(part.padEnd(Math.ceil(part.length / 4) * 4, '=')));
    return typeof payload.exp === 'number' ? payload.exp * 1000 : null;
  } catch {
    return null;
  }
}

function ensureSchema(env) {
  if (!schemaReady) {
    schemaReady = env.DB.batch([env.DB.prepare(SCHEMA), env.DB.prepare(SCHEMA_PREVIOUS)]).catch((err) => {
      schemaReady = null;
      throw err;
    });
  }
  return schemaReady;
}

/** Who sent this request, according to Nuvio. Throws 401 if not signed in, 503 if Nuvio can't be reached. */
async function whoIs(request, env) {
  const match = /^Bearer\s+([A-Za-z0-9._-]{20,4096})$/.exec(request.headers.get('authorization') || '');
  if (!match || match[1].split('.').length !== 3) throw new HttpError(401, 'sign_in_required');
  const token = match[1];

  const expiry = tokenExpiry(token);
  if (expiry !== null && expiry <= Date.now()) throw new HttpError(401, 'sign_in_required');

  const cacheKey = await sha256Hex(token);
  const hit = checked.get(cacheKey);
  if (hit && hit.until > Date.now()) return hit.userId;

  // Nuvio's gateway wants the app's public key next to the token. The app sends the one it was
  // built with, so a key change on Nuvio's side needs no change here.
  const key = request.headers.get('apikey') || env.NUVIO_PUBLISHABLE_KEY || '';
  if (!key) throw new HttpError(401, 'sign_in_required');

  const base = (env.NUVIO_API_URL || DEFAULT_NUVIO_API).replace(/\/+$/, '');
  let res;
  try {
    res = await fetch(`${base}/auth/v1/user`, {
      headers: { authorization: `Bearer ${token}`, apikey: key, accept: 'application/json' },
      signal: AbortSignal.timeout(NUVIO_TIMEOUT_MS),
    });
  } catch {
    throw new HttpError(503, 'nuvio_unreachable');
  }
  if (res.status === 401 || res.status === 403) throw new HttpError(401, 'sign_in_required');
  if (!res.ok) throw new HttpError(503, 'nuvio_unreachable');

  let user;
  try {
    user = await res.json();
  } catch {
    throw new HttpError(503, 'nuvio_unreachable');
  }
  const userId = typeof user?.id === 'string' ? user.id : '';
  if (!/^[0-9a-f-]{32,40}$/i.test(userId)) throw new HttpError(401, 'sign_in_required');

  if (checked.size > 2000) checked.clear();
  checked.set(cacheKey, { userId, until: Math.min(Date.now() + TOKEN_CACHE_MS, expiry ?? Infinity) });
  return userId;
}

async function readJsonBody(request) {
  const declared = Number(request.headers.get('content-length') || 0);
  if (declared > MAX_BODY_BYTES) throw new HttpError(413, 'too_large');
  const text = await request.text();
  if (new TextEncoder().encode(text).length > MAX_BODY_BYTES) throw new HttpError(413, 'too_large');
  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError(400, 'bad_json');
  }
}

const text = (value, max) => (typeof value === 'string' ? value.slice(0, max) : '');

async function getRow(env, userId) {
  return env.DB.prepare('SELECT * FROM setups WHERE user_id = ?').bind(userId).first();
}

async function getSetup(env, userId) {
  const row = await getRow(env, userId);
  if (!row) throw new HttpError(404, 'none');
  const data = JSON.parse(await decryptText(env, userId, row.data));
  await upgradeRow(env, userId, row);
  return reply(200, {
    revision: row.revision,
    savedAt: row.saved_at,
    device: row.device,
    deviceId: row.device_id,
    data,
  });
}

async function getPrevious(env, userId) {
  const row = await getRow(env, userId);
  if (!row) throw new HttpError(404, 'none');
  const moved = await env.DB.prepare('SELECT * FROM setup_previous WHERE user_id = ?').bind(userId).first();
  if (moved) {
    return reply(200, {
      revision: moved.revision,
      savedAt: moved.saved_at,
      currentRevision: row.revision,
      data: JSON.parse(await decryptText(env, userId, moved.data)),
    });
  }
  if (!row.prev_data) throw new HttpError(404, 'none');
  const data = JSON.parse(await decryptText(env, userId, row.prev_data));
  await upgradeRow(env, userId, row);
  return reply(200, {
    revision: row.prev_revision,
    savedAt: row.prev_saved_at,
    currentRevision: row.revision,
    data,
  });
}

async function putSetup(request, env, userId) {
  const body = await readJsonBody(request);
  const data = body?.data;
  if (!data || typeof data !== 'object' || Array.isArray(data) || Object.keys(data).length === 0) {
    throw new HttpError(422, 'empty_setup');
  }
  const base = Number.isInteger(body.baseRevision) && body.baseRevision >= 0 ? body.baseRevision : 0;
  const device = text(body.device, 60);
  const deviceId = text(body.deviceId, 80);
  const now = Date.now();
  const today = new Date(now).toISOString().slice(0, 10);
  const encoded = await encryptText(env, userId, JSON.stringify(data));
  if (encoded.length > MAX_STORED_CHARS) throw new HttpError(413, 'too_large');

  const row = await getRow(env, userId);

  if (!row) {
    // Nothing saved yet. Only a TV that also believes nothing is saved may create the first copy.
    if (base !== 0) throw new HttpError(409, 'conflict', { revision: 0 });
    const made = await env.DB.prepare(
      `INSERT OR IGNORE INTO setups (user_id, revision, data, saved_at, device, device_id, saves_day, saves_count)
       VALUES (?, 1, ?, ?, ?, ?, ?, 1)`
    ).bind(userId, encoded, now, device, deviceId, today).run();
    if (!made.meta.changes) {
      const current = await getRow(env, userId);
      throw new HttpError(409, 'conflict', { revision: current?.revision ?? 0, savedAt: current?.saved_at, device: current?.device });
    }
    return reply(200, { revision: 1, savedAt: now });
  }

  if (base !== row.revision) {
    throw new HttpError(409, 'conflict', { revision: row.revision, savedAt: row.saved_at, device: row.device });
  }
  if (row.saves_day === today && row.saves_count >= SAVES_PER_DAY) {
    const midnight = Date.parse(`${today}T00:00:00Z`) + 86_400_000;
    throw new HttpError(429, 'too_many_saves', { retryAfter: Math.max(60, Math.ceil((midnight - now) / 1000)) });
  }

  // The copy being replaced moves aside (encrypted, if it still was readable text).
  const previous = isEncrypted(row.data) ? row.data : await encryptText(env, userId, row.data);

  // The save only goes through if nobody saved in between; then (in the same transaction) the
  // replaced copy moves to its own row. Any copy still kept in this row the old way is cleared.
  const [saved] = await env.DB.batch([
    env.DB.prepare(
      `UPDATE setups SET
         prev_revision = NULL, prev_data = NULL, prev_saved_at = NULL,
         revision = revision + 1, data = ?, saved_at = ?, device = ?, device_id = ?,
         saves_count = CASE WHEN saves_day = ? THEN saves_count + 1 ELSE 1 END, saves_day = ?
       WHERE user_id = ? AND revision = ?`
    ).bind(encoded, now, device, deviceId, today, today, userId, row.revision),
    env.DB.prepare(
      `INSERT OR REPLACE INTO setup_previous (user_id, revision, data, saved_at)
       SELECT ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM setups WHERE user_id = ? AND revision = ? AND saved_at = ? AND device_id = ?)`
    ).bind(userId, row.revision, previous, row.saved_at, userId, row.revision + 1, now, deviceId),
  ]);
  if (!saved.meta.changes) {
    const current = await getRow(env, userId);
    throw new HttpError(409, 'conflict', { revision: current?.revision ?? 0, savedAt: current?.saved_at, device: current?.device });
  }
  return reply(200, { revision: row.revision + 1, savedAt: now });
}

async function deleteSetup(env, userId) {
  await env.DB.batch([
    env.DB.prepare('DELETE FROM setups WHERE user_id = ?').bind(userId),
    env.DB.prepare('DELETE FROM setup_previous WHERE user_id = ?').bind(userId),
  ]);
  return reply(200, { ok: true });
}

// ---------------------------------------------------------------------------------------------
// Test builds: lets the test app (and a few testers) update from a private GitHub repo.
//
// The APKs are release files in a private repo. The TV can't sign in to GitHub, and a GitHub token
// inside an app can be pulled out, so this Worker holds the token and hands the files only to a
// caller with the tester key. Nothing here is stored; it only passes GitHub's answer along.
//
// One release per test build: tag "test-<versionCode>", release name = the version name, release
// text = what changed, and one .apk file. Secrets (set in the Cloudflare dashboard, never in code):
//   TESTER_KEY          the key testers use (several can be given, separated by commas; 16+ characters each)
//   TEST_BUILDS_TOKEN   a GitHub token that can only read the private repo's contents
// Optional: TEST_BUILDS_REPO ("owner/name", default homelessbrian/Nuvio_Testing).
// Until both secrets are set every one of these routes simply answers 404/503.
// ---------------------------------------------------------------------------------------------

const GITHUB_API = 'https://api.github.com';
const DEFAULT_TEST_REPO = 'homelessbrian/Nuvio_Testing';
const TEST_LIST_CACHE_MS = 60 * 1000;
const GITHUB_TIMEOUT_MS = 8000;
const MIN_TESTER_KEY_LENGTH = 16;
let testListCache = null; // { until, releases }

const testKeys = (env) =>
  String(env.TESTER_KEY || '').split(',').map((k) => k.trim()).filter((k) => k.length >= MIN_TESTER_KEY_LENGTH);

/** Same length, compared without stopping at the first difference. */
function sameHex(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function testerAllowed(request, env) {
  const given = request.headers.get('x-tester-key') || new URL(request.url).searchParams.get('key') || '';
  const keys = testKeys(env);
  if (!given || keys.length === 0) return false;
  const givenHash = await sha256Hex(given);
  let allowed = false;
  for (const key of keys) if (sameHex(givenHash, await sha256Hex(key))) allowed = true;
  return allowed;
}

function githubHeaders(env, accept = 'application/vnd.github+json') {
  return {
    authorization: `Bearer ${env.TEST_BUILDS_TOKEN}`,
    accept,
    'user-agent': 'livetv-cloud',
    'x-github-api-version': '2022-11-28',
  };
}

function testRepo(env) {
  const repo = String(env.TEST_BUILDS_REPO || DEFAULT_TEST_REPO).trim();
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) throw new HttpError(503, 'test_updates_not_set');
  return repo;
}

// Which build a GitHub tag belongs to: test-<code> (TV test app), mobile-test-<code> (phone test
// app), release-check-<code> (the TV app as users get it, built for a private check first).
const BUILD_KINDS = { test: 'test', 'mobile-test': 'mobile-test', 'release-check': 'release-check' };

/** Every private build that exists (TV, phone and release checks), newest first (a minute of memory, so GitHub is not asked on every check). */
async function allTestReleases(env) {
  if (testListCache && testListCache.until > Date.now()) return testListCache.releases;
  if (!env.TEST_BUILDS_TOKEN) throw new HttpError(503, 'test_updates_not_set');
  let res;
  try {
    res = await fetch(`${GITHUB_API}/repos/${testRepo(env)}/releases?per_page=50`, {
      headers: githubHeaders(env),
      signal: AbortSignal.timeout(GITHUB_TIMEOUT_MS),
    });
  } catch {
    throw new HttpError(503, 'github_unreachable');
  }
  if (!res.ok) throw new HttpError(503, 'github_unreachable');
  let list;
  try {
    list = await res.json();
  } catch {
    throw new HttpError(503, 'github_unreachable');
  }
  const releases = (Array.isArray(list) ? list : [])
    .filter((r) => r && !r.draft && /^(mobile-test|test|release-check)-\d{1,10}$/.test(r.tag_name || ''))
    .map((r) => ({
      kind: r.tag_name.slice(0, r.tag_name.lastIndexOf('-')),
      versionCode: Number(r.tag_name.slice(r.tag_name.lastIndexOf('-') + 1)),
      versionName: text(r.name, 80) || r.tag_name,
      notes: text(r.body, 4000),
      publishedAt: r.published_at || r.created_at || null,
      asset: (r.assets || []).find((a) => /\.apk$/i.test(a.name || '') && a.state === 'uploaded'),
    }))
    .filter((r) => r.asset)
    .sort((a, b) => b.versionCode - a.versionCode);
  testListCache = { until: Date.now() + TEST_LIST_CACHE_MS, releases };
  return releases;
}

/** The builds of one kind (see BUILD_KINDS), newest first. */
async function testReleases(env, kind) {
  const all = await allTestReleases(env);
  return all
    .filter((r) => r.kind === kind)
    .map((r) => (kind === 'mobile-test' ? { ...r, versionName: r.versionName.replace(/^Mobile\s+/i, '') } : r));
}

function testManifest(origin, releases, route) {
  const [latest, ...older] = releases;
  const sha = /^sha256:([0-9a-f]{64})$/i.exec(latest.asset.digest || '');
  return {
    channel: route === 'release-check' ? 'release-check' : 'test',
    versionName: latest.versionName,
    versionCode: latest.versionCode,
    publishedAt: latest.publishedAt,
    notes: latest.notes,
    apk: {
      name: latest.asset.name,
      size: latest.asset.size ?? null,
      sha256: sha ? sha[1].toLowerCase() : null,
      url: `${origin}/v1/updates/${route}/apk/${latest.versionCode}`,
    },
    previous: older.slice(0, 4).map((r) => ({
      versionName: r.versionName,
      versionCode: r.versionCode,
      url: `${origin}/v1/updates/${route}/apk/${r.versionCode}`,
    })),
  };
}

/** Passes the APK from the private repo through to the caller without keeping it. */
async function streamTestApk(env, release) {
  const asset = release.asset;
  let res;
  try {
    // GitHub answers with a short-lived signed address. That address must be asked for WITHOUT the
    // token, so the first answer is read here and not followed automatically.
    res = await fetch(`${GITHUB_API}/repos/${testRepo(env)}/releases/assets/${asset.id}`, {
      headers: githubHeaders(env, 'application/octet-stream'),
      redirect: 'manual',
      signal: AbortSignal.timeout(GITHUB_TIMEOUT_MS),
    });
    if (res.status >= 300 && res.status < 400) {
      const where = res.headers.get('location') || '';
      if (!/^https:\/\//i.test(where)) throw new Error('bad redirect');
      res = await fetch(where);
    }
  } catch {
    throw new HttpError(503, 'github_unreachable');
  }
  if (!res.ok || !res.body) throw new HttpError(503, 'github_unreachable');
  const headers = {
    'content-type': 'application/vnd.android.package-archive',
    'content-disposition': `attachment; filename="${String(asset.name).replace(/[^A-Za-z0-9._-]/g, '_')}"`,
    'cache-control': 'no-store',
  };
  const length = res.headers.get('content-length');
  if (length) headers['content-length'] = length;
  return new Response(res.body, { status: 200, headers });
}

async function testUpdates(request, env, pathname) {
  // Anyone without the key gets the same answer as for a page that doesn't exist.
  if (request.method !== 'GET' || !(await testerAllowed(request, env))) throw new HttpError(404, 'not_found');
  const path = pathname.replace(/\/+$/, '');
  const route = BUILD_KINDS[path.split('/')[3]];
  if (!route) throw new HttpError(404, 'not_found');
  const releases = await testReleases(env, route);
  const base = `/v1/updates/${route}`;

  if (path === `${base}/latest`) {
    if (!releases.length) throw new HttpError(404, 'none');
    return reply(200, testManifest(new URL(request.url).origin, releases, route));
  }
  if (path === `${base}/download`) {
    if (!releases.length) throw new HttpError(404, 'none');
    return streamTestApk(env, releases[0]);
  }
  const apk = new RegExp(`^${base}/apk/(\\d{1,10})$`).exec(path);
  if (apk) {
    const release = releases.find((r) => r.versionCode === Number(apk[1]));
    if (!release) throw new HttpError(404, 'none');
    return streamTestApk(env, release);
  }
  throw new HttpError(404, 'not_found');
}

// ---------------------------------------------------------------------------------------------
// App key: only our own apps (TV and phone) may use the /v2/ routes.
//
// The key is put into our release and test builds from a GitHub secret (never in the source), so
// other people's builds of the code don't have it. Secret (Cloudflare dashboard):
//   APP_KEY   the key (24+ characters; several can be given, separated by commas, to change it)
// Until it is set every /v2/ route is refused.
//
// OLD_DOOR_CLOSES_AT (a plain variable, e.g. 2026-12-01): from then on the old /v1/setup routes
// answer 410 update_required. Not set = the old door stays open.
// ---------------------------------------------------------------------------------------------

const MIN_APP_KEY_LENGTH = 24;

const appKeys = (env) =>
  String(env.APP_KEY || '').split(',').map((k) => k.trim()).filter((k) => k.length >= MIN_APP_KEY_LENGTH);

async function appAllowed(request, env) {
  const given = request.headers.get('x-app-key') || '';
  const keys = appKeys(env);
  if (!given || keys.length === 0) return false;
  const givenHash = await sha256Hex(given);
  let allowed = false;
  for (const key of keys) if (sameHex(givenHash, await sha256Hex(key))) allowed = true;
  return allowed;
}

/** When the old open door closes (ms), or null if it stays open. */
function oldDoorClosesAt(env) {
  const at = Date.parse(String(env.OLD_DOOR_CLOSES_AT || '').trim());
  return Number.isFinite(at) ? at : null;
}

const oldDoorClosed = (env) => {
  const at = oldDoorClosesAt(env);
  return at !== null && Date.now() >= at;
};

// ---------------------------------------------------------------------------------------------
// Sports data: the files the nuvio-data job makes, kept in the R2 bucket bound as DATA (the job
// uploads each file it changes). Handed only to callers with the app key. The app's own
// "has this changed?" check (If-None-Match) is answered with 304 and no file.
// ---------------------------------------------------------------------------------------------

const DATA_PATH = /^[A-Za-z0-9][A-Za-z0-9._-]*(\/[A-Za-z0-9][A-Za-z0-9._-]*){0,6}$/;

function dataType(name) {
  if (/\.json$/i.test(name)) return 'application/json; charset=utf-8';
  if (/\.txt$/i.test(name)) return 'text/plain; charset=utf-8';
  return 'application/octet-stream';
}

// Every app asks for the same few files, so each copy is kept for a short while (default 60
// seconds, setting DATA_CACHE_SECONDS; 0 = off) instead of reading R2 on every request:
//   1. in this Worker's own memory (files up to 1 MB, 32 MB in all), then
//   2. in Cloudflare's cache for this location,
//   3. and only then from R2.
// The app keeps its own "has this changed?" check, answered from whichever copy is used.
// The files change at most every few minutes and the app accepts copies up to 20 minutes old.
// The response header x-data-from says which one answered (memory, cache or r2).

const MEMO_MAX_FILE = 1_000_000;
const MEMO_MAX_TOTAL = 32_000_000;
const memo = new Map(); // file -> { until, missing, etag, modified, bytes }
let memoBytes = 0;

function cacheSeconds(env) {
  const raw = String(env.DATA_CACHE_SECONDS ?? '').trim();
  const n = raw === '' ? 60 : Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.min(Math.floor(n), 600) : 0;
}

function memoGet(file, now) {
  const e = memo.get(file);
  if (!e) return null;
  if (e.until > now) return e;
  memoDrop(file);
  return null;
}

function memoDrop(file) {
  const e = memo.get(file);
  if (!e) return;
  memo.delete(file);
  memoBytes -= e.bytes ? e.bytes.byteLength : 0;
}

function memoPut(file, entry) {
  const size = entry.bytes ? entry.bytes.byteLength : 0;
  if (size > MEMO_MAX_FILE) return;
  memoDrop(file);
  // Oldest first (a Map keeps the order things were added).
  for (const key of memo.keys()) {
    if (memoBytes + size <= MEMO_MAX_TOTAL && memo.size < 5000) break;
    memoDrop(key);
  }
  memo.set(file, entry);
  memoBytes += size;
}

/** Does the caller's If-None-Match match this copy? */
function stillCurrent(request, etag) {
  const wanted = request.headers.get('if-none-match');
  if (!wanted || !etag) return false;
  const bare = (t) => t.trim().replace(/^W\//, '');
  return wanted.split(',').some((t) => t.trim() === '*' || bare(t) === bare(etag));
}

function dataReply(request, file, { etag, modified, body }, from) {
  const headers = { 'content-type': dataType(file), 'cache-control': 'no-cache', 'x-data-from': from };
  if (etag) headers.etag = etag;
  if (modified) headers['last-modified'] = modified;
  if (stillCurrent(request, etag)) return new Response(null, { status: 304, headers });
  if (request.method === 'HEAD') return new Response(null, { status: 200, headers });
  return new Response(body, { status: 200, headers });
}

async function getData(request, env, file, ctx) {
  if (request.method !== 'GET' && request.method !== 'HEAD') throw new HttpError(405, 'method_not_allowed');
  if (!DATA_PATH.test(file) || file.includes('..')) throw new HttpError(404, 'not_found');
  if (!env.DATA) throw new HttpError(503, 'data_not_set');
  const keep = cacheSeconds(env);
  const now = Date.now();

  // 1. This Worker's memory.
  if (keep) {
    const e = memoGet(file, now);
    if (e?.missing) throw new HttpError(404, 'not_found');
    if (e) return dataReply(request, file, { etag: e.etag, modified: e.modified, body: e.bytes }, 'memory');
  }

  // 2. Cloudflare's cache (the key has no app key or other headers in it).
  const cache = keep && typeof caches !== 'undefined' ? caches.default : null;
  const cacheKey = new Request(new URL(`/v2/data/${file}`, request.url).toString());
  if (cache) {
    let hit = null;
    try {
      hit = await cache.match(cacheKey);
    } catch {
      hit = null;
    }
    if (hit) {
      const etag = hit.headers.get('etag');
      const modified = hit.headers.get('last-modified');
      const size = Number(hit.headers.get('content-length') || 0);
      if (size && size <= MEMO_MAX_FILE) {
        const bytes = await hit.arrayBuffer();
        // Kept in memory only for what is left of the cache's own time.
        const age = Number(hit.headers.get('age') || 0);
        memoPut(file, { until: now + Math.max(1, keep - age) * 1000, etag, modified, bytes });
        return dataReply(request, file, { etag, modified, body: bytes }, 'cache');
      }
      return dataReply(request, file, { etag, modified, body: hit.body }, 'cache');
    }
  }

  // 3. R2.
  let object;
  try {
    object = keep ? await env.DATA.get(file) : await env.DATA.get(file, { onlyIf: request.headers });
  } catch {
    throw new HttpError(503, 'data_unreachable');
  }
  if (!object) {
    if (keep) memoPut(file, { until: now + keep * 1000, missing: true });
    throw new HttpError(404, 'not_found');
  }
  const etag = object.httpEtag;
  const modified = object.uploaded ? object.uploaded.toUTCString() : null;
  if (!keep) {
    // No copies kept: R2 itself answers the caller's "has this changed?" check.
    const headers = { etag, 'content-type': dataType(file), 'cache-control': 'no-cache', 'x-data-from': 'r2' };
    if (modified) headers['last-modified'] = modified;
    if (!('body' in object) || !object.body) return new Response(null, { status: 304, headers });
    if (request.method === 'HEAD') return new Response(null, { status: 200, headers });
    return new Response(object.body, { status: 200, headers });
  }
  const stored = { etag, 'content-type': dataType(file), 'cache-control': `public, max-age=${keep}` };
  if (modified) stored['last-modified'] = modified;
  if (object.size <= MEMO_MAX_FILE) {
    const bytes = await object.arrayBuffer();
    memoPut(file, { until: now + keep * 1000, etag, modified, bytes });
    if (cache && ctx) ctx.waitUntil(cache.put(cacheKey, new Response(bytes, { headers: stored })).catch(() => {}));
    return dataReply(request, file, { etag, modified, body: bytes }, 'r2');
  }
  // Big files: sent on as they arrive, with a second copy going into the cache.
  let body = object.body;
  if (cache && ctx) {
    const [mine, forCache] = object.body.tee();
    body = mine;
    stored['content-length'] = String(object.size);
    ctx.waitUntil(cache.put(cacheKey, new Response(forCache, { headers: stored })).catch(() => {}));
  }
  return dataReply(request, file, { etag, modified, body }, 'r2');
}

// nuvio-data jobs started from the cron below: the ESPN job (ready-made score files) and the
// TheSportsDB scores run (games on now). GitHub's own 5-minute schedules are often skipped for hours.
const NUVIO_DATA_JOBS = [
  { name: 'ESPN job', path: 'repos/homelessbrian/nuvio-data/actions/workflows/espn-schedule.yml/dispatches', body: { ref: 'main' } },
  { name: 'TheSportsDB scores', path: 'repos/homelessbrian/nuvio-data/actions/workflows/nuvio-data.yml/dispatches', body: { ref: 'main', inputs: { mode: 'scores' } } },
];

/** Asks GitHub to run one nuvio-data job now. Returns GitHub's status code, 0 if not asked, -1 if unreachable. */
async function startJob(env, job) {
  const token = typeof env.ESPN_TRIGGER_TOKEN === 'string' ? env.ESPN_TRIGGER_TOKEN.trim() : '';
  if (!token) return 0;
  try {
    const res = await fetch(`${GITHUB_API}/${job.path}`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        accept: 'application/vnd.github+json',
        'content-type': 'application/json',
        'user-agent': 'livetv-cloud',
        'x-github-api-version': '2022-11-28',
      },
      body: JSON.stringify(job.body),
      signal: AbortSignal.timeout(GITHUB_TIMEOUT_MS),
    });
    if (res.status !== 204) console.log(`${job.name} not started: GitHub answered ${res.status}`);
    return res.status;
  } catch {
    console.log(`${job.name} not started: GitHub unreachable`);
    return -1;
  }
}

const startEspnJob = (env) => startJob(env, NUVIO_DATA_JOBS[0]);
const startScoresJob = (env) => startJob(env, NUVIO_DATA_JOBS[1]);

// ---------------------------------------------------------------------------------------------
// ESPN scores, fetched here (every 5 minutes, the cron) and saved straight to the R2 bucket.
// Same files and the same timing as nuvio-data's scripts/espn.py, which this replaces; the
// nuvio-data job still makes the ready-made files from them (started right after this run).
//
// A league's file is saved only when one of its days really changed (ESPN's answer is the same
// text most of the time; only the "fetched at" time moved, and saving that every run was most
// of the R2 bill), or when its saved time is getting old. When each day was last asked for is
// kept in one small file, espn/_state.json, which the nuvio-data job reads too.
//
// Setting ESPN_FETCH = "off" turns this off; the nuvio-data job then asks ESPN itself again,
// as it also does by itself whenever this hasn't finished a good run in the last 15 minutes.
// ---------------------------------------------------------------------------------------------

const ESPN_API = 'https://site.api.espn.com/apis/site/v2/sports/';
const ESPN_LEAGUES_URL = 'https://raw.githubusercontent.com/homelessbrian/nuvio-data/main/espn-leagues.txt';
const ESPN_STATE = 'espn/_state.json';
const ESPN_SOURCE = 'ESPN (site.api.espn.com), unofficial';
const MIN = 60_000;
// How long a day may go before ESPN is asked again (as in espn.py).
const ESPN_TTL = { live: 1.5 * MIN, today: 8 * MIN, edge: 45 * MIN, far: 5 * 60 * MIN };
// Unchanged days are saved again once their saved time is this old, so a copy read straight
// from the file (older apps) never looks out of date (the app allows 20 min / 90 min / 6 h).
const ESPN_RESAVE = { today: 15 * MIN, edge: 60 * MIN, far: 4 * 60 * MIN };
const ESPN_BUDGET_MS = 9 * MIN;
const ESPN_PARALLEL = 6;
const ESPN_UA = 'Mozilla/5.0 (Linux; Android 12; TV) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36';

function parseEspnLeagues(text) {
  const out = [];
  for (const raw of String(text).split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const parts = line.split('|');
    if (parts.length < 2) continue;
    const id = parts[0].trim();
    const path = parts[1].trim();
    if (id && path) out.push({ id, path, query: (parts[2] || '').trim() });
  }
  return out;
}

const espnSafe = (id) => id.replace(/[^a-zA-Z0-9]+/g, '_');

/** Yesterday to a week ahead as yyyyMMdd in US Eastern (the days ESPN groups games by), with what kind of day each is. */
function espnDays(now) {
  const fmt = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/New_York', year: 'numeric', month: '2-digit', day: '2-digit' });
  const out = [];
  for (let d = -1; d <= 7; d++) {
    const day = fmt.format(new Date(now + d * 86_400_000)).replace(/-/g, '');
    if (!out.some((o) => o.day === day)) out.push({ day, kind: d === 0 ? 'today' : d === -1 || d === 1 ? 'edge' : 'far' });
  }
  return out;
}

/** Is anything live, or starting within 30 minutes? (A quick look; the app does the real reading.) */
function liveOrSoon(raw, now) {
  if (!raw) return false;
  if (/"state"\s*:\s*"in"/.test(raw)) return true;
  for (const m of raw.matchAll(/"date"\s*:\s*"(\d{4}-\d\d-\d\dT\d\d:\d\dZ)"/g)) {
    const start = Date.parse(m[1]);
    if (start - now >= 0 && start - now <= 30 * MIN) return true;
  }
  return false;
}

async function espnHash(text) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].slice(0, 10).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function espnDue(info, kind, now) {
  if (!info) return true;
  const age = now - (info.at || 0);
  if (info.live) return age > ESPN_TTL.live;
  return age > ESPN_TTL[kind];
}

async function espnGet(url) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await fetch(url, { headers: { 'user-agent': ESPN_UA, accept: 'application/json' }, signal: AbortSignal.timeout(20_000) });
      if (res.ok) return await res.text();
      await res.body?.cancel();
      if (res.status !== 429 && res.status < 500) return null; // an unknown league path: asking again won't help
    } catch {
      // timed out or unreachable: try again
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
  return null;
}

async function readJson(env, key) {
  try {
    const obj = await env.DATA.get(key);
    return obj ? await obj.json() : null;
  } catch {
    return null;
  }
}

/**
 * One ESPN round. Returns what it did ({ asked, failed, written, skipped }), or null when it
 * didn't run (turned off, no bucket, another round still going, league list unreachable).
 */
async function runEspn(env, now = Date.now(), fetchLeagues = null) {
  if (!env.DATA || String(env.ESPN_FETCH || '').trim().toLowerCase() === 'off') return null;
  const started = Date.now();
  const state = (await readJson(env, ESPN_STATE)) || {};
  if (state.v !== 1) Object.assign(state, { v: 1, leagues: {} });
  state.leagues ||= {};
  if (state.runningSince && now - state.runningSince < ESPN_BUDGET_MS + MIN) return null;

  let leagues;
  try {
    const text = fetchLeagues ? await fetchLeagues() : await (async () => {
      const res = await fetch(ESPN_LEAGUES_URL, { headers: { 'user-agent': 'livetv-cloud' }, signal: AbortSignal.timeout(15_000) });
      if (!res.ok) throw new Error(String(res.status));
      return res.text();
    })();
    leagues = parseEspnLeagues(text);
  } catch {
    leagues = [];
  }
  if (!leagues.length) return null;

  state.runningSince = now;
  await env.DATA.put(ESPN_STATE, JSON.stringify(state), { httpMetadata: { contentType: 'application/json; charset=utf-8' } });

  const days = espnDays(now);
  const oldest = days[0].day;
  const stats = { asked: 0, failed: 0, written: 0, skipped: 0 };
  const queue = [...leagues];

  const doLeague = async (lg) => {
    const ls = (state.leagues[lg.id] ||= { days: {} });
    ls.days ||= {};
    for (const d of Object.keys(ls.days)) if (d < oldest) delete ls.days[d];
    const fresh = {};
    let changed = false;
    for (const { day, kind } of days) {
      const info = ls.days[day];
      if (!espnDue(info, kind, now)) continue;
      if (Date.now() - started > ESPN_BUDGET_MS) { stats.skipped++; return; }
      stats.asked++;
      const raw = await espnGet(`${ESPN_API}${lg.path}/scoreboard?dates=${day}&limit=1000${lg.query}`);
      if (raw === null) { stats.failed++; continue; }
      const h = await espnHash(raw);
      const live = liveOrSoon(raw, now);
      const old = info || {};
      const resave = now - (old.w || 0) > ESPN_RESAVE[kind];
      if (h !== old.h || resave || !!old.live !== live) changed = true;
      fresh[day] = raw;
      ls.days[day] = { at: now, live, h, w: old.w || 0 };
    }
    if (!changed) return;
    // Something to save: the file keeps the days not asked for this time as they were.
    const key = `espn/${espnSafe(lg.id)}.json`;
    const file = (await readJson(env, key)) || {};
    const out = {};
    for (const [d, v] of Object.entries(file.days || {})) if (d >= oldest) out[d] = v;
    for (const [d, raw] of Object.entries(fresh)) {
      out[d] = { fetchedAt: now, raw, liveOrSoon: ls.days[d].live };
      ls.days[d].w = now;
    }
    const text = JSON.stringify({ source: ESPN_SOURCE, id: lg.id, days: out }) + '\n';
    try {
      await env.DATA.put(key, text, { httpMetadata: { contentType: 'application/json; charset=utf-8', cacheControl: 'no-cache' } });
      stats.written++;
    } catch {
      // Not saved: ask again next round.
      for (const d of Object.keys(fresh)) ls.days[d].w = 0, (ls.days[d].h = '');
    }
  };

  await Promise.all(Array.from({ length: ESPN_PARALLEL }, async () => {
    while (queue.length) {
      const lg = queue.shift();
      try {
        await doLeague(lg);
      } catch (e) {
        console.log(`ESPN ${lg.id}: ${e?.message || e}`);
      }
    }
  }));

  // Leagues taken off the list are forgotten.
  const ids = new Set(leagues.map((l) => l.id));
  for (const id of Object.keys(state.leagues)) if (!ids.has(id)) delete state.leagues[id];
  delete state.runningSince;
  const ok = stats.asked === 0 || stats.failed / stats.asked < 0.5;
  state.lastRun = { at: now, tookMs: Date.now() - started, ok, ...stats };
  await env.DATA.put(ESPN_STATE, JSON.stringify(state), { httpMetadata: { contentType: 'application/json; charset=utf-8' } });
  console.log(`ESPN: ${stats.asked} asked, ${stats.failed} failed, ${stats.written} files saved, ${stats.skipped} put off`);
  return stats;
}

async function espnStatus(env) {
  if (String(env.ESPN_FETCH || '').trim().toLowerCase() === 'off') return 'off';
  if (!env.DATA) return 'not_set';
  const state = await readJson(env, ESPN_STATE);
  const r = state?.lastRun;
  if (!r) return 'no_run_yet';
  return { at: new Date(r.at).toISOString(), ok: r.ok, asked: r.asked, failed: r.failed, saved: r.written, tookSeconds: Math.round(r.tookMs / 1000) };
}

export default {
  async scheduled(event, env, ctx) {
    // ESPN first, then the nuvio-data job (it makes the ready-made files from what was saved).
    ctx.waitUntil(
      runEspn(env)
        .catch((e) => console.log(`ESPN round failed: ${e?.message || e}`))
        .then(() => startEspnJob(env)),
    );
    // TheSportsDB scores don't wait for ESPN.
    ctx.waitUntil(startScoresJob(env));
  },

  async fetch(request, env, ctx) {
    try {
      const { pathname } = new URL(request.url);
      if (pathname === '/v1/health') {
        // Says only whether the secret is set and long enough, never what it is.
        const secret = typeof env.SYNC_ENCRYPTION_KEY === 'string' ? env.SYNC_ENCRYPTION_KEY.trim() : '';
        return reply(200, {
          ok: true,
          encryption: secret.length >= MIN_SECRET_LENGTH ? 'ready' : secret ? 'secret_too_short' : 'secret_missing',
          testUpdates: testKeys(env).length > 0 && env.TEST_BUILDS_TOKEN ? 'ready' : 'not_set',
          espnTimer: env.ESPN_TRIGGER_TOKEN ? 'ready' : 'not_set',
          appKey: appKeys(env).length ? 'ready' : env.APP_KEY ? 'key_too_short' : 'not_set',
          sportsData: env.DATA ? 'ready' : 'not_set',
          dataCacheSeconds: cacheSeconds(env),
          espnFetch: await espnStatus(env),
          oldDoor: oldDoorClosesAt(env) === null ? 'open' : oldDoorClosed(env) ? 'closed' : `closes ${new Date(oldDoorClosesAt(env)).toISOString().slice(0, 10)}`,
        });
      }
      if (Object.keys(BUILD_KINDS).some((k) => pathname.startsWith(`/v1/updates/${k}/`))) return await testUpdates(request, env, pathname);

      // Everything under /v2/ is for our own apps only.
      const v2 = pathname.startsWith('/v2/');
      if (v2 && !(await appAllowed(request, env))) {
        throw new HttpError(appKeys(env).length ? 403 : 503, appKeys(env).length ? 'app_not_allowed' : 'app_key_not_set');
      }
      if (pathname.startsWith('/v2/data/')) return await getData(request, env, pathname.slice('/v2/data/'.length), ctx);

      const routes = {
        '/setup': { GET: getSetup, PUT: (e, u) => putSetup(request, e, u), DELETE: deleteSetup },
        '/setup/previous': { GET: getPrevious },
      };
      const path = pathname.replace(/\/+$/, '');
      const version = path.slice(0, 4);
      const route = version === '/v1/' || version === '/v2/' ? routes[path.slice(3)] : null;
      if (!route) throw new HttpError(404, 'not_found');
      if (version === '/v1/' && oldDoorClosed(env)) throw new HttpError(410, 'update_required');
      const handler = route[request.method];
      if (!handler) throw new HttpError(405, 'method_not_allowed');

      const userId = await whoIs(request, env);
      await ensureSchema(env);
      return await handler(env, userId);
    } catch (err) {
      if (err instanceof HttpError) {
        const headers = err.extra.retryAfter ? { 'retry-after': String(err.extra.retryAfter) } : {};
        return reply(err.status, { error: err.code, ...err.extra }, headers);
      }
      // Never include the request or token in an error.
      return reply(500, { error: 'server_error' });
    }
  },
};
