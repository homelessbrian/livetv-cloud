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
// The saved setup (it holds IPTV logins and the parental PIN) is encrypted before it goes into the
// database: AES-256-GCM, with a separate key per Nuvio account made from the secret
// SYNC_ENCRYPTION_KEY (set in the Cloudflare dashboard, never in the code). Without that secret a
// save is refused, so nothing readable is ever written. A copy saved before this was added is
// still read fine and is encrypted the next time it is touched.
//
// A save carries the revision it was based on. If someone else saved in between, it is refused
// with 409 and the current revision, so a TV that was offline can never overwrite newer work.

const MAX_BODY_BYTES = 256 * 1024;
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

const ENC_PREFIX = 'enc1:';
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

/** Text -> "enc1:<iv>:<encrypted>". The account id is bound in, so a row can't be moved to another account. */
async function encryptText(env, userId, plain) {
  const key = await accountKey(env, userId);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(userId) },
    key,
    new TextEncoder().encode(plain)
  );
  return `${ENC_PREFIX}${toB64(iv)}:${toB64(new Uint8Array(sealed))}`;
}

const isEncrypted = (stored) => typeof stored === 'string' && stored.startsWith(ENC_PREFIX);

/** Back to text. A copy saved before encryption existed is returned as it is. */
async function decryptText(env, userId, stored) {
  if (!isEncrypted(stored)) return stored;
  const key = await accountKey(env, userId);
  try {
    const [iv, sealed] = stored.slice(ENC_PREFIX.length).split(':');
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(iv), additionalData: new TextEncoder().encode(userId) },
      key,
      fromB64(sealed)
    );
    return new TextDecoder().decode(plain);
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
    schemaReady = env.DB.prepare(SCHEMA).run().catch((err) => {
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
  if (!row || !row.prev_data) throw new HttpError(404, 'none');
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

  // The previous copy moves aside, and the save only goes through if nobody saved in between.
  const saved = await env.DB.prepare(
    `UPDATE setups SET
       prev_revision = revision, prev_data = ?, prev_saved_at = saved_at,
       revision = revision + 1, data = ?, saved_at = ?, device = ?, device_id = ?,
       saves_count = CASE WHEN saves_day = ? THEN saves_count + 1 ELSE 1 END, saves_day = ?
     WHERE user_id = ? AND revision = ?`
  ).bind(previous, encoded, now, device, deviceId, today, today, userId, row.revision).run();
  if (!saved.meta.changes) {
    const current = await getRow(env, userId);
    throw new HttpError(409, 'conflict', { revision: current?.revision ?? 0, savedAt: current?.saved_at, device: current?.device });
  }
  return reply(200, { revision: row.revision + 1, savedAt: now });
}

async function deleteSetup(env, userId) {
  await env.DB.prepare('DELETE FROM setups WHERE user_id = ?').bind(userId).run();
  return reply(200, { ok: true });
}

export default {
  async fetch(request, env) {
    try {
      const { pathname } = new URL(request.url);
      if (pathname === '/v1/health') return reply(200, { ok: true });

      const routes = {
        '/v1/setup': { GET: getSetup, PUT: (e, u) => putSetup(request, e, u), DELETE: deleteSetup },
        '/v1/setup/previous': { GET: getPrevious },
      };
      const route = routes[pathname.replace(/\/+$/, '')];
      if (!route) throw new HttpError(404, 'not_found');
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
