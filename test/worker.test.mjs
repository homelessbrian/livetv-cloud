// Runs the Worker locally against an emulated D1 database and a pretend Nuvio sign-in server.
//   npm i --no-save miniflare && node test/worker.test.mjs
import { Miniflare } from 'miniflare';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (sub, expSec = Math.floor(Date.now() / 1000) + 3600) => `${b64({ alg: 'HS256' })}.${b64({ sub, exp: expSec })}.sig${sub}`;
const USERS = {
  A: '11111111-1111-4111-8111-111111111111',
  B: '22222222-2222-4222-8222-222222222222',
  C: '33333333-3333-4333-8333-333333333333',
  D: '44444444-4444-4444-8444-444444444444',
};
const KEY = 'public-key';
const tokens = Object.fromEntries(Object.keys(USERS).map((k) => [k, jwt(k)]));

let nuvioCalls = 0;
let nuvioMode = 'ok'; // ok | down | error500
const SECRET = 'test-secret-0123456789-abcdefghijklmnop-XYZ';
const mf = new Miniflare({
  modules: true,
  bindings: { SYNC_ENCRYPTION_KEY: SECRET },
  scriptPath: fileURLToPath(new URL('../src/index.js', import.meta.url)),
  compatibilityDate: '2025-06-01',
  d1Databases: { DB: 'test-db' },
  outboundService: async (req) => {
    const url = new URL(req.url);
    assert.equal(url.host, 'api.nuvio.tv');
    assert.equal(url.pathname, '/auth/v1/user');
    nuvioCalls++;
    if (nuvioMode === 'down') throw new Error('network down');
    if (nuvioMode === 'error500') return new Response('oops', { status: 500 });
    if (req.headers.get('apikey') !== KEY) return new Response('{}', { status: 401 });
    const bearer = (req.headers.get('authorization') || '').replace('Bearer ', '');
    const who = Object.keys(tokens).find((k) => tokens[k] === bearer);
    if (!who) return new Response('{"msg":"bad jwt"}', { status: 401 });
    return Response.json({ id: USERS[who], email: `${who}@example.com` });
  },
});

const call = (method, path, who, body, headers = {}) =>
  mf.dispatchFetch(`https://sync.test${path}`, {
    method,
    headers: {
      ...(who ? { authorization: `Bearer ${tokens[who] ?? who}`, apikey: KEY } : {}),
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
const json = async (res) => res.json();
const setup = (n, extra = {}) => ({ playlists: { t: 'str', v: `list-${n}` }, ...extra });

const SCHEMA_FOR_TEST = `CREATE TABLE IF NOT EXISTS setups (
  user_id TEXT PRIMARY KEY, revision INTEGER NOT NULL, data TEXT NOT NULL, saved_at INTEGER NOT NULL,
  device TEXT NOT NULL DEFAULT '', device_id TEXT NOT NULL DEFAULT '', prev_revision INTEGER, prev_data TEXT,
  prev_saved_at INTEGER, saves_day TEXT NOT NULL DEFAULT '', saves_count INTEGER NOT NULL DEFAULT 0)`;
let passed = 0;
const test = async (name, fn) => {
  await fn();
  passed++;
  console.log('ok -', name);
};

await test('health needs no sign-in', async () => {
  const res = await call('GET', '/v1/health');
  assert.equal(res.status, 200);
  assert.equal((await json(res)).encryption, 'ready');
});

await test('sign-in problems are 401 and unknown routes are refused', async () => {
  assert.equal((await call('GET', '/v1/setup')).status, 401);
  assert.equal((await call('GET', '/v1/setup', 'not-a-token-at-all-1234567890')).status, 401);
  const before = nuvioCalls;
  const expired = jwt('A', Math.floor(Date.now() / 1000) - 10);
  assert.equal((await call('GET', '/v1/setup', expired)).status, 401);
  assert.equal(nuvioCalls, before, 'an expired token must not reach Nuvio');
  const noKey = await mf.dispatchFetch('https://sync.test/v1/setup', { headers: { authorization: `Bearer ${tokens.A}` } });
  assert.equal(noKey.status, 401);
  const wrongKey = await mf.dispatchFetch('https://sync.test/v1/setup', { headers: { authorization: `Bearer ${tokens.A}`, apikey: 'nope' } });
  assert.equal(wrongKey.status, 401);
  assert.equal((await call('GET', '/v1/nothing', 'A')).status, 404);
  assert.equal((await call('POST', '/v1/setup', 'A', {})).status, 405);
});

await test('nothing saved yet is 404', async () => {
  assert.equal((await call('GET', '/v1/setup', 'A')).status, 404);
  assert.equal((await call('GET', '/v1/setup/previous', 'A')).status, 404);
});

await test('first save, read back, and a second first-save is refused', async () => {
  const put = await call('PUT', '/v1/setup', 'A', { baseRevision: 0, device: 'Living room', deviceId: 'tv-1', data: setup(1) });
  assert.equal(put.status, 200);
  assert.equal((await json(put)).revision, 1);
  const got = await json(await call('GET', '/v1/setup', 'A'));
  assert.equal(got.revision, 1);
  assert.equal(got.device, 'Living room');
  assert.deepEqual(got.data, setup(1));
  const again = await call('PUT', '/v1/setup', 'A', { baseRevision: 0, data: setup(9) });
  assert.equal(again.status, 409);
  assert.equal((await json(again)).revision, 1);
});

await test('save keeps the previous copy; stale saves are refused', async () => {
  const put = await call('PUT', '/v1/setup', 'A', { baseRevision: 1, device: 'Bedroom', deviceId: 'tv-2', data: setup(2) });
  assert.equal((await json(put)).revision, 2);
  const prev = await json(await call('GET', '/v1/setup/previous', 'A'));
  assert.equal(prev.revision, 1);
  assert.deepEqual(prev.data, setup(1));
  const stale = await call('PUT', '/v1/setup', 'A', { baseRevision: 1, data: setup(3) });
  assert.equal(stale.status, 409);
  const body = await json(stale);
  assert.equal(body.revision, 2);
  assert.equal(body.device, 'Bedroom');
  assert.deepEqual((await json(await call('GET', '/v1/setup', 'A'))).data, setup(2));
});

await test('accounts are separate', async () => {
  assert.equal((await call('GET', '/v1/setup', 'B')).status, 404);
  assert.equal((await call('PUT', '/v1/setup', 'B', { baseRevision: 0, data: setup('b') })).status, 200);
  assert.deepEqual((await json(await call('GET', '/v1/setup', 'A'))).data, setup(2));
  assert.deepEqual((await json(await call('GET', '/v1/setup', 'B'))).data, setup('b'));
});

await test('empty, oversized and broken saves are refused', async () => {
  assert.equal((await call('PUT', '/v1/setup', 'A', { baseRevision: 2, data: {} })).status, 422);
  assert.equal((await call('PUT', '/v1/setup', 'A', { baseRevision: 2 })).status, 422);
  assert.equal((await call('PUT', '/v1/setup', 'A', { baseRevision: 2, data: [1] })).status, 422);
  const big = { x: { t: 'str', v: 'y'.repeat(1200 * 1024) } };
  assert.equal((await call('PUT', '/v1/setup', 'A', { baseRevision: 2, data: big })).status, 413);
  const noise = Array.from({ length: 900 * 1024 }, () => Math.random().toString(36)[2] ?? 'a').join('');
  assert.equal((await call('PUT', '/v1/setup', 'A', { baseRevision: 2, data: { x: { t: 'str', v: noise } } })).status, 413, 'too big even squeezed');
  const broken = await mf.dispatchFetch('https://sync.test/v1/setup', {
    method: 'PUT', headers: { authorization: `Bearer ${tokens.A}`, apikey: KEY }, body: '{nope',
  });
  assert.equal(broken.status, 400);
  assert.equal((await json(await call('GET', '/v1/setup', 'A'))).revision, 2, 'refused saves change nothing');
});

await test('two saves at the same moment: one wins, one is told to re-sync', async () => {
  const [one, two] = await Promise.all([
    call('PUT', '/v1/setup', 'A', { baseRevision: 2, data: setup('x') }),
    call('PUT', '/v1/setup', 'A', { baseRevision: 2, data: setup('y') }),
  ]);
  assert.deepEqual([one.status, two.status].sort(), [200, 409]);
  assert.equal((await json(await call('GET', '/v1/setup', 'A'))).revision, 3);
});

await test('a checked token is remembered; Nuvio is not asked every time', async () => {
  await call('GET', '/v1/setup', 'D'); // first time
  const before = nuvioCalls;
  for (let i = 0; i < 5; i++) await call('GET', '/v1/setup', 'D');
  assert.equal(nuvioCalls, before);
});

await test('Nuvio trouble is 503 (keep working offline), a rejected token is 401', async () => {
  const fresh = jwt('B', Math.floor(Date.now() / 1000) + 7200);
  tokens.B2 = fresh; // not known to the pretend Nuvio
  assert.equal((await call('GET', '/v1/setup', 'B2')).status, 401);
  nuvioMode = 'down';
  assert.equal((await call('GET', '/v1/setup', jwt('C', Math.floor(Date.now() / 1000) + 5000))).status, 503);
  nuvioMode = 'error500';
  assert.equal((await call('GET', '/v1/setup', jwt('C', Math.floor(Date.now() / 1000) + 5001))).status, 503);
  nuvioMode = 'ok';
});

await test('delete removes both copies and a later save starts over', async () => {
  assert.equal((await call('DELETE', '/v1/setup', 'A')).status, 200);
  assert.equal((await call('GET', '/v1/setup', 'A')).status, 404);
  assert.equal((await call('GET', '/v1/setup/previous', 'A')).status, 404);
  const old = await call('PUT', '/v1/setup', 'A', { baseRevision: 3, data: setup('z') });
  assert.equal(old.status, 409);
  assert.equal((await json(old)).revision, 0);
  assert.equal((await call('PUT', '/v1/setup', 'A', { baseRevision: 0, data: setup('z') })).status, 200);
});

await test('daily save limit', async () => {
  let rev = 0;
  let okCount = 0;
  let refused;
  for (let i = 0; i < 520; i++) {
    const res = await call('PUT', '/v1/setup', 'C', { baseRevision: rev, data: setup(i) });
    if (res.status === 200) { rev = (await json(res)).revision; okCount++; } else { refused = res; break; }
  }
  assert.equal(okCount, 500);
  assert.equal(refused.status, 429);
  assert.ok(Number(refused.headers.get('retry-after')) >= 60);
});

// ---- encryption ----
const dbOf = () => mf.getD1Database('DB');
const rowOf = (id) => dbOf().then((db) => db.prepare('SELECT * FROM setups WHERE user_id = ?').bind(id).first());

await test('what is stored is encrypted, not readable text', async () => {
  const secretSetup = { xtream: { t: 'str', v: 'http://host/get.php?username=bob&password=hunter2-PIN-4321' } };
  assert.equal((await call('PUT', '/v1/setup', 'D', { baseRevision: 0, data: secretSetup })).status, 200);
  assert.equal((await call('PUT', '/v1/setup', 'D', { baseRevision: 1, data: secretSetup })).status, 200);
  const row = await rowOf(USERS.D);
  for (const stored of [row.data, row.prev_data]) {
    assert.ok(stored.startsWith('enc2:'));
    assert.ok(!stored.includes('hunter2') && !stored.includes('bob'));
  }
  assert.deepEqual((await json(await call('GET', '/v1/setup', 'D'))).data, secretSetup);
  assert.deepEqual((await json(await call('GET', '/v1/setup/previous', 'D'))).data, secretSetup);
});

await test('same setup saved twice gives different stored text', async () => {
  const one = (await rowOf(USERS.D)).data;
  const prev = (await rowOf(USERS.D)).prev_data;
  assert.notEqual(one, prev);
});

await test('a large setup (250 KB) saves and reads back', async () => {
  const big = { x: { t: 'str', v: 'y'.repeat(250 * 1024) } };
  const rev = (await json(await call('GET', '/v1/setup', 'D'))).revision;
  assert.equal((await call('PUT', '/v1/setup', 'D', { baseRevision: rev, data: big })).status, 200);
  assert.deepEqual((await json(await call('GET', '/v1/setup', 'D'))).data, big);
});

await test('a copy moved to another account cannot be read', async () => {
  const db = await dbOf();
  const mine = await rowOf(USERS.D);
  await call('DELETE', '/v1/setup', 'B');
  await db.prepare(`INSERT INTO setups (user_id, revision, data, saved_at) VALUES (?, 1, ?, 1)`).bind(USERS.B, mine.data).run();
  assert.equal((await call('GET', '/v1/setup', 'B')).status, 503);
  await call('DELETE', '/v1/setup', 'B');
});

await test('an older readable copy is still read, and gets encrypted', async () => {
  const db = await dbOf();
  const old = JSON.stringify(setup('old'));
  await db.prepare(`INSERT INTO setups (user_id, revision, data, saved_at, prev_revision, prev_data, prev_saved_at) VALUES (?, 5, ?, 1, 4, ?, 1)`)
    .bind(USERS.B, old, JSON.stringify(setup('older'))).run();
  assert.deepEqual((await json(await call('GET', '/v1/setup', 'B'))).data, setup('old'));
  const row = await rowOf(USERS.B);
  assert.ok(row.data.startsWith('enc2:') && row.prev_data.startsWith('enc2:'));
  assert.equal(row.revision, 5);
  assert.deepEqual((await json(await call('GET', '/v1/setup/previous', 'B'))).data, setup('older'));
});

await test('saving over an older readable copy encrypts the moved-aside copy too', async () => {
  const db = await dbOf();
  await call('DELETE', '/v1/setup', 'B');
  await db.prepare(`INSERT INTO setups (user_id, revision, data, saved_at) VALUES (?, 2, ?, 1)`).bind(USERS.B, JSON.stringify(setup('legacy'))).run();
  assert.equal((await call('PUT', '/v1/setup', 'B', { baseRevision: 2, data: setup('new') })).status, 200);
  const row = await rowOf(USERS.B);
  assert.ok(row.data.startsWith('enc2:') && row.prev_data.startsWith('enc2:'));
  assert.deepEqual((await json(await call('GET', '/v1/setup/previous', 'B'))).data, setup('legacy'));
});

// ---- no secret / wrong secret ----
const mf2 = (bindings) => new Miniflare({
  modules: true,
  bindings,
  scriptPath: fileURLToPath(new URL('../src/index.js', import.meta.url)),
  compatibilityDate: '2025-06-01',
  d1Databases: { DB: 'test-db' },
  d1Persist: false,
  outboundService: async () => Response.json({ id: USERS.A }),
});
const call2 = (m, method, path, body) => m.dispatchFetch(`https://sync.test${path}`, {
  method,
  headers: { authorization: `Bearer ${jwt('A')}`, apikey: KEY, ...(body ? { 'content-type': 'application/json' } : {}) },
  body: body ? JSON.stringify(body) : undefined,
});

await test('without the secret a save is refused and nothing readable is stored', async () => {
  const m = mf2({});
  assert.equal((await call2(m, 'PUT', '/v1/setup', { baseRevision: 0, data: setup(1) })).status, 503);
  const db = await m.getD1Database('DB');
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM setups').first()).n, 0);
  await m.dispose();
});

await test('a short secret counts as no secret', async () => {
  const m = mf2({ SYNC_ENCRYPTION_KEY: 'too-short' });
  assert.equal((await (await m.dispatchFetch('https://sync.test/v1/health')).json()).encryption, 'secret_too_short');
  const res = await call2(m, 'PUT', '/v1/setup', { baseRevision: 0, data: setup(1) });
  assert.equal(res.status, 503);
  assert.equal((await res.json()).error, 'encryption_not_set');
  await m.dispose();
});

await test('a different secret cannot read the copy', async () => {
  const db = await dbOf();
  const mine = await rowOf(USERS.D);
  const m = mf2({ SYNC_ENCRYPTION_KEY: 'another-secret-0123456789-abcdefghijklmnop' });
  const mdb = await m.getD1Database('DB');
  await mdb.prepare(SCHEMA_FOR_TEST).run();
  await mdb.prepare(`INSERT INTO setups (user_id, revision, data, saved_at) VALUES (?, 1, ?, 1)`).bind(USERS.A, mine.data).run();
  const res = await call2(m, 'GET', '/v1/setup');
  assert.equal(res.status, 503);
  assert.equal((await res.json()).error, 'cannot_decrypt');
  await m.dispose();
});

await test('a big but ordinary setup (600 KB of text) is squeezed, saved and read back', async () => {
  const before = await json(await call('GET', '/v1/setup', 'A'));
  const REV = before.revision;
  const lots = { x: { t: 'str', v: Array.from({ length: 12000 }, (_, i) => `channel-${i}|Some Channel Name ${i}|group ${i % 40}`).join('\n') } };
  assert.ok(JSON.stringify(lots).length > 500 * 1024);
  const put = await call('PUT', '/v1/setup', 'A', { baseRevision: REV, data: lots });
  assert.equal(put.status, 200);
  assert.deepEqual((await json(await call('GET', '/v1/setup', 'A'))).data, lots);
  assert.deepEqual((await json(await call('GET', '/v1/setup/previous', 'A'))).data, before.data);
  // put it back so later tests see the revision they expect
  assert.equal((await call('PUT', '/v1/setup', 'A', { baseRevision: REV + 1, data: before.data })).status, 200);
});

console.log(`\n${passed} tests passed`);
await mf.dispose();
