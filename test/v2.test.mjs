// The app-key door (/v2/), the sports data files and closing the old /v1/ door.
//   npm i --no-save miniflare && node test/v2.test.mjs
import { Miniflare } from 'miniflare';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (sub) => `${b64({ alg: 'HS256' })}.${b64({ sub, exp: Math.floor(Date.now() / 1000) + 3600 })}.sig${sub}`;
const USER = '11111111-1111-4111-8111-111111111111';
const TOKEN = jwt('A');
const PUBLIC_KEY = 'public-key';
const APP_KEY = 'app-key-0123456789-abcdefghij';
const OLD_APP_KEY = 'old-app-key-0123456789-abcdef';

const make = (bindings = {}, withData = true) =>
  new Miniflare({
    modules: true,
    bindings: { SYNC_ENCRYPTION_KEY: 'test-secret-0123456789-abcdefghijklmnop-XYZ', ...bindings },
    scriptPath: fileURLToPath(new URL('../src/index.js', import.meta.url)),
    compatibilityDate: '2025-06-01',
    d1Databases: { DB: 'test-db' },
    ...(withData ? { r2Buckets: ['DATA'] } : {}),
    outboundService: async (req) => {
      if (req.headers.get('authorization') !== `Bearer ${TOKEN}`) return new Response('{}', { status: 401 });
      return Response.json({ id: USER });
    },
  });

const call = (mf, method, path, { appKey, signedIn = true, body, headers = {} } = {}) =>
  mf.dispatchFetch(`https://sync.test${path}`, {
    method,
    headers: {
      ...(signedIn ? { authorization: `Bearer ${TOKEN}`, apikey: PUBLIC_KEY } : {}),
      ...(appKey ? { 'x-app-key': appKey } : {}),
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });

let passed = 0;
const test = async (name, fn) => {
  await fn();
  passed++;
  console.log('ok -', name);
};

const mf = make({ APP_KEY: `${APP_KEY}, ${OLD_APP_KEY}` });
const bucket = await mf.getR2Bucket('DATA');
await bucket.put('sportsdb/index.json', '{"leagues":[1,2,3]}');
await bucket.put('espn/compact/index.json', '{"v":1}');

await test('health shows the new settings', async () => {
  const h = await (await call(mf, 'GET', '/v1/health')).json();
  assert.equal(h.appKey, 'ready');
  assert.equal(h.sportsData, 'ready');
  assert.equal(h.oldDoor, 'open');
});

await test('v2 sync needs the app key', async () => {
  assert.equal((await call(mf, 'GET', '/v2/setup')).status, 403);
  assert.equal((await call(mf, 'GET', '/v2/setup', { appKey: 'wrong-key-0123456789-abcdefghij' })).status, 403);
  assert.equal((await call(mf, 'GET', '/v2/setup', { appKey: APP_KEY })).status, 404, 'nothing saved yet');
  assert.equal((await call(mf, 'GET', '/v2/setup', { appKey: OLD_APP_KEY })).status, 404, 'second key works too');
});

await test('v2 sync still needs the Nuvio sign-in', async () => {
  assert.equal((await call(mf, 'GET', '/v2/setup', { appKey: APP_KEY, signedIn: false })).status, 401);
});

await test('v1 and v2 share the same saved copy', async () => {
  const saved = await call(mf, 'PUT', '/v2/setup', { appKey: APP_KEY, body: { baseRevision: 0, data: { a: 1 } } });
  assert.equal(saved.status, 200);
  const old = await (await call(mf, 'GET', '/v1/setup')).json();
  assert.equal(old.revision, 1);
  assert.deepEqual(old.data, { a: 1 });
  const again = await call(mf, 'PUT', '/v1/setup', { body: { baseRevision: 1, data: { a: 2 } } });
  assert.equal(again.status, 200);
  const prev = await (await call(mf, 'GET', '/v2/setup/previous', { appKey: APP_KEY })).json();
  assert.deepEqual(prev.data, { a: 1 });
});

await test('data files need the app key, not a sign-in', async () => {
  assert.equal((await call(mf, 'GET', '/v2/data/sportsdb/index.json', { signedIn: false })).status, 403);
  const res = await call(mf, 'GET', '/v2/data/sportsdb/index.json', { signedIn: false, appKey: APP_KEY });
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /json/);
  assert.deepEqual(await res.json(), { leagues: [1, 2, 3] });
  assert.ok(res.headers.get('etag'));
});

await test('an unchanged file is 304 with no body', async () => {
  const first = await call(mf, 'GET', '/v2/data/espn/compact/index.json', { signedIn: false, appKey: APP_KEY });
  const etag = first.headers.get('etag');
  await first.arrayBuffer();
  const again = await call(mf, 'GET', '/v2/data/espn/compact/index.json', { signedIn: false, appKey: APP_KEY, headers: { 'if-none-match': etag } });
  assert.equal(again.status, 304);
  assert.equal((await again.arrayBuffer()).byteLength, 0);
  // A changed file shows up once the short-lived copy runs out (60 seconds by default).
  await bucket.put('espn/compact/index.json', '{"v":2}');
  const kept = await call(mf, 'GET', '/v2/data/espn/compact/index.json', { signedIn: false, appKey: APP_KEY, headers: { 'if-none-match': etag } });
  assert.equal(kept.status, 304, 'the kept copy still answers');
  assert.equal(kept.headers.get('x-data-from'), 'memory');
});

await test('repeat reads come from the kept copy, not R2', async () => {
  await bucket.put('espn/compact/day/x.json', '{"g":[1]}');
  const first = await call(mf, 'GET', '/v2/data/espn/compact/day/x.json', { signedIn: false, appKey: APP_KEY });
  assert.equal(first.headers.get('x-data-from'), 'r2');
  assert.deepEqual(await first.json(), { g: [1] });
  const second = await call(mf, 'GET', '/v2/data/espn/compact/day/x.json', { signedIn: false, appKey: APP_KEY });
  assert.equal(second.headers.get('x-data-from'), 'memory');
  assert.equal(second.headers.get('etag'), first.headers.get('etag'));
  assert.deepEqual(await second.json(), { g: [1] });
  const head = await call(mf, 'HEAD', '/v2/data/espn/compact/day/x.json', { signedIn: false, appKey: APP_KEY });
  assert.equal(head.status, 200);
  const h = await (await call(mf, 'GET', '/v1/health')).json();
  assert.equal(h.dataCacheSeconds, 60);
});

await test('big files are kept in Cloudflare\'s cache, not memory', async () => {
  const big = JSON.stringify({ raw: 'x'.repeat(1_200_000) });
  await bucket.put('espn/big.json', big);
  const first = await call(mf, 'GET', '/v2/data/espn/big.json', { signedIn: false, appKey: APP_KEY });
  assert.equal(first.headers.get('x-data-from'), 'r2');
  assert.equal((await first.text()).length, big.length);
  await new Promise((r) => setTimeout(r, 200));
  const second = await call(mf, 'GET', '/v2/data/espn/big.json', { signedIn: false, appKey: APP_KEY });
  assert.equal(second.headers.get('x-data-from'), 'cache');
  assert.equal((await second.text()).length, big.length);
  const etag = second.headers.get('etag');
  const same = await call(mf, 'GET', '/v2/data/espn/big.json', { signedIn: false, appKey: APP_KEY, headers: { 'if-none-match': etag } });
  assert.equal(same.status, 304);
  await same.arrayBuffer();
});

await test('a missing file is remembered too', async () => {
  const a = await call(mf, 'GET', '/v2/data/espn/later.json', { signedIn: false, appKey: APP_KEY });
  assert.equal(a.status, 404);
  await a.arrayBuffer();
  await bucket.put('espn/later.json', '{}');
  const b = await call(mf, 'GET', '/v2/data/espn/later.json', { signedIn: false, appKey: APP_KEY });
  assert.equal(b.status, 404, 'still missing until the kept answer runs out');
  await b.arrayBuffer();
});

await test('missing files and odd paths are 404', async () => {
  for (const p of ['/v2/data/nope.json', '/v2/data/../secret', '/v2/data/a/../b.json', '/v2/data/.hidden', '/v2/data/']) {
    const res = await call(mf, 'GET', p, { signedIn: false, appKey: APP_KEY });
    assert.equal(res.status, 404, p);
    await res.arrayBuffer();
  }
});

await test('data files can only be read', async () => {
  const res = await call(mf, 'PUT', '/v2/data/sportsdb/index.json', { signedIn: false, appKey: APP_KEY, body: { x: 1 } });
  assert.equal(res.status, 405);
});

await test('unknown v2 routes are 404 once the key is right', async () => {
  assert.equal((await call(mf, 'GET', '/v2/whatever', { appKey: APP_KEY })).status, 404);
});
await mf.dispose();

await test('with DATA_CACHE_SECONDS=0 every read goes to R2', async () => {
  const off = make({ APP_KEY, DATA_CACHE_SECONDS: '0' });
  const b = await off.getR2Bucket('DATA');
  await b.put('espn/compact/index.json', '{"v":1}');
  const first = await call(off, 'GET', '/v2/data/espn/compact/index.json', { signedIn: false, appKey: APP_KEY });
  const etag = first.headers.get('etag');
  await first.arrayBuffer();
  const same = await call(off, 'GET', '/v2/data/espn/compact/index.json', { signedIn: false, appKey: APP_KEY, headers: { 'if-none-match': etag } });
  assert.equal(same.status, 304);
  assert.equal(same.headers.get('x-data-from'), 'r2');
  await b.put('espn/compact/index.json', '{"v":2}');
  const changed = await call(off, 'GET', '/v2/data/espn/compact/index.json', { signedIn: false, appKey: APP_KEY, headers: { 'if-none-match': etag } });
  assert.equal(changed.status, 200);
  assert.deepEqual(await changed.json(), { v: 2 });
  await off.dispose();
});

await test('without APP_KEY every v2 route is refused, v1 keeps working', async () => {
  const bare = make({}, false);
  assert.equal((await call(bare, 'GET', '/v2/setup', { appKey: APP_KEY })).status, 503);
  assert.equal((await call(bare, 'GET', '/v2/data/x.json', { appKey: APP_KEY })).status, 503);
  assert.equal((await call(bare, 'GET', '/v1/setup')).status, 404);
  const h = await (await call(bare, 'GET', '/v1/health')).json();
  assert.equal(h.appKey, 'not_set');
  assert.equal(h.sportsData, 'not_set');
  await bare.dispose();
});

await test('a short APP_KEY counts as not set', async () => {
  const short = make({ APP_KEY: 'short' }, false);
  assert.equal((await call(short, 'GET', '/v2/setup', { appKey: 'short' })).status, 503);
  assert.equal((await (await call(short, 'GET', '/v1/health')).json()).appKey, 'key_too_short');
  await short.dispose();
});

await test('with the key but no bucket, data is 503', async () => {
  const nob = make({ APP_KEY }, false);
  assert.equal((await call(nob, 'GET', '/v2/data/x.json', { appKey: APP_KEY, signedIn: false })).status, 503);
  await nob.dispose();
});

await test('a closing date in the future leaves v1 open', async () => {
  const soon = make({ APP_KEY, OLD_DOOR_CLOSES_AT: '2099-01-01' }, false);
  assert.equal((await call(soon, 'GET', '/v1/setup')).status, 404);
  assert.equal((await (await call(soon, 'GET', '/v1/health')).json()).oldDoor, 'closes 2099-01-01');
  await soon.dispose();
});

await test('after the closing date v1 sync is 410 and v2 still works', async () => {
  const closed = make({ APP_KEY, OLD_DOOR_CLOSES_AT: '2020-01-01' }, false);
  const res = await call(closed, 'GET', '/v1/setup');
  assert.equal(res.status, 410);
  assert.equal((await res.json()).error, 'update_required');
  assert.equal((await call(closed, 'PUT', '/v1/setup', { body: { baseRevision: 0, data: { a: 1 } } })).status, 410);
  assert.equal((await call(closed, 'GET', '/v2/setup', { appKey: APP_KEY })).status, 404);
  assert.equal((await (await call(closed, 'GET', '/v1/health')).json()).oldDoor, 'closed');
  await closed.dispose();
});

console.log(`${passed} passed`);
