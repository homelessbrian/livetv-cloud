// Tests the private test-build routes against a pretend GitHub.
//   npm i --no-save miniflare && node test/updates.test.mjs
import { Miniflare } from 'miniflare';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

const KEY = 'tester-key-0123456789';
const KEY2 = 'second-key-abcdefghij';
const APK_BYTES = Buffer.from('PK-fake-apk-bytes-'.repeat(200));
const sha = 'a'.repeat(64);

const release = (code, extra = {}) => ({
  tag_name: `test-${code}`,
  name: `1.1.0-beta.9-test.${code}`,
  body: `notes ${code}`,
  draft: false,
  published_at: '2026-11-02T01:00:00Z',
  assets: [{ id: code * 10, name: `NuvioIPTV-Test-${code}.apk`, size: APK_BYTES.length, state: 'uploaded', digest: `sha256:${sha}` }],
  ...extra,
});

let githubCalls = 0;
let githubMode = 'ok'; // ok | down | error
let releases = [];
let sawTokenOnGithub = null;
let sawTokenOnDownload = null;

function make(bindings = {}) {
  return new Miniflare({
    modules: true,
    bindings: { TESTER_KEY: KEY, TEST_BUILDS_TOKEN: 'ghp_fake_token', ...bindings },
    scriptPath: fileURLToPath(new URL('../src/index.js', import.meta.url)),
    compatibilityDate: '2025-06-01',
    d1Databases: { DB: 'test-db' },
    outboundService: async (req) => {
      const url = new URL(req.url);
      if (url.host === 'api.github.com') {
        githubCalls++;
        if (githubMode === 'down') throw new Error('network down');
        if (githubMode === 'error') return new Response('{}', { status: 500 });
        sawTokenOnGithub = req.headers.get('authorization');
        if (url.pathname === '/repos/homelessbrian/Nuvio_Testing/releases') return Response.json(releases);
        const m = /^\/repos\/homelessbrian\/Nuvio_Testing\/releases\/assets\/(\d+)$/.exec(url.pathname);
        if (m) return new Response(null, { status: 302, headers: { location: `https://objects.example/signed/${m[1]}?sig=1` } });
        return new Response('{}', { status: 404 });
      }
      if (url.host === 'objects.example') {
        sawTokenOnDownload = req.headers.get('authorization');
        return new Response(APK_BYTES, { headers: { 'content-length': String(APK_BYTES.length) } });
      }
      throw new Error(`unexpected host ${url.host}`);
    },
  });
}

const get = (m, path, headers = {}, method = 'GET') => m.dispatchFetch(`https://sync.test${path}`, { method, headers });
let passed = 0;
const test = async (name, fn) => {
  githubMode = 'ok';
  githubCalls = 0;
  releases = [release(55), release(57), release(56), release(54), release(53), release(52)];
  const m = make();
  try {
    await fn(m);
  } finally {
    await m.dispose();
  }
  passed++;
  console.log('ok -', name);
};

await test('without the right key it looks like a page that does not exist', async (m) => {
  for (const headers of [{}, { 'x-tester-key': 'wrong-key-wrong-key-1' }, { 'x-tester-key': KEY.slice(0, 10) }]) {
    const res = await get(m, '/v1/updates/test/latest', headers);
    assert.equal(res.status, 404);
    assert.equal((await res.json()).error, 'not_found');
  }
  assert.equal((await get(m, '/v1/updates/test/latest?key=nope-nope-nope-nope')).status, 404);
  assert.equal(githubCalls, 0, 'GitHub must not be asked for strangers');
  assert.equal((await get(m, '/v1/updates/test/latest', { 'x-tester-key': KEY }, 'POST')).status, 404);
});

await test('the key works in a header or in the address', async (m) => {
  assert.equal((await get(m, '/v1/updates/test/latest', { 'x-tester-key': KEY })).status, 200);
  assert.equal((await get(m, `/v1/updates/test/latest?key=${KEY}`)).status, 200);
});

await test('several keys can be allowed, and short ones never are', async () => {
  const m = make({ TESTER_KEY: `${KEY2}, short ,${KEY}` });
  assert.equal((await get(m, '/v1/updates/test/latest', { 'x-tester-key': KEY2 })).status, 200);
  assert.equal((await get(m, '/v1/updates/test/latest', { 'x-tester-key': KEY })).status, 200);
  assert.equal((await get(m, '/v1/updates/test/latest', { 'x-tester-key': 'short' })).status, 404);
  await m.dispose();
  const none = make({ TESTER_KEY: 'tooshort' });
  assert.equal((await get(none, '/v1/updates/test/latest', { 'x-tester-key': 'tooshort' })).status, 404);
  await none.dispose();
});

await test('the manifest names the newest build, with a checksum and older ones', async (m) => {
  const res = await get(m, '/v1/updates/test/latest', { 'x-tester-key': KEY });
  const body = await res.json();
  assert.equal(body.channel, 'test');
  assert.equal(body.versionCode, 57);
  assert.equal(body.versionName, '1.1.0-beta.9-test.57');
  assert.equal(body.notes, 'notes 57');
  assert.equal(body.apk.sha256, sha);
  assert.equal(body.apk.size, APK_BYTES.length);
  assert.equal(body.apk.url, 'https://sync.test/v1/updates/test/apk/57');
  assert.deepEqual(body.previous.map((p) => p.versionCode), [56, 55, 54, 53]);
  assert.ok(!JSON.stringify(body).includes(KEY), 'the key must never be echoed');
  assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.equal(sawTokenOnGithub, 'Bearer ghp_fake_token');
});

await test('drafts, other tags and releases without an APK are ignored', async (m) => {
  releases = [
    release(70, { draft: true }),
    release(69, { tag_name: 'v1.2.3' }),
    release(68, { assets: [] }),
    release(67, { assets: [{ id: 1, name: 'notes.txt', state: 'uploaded' }] }),
    release(66, { assets: [{ id: 2, name: 'x.apk', state: 'starter' }] }),
    release(60),
  ];
  const body = await (await get(m, '/v1/updates/test/latest', { 'x-tester-key': KEY })).json();
  assert.equal(body.versionCode, 60);
  assert.deepEqual(body.previous, []);
});

await test('a missing checksum is reported as null, not guessed', async (m) => {
  releases = [release(60, { assets: [{ id: 600, name: 'a.apk', state: 'uploaded', size: 5 }] })];
  const body = await (await get(m, '/v1/updates/test/latest', { 'x-tester-key': KEY })).json();
  assert.equal(body.apk.sha256, null);
});

await test('no test builds yet is 404', async (m) => {
  releases = [];
  const res = await get(m, '/v1/updates/test/latest', { 'x-tester-key': KEY });
  assert.equal(res.status, 404);
  assert.equal((await res.json()).error, 'none');
});

await test('the APK is passed through, and the GitHub token is not sent to the file host', async (m) => {
  const res = await get(m, '/v1/updates/test/apk/56', { 'x-tester-key': KEY });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'application/vnd.android.package-archive');
  assert.equal(res.headers.get('content-length'), String(APK_BYTES.length));
  assert.match(res.headers.get('content-disposition'), /NuvioIPTV-Test-56\.apk/);
  assert.deepEqual(Buffer.from(await res.arrayBuffer()), APK_BYTES);
  assert.equal(sawTokenOnDownload, null);
  assert.equal((await get(m, '/v1/updates/test/apk/999', { 'x-tester-key': KEY })).status, 404);
  assert.equal((await get(m, '/v1/updates/test/apk/abc', { 'x-tester-key': KEY })).status, 404);
  assert.equal((await get(m, '/v1/updates/test/apk/56', {})).status, 404);
});

await test('download gives the newest APK for a first install', async (m) => {
  const res = await get(m, `/v1/updates/test/download?key=${KEY}`);
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-disposition'), /NuvioIPTV-Test-57\.apk/);
  assert.equal((await res.arrayBuffer()).byteLength, APK_BYTES.length);
});

await test('GitHub being down is a clear 503, not a crash', async (m) => {
  githubMode = 'down';
  let res = await get(m, '/v1/updates/test/latest', { 'x-tester-key': KEY });
  assert.equal(res.status, 503);
  assert.equal((await res.json()).error, 'github_unreachable');
  githubMode = 'error';
  const fresh = make();
  res = await get(fresh, '/v1/updates/test/latest', { 'x-tester-key': KEY });
  assert.equal(res.status, 503);
  await fresh.dispose();
});

await test('without the GitHub token it says so, and health reflects it', async () => {
  const m = make({ TEST_BUILDS_TOKEN: '' });
  const res = await get(m, '/v1/updates/test/latest', { 'x-tester-key': KEY });
  assert.equal(res.status, 503);
  assert.equal((await res.json()).error, 'test_updates_not_set');
  assert.equal((await (await get(m, '/v1/health')).json()).testUpdates, 'not_set');
  await m.dispose();
  const ok = make();
  const health = await (await get(ok, '/v1/health')).json();
  assert.equal(health.testUpdates, 'ready');
  assert.ok(!JSON.stringify(health).includes('ghp_fake_token') && !JSON.stringify(health).includes(KEY));
  await ok.dispose();
});

await test('the list is remembered for a minute so GitHub is not asked every time', async (m) => {
  await get(m, '/v1/updates/test/latest', { 'x-tester-key': KEY });
  await get(m, '/v1/updates/test/latest', { 'x-tester-key': KEY });
  await get(m, '/v1/updates/test/apk/57', { 'x-tester-key': KEY });
  assert.equal(githubCalls, 1 + 1, 'one list call plus one file call');
});

await test('phone test builds have their own list and never mix with the TV ones', async (m) => {
  const mobile = (code) => release(code, {
    tag_name: `mobile-test-${code}`,
    name: `Mobile 0.6.6-test.${code}`,
    assets: [{ id: code * 10, name: `Nuvio-IPTV-Mobile-Test-${code}.apk`, size: APK_BYTES.length, state: 'uploaded', digest: `sha256:${sha}` }],
  });
  releases = [mobile(900), release(57), mobile(899), release(56)];
  const tv = await (await get(m, '/v1/updates/test/latest', { 'x-tester-key': KEY })).json();
  assert.equal(tv.versionCode, 57);
  assert.deepEqual(tv.previous.map((p) => p.versionCode), [56]);
  const res = await get(m, '/v1/updates/mobile-test/latest', { 'x-tester-key': KEY });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.versionCode, 900);
  assert.equal(body.versionName, '0.6.6-test.900');
  assert.equal(body.apk.sha256, sha);
  assert.equal(body.apk.url, 'https://sync.test/v1/updates/mobile-test/apk/900');
  assert.deepEqual(body.previous.map((p) => p.versionCode), [899]);
  const apk = await get(m, '/v1/updates/mobile-test/apk/899', { 'x-tester-key': KEY });
  assert.equal(apk.status, 200);
  assert.match(apk.headers.get('content-disposition'), /Mobile-Test-899\.apk/);
  assert.equal((await get(m, '/v1/updates/mobile-test/apk/57', { 'x-tester-key': KEY })).status, 404, 'a TV build is not a phone build');
  assert.equal((await get(m, '/v1/updates/test/apk/900', { 'x-tester-key': KEY })).status, 404);
  assert.equal((await get(m, `/v1/updates/mobile-test/download?key=${KEY}`)).status, 200);
  assert.equal((await get(m, '/v1/updates/mobile-test/latest')).status, 404, 'the key is needed here too');
});

await test('phone routes say "none" when there is no phone build yet', async (m) => {
  const res = await get(m, '/v1/updates/mobile-test/latest', { 'x-tester-key': KEY });
  assert.equal(res.status, 404);
  assert.equal((await res.json()).error, 'none');
});

await test('a bad repo setting is refused', async () => {
  const m = make({ TEST_BUILDS_REPO: '../../etc' });
  assert.equal((await get(m, '/v1/updates/test/latest', { 'x-tester-key': KEY })).status, 503);
  await m.dispose();
});

console.log(`\n${passed} tests passed`);
process.exit(0);
