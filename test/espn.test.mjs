// The ESPN round the cron runs: asks ESPN, saves to the R2 bucket only what really changed.
//   npm i --no-save miniflare && node test/espn.test.mjs
import { Miniflare } from 'miniflare';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

const LEAGUES = `# a comment
basketball/nba|basketball/nba|
football/college-football|football/college-football|&groups=80

broken line
`;

let asked = [];
let answer = (path, day) => JSON.stringify({ events: [{ id: `${path}-${day}`, status: { type: { state: 'pre' } } }] });
let leaguesUp = true;
let espnUp = true;

const make = (bindings = {}) =>
  new Miniflare({
    modules: true,
    bindings: { SYNC_ENCRYPTION_KEY: 'test-secret-0123456789-abcdefghijklmnop-XYZ', ...bindings },
    scriptPath: fileURLToPath(new URL('../src/index.js', import.meta.url)),
    compatibilityDate: '2025-06-01',
    d1Databases: { DB: 'test-db' },
    r2Buckets: ['DATA'],
    outboundService: async (req) => {
      const url = new URL(req.url);
      if (url.hostname === 'raw.githubusercontent.com') return leaguesUp ? new Response(LEAGUES) : new Response('', { status: 404 });
      if (url.hostname === 'site.api.espn.com') {
        if (!espnUp) return new Response('', { status: 404 });
        const path = url.pathname.replace('/apis/site/v2/sports/', '').replace('/scoreboard', '');
        const day = url.searchParams.get('dates');
        asked.push(`${path}|${day}|${url.searchParams.get('groups') || ''}`);
        return new Response(answer(path, day));
      }
      return new Response('{}', { status: 404 });
    },
  });

let passed = 0;
const test = async (name, fn) => {
  await fn();
  passed++;
  console.log('ok -', name);
};

const mf = make();
const bucket = await mf.getR2Bucket('DATA');
const worker = await mf.getWorker();
const round = async () => {
  asked = [];
  await worker.scheduled({ cron: '*/5 * * * *' });
};
const state = async () => JSON.parse(await (await bucket.get('espn/_state.json')).text());
const putState = (s) => bucket.put('espn/_state.json', JSON.stringify(s));
const file = async (name) => {
  const o = await bucket.get(`espn/${name}.json`);
  return o ? JSON.parse(await o.text()) : null;
};
const uploaded = async (name) => (await bucket.head(`espn/${name}.json`))?.uploaded?.getTime();
const health = async () => (await (await mf.dispatchFetch('https://x.test/v1/health')).json()).espnFetch;

await test('before any round, health says so', async () => {
  assert.equal(await health(), 'no_run_yet');
});

await test('the first round asks for every day of every league and saves each file', async () => {
  await round();
  assert.equal(asked.length, 2 * 9, 'two leagues, yesterday to a week ahead');
  assert.ok(asked.includes(asked.find((a) => a.startsWith('football/college-football|') && a.endsWith('|80'))), 'extra query kept');
  const nba = await file('basketball_nba');
  assert.equal(nba.id, 'basketball/nba');
  assert.equal(nba.source, 'ESPN (site.api.espn.com), unofficial');
  assert.equal(Object.keys(nba.days).length, 9);
  const d = Object.values(nba.days)[0];
  assert.ok(d.fetchedAt > 0 && typeof d.raw === 'string' && d.liveOrSoon === false);
  assert.ok(await file('football_college_football'));
  const s = await state();
  assert.equal(s.lastRun.ok, true);
  assert.equal(s.lastRun.written, 2);
  assert.equal(s.runningSince, undefined);
  const h = await health();
  assert.equal(h.ok, true);
  assert.equal(h.saved, 2);
});

await test('a round straight after asks nothing and saves nothing', async () => {
  const before = await uploaded('basketball_nba');
  await round();
  assert.equal(asked.length, 0);
  assert.equal(await uploaded('basketball_nba'), before);
  assert.equal((await state()).lastRun.written, 0);
});

const ageDays = async (id, { asked: a = true, saved = false } = {}) => {
  const s = await state();
  for (const d of Object.values(s.leagues[id].days)) {
    if (a) d.at = 1;
    if (saved) d.w = 1;
  }
  await putState(s);
};

await test('the same answer again is not saved', async () => {
  await ageDays('basketball/nba');
  const before = await uploaded('basketball_nba');
  await round();
  assert.equal(asked.length, 9);
  assert.equal(await uploaded('basketball_nba'), before, 'file untouched');
  const s = await state();
  assert.ok(Object.values(s.leagues['basketball/nba'].days).every((d) => d.at > 1), 'asked-at times moved on');
});

await test('a changed answer is saved, other days kept as they were', async () => {
  const s = await state();
  const days = Object.keys(s.leagues['basketball/nba'].days).sort();
  const today = days[1];
  s.leagues['basketball/nba'].days[today].at = 1;
  await putState(s);
  const old = await file('basketball_nba');
  answer = (path, day) => JSON.stringify({ events: [{ id: `${path}-${day}`, status: { type: { state: 'in' } } }] });
  await round();
  assert.deepEqual(asked, [`basketball/nba|${today}|`]);
  const now = await file('basketball_nba');
  assert.match(now.days[today].raw, /"state":"in"/);
  assert.equal(now.days[today].liveOrSoon, true);
  assert.ok(now.days[today].fetchedAt > old.days[today].fetchedAt);
  assert.deepEqual(now.days[days[0]], old.days[days[0]], 'a day not asked for is unchanged');
  assert.equal((await state()).leagues['basketball/nba'].days[today].live, true);
});

await test('an unchanged day whose saved time is old is saved again', async () => {
  answer = (path, day) => JSON.stringify({ events: [{ id: `${path}-${day}`, status: { type: { state: 'pre' } } }] });
  await ageDays('football/college-football', { saved: true });
  const before = await uploaded('football_college_football');
  await new Promise((r) => setTimeout(r, 5));
  await round();
  assert.equal(asked.length, 9);
  assert.ok((await uploaded('football_college_football')) > before);
});

await test('when ESPN is down nothing is lost and the round says it went badly', async () => {
  espnUp = false;
  await ageDays('basketball/nba');
  const before = await file('basketball_nba');
  await round();
  assert.deepEqual(await file('basketball_nba'), before);
  const s = await state();
  assert.equal(s.lastRun.ok, false);
  assert.ok(Object.values(s.leagues['basketball/nba'].days).every((d) => d.at === 1), 'asked again next round');
  espnUp = true;
});

await test('a round still going stops a second one', async () => {
  const s = await state();
  s.runningSince = Date.now();
  await ageDays('basketball/nba');
  const t = await state();
  t.runningSince = Date.now();
  await putState(t);
  await round();
  assert.equal(asked.length, 0);
  t.runningSince = Date.now() - 11 * 60_000; // an old one that never finished
  await putState(t);
  await round();
  assert.equal(asked.length, 9);
});

await test('no league list means no round', async () => {
  leaguesUp = false;
  await ageDays('basketball/nba');
  const before = (await state()).lastRun.at;
  await round();
  assert.equal(asked.length, 0);
  assert.equal((await state()).lastRun.at, before);
  leaguesUp = true;
});
await mf.dispose();

await test('ESPN_FETCH=off leaves it all to the nuvio-data job', async () => {
  const off = make({ ESPN_FETCH: 'off' });
  asked = [];
  await (await off.getWorker()).scheduled({ cron: '*/5 * * * *' });
  assert.equal(asked.length, 0);
  assert.equal(await (await off.getR2Bucket('DATA')).get('espn/_state.json'), null);
  assert.equal((await (await off.dispatchFetch('https://x.test/v1/health')).json()).espnFetch, 'off');
  await off.dispose();
});

console.log(`${passed} passed`);
