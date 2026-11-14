# livetv-cloud

A small Cloudflare Worker that keeps one copy of a person's Live TV setup per Nuvio account, so a new TV that signs in to Nuvio gets the same setup.

How it works:

- The app sends the Nuvio access token it already has. The Worker asks Nuvio's sign-in server whose token it is (and remembers the answer for 5 minutes). The token is never stored, logged or refreshed.
- One copy per Nuvio account is stored in a D1 database, plus the copy from before the last save.
- A save says which revision it was based on. If another TV saved in between, it is refused (409), so an out-of-date TV can't overwrite newer settings.
- Limits: 5 MB of setup per save (stored squeezed and encrypted; each stored copy up to about 1.9 MB), the current and the earlier copy in separate rows, 500 saves per account per day. An empty setup is refused.

## Endpoints

All except `/v1/health` need `Authorization: Bearer <Nuvio access token>` and the app's public key in an `apikey` header.

| Method | Path | Does |
|---|---|---|
| GET | `/v1/health` | Is the service up |
| GET | `/v1/setup` | The saved copy: `{revision, savedAt, device, deviceId, data}` or 404 |
| PUT | `/v1/setup` | Save `{baseRevision, device, deviceId, data}`; 409 with the current revision if out of date |
| DELETE | `/v1/setup` | Delete the saved copy |
| GET | `/v1/setup/previous` | The copy from before the last save, or 404 |

## App key door (/v2/)

Our own apps use `/v2/setup` and `/v2/setup/previous` (same as the `/v1/` routes, same saved copy) plus `/v2/data/<file>` for the sports files. Every `/v2/` request needs the app key in an `X-App-Key` header; other people's builds don't have it and get 403. Sync still needs the Nuvio sign-in as well.

- Secret `APP_KEY` (24+ characters; several allowed, separated by commas, for changing it). The same key is the `LIVETV_APP_KEY` GitHub secret in the TV and phone repos. Until it is set every `/v2/` route answers 503.
- Sports files come from the R2 bucket bound as `DATA` (`nuvio-sports`), which the nuvio-data job fills. An unchanged file (`If-None-Match`) is 304.
- Variable `OLD_DOOR_CLOSES_AT` (a date such as `2026-12-01`): from then on the old `/v1/setup` routes answer 410 `update_required`. Not set = open.
- `/v1/health` also shows `appKey`, `sportsData` and `oldDoor`.

## Test builds (private)

Lets the test app and a few testers update from release files in a private GitHub repo. Only callers with the tester key get anything; everyone else gets 404. Nothing is stored.

| Method | Path | Does |
|---|---|---|
| GET | `/v1/updates/test/latest` | Newest test build: version, notes, SHA-256, download address |
| GET | `/v1/updates/test/apk/<versionCode>` | That build's APK |
| GET | `/v1/updates/test/download?key=...` | Newest APK, for a first install |

The key goes in an `X-Tester-Key` header (or `?key=`). Releases must be tagged `test-<versionCode>` with one `.apk` file.

Secrets (Settings → Variables and secrets): `TESTER_KEY` (16+ characters; several allowed, separated by commas) and `TEST_BUILDS_TOKEN` (a GitHub token that can only read the private repo's contents). Optional: `TEST_BUILDS_REPO`, default `homelessbrian/Nuvio_Testing`. Until both secrets are set these routes answer 404/503 and `/v1/health` shows `testUpdates: not_set`.

## ESPN scores (every 5 minutes)

The cron in `wrangler.toml` runs an ESPN round: it asks ESPN for yesterday to a week ahead for every league in nuvio-data's `espn-leagues.txt` (same timing as nuvio-data's old `scripts/espn.py`) and saves the answers straight to the R2 bucket (`espn/<league>.json`). A league's file is saved only when one of its days really changed, or when its saved time gets old (15 min for today, 1 h for yesterday/tomorrow, 4 h further ahead). When each day was last asked for, and how the last round went, is kept in `espn/_state.json`. `/v1/health` shows the last round under `espnFetch`.

Then it starts nuvio-data's "ESPN shared schedule cache" job (GitHub often skips that job's own schedule for hours), which gets these files, makes the ready-made ones and keeps copies in that repo. If the Worker's last round is missing, over 15 minutes old or went badly (half the questions unanswered), that job asks ESPN itself as before.

Secret: `ESPN_TRIGGER_TOKEN`, a fine-grained GitHub token for `homelessbrian/nuvio-data` only, with **Actions: Read and write**. Until it is set the job isn't started and `/v1/health` shows `espnTimer: not_set`.

## Settings (optional)

- `ESPN_FETCH`: `off` stops the Worker's own ESPN rounds (the nuvio-data job then asks ESPN itself).
- `DATA_CACHE_SECONDS`: how long each sports file is kept before R2 is read again, default 60 (0 = read R2 every time). Copies are kept in the Worker's memory and in Cloudflare's cache; the `x-data-from` header on each answer says which one answered (`memory`, `cache` or `r2`).

- `NUVIO_API_URL`: Nuvio's server, default `https://api.nuvio.tv`.
- `NUVIO_PUBLISHABLE_KEY`: only used if a request has no `apikey` header.

## Tests

`npm i --no-save miniflare && node test/worker.test.mjs && node test/updates.test.mjs && node test/v2.test.mjs && node test/espn.test.mjs`
