# livetv-cloud

A small Cloudflare Worker that keeps one copy of a person's Live TV setup per Nuvio account, so a new TV that signs in to Nuvio gets the same setup.

How it works:

- The app sends the Nuvio access token it already has. The Worker asks Nuvio's sign-in server whose token it is (and remembers the answer for 5 minutes). The token is never stored, logged or refreshed.
- One copy per Nuvio account is stored in a D1 database, plus the copy from before the last save.
- A save says which revision it was based on. If another TV saved in between, it is refused (409), so an out-of-date TV can't overwrite newer settings.
- Limits: 256 KB per copy, 500 saves per account per day. An empty setup is refused.

## Endpoints

All except `/v1/health` need `Authorization: Bearer <Nuvio access token>` and the app's public key in an `apikey` header.

| Method | Path | Does |
|---|---|---|
| GET | `/v1/health` | Is the service up |
| GET | `/v1/setup` | The saved copy: `{revision, savedAt, device, deviceId, data}` or 404 |
| PUT | `/v1/setup` | Save `{baseRevision, device, deviceId, data}`; 409 with the current revision if out of date |
| DELETE | `/v1/setup` | Delete the saved copy |
| GET | `/v1/setup/previous` | The copy from before the last save, or 404 |

## Settings (optional)

- `NUVIO_API_URL`: Nuvio's server, default `https://api.nuvio.tv`.
- `NUVIO_PUBLISHABLE_KEY`: only used if a request has no `apikey` header.

## Tests

`npm i --no-save miniflare && node test/worker.test.mjs`
