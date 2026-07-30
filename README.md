# Anjadhe Connect

Hosted services for the [Anjadhe app](https://anjadhe.com), served from
`api.anjadhe.com`. First capability: a metered **web-search API** so the
in-app assistant gets web access instantly — no signup, no key-hunting.
Also hosts the app's **opt-in usage analytics** ingest and the
**zero-knowledge mobile-sync relay** (both below). Future capabilities
(hosted LLM inference) join as new `/v1/*` routes on the same key/tier
machinery.

The source is public so the privacy claim below is verifiable.

## Privacy

**Query text is never logged and never stored.** The database holds usage
*counters* keyed by a SHA-256 hash of the installation id — the raw id
(which can be a machine hostname on old app versions) is hashed at the API
boundary and never written to disk, and mint IPs are not stored. Request
logs carry method, path, status, and latency only. Searches from all users
exit through Connect's own upstream accounts and server address, so
upstream search providers cannot profile individual users — a stronger
position than each user holding their own provider key.

App analytics (`/v1/analytics/events`) follow the same discipline: the
feature is off by default in the app, event names are checked against a
fixed allowlist on both ends, and the server folds each batch into
per-day counters at the boundary — no raw event rows, no timestamps finer
than a UTC day. The analytics install id is a separate random UUID from
the Connect key's install id, hashed at rest like everything else, so
app-usage counters can never be joined against a machine's search usage.

The relay (`/v1/relay/<routingId>`, WebSocket) is a zero-knowledge
rendezvous: a user's Mac dials out and holds a connection; their phone
connects with the same opaque routing id; the relay forwards frames
between them. Payloads are end-to-end encrypted with a Noise session
established directly between the Mac and the phone — the relay never
holds a key and never inspects a payload, only the tiny routing envelope.
Routing ids exist in process memory only; nothing about a room is ever
written to the database or logs. Like analytics, the relay is keyless by
design, so relay activity can't be joined against search usage either.

## API

Auth: `Authorization: Bearer anck_…` (except `/v1/keys`, `/v1/analytics/events`, and `/healthz`).

| Endpoint | What it does |
|---|---|
| `POST /v1/keys` `{installId}` | Mint (or rotate) the key for an installation. Rotation preserves tier and usage — re-minting can't refill a quota. |
| `POST /v1/keys/migrate` `{newInstallId}` | Rename this key's install id (tier and usage travel with it) — how the app moves legacy hostname-derived ids onto random UUIDs. |
| `POST /v1/search` `{query, maxResults?}` | Search. Returns `{results: [{title, url, snippet}], provider: "anjadhe", upstream, used, quota}` — the shape the app's other search providers already use. `429` with `code: "quota"` when the month is spent, `code: "rate"` for per-minute limits. |
| `GET /v1/usage` | `{tier, used, quota, period, resetsAt}` |
| `POST /v1/analytics/events` `{installId, events}` | Opt-in app-analytics ingest (keyless — see Privacy). Events outside the vocabulary are dropped; the batch is aggregated into daily counters on arrival. Returns `{accepted, dropped}`. |
| `wss://…/v1/relay/<routingId>` | Zero-knowledge mobile-sync relay (WebSocket, keyless — see Privacy). Frames are capped at 1 MiB; the app's channel layer chunks larger payloads. Per-IP connect limits and per-connection forwarding budgets apply. |
| `POST /v1/admin/tier` `{installId, tier}` | Manual tier change (header `x-admin-token`). Stripe replaces this in phase 2. |
| `GET /v1/admin/stats` | Key counts, per-tier counts, this month's usage. |
| `GET /v1/admin/overview?days=N` | Everything the `/admin` dashboard shows: daily counters, active installs, provider status, alerts, install list. |
| `GET /admin` | Operator dashboard (browser page; enter `ADMIN_TOKEN` in the page). |
| `GET /healthz` | `{ok, providers}` |

Tiers (defaults, env-tunable): `free` 300 searches/mo, `plus` 3,000,
`pro` 15,000, with per-minute caps of 20/60/120.

## Observability & alerts

`/admin` is a single-page operator dashboard: searches per day (served /
blocked / failed), key mints, latency buckets, provider budget meters, active
installs, and an install list for manual tier changes. Everything it shows
comes from **service-wide daily counters** (`metrics_daily`) plus a
day-granularity `last_seen_day` per install — no per-request records, no
query text, no IPs. Install ids appear only in their stored (hashed) form;
each Mac's Settings card shows the same hash for matching.

Two things to know when reading the charts. Days are **UTC** calendar days,
so a bar labelled `07-29` starts at 5pm PDT on the 28th. And the counters
are service-wide with no notion of who: a developer smoke test against
production lands in them looking exactly like a user's device (the relay
smoke in the app repo now needs `ALLOW_PROD_RELAY=1` for that reason).

Alerts (provider budget nearly spent, all upstreams down, high upstream
failure rate, mint spikes, installs hitting quota) always appear on the
dashboard. Set `ALERT_WEBHOOK_URL` (Slack/Discord webhook or an ntfy.sh
topic; `ALERT_WEBHOOK_KIND` picks the payload shape) to also get pushed
notifications, checked every 10 minutes and re-sent at most every
`ALERT_RESEND_HOURS`. Alert text carries service-wide numbers only.

## How routing works

`lib/router.js` walks `PROVIDER_ORDER` (default `serper,brave,tavily` —
cheapest adequate first) and uses the first provider that has a key, is
under its `PROVIDER_BUDGETS` monthly cap, and isn't cooling down after 3
consecutive failures. Budgets are the cost backstop; cooldown + failover
keep one flaky upstream from taking the service down.

## Run locally

```bash
npm install
SEARCH_MOCK=1 npm start          # canned results, no keys needed
npm test                         # end-to-end smoke test on the mock provider
```

With real keys: put them in `.env` (see `.env.example`), export, `npm start`.

## Run your own

The service is a single Node process with a SQLite file — it runs anywhere
that gives you a persistent disk. On Railway (what `railway.json` targets):

1. New project → deploy from your fork of this repo (`railway.json` sets
   the start command and healthcheck).
2. **Attach a volume** (mount path `/data` is fine — the app uses
   `RAILWAY_VOLUME_MOUNT_PATH` automatically). Without one, every deploy
   wipes all keys and usage.
3. Set service variables: provider keys, `ADMIN_TOKEN`, optionally
   `PROVIDER_BUDGETS` / quota overrides (see `.env.example`).
4. Point a domain at it if you want one (CNAME to the service), and back up
   the volume (`sqlite3 connect.db .backup`, or your host's volume backups).

Then point the Anjadhe app at it with `ANJADHE_CONNECT_URL=https://your.host`.
Note the license below: self-hosting for yourself is fine; running it as a
commercial service is not.

## Staging

A second service, same repo, own volume — so test traffic never lands in
production's counters and destructive things (schema changes, tier edits,
alert webhooks) have somewhere to fail. Because the service is entirely
env-configured, staging needs no code of its own.

Set it up the same way as above, in the same Railway project, with these
differences:

- **Never production's volume** (Railway volumes are per-service, so this
  is the default). Staging can also run with no volume at all — its DB then
  resets on every deploy, which for staging is usually a feature.
- **No provider keys**, plus `SEARCH_MOCK=1` — searches return canned
  results, so staging never spends upstream quota. Add a key only for the
  rare test that must exercise a real upstream, and give it a tiny
  `PROVIDER_BUDGETS` cap.
- **A different `ADMIN_TOKEN`.** Staging's dashboard should not open with
  production's token.
- **No `ALERT_WEBHOOK_URL`**, unless you are specifically testing alerts —
  otherwise staging pages you about staging.
- **The Railway-generated `*.up.railway.app` domain** is enough; no DNS
  change, and nothing about the app hardcodes it.

Point things at it per-run, nothing is committed:

```bash
ANJADHE_CONNECT_URL=https://<staging-host> npm start            # app, in the app repo
ANJADHE_RELAY_URL=wss://<staging-host>/v1/relay npm start        # app, relay only
RELAY_URL=wss://<staging-host>/v1/relay node relay/worker/smoke.mjs
```

What this does **not** buy: a release gate. Both services deploy from
`main`, so staging gets a change at the same time production does. If you
later want a gate, move production to deploying from a `release` branch and
leave staging on `main`.

## Roadmap

- `/v1/relay` — mobile-sync relay.
- `/v1/llm` — hosted inference; would be an explicit opt-in in the app,
  never a default.

## License

PolyForm Noncommercial 1.0.0 — same as the Anjadhe app. You can read and
verify this code; you can't run it as a commercial service.
