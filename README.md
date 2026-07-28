# Anjadhe Connect

Hosted services for the [Anjadhe app](https://anjadhe.com), served from
`api.anjadhe.com`. First capability: a metered **web-search API** so the
in-app assistant gets web access instantly — no signup, no key-hunting.
Future capabilities (mobile-sync relay, hosted LLM inference) join as new
`/v1/*` routes on the same key/tier machinery.

The source is public so the privacy claim below is verifiable.

## Privacy

**Query text is never logged and never stored.** The database holds usage
*counters* keyed by installation id; request logs carry method, path,
status, and latency only. Searches from all users exit through Connect's
own upstream accounts and server address, so upstream search providers
cannot profile individual users — a stronger position than each user
holding their own provider key.

## API

Auth: `Authorization: Bearer anck_…` (except `/v1/keys` and `/healthz`).

| Endpoint | What it does |
|---|---|
| `POST /v1/keys` `{installId}` | Mint (or rotate) the key for an installation. Rotation preserves tier and usage — re-minting can't refill a quota. |
| `POST /v1/search` `{query, maxResults?}` | Search. Returns `{results: [{title, url, snippet}], provider: "anjadhe", upstream, used, quota}` — the shape the app's other search providers already use. `429` with `code: "quota"` when the month is spent, `code: "rate"` for per-minute limits. |
| `GET /v1/usage` | `{tier, used, quota, period, resetsAt}` |
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
query text, no IPs. Install ids (which can be machine hostnames) are masked
by default.

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

## Roadmap

- `/v1/relay` — mobile-sync relay.
- `/v1/llm` — hosted inference; would be an explicit opt-in in the app,
  never a default.

## License

PolyForm Noncommercial 1.0.0 — same as the Anjadhe app. You can read and
verify this code; you can't run it as a commercial service.
