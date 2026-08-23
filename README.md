# Anjadhe Connect

Hosted services for the [Anjadhe app](https://anjadhe.com), served from
`api.anjadhe.com`. First capability: a metered **web-search API** so the
in-app assistant gets web access instantly — no signup, no key-hunting.
Second: metered **LLM inference** (`/v1/llm`) — open-weight models behind
an OpenAI-compatible endpoint, so the assistant works on machines that
can't run a capable model locally. Also hosts the app's **opt-in usage
analytics** ingest and the **zero-knowledge mobile-sync relay** (both
below). All of it rides one key/tier machinery.

The source is public so the privacy claim below is verifiable. This repo
receives a sanitized single-commit snapshot per release from the private
development repo, and production deploys from this repo's `main`: the code
you can read here is the code that runs.

## Privacy

**Query text is never logged and never stored.** The database holds usage
*counters* keyed by a SHA-256 hash of the installation id — the raw id
(which can be a machine hostname on old app versions) is hashed at the API
boundary and never written to disk, and mint IPs are not stored. Request
logs carry method, path, status, and latency only. Searches from all users
exit through Connect's own upstream accounts and server address, so
upstream search providers cannot profile individual users — a stronger
position than each user holding their own provider key.

LLM inference (`/v1/llm`) extends the same invariant to conversations:
**prompt and completion text are never logged and never stored** — the
server is a metering passthrough, and the only things written are counters
(requests and token counts per hashed install id, per month). Requests
exit through Connect's account with one inference provider chosen for its
zero-data-retention terms; the provider sees Anjadhe's server, never the
user. Upstream error bodies are not forwarded or logged, since they can
echo request text.

App analytics (`/v1/analytics/events`) follow the same discipline: the
feature is off by default in the app, event names are checked against a
fixed allowlist on both ends, and the server folds each batch into
per-day counters at the boundary — no raw event rows, no timestamps finer
than a UTC day. The analytics install id is a separate random UUID from
the Connect key's install id, hashed at rest like everything else, so
app-usage counters can never be joined against a machine's search usage.

Feedback (`/v1/feedback`) is the one endpoint that stores user-written
text, because that is its purpose: the app's Settings › Send Feedback card
posts a message the user wrote to the operator, and pressing Send is the
consent. The same discipline wraps around it — keyless, no install id of
any kind on the row (not even the analytics UUID), no IPs at rest — so a
message can never be joined to a machine's search or analytics usage. An
optional reply-to email is stored only if the user typed one.

Feedback is **kept for one year, then deleted** — status makes no
difference, since a closed report and a forgotten one are the same
liability. The sweep runs at startup and daily
(`FEEDBACK_RETENTION_DAYS`); analytics counters age out on their own
clock (`ANALYTICS_RETENTION_DAYS`, 400 days).

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
| `POST /v1/keys` `{installId}` | Mint the key for a NEW installation. A known install id answers 409 — knowing an id must never be enough to revoke the owner's key. |
| `POST /v1/keys/rotate` | Rotate this key (Bearer auth — holding the current key proves ownership). Preserves tier and usage, so rotating can't refill a quota. |
| `POST /v1/keys/migrate` `{newInstallId}` | Rename this key's install id (tier and usage travel with it) — how the app moves legacy hostname-derived ids onto random UUIDs. |
| `POST /v1/search` `{query, maxResults?}` | Search. Returns `{results: [{title, url, snippet}], provider: "anjadhe", upstream, used, quota}` — the shape the app's other search providers already use. `429` with `code: "quota"` when the month is spent, `code: "rate"` for per-minute limits. |
| `POST /v1/llm/chat/completions` | Metered LLM inference, OpenAI-compatible (streaming via SSE with `stream: true`). `model` must be a served public name (`GET /healthz` lists them). Quota is monthly **requests AND tokens**, whichever trips first; `429 code: "quota"` / `"rate"` / `"busy"`, `503 code: "budget"` when the service-wide token budget is spent. |
| `GET /v1/usage` | `{tier, used, quota, llm: {requests, requestQuota, tokens, tokenQuota}, period, resetsAt}` |
| `POST /v1/analytics/events` `{installId, events}` | Opt-in app-analytics ingest (keyless — see Privacy). Events outside the vocabulary are dropped; the batch is aggregated into daily counters on arrival. Returns `{accepted, dropped}`. |
| `wss://…/v1/relay/<routingId>` | Zero-knowledge mobile-sync relay (WebSocket, keyless — see Privacy). Frames are capped at 1 MiB; the app's channel layer chunks larger payloads. Per-IP connect limits and per-connection forwarding budgets apply. |
| `POST /v1/feedback` `{message, kind?, email?, appVersion?, platform?}` | Feedback / support ingest (keyless — see Privacy). `kind` is `feedback` (default) or `support`; per-IP hourly limit. |
| `POST /v1/admin/tier` `{installId, tier}` | Manual tier change (header `x-admin-token`). Stripe replaces this in phase 2. |
| `GET /v1/admin/stats` | Key counts, per-tier counts, this month's usage. |
| `GET /v1/admin/overview?days=N` | Everything the `/admin` dashboard shows: daily counters, active installs, provider status, alerts, install list. |
| `GET /v1/admin/analytics?days=N&limit=M` | App-analytics installs (busiest first), each with its per-UTC-day event totals — the dashboard's install × day grid. |
| `GET /v1/admin/analytics/install?id=<hash>&days=N` | One analytics install's counters, by day and event name. Takes the stored (hashed) id. |
| `GET /v1/admin/feedback?status=new\|all\|closed&limit=N` | Feedback list + counts. |
| `POST /v1/admin/feedback/status` `{id, status}` | Move a feedback item between `new` / `read` / `closed`. |
| `GET /admin` | Operator pages (browser; enter `ADMIN_TOKEN` in the page). `/admin` is service health; `/admin/analytics`, `/admin/installs` and `/admin/feedback` are its siblings. |
| `GET /healthz` | `{ok, providers, llmModels}` |

Tiers (defaults, env-tunable): `free` 300 searches/mo, `plus` 3,000,
`pro` 15,000, with per-minute caps of 20/60/120. LLM quotas ride the same
tier field: `free` 1,000 requests + 2.5M tokens/mo, `plus` 10,000 + 25M,
`pro` 50,000 + 100M, with per-minute caps of 60/120/240 and 4/6/8 concurrent
streams. The per-minute caps sit well above one full agentic chat turn (up to
16 requests: 15 tool iterations + a synthesis pass, sharing the window with
the app's background work) — they brake runaway loops, not spend. Request caps are generous on purpose — the token ceiling is what
bounds spend, and the app's ambient email analysis makes hundreds of small
calls a month that must not starve the user's visible chat allowance. `LLM_BUDGET_TOKENS` is the service-wide monthly ceiling behind
all of it.

## Observability & alerts

`/admin` is a small multi-page operator console (one shell, four pages):
**Overview** is service health — alerts, today's tiles, searches / mints /
relay per day, latency buckets, provider budget meters; **Analytics** holds
the opt-in app-analytics charts and the install × day grid with its
drill-down; **Installs** is the Connect-key list for manual tier changes;
**Feedback** is where user messages are read and closed. Apart from
feedback's user-written messages, everything shown comes from
**service-wide daily counters** (`metrics_daily`) plus a day-granularity
`last_seen_day` per install — no per-request records, no query text, no
IPs. Install ids appear only in their stored (hashed) form; each Mac's
Settings card shows the same hash for matching.

Opt-in app analytics get their own panel, **App events per install, per day**:
a grid of installs (busiest first) against UTC days, and a per-install
drill-down showing which event counters that machine sent on which day. The
ids there are analytics ids — a separate id space from the Connect installs
in the table below it, so nothing on the page joins the two. That grid loads
from its own endpoint rather than the overview, since it is
O(installs × days) and the page re-polls every 60 seconds.

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

Upstreams with hard req/s limits are paced server-side: `PROVIDER_PACE_MS`
(default `{"brave":1100}` — Brave's free tier is 1 req/s) serializes calls
to that provider with starts spaced that many ms apart. Client machines
throttle themselves individually, but they all share these upstream keys,
so only the server can enforce the aggregate rate. A paced provider whose
queue exceeds ~10s of projected wait fails over to the next provider
immediately (metric `provider.<name>.busy`) without counting toward its
failure cooldown — congestion is not illness.

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
- **`ENV_LABEL=staging`** (and `ENV_LABEL=production` on the real one) — puts
  a banner across the top of `/admin` and the label in the browser tab, so
  two identical-looking dashboards can't be mistaken for each other. The
  banner renders before the token gate, from the public `/healthz`.
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

- Stripe checkout/webhooks for self-serve tier upgrades (replacing
  `POST /v1/admin/tier`).
- Self-hosted inference (own GPUs) if scale ever beats per-token pricing —
  the `/v1/llm` contract wouldn't change.

## License

PolyForm Noncommercial 1.0.0 — same as the Anjadhe app. You can read and
verify this code; you can't run it as a commercial service.
