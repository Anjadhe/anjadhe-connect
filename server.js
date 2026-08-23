// Anjadhe Connect — hosted services for the Anjadhe app (api.anjadhe.com).
// Capabilities: /v1/search (metered web search), /v1/llm (metered LLM
// inference), /v1/news, the analytics/feedback ingests and the sync relay —
// all riding one key/tier/usage machinery.
//
// PRIVACY INVARIANT (this is the product): query text is never logged and
// never stored. Request logs carry method/path/status/latency only; SQLite
// holds counters keyed by a SHA-256 HASH of the install id — nothing about
// what was searched, and no raw machine identifiers (legacy install ids
// were hostname-derived) or IP addresses at rest. Every change to this
// file must preserve that.
'use strict';
const crypto = require('crypto');
const path = require('path');
const express = require('express');
const config = require('./lib/config');
const db = require('./lib/db');
const router = require('./lib/router');
const alerts = require('./lib/alerts');
const relay = require('./lib/relay');
const llm = require('./lib/llm');
const { capLimiter, ipBucket } = require('./lib/limiter');

const KEY_PREFIX = 'anck_';

const app = express();
app.set('trust proxy', 1); // Railway terminates TLS in front of us
app.disable('x-powered-by');

// Baseline security headers on every response. HSTS only when the request
// actually arrived over TLS (Railway terminates it and forwards the proto),
// so local dev over plain http isn't pinned to https.
app.use((req, res, next) => {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('X-Frame-Options', 'DENY');
    res.set('Referrer-Policy', 'no-referrer');
    if (req.secure) res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});
// Analytics batches (up to 500 queued events from an offline machine) need
// more room than every other body, and LLM chat bodies carry whole
// conversations plus injected context; keep the tight cap for the rest.
const jsonBody = express.json({ limit: '10kb' });
const jsonBodyAnalytics = express.json({ limit: '64kb' });
const jsonBodyLlm = express.json({ limit: '256kb' });
app.use((req, res, next) => {
    const parser = req.path === '/v1/analytics/events' ? jsonBodyAnalytics
        : req.path.startsWith('/v1/llm/') ? jsonBodyLlm : jsonBody;
    return parser(req, res, next);
});

// Request log: path only — request bodies (queries) never appear here.
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        console.log(`${req.method} ${req.path} ${res.statusCode} ${Date.now() - start}ms`);
    });
    next();
});

function hashKey(key) {
    return crypto.createHash('sha256').update(key).digest('hex');
}

function mintKey() {
    return KEY_PREFIX + crypto.randomBytes(24).toString('hex');
}

// First of next month, UTC — when monthly quotas reset.
function resetsAt() {
    const now = new Date();
    return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1))
        .toISOString().slice(0, 10);
}

function quotaFor(tier) {
    return config.tierQuotas[tier] ?? config.tierQuotas.free;
}

function llmQuotaFor(tier) {
    return config.llmTierQuotas[tier] ?? config.llmTierQuotas.free;
}

// ── In-memory rate limiters ─────────────────────────────────────────────
// Single-instance service (Railway + volume), so process memory is the
// source of truth. A restart resets windows — acceptable at this scale.

const _mintByIp = new Map(); // ip bucket -> {day, count}
const _mintGlobal = { day: '', count: 0 }; // aggregate brake — per-IP scales
                                           // with the attacker's address pool
function allowMint(rawIp) {
    const ip = ipBucket(rawIp);
    const day = new Date().toISOString().slice(0, 10);
    if (_mintGlobal.day !== day) { _mintGlobal.day = day; _mintGlobal.count = 0; }
    if (_mintGlobal.count >= config.mintPerDayGlobal) return false;
    capLimiter(_mintByIp, (v) => v.day !== day);
    const cur = _mintByIp.get(ip);
    if (!cur || cur.day !== day) {
        _mintByIp.set(ip, { day, count: 1 });
        _mintGlobal.count++;
        return true;
    }
    if (cur.count >= config.mintPerIpPerDay) return false;
    cur.count++;
    _mintGlobal.count++;
    return true;
}

// News fetches are unmetered (server-side topic cache makes them nearly
// free), so a simple fixed per-minute window is the only brake needed.
const NEWS_PER_MINUTE = 12;
const _newsByInstall = new Map(); // installId -> {windowStart, count}
function allowNewsMinute(installId) {
    const now = Date.now();
    capLimiter(_newsByInstall, (v) => now - v.windowStart >= 60000);
    const cur = _newsByInstall.get(installId);
    if (!cur || now - cur.windowStart >= 60000) {
        _newsByInstall.set(installId, { windowStart: now, count: 1 });
        return true;
    }
    if (cur.count >= NEWS_PER_MINUTE) return false;
    cur.count++;
    return true;
}

// Analytics ingest is keyless (see the route for why), so the brake is
// per-IP. Clients batch and post at most hourly; 10/min absorbs a NAT'd
// office without opening a flood door.
const ANALYTICS_PER_MINUTE = 10;
const _analyticsByIp = new Map(); // ip bucket -> {windowStart, count}
function allowAnalyticsMinute(rawIp) {
    const ip = ipBucket(rawIp);
    const now = Date.now();
    capLimiter(_analyticsByIp, (v) => now - v.windowStart >= 60000);
    const cur = _analyticsByIp.get(ip);
    if (!cur || now - cur.windowStart >= 60000) {
        _analyticsByIp.set(ip, { windowStart: now, count: 1 });
        return true;
    }
    if (cur.count >= ANALYTICS_PER_MINUTE) return false;
    cur.count++;
    return true;
}

// Feedback is rare by nature — a handful per hour per IP absorbs a shared
// office without opening a spam door. Keyless like analytics, so per-IP is
// the only handle there is.
const FEEDBACK_PER_HOUR = 5;
const _feedbackByIp = new Map(); // ip bucket -> {windowStart, count}
function allowFeedbackHour(rawIp) {
    const ip = ipBucket(rawIp);
    const now = Date.now();
    capLimiter(_feedbackByIp, (v) => now - v.windowStart >= 3600000);
    const cur = _feedbackByIp.get(ip);
    if (!cur || now - cur.windowStart >= 3600000) {
        _feedbackByIp.set(ip, { windowStart: now, count: 1 });
        return true;
    }
    if (cur.count >= FEEDBACK_PER_HOUR) return false;
    cur.count++;
    return true;
}

const _llmByInstall = new Map(); // installId -> {windowStart, count}
// Returns 0 when the request is allowed (and counts it), otherwise the ms
// until this install's window reopens — the app paces its background drains
// off that number instead of guessing (initial email connect queues dozens
// of insight calls, and "retry immediately" was just re-hitting the wall).
function llmMinuteWait(installId, tier) {
    const limit = config.llmPerMinute[tier] ?? config.llmPerMinute.free;
    const now = Date.now();
    capLimiter(_llmByInstall, (v) => now - v.windowStart >= 60000);
    const cur = _llmByInstall.get(installId);
    if (!cur || now - cur.windowStart >= 60000) {
        _llmByInstall.set(installId, { windowStart: now, count: 1 });
        return 0;
    }
    if (cur.count >= limit) return Math.max(1000, cur.windowStart + 60000 - now);
    cur.count++;
    return 0;
}

// In-flight LLM calls per install. Streams hold a slot for their whole
// duration, so this — not the per-minute window — is what stops one
// install fanning out parallel long-running generations.
const _llmInflight = new Map(); // installId -> count
function llmSlot(installId, tier) {
    const limit = config.llmMaxConcurrent[tier] ?? config.llmMaxConcurrent.free;
    const cur = _llmInflight.get(installId) || 0;
    if (cur >= limit) return null;
    _llmInflight.set(installId, cur + 1);
    return () => {
        const n = (_llmInflight.get(installId) || 1) - 1;
        if (n <= 0) _llmInflight.delete(installId);
        else _llmInflight.set(installId, n);
    };
}

const _searchByInstall = new Map(); // installId -> {windowStart, count}
function allowMinute(installId, tier) {
    const limit = config.perMinute[tier] ?? config.perMinute.free;
    const now = Date.now();
    capLimiter(_searchByInstall, (v) => now - v.windowStart >= 60000);
    const cur = _searchByInstall.get(installId);
    if (!cur || now - cur.windowStart >= 60000) {
        _searchByInstall.set(installId, { windowStart: now, count: 1 });
        return true;
    }
    if (cur.count >= limit) return false;
    cur.count++;
    return true;
}

// ── Auth ────────────────────────────────────────────────────────────────

function auth(req, res, next) {
    const m = /^Bearer (anck_[a-f0-9]{48})$/.exec(req.get('authorization') || '');
    if (!m) {
        db.bumpMetric('auth.fail');
        return res.status(401).json({ error: 'Missing or malformed API key' });
    }
    const row = db.getKeyByHash(hashKey(m[1]));
    if (!row) {
        db.bumpMetric('auth.fail');
        return res.status(401).json({ error: 'Unknown API key' });
    }
    // Day-granularity activity marker (drives the dashboard's active-install
    // counts). Deliberately never a timestamp.
    if (row.last_seen_day !== db.day()) db.touchSeen(row.install_id);
    req.install = row;
    next();
}

// Admin token guard. The token is the ONLY admin credential, so guessing it
// must never be cheap. Three layers, and both compares are over SHA-256
// digests so even the token's length can't leak from the comparison:
//
//  1. per-IP: 10 failures per 15 minutes (the /64 bucket, so IPv6 doesn't
//     hand an attacker a fresh identity per request);
//  2. service-wide: 100 failures per 15 minutes, which is the layer per-IP
//     can't be — distributed guessing across a thousand addresses walks
//     straight past (1) while barely registering on its own counters;
//  3. an exemption so (2) can't be used to lock the operator out: an IP
//     that authenticated successfully in the last 7 days keeps its access
//     while the global brake is engaged. Without it, sustained guessing
//     from anywhere would deny the console to everyone, turning a
//     brute-force attempt into a guaranteed outage.
//
// None of this substitutes for token entropy — it bounds an online guess
// rate, it does not make a weak token safe. ADMIN_TOKEN should be 32+
// random chars; the boot log warns when it is short.
const ADMIN_FAILS_PER_WINDOW = 10;
const ADMIN_GLOBAL_FAILS_PER_WINDOW = 100;
const ADMIN_FAIL_WINDOW_MS = 15 * 60 * 1000;
const ADMIN_KNOWN_GOOD_MS = 7 * 24 * 60 * 60 * 1000;
const _adminFailsByIp = new Map();  // ip bucket -> {windowStart, count}
const _adminGoodIps = new Map();    // ip bucket -> last successful auth (ms)
const _adminFailsGlobal = { windowStart: 0, count: 0 };
function adminAuth(req, res, next) {
    if (!config.adminToken) return res.status(503).json({ error: 'Admin endpoints disabled (no ADMIN_TOKEN set)' });
    const now = Date.now();
    const ip = ipBucket(req.ip);
    const knownGood = now - (_adminGoodIps.get(ip) || 0) < ADMIN_KNOWN_GOOD_MS;

    const fails = _adminFailsByIp.get(ip);
    if (fails && now - fails.windowStart < ADMIN_FAIL_WINDOW_MS && fails.count >= ADMIN_FAILS_PER_WINDOW) {
        return res.status(429).json({ error: 'Too many failed admin attempts — wait a few minutes' });
    }
    if (now - _adminFailsGlobal.windowStart >= ADMIN_FAIL_WINDOW_MS) {
        _adminFailsGlobal.windowStart = now;
        _adminFailsGlobal.count = 0;
    }
    if (!knownGood && _adminFailsGlobal.count >= ADMIN_GLOBAL_FAILS_PER_WINDOW) {
        db.bumpMetric('admin.brake');
        return res.status(429).json({ error: 'Admin authentication temporarily locked — try again later' });
    }

    const given = crypto.createHash('sha256').update(req.get('x-admin-token') || '').digest();
    const want = crypto.createHash('sha256').update(config.adminToken).digest();
    if (!crypto.timingSafeEqual(given, want)) {
        capLimiter(_adminFailsByIp, (v) => now - v.windowStart >= ADMIN_FAIL_WINDOW_MS);
        capLimiter(_adminGoodIps, (v) => now - v >= ADMIN_KNOWN_GOOD_MS);
        if (!fails || now - fails.windowStart >= ADMIN_FAIL_WINDOW_MS) {
            _adminFailsByIp.set(ip, { windowStart: now, count: 1 });
        } else {
            fails.count++;
        }
        _adminFailsGlobal.count++;
        db.bumpMetric('admin.fail');
        return res.status(401).json({ error: 'Bad admin token' });
    }
    _adminFailsByIp.delete(ip);
    _adminGoodIps.set(ip, now);
    next();
}

// ── Routes ──────────────────────────────────────────────────────────────

// `env` carries ENV_LABEL when the operator set one, so /admin can name the
// deployment it is showing before any token is entered — the point being that
// production and staging dashboards are otherwise identical.
app.get('/healthz', (req, res) => {
    const body = { ok: true, providers: router.available(), llmModels: llm.available() };
    if (config.envLabel) body.env = config.envLabel;
    res.json(body);
});

// Mint the key for a NEW installation. Mint-only since 2026-08-05: it used
// to also rotate a known id's key, which meant knowing an install id was
// enough to revoke the owner's key and receive a working one at their tier —
// and legacy hostname-derived ids are guessable by design (that's why
// /v1/keys/migrate exists). A known id now answers 409; rotation moved to
// /v1/keys/rotate, where holding the current key proves ownership. A client
// that genuinely lost its key starts over under a fresh UUID (free tier —
// the operator restores a paid tier manually). The raw id is hashed here at
// the boundary and never stored.
app.post('/v1/keys', (req, res) => {
    const installId = String(req.body?.installId || '').trim();
    if (!/^[A-Za-z0-9_-]{8,64}$/.test(installId)) {
        return res.status(400).json({ error: 'installId must be 8-64 chars of letters, digits, - or _' });
    }
    if (!allowMint(req.ip)) {
        db.bumpMetric('mint.rate');
        return res.status(429).json({ error: 'Too many key requests from this address today' });
    }
    const idHash = db.hashInstallId(installId);
    if (db.getKeyByInstall(idHash)) {
        db.bumpMetric('mint.blocked');
        return res.status(409).json({
            error: 'This install id already has a key. Rotate it with POST /v1/keys/rotate (Bearer auth), or mint under a new install id.',
            code: 'already-registered'
        });
    }
    const key = mintKey();
    db.createKey(idHash, hashKey(key));
    db.bumpMetric('mint.new');
    res.json({ apiKey: key, tier: 'free', monthlyQuota: quotaFor('free'), rotated: false });
});

// Rotate this install's key — holding the current key is the proof of
// ownership. The old key stops working immediately. Usage and tier stay
// (usage keys off the install id), so rotating can't refill a quota.
app.post('/v1/keys/rotate', auth, (req, res) => {
    const key = mintKey();
    db.rotateKey(req.install.install_id, hashKey(key));
    db.bumpMetric('mint.rotate');
    const tier = req.install.tier;
    res.json({ apiKey: key, tier, monthlyQuota: quotaFor(tier), rotated: true });
});

// Rename this key's install id — how the app moves off a legacy
// hostname-derived id onto a random UUID it generated locally. Bearer-auth
// only: holding the key proves ownership of the install. Tier and usage
// travel with the rename, so migrating can't refill a quota.
app.post('/v1/keys/migrate', auth, (req, res) => {
    const newId = String(req.body?.newInstallId || '').trim();
    if (!/^[A-Za-z0-9_-]{8,64}$/.test(newId)) {
        return res.status(400).json({ error: 'newInstallId must be 8-64 chars of letters, digits, - or _' });
    }
    const newHash = db.hashInstallId(newId);
    const oldHash = req.install.install_id; // stored form is already the hash
    if (newHash === oldHash) return res.json({ success: true, installId: newId });
    if (db.getKeyByInstall(newHash)) return res.status(409).json({ error: 'newInstallId already in use' });
    db.migrateInstall(oldHash, newHash);
    db.bumpMetric('mint.migrate');
    res.json({ success: true, installId: newId });
});

app.post('/v1/search', auth, async (req, res) => {
    const query = String(req.body?.query || '').trim();
    if (!query) return res.status(400).json({ error: 'query required' });
    if (query.length > 400) return res.status(400).json({ error: 'query too long (max 400 chars)' });
    const maxResults = Math.max(1, Math.min(10, parseInt(req.body?.maxResults, 10) || 5));

    const { install_id: installId, tier } = req.install;
    const quota = quotaFor(tier);
    const used = db.getUsed(installId);
    if (used >= quota) {
        db.bumpMetric('search.quota');
        return res.status(429).json({
            error: `Monthly quota reached (${quota} searches on the ${tier} plan). Resets ${resetsAt()}.`,
            code: 'quota', used, quota, resetsAt: resetsAt()
        });
    }
    if (!allowMinute(installId, tier)) {
        db.bumpMetric('search.rate');
        return res.status(429).json({ error: 'Rate limit: too many searches this minute — retry shortly.', code: 'rate' });
    }

    const start = Date.now();
    try {
        const { results, upstream } = await router.search(query, maxResults);
        db.bumpUsage(installId);
        db.bumpMetric('search.ok');
        db.bumpMetric(latencyBucket(Date.now() - start));
        res.json({ results, provider: 'anjadhe', upstream, used: used + 1, quota });
    } catch (e) {
        db.bumpMetric('search.upstream_fail');
        // Fixed message — e.message names upstream providers and their HTTP
        // statuses, which is operator detail, not client detail (the LLM
        // route already does it this way). The router logs the specifics.
        res.status(502).json({ error: 'Search temporarily unavailable — try again shortly.' });
    }
});

// Coarse latency histogram for successful searches — daily counters, no
// per-request records.
function latencyBucket(ms) {
    if (ms < 500) return 'search.ms.lt500';
    if (ms < 1500) return 'search.ms.lt1500';
    if (ms < 4000) return 'search.ms.lt4000';
    return 'search.ms.gte4000';
}

// Current headlines for a batch of user-chosen topics (the Anjadhe app's
// Discover pane). NOT metered against the search quota — the per-topic
// cache in lib/news.js means one upstream fetch serves every user
// following that topic within the window. Topics are never logged.
app.post('/v1/news', auth, async (req, res) => {
    const raw = Array.isArray(req.body?.topics) ? req.body.topics : [];
    const topics = raw.map(t => String(t || '').trim()).filter(t => t && t.length <= 80).slice(0, 8);
    if (!topics.length) return res.status(400).json({ error: 'topics required (1-8 strings, max 80 chars each)' });
    if (!allowNewsMinute(req.install.install_id)) {
        db.bumpMetric('news.rate');
        return res.status(429).json({ error: 'Rate limit: too many news requests this minute — retry shortly.', code: 'rate' });
    }
    db.bumpMetric('news.ok');
    const news = require('./lib/news');
    const out = await Promise.all(topics.map(async (topic) => {
        try {
            return { topic, items: await news.topicNews(topic) };
        } catch {
            // Error details stay server-side; they could echo upstream URLs.
            return { topic, items: [], error: 'unavailable' };
        }
    }));
    res.json({ topics: out, provider: 'anjadhe' });
});

// ── LLM inference (metered, OpenAI-compatible) ──────────────────────────
// The app's 'anjadhe' engine points its normal OpenAI-request path here.
// Quota is two-dimensional: monthly requests (what the app's meter shows)
// AND monthly tokens (the cost backstop) — whichever trips first. Errors
// use Connect's house shape ({error, code}), which the app's engine maps
// to its own quota/rate handling.

// The model catalog the app's Settings picker renders. Keyless like
// /healthz (which already lists the ids): model names are product surface,
// not a secret, and Settings shows the picker before any key is minted.
app.get('/v1/llm/models', (req, res) => {
    res.json({ models: llm.catalog() });
});

app.post('/v1/llm/chat/completions', auth, async (req, res) => {
    const models = llm.available();
    if (!models.length) {
        return res.status(503).json({ error: 'LLM inference is not configured on this deployment', code: 'unconfigured' });
    }
    const model = String(req.body?.model || '');
    if (!models.includes(model)) {
        return res.status(400).json({ error: `Unknown model — one of: ${models.join(', ')}`, code: 'model', models });
    }
    if (!Array.isArray(req.body?.messages) || !req.body.messages.length) {
        return res.status(400).json({ error: 'messages required', code: 'request' });
    }

    const { install_id: installId, tier } = req.install;
    const quota = llmQuotaFor(tier);
    const used = db.llmUsed(installId);
    if (used.requests >= quota.requests || used.tokens >= quota.tokens) {
        db.bumpMetric('llm.quota');
        return res.status(429).json({
            error: `Monthly AI quota reached on the ${tier} plan. Resets ${resetsAt()}.`,
            code: 'quota',
            used: used.requests, quota: quota.requests,
            tokensUsed: used.tokens, tokenQuota: quota.tokens,
            resetsAt: resetsAt()
        });
    }
    // Service-wide budget breaker — the deploy's hard cost ceiling. Enforced
    // before the upstream call so a spent budget costs nothing more.
    if (config.llmBudgetTokens && db.llmPeriodTotals().tokens >= config.llmBudgetTokens) {
        db.bumpMetric('llm.budget');
        return res.status(503).json({
            error: 'Hosted AI is temporarily unavailable (service capacity reached this month).',
            code: 'budget', resetsAt: resetsAt()
        });
    }
    const minuteWait = llmMinuteWait(installId, tier);
    if (minuteWait) {
        db.bumpMetric('llm.rate');
        res.set('Retry-After', String(Math.ceil(minuteWait / 1000)));
        return res.status(429).json({
            error: 'Rate limit: too many AI requests this minute — retry shortly.',
            code: 'rate', retryAfterMs: minuteWait
        });
    }
    const release = llmSlot(installId, tier);
    if (!release) {
        db.bumpMetric('llm.busy');
        // No window to compute here — the wait ends when an in-flight call
        // finishes — so offer a short fixed hint.
        res.set('Retry-After', '5');
        return res.status(429).json({
            error: 'Too many concurrent AI requests — wait for one to finish.',
            code: 'busy', retryAfterMs: 5000
        });
    }

    const start = Date.now();
    const stream = req.body.stream === true;
    try {
        if (stream) {
            // chatStream owns the response from here (SSE passthrough).
            const { usage } = await llm.chatStream(model, req.body, res);
            meterLlm(installId, usage);
            if (usage.estimated) db.bumpMetric('llm.stream.estimated');
        } else {
            const { json, usage } = await llm.chat(model, req.body);
            meterLlm(installId, usage);
            db.bumpMetric(llmLatencyBucket(Date.now() - start));
            res.json(json);
        }
    } catch (e) {
        // e.message never contains request content (llm.js invariant).
        db.bumpMetric('llm.upstream_fail');
        console.error(`[llm] upstream failed: ${e.message}`);
        if (!res.headersSent) {
            res.status(502).json({ error: 'AI request failed — retry shortly.', code: 'upstream' });
        } else if (!res.writableEnded) {
            res.end();
        }
    } finally {
        release();
    }
});

// A request is metered even when a stream lost its usage chunk (client
// disconnected early) — the request bucket is what the app's meter shows,
// and a started generation was real work. In that case llm.chatStream
// returns an ESTIMATE rather than zeros, so tokens (the ceiling that
// actually bounds spend) can't be walked past by disconnecting early.
function meterLlm(installId, usage) {
    db.bumpLlmUsage(installId, usage.prompt_tokens || 0, usage.completion_tokens || 0);
    db.bumpMetric('llm.ok');
    const total = (usage.prompt_tokens || 0) + (usage.completion_tokens || 0);
    if (total) db.bumpMetricBy('llm.tokens', total);
}

function llmLatencyBucket(ms) {
    if (ms < 2000) return 'llm.ms.lt2000';
    if (ms < 8000) return 'llm.ms.lt8000';
    if (ms < 20000) return 'llm.ms.lt20000';
    return 'llm.ms.gte20000';
}

// ── App analytics (opt-in, content-free) ────────────────────────────────
// Ingest for the desktop app's AnalyticsManager (Settings › Privacy, off by
// default) — replaces the old anjadhe-analytics Cloudflare Worker. Three
// deliberate properties:
//   1. Keyless, and keyed by a SEPARATE per-machine analytics UUID — never
//      the Connect install id or an anck_ key — so app-usage counters can't
//      be joined against a machine's search usage.
//   2. Vocabulary-bound: event names outside the allowlist are dropped, so
//      a typo'd or rogue event can't smuggle content in.
//   3. Aggregated at the boundary into per-UTC-day counters (props folded
//      into the counter name). No raw event rows, no timestamps finer than
//      a day, and the analytics id is stored only as a SHA-256 hash.
// Must stay in lockstep with AnalyticsManager.VOCABULARY in the app.
const ANALYTICS_VOCABULARY = {
    'app.opened': ['app'],
    'email.analyzed': ['result', 'model'],
    'email.action_synced': [],
    'agent.query.sent': ['model'],
    'model.added': ['engine', 'source'],
    'agent.reply.feedback': ['rating'],
    'goal.status_updated': [],
    'schedule.task_completed': [],
    'journal.entry_written': [],
    'settings.analytics_enabled': [],
    'settings.analytics_disabled': []
};
const ANALYTICS_MAX_BATCH = 500; // matches the client's MAX_EVENTS buffer
const ANALYTICS_MAX_DISTINCT = 100; // distinct counters one request may create

// The app posts from the renderer, where CORS applies (the old Worker sent
// these same headers). Wide-open is fine: the endpoint only accepts counts.
// CORS for the two keyless ingests. This echoed '*', which let ANY website
// make its visitors POST here — these bodies are JSON, so the browser
// preflights, and a permissive reply is exactly what turns that preflight
// into a write. The app posts from its renderer, which loads over file://
// and so sends `Origin: null`; native/main-process callers send no Origin
// at all and CORS never applies to them.
//
// `null` is NOT an identity — a sandboxed iframe or a data: URL presents it
// too — so this raises the bar rather than sealing the door; the per-IP
// rate limits stay the real brake on volume. INGEST_ALLOWED_ORIGINS exists
// for a future web client that would have a real origin.
const INGEST_ORIGINS = new Set(['null', ...(process.env.INGEST_ALLOWED_ORIGINS || '')
    .split(',').map((s) => s.trim()).filter(Boolean)]);
function analyticsCors(req, res) {
    const origin = req.get('origin');
    res.set('Vary', 'Origin');
    // No Origin: a native client, not a browser — nothing to grant.
    // Unknown Origin: no ACAO header, so the browser blocks the response
    // and (for a preflight) never sends the request at all.
    if (!origin || !INGEST_ORIGINS.has(origin)) return;
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Content-Type');
    res.set('Access-Control-Max-Age', '86400');
}

app.options('/v1/analytics/events', (req, res) => {
    analyticsCors(req, res);
    res.sendStatus(204);
});

app.post('/v1/analytics/events', (req, res) => {
    analyticsCors(req, res);
    const installId = String(req.body?.installId || '').trim();
    if (!/^[A-Za-z0-9_-]{8,64}$/.test(installId)) {
        db.bumpMetric('analytics.reject');
        return res.status(400).json({ error: 'installId must be 8-64 chars of letters, digits, - or _' });
    }
    if (!allowAnalyticsMinute(req.ip)) {
        db.bumpMetric('analytics.rate');
        return res.status(429).json({ error: 'Rate limit: too many analytics posts this minute — retry later.', code: 'rate' });
    }
    const raw = Array.isArray(req.body?.events) ? req.body.events : [];
    const batch = raw.slice(0, ANALYTICS_MAX_BATCH);

    // Fold the batch into (day, counterName) counts. A client timestamp only
    // picks the day bucket, and only within the last 30 days — anything
    // else (missing, future, ancient, forged) lands on today.
    const today = db.day();
    const oldest = db.daysAgo(30);
    const counts = new Map();
    let accepted = 0;
    for (const ev of batch) {
        const allowedProps = ANALYTICS_VOCABULARY[ev?.name];
        if (!allowedProps) continue;
        let bucket = today;
        const ts = Number(ev.ts);
        // Range-check before Date: a finite-but-absurd epoch (1e20) makes
        // toISOString throw, which used to 500 the whole batch.
        if (Number.isFinite(ts) && ts > 0 && ts < 4102444800000 /* 2100 */) {
            const d = db.day(new Date(ts));
            if (d >= oldest && d <= today) bucket = d;
        }
        const parts = [];
        for (const key of allowedProps) {
            const v = ev.props?.[key];
            if (typeof v !== 'string' || !v) continue;
            parts.push(`${key}=${v.slice(0, 64).replace(/[^\w.:+/@-]/g, '_')}`);
        }
        const name = ev.name + (parts.length ? '|' + parts.join('|') : '');
        const k = `${bucket} ${name}`;
        // Event NAMES are allowlisted but prop VALUES are free strings that
        // become part of the counter's row key — without a cap on distinct
        // counters, a random value per event would write a new row per
        // event, unbounded. Bumping an existing counter is always fine.
        if (!counts.has(k) && counts.size >= ANALYTICS_MAX_DISTINCT) continue;
        counts.set(k, (counts.get(k) || 0) + 1);
        accepted++;
    }
    const rows = [...counts].map(([k, count]) => {
        const [day, name] = k.split(' ');
        return { day, name, count };
    });
    if (rows.length) db.recordAnalytics(db.hashInstallId(installId), rows);
    db.bumpMetric('analytics.ok');
    res.json({ accepted, dropped: raw.length - accepted });
});

// ── User feedback / support requests ────────────────────────────────────
// The app's Settings › Send feedback card posts here. Same privacy stance
// as analytics, applied to content the user WROTE to the operator: keyless
// (no anck_ key, so a message can't be joined to search usage), no install
// id of any kind on the row, no IP at rest. The message itself is stored —
// that is the entire point, and pressing Send is the consent. An optional
// email rides along only if the user typed one, for replies.
app.options('/v1/feedback', (req, res) => {
    analyticsCors(req, res);
    res.sendStatus(204);
});

app.post('/v1/feedback', (req, res) => {
    analyticsCors(req, res);
    const message = String(req.body?.message || '').trim();
    if (message.length < 3) return res.status(400).json({ error: 'message required' });
    if (message.length > 4000) return res.status(400).json({ error: 'message too long (max 4000 chars)' });
    const kind = req.body?.kind === 'support' ? 'support' : 'feedback';
    const email = String(req.body?.email || '').trim().slice(0, 200) || null;
    const appVersion = String(req.body?.appVersion || '').trim().slice(0, 40) || null;
    const platform = String(req.body?.platform || '').trim().slice(0, 40) || null;
    // App-details line the card shows before sending (model, OS, setup
    // facts) — plain text, capped, optional.
    const diagnostics = String(req.body?.diagnostics || '').trim().slice(0, 500) || null;
    // Present only when the user ticked the card's default-off checkbox.
    // Stored as its SHA-256 — the same form analytics_daily keys on — so
    // the admin can match the report to that install's usage; the raw id
    // never touches disk here either.
    const rawAnalyticsId = String(req.body?.analyticsId || '').trim();
    const analyticsHash = /^[A-Za-z0-9_-]{8,64}$/.test(rawAnalyticsId)
        ? db.hashInstallId(rawAnalyticsId) : null;
    if (!allowFeedbackHour(req.ip)) {
        db.bumpMetric('feedback.rate');
        return res.status(429).json({ error: 'Too many messages from this address this hour — please retry later.', code: 'rate' });
    }
    const id = db.addFeedback({ kind, message, email, appVersion, platform, diagnostics, analyticsHash });
    db.bumpMetric('feedback.ok');
    res.json({ success: true, id });
});

app.get('/v1/admin/feedback', adminAuth, (req, res) => {
    const status = ['new', 'read', 'closed', 'all'].includes(req.query.status) ? req.query.status : 'all';
    const limit = Math.max(1, Math.min(500, parseInt(req.query.limit, 10) || 200));
    res.json({ counts: db.feedbackCounts(), items: db.feedbackList(status, limit) });
});

app.post('/v1/admin/feedback/status', adminAuth, (req, res) => {
    const id = parseInt(req.body?.id, 10);
    const status = String(req.body?.status || '');
    if (!Number.isFinite(id) || !['new', 'read', 'closed'].includes(status)) {
        return res.status(400).json({ error: 'id and status (new|read|closed) required' });
    }
    if (!db.setFeedbackStatus(id, status)) return res.status(404).json({ error: 'Unknown feedback id' });
    res.json({ success: true, id, status });
});

// The relay speaks WebSocket only — connections arrive via the HTTP
// server's `upgrade` event (see relay.attach in the listen block), never
// through Express. A plain GET here is a client mistake.
app.all(['/v1/relay', '/v1/relay/*'], (req, res) => {
    res.status(426).json({ error: 'WebSocket upgrade required' });
});

app.get('/v1/usage', auth, (req, res) => {
    const { install_id: installId, tier } = req.install;
    const llmUsed = db.llmUsed(installId);
    const llmQuota = llmQuotaFor(tier);
    res.json({
        tier,
        used: db.getUsed(installId),
        quota: quotaFor(tier),
        llm: {
            requests: llmUsed.requests,
            requestQuota: llmQuota.requests,
            tokens: llmUsed.tokens,
            tokenQuota: llmQuota.tokens
        },
        period: db.period(),
        resetsAt: resetsAt()
    });
});

// Manual tier changes until Stripe lands (phase 2). Example:
//   curl -X POST .../v1/admin/tier -H 'x-admin-token: ...' \
//        -H 'Content-Type: application/json' -d '{"installId":"...","tier":"plus"}'
app.post('/v1/admin/tier', adminAuth, (req, res) => {
    const installId = String(req.body?.installId || '').trim();
    const tier = String(req.body?.tier || '').trim();
    // hasOwn, not `in` — `in` walks the prototype chain, so "toString" was
    // accepted as a tier, and quotaFor() returning a function disabled that
    // install's quota and rate limits entirely.
    if (!Object.hasOwn(config.tierQuotas, tier)) {
        return res.status(400).json({ error: `Unknown tier — one of: ${Object.keys(config.tierQuotas).join(', ')}` });
    }
    // Accept either the stored (hashed) id — what the dashboard shows — or a
    // raw install id read off a user's Settings card.
    const stored = db.getKeyByInstall(installId) ? installId : db.hashInstallId(installId);
    if (!db.getKeyByInstall(stored)) return res.status(404).json({ error: 'Unknown installId' });
    db.setTier(stored, tier);
    res.json({ success: true, installId: stored, tier, monthlyQuota: quotaFor(tier) });
});

// ── LLM model catalog management (/admin/models) ────────────────────────
// The llm_models table is what /v1/llm/models serves and the chat route
// validates against; these endpoints are its only writer (LLM_MODELS env
// seeds an empty table once — see db.js). Every write answers with the
// full list so the page re-renders from the same truth it just changed.

const LLM_MODEL_ID_RX = /^[a-z0-9][a-z0-9.-]{0,63}$/;

function llmModelsPayload() {
    return {
        models: db.llmModelsAll(),
        upstreamConfigured: !!(config.llmUpstreamUrl && config.llmUpstreamKey),
        mock: config.llmMock
    };
}

app.get('/v1/admin/llm-models', adminAuth, (req, res) => {
    res.json(llmModelsPayload());
});

// Create or update (upsert on id — editing keeps position and created_at).
app.post('/v1/admin/llm-models', adminAuth, (req, res) => {
    const id = String(req.body?.id || '').trim();
    if (!LLM_MODEL_ID_RX.test(id)) {
        return res.status(400).json({ error: 'id must be lowercase letters, digits, dots or dashes (max 64)' });
    }
    const upstream = String(req.body?.upstream || '').trim();
    if (!upstream || upstream.length > 200) {
        return res.status(400).json({ error: 'upstream model id required (max 200 chars)' });
    }
    const label = String(req.body?.label || '').trim().slice(0, 80) || id;
    const description = String(req.body?.description || '').trim().slice(0, 200) || null;
    const enabled = req.body?.enabled === undefined ? true : !!req.body.enabled;
    db.llmModelUpsert({ id, upstream, label, description, enabled });
    res.json({ success: true, ...llmModelsPayload() });
});

app.post('/v1/admin/llm-models/delete', adminAuth, (req, res) => {
    const id = String(req.body?.id || '').trim();
    if (!db.llmModelDelete(id)) return res.status(404).json({ error: 'Unknown model id' });
    res.json({ success: true, ...llmModelsPayload() });
});

// Reorder: the full id list in the wanted order — must name every row
// exactly once, so a stale page can't silently scramble positions.
app.post('/v1/admin/llm-models/order', adminAuth, (req, res) => {
    const ids = Array.isArray(req.body?.ids) ? req.body.ids.map(String) : [];
    const current = db.llmModelsAll().map((m) => m.id);
    if (ids.length !== current.length || new Set(ids).size !== ids.length
        || !current.every((id) => ids.includes(id))) {
        return res.status(400).json({ error: 'ids must list every model exactly once', current });
    }
    db.llmModelsReorder(ids);
    res.json({ success: true, ...llmModelsPayload() });
});

app.get('/v1/admin/stats', adminAuth, (req, res) => {
    res.json(db.stats());
});

// Shared by every windowed admin read, so a `days` value means the same
// thing on all of them.
function rangeDays(req) {
    return Math.max(1, Math.min(90, parseInt(req.query.days, 10) || 30));
}

// App analytics sliced by install: the busiest installs in the window, each
// with its per-day event totals. Its own endpoint rather than a field on
// /v1/admin/overview because the grid is O(installs × days) and would bloat
// the dashboard's 60-second poll for everyone reading the other panels.
// Still counters only — a hashed analytics id, a UTC day, a number.
app.get('/v1/admin/analytics', adminAuth, (req, res) => {
    const days = rangeDays(req);
    const limit = Math.max(1, Math.min(500, parseInt(req.query.limit, 10) || 100));
    const installs = db.analyticsByInstall(db.daysAgo(days - 1), limit);
    res.json({ day: db.day(), days, limit, installs });
});

// One install's counters, broken out by day and event name — the drill-down
// under the grid. Takes the stored (hashed) id: the raw analytics UUID is
// never at rest here, so there is nothing else to look up by.
app.get('/v1/admin/analytics/install', adminAuth, (req, res) => {
    const id = String(req.query.id || '').trim();
    if (!/^[0-9a-f]{64}$/.test(id)) {
        return res.status(400).json({ error: 'id must be a stored (SHA-256) install id' });
    }
    const days = rangeDays(req);
    res.json({ installId: id, day: db.day(), days, ...db.analyticsInstall(id, db.daysAgo(days - 1)) });
});

// The install table for /admin/installs — its own endpoint, server-sorted
// and paged, for the same reason /v1/admin/analytics left the overview: a
// fixed top-200 list bloated every page's 60-second poll, and sorting a
// pre-ranked slice client-side could never answer "oldest install" or
// "least active" truthfully. Rows are still install ids + counts only.
app.get('/v1/admin/installs', adminAuth, (req, res) => {
    const q = String(req.query.q || '').trim().toLowerCase();
    if (q && !/^[0-9a-f]{1,64}$/.test(q)) {
        return res.status(400).json({ error: 'q must be a hex prefix of a stored (SHA-256) install id' });
    }
    const sort = String(req.query.sort || 'usage');
    const dir = req.query.dir === 'asc' ? 'asc' : 'desc';
    const limit = Math.max(1, Math.min(500, parseInt(req.query.limit, 10) || 100));
    const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
    const page = db.installPage({ sort, dir, limit, offset, q });
    if (!page) return res.status(400).json({ error: 'unknown sort key', sortKeys: db.installSortKeys });
    res.json({ day: db.day(), sort, dir, limit, offset, ...page });
});

// Everything the /admin dashboard renders, in one call. Metrics are
// service-wide daily counters — the per-install table lives on
// /v1/admin/installs (above), fetched only by the page that shows it.
app.get('/v1/admin/overview', adminAuth, (req, res) => {
    const days = rangeDays(req);
    res.json({
        ...db.stats(),
        day: db.day(),
        metrics: db.metricsSince(db.daysAgo(days - 1)),
        actives: db.actives(),
        analytics: {
            daily: db.analyticsDaily(db.daysAgo(days - 1)),
            top: db.analyticsTop(db.daysAgo(days - 1), 40),
            actives: db.analyticsActives()
        },
        providers: router.statusSnapshot(),
        llm: {
            models: llm.available(),
            ...db.llmPeriodTotals(),
            budgetTokens: config.llmBudgetTokens || null
        },
        relay: relay.stats(),
        tierQuotas: config.tierQuotas,
        llmTierQuotas: config.llmTierQuotas,
        feedback: db.feedbackCounts(),
        alerts: alerts.evaluate(),
        webhookConfigured: !!config.alertWebhookUrl
    });
});

// The admin pages. Multi-page since 2026-08-04 (one dashboard had grown
// every panel the service owns): /admin is service health, with analytics,
// installs and feedback as sibling pages sharing one shell (public/admin/).
// Serving them without auth is fine — the files contain no data (this repo
// is public anyway); every data fetch goes through adminAuth with the
// token the operator enters, and shared.js carries it between pages.
const ADMIN_PAGES = { '': 'overview', overview: 'overview', analytics: 'analytics', installs: 'installs', feedback: 'feedback', models: 'models' };
app.get(['/admin', '/admin/:page'], (req, res, next) => {
    // hasOwn, not a bare index — '/admin/__proto__' resolved to
    // Object.prototype, and sendFile on that threw a path-leaking 500.
    const slug = req.params.page || '';
    if (!Object.hasOwn(ADMIN_PAGES, slug)) return next();
    // CSP on the pages that render user-written text (feedback). The inline
    // scripts these pages use need 'unsafe-inline', so this is defence in
    // depth, not a wall: it still blocks external script loads, fetch/img
    // exfiltration to other hosts, and framing.
    res.set('Content-Security-Policy',
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        + "img-src 'self' data:; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'");
    res.sendFile(path.join(__dirname, 'public', 'admin', ADMIN_PAGES[slug] + '.html'));
});
app.use('/admin/assets', express.static(path.join(__dirname, 'public', 'admin', 'assets')));

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// Terminal error handler. Without one, Express's default prints the full
// stack trace — absolute filesystem paths included — into the response body
// whenever NODE_ENV isn't 'production', and nothing in the deploy config
// guarantees it is set. Body-parser errors keep their 4xx status; anything
// else is a plain 500 with no internals.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    const status = err.status || err.statusCode || 500;
    if (status >= 500) {
        db.bumpMetric('server.error');
        console.error(`[error] ${req.method} ${req.path}: ${err.message}`);
    }
    res.status(status).json({ error: status >= 500 ? 'Internal error' : 'Bad request' });
});

if (require.main === module) {
    // Cost ceilings ship ON by default (config.js); running uncapped is an
    // explicit choice and gets named at boot so it can't be an accident.
    if (config.llmUpstreamUrl && !config.llmBudgetTokens) {
        console.warn('[config] LLM_BUDGET_TOKENS=0 — /v1/llm has NO service-wide spend ceiling');
    }
    for (const [name, k] of Object.entries(config.providerKeys)) {
        if (k && !config.providerBudgets[name]) {
            console.warn(`[config] provider ${name} has no PROVIDER_BUDGETS cap — uncapped spend`);
        }
    }
    if (config.adminToken && config.adminToken.length < 24) {
        console.warn('[config] ADMIN_TOKEN is short — it is the only admin credential; use 24+ random chars');
    }
    // Retention sweep: once at boot, then daily. Cheap (two indexed
    // DELETEs), and running it at boot means a long-lived deployment can't
    // sit years past its stated retention because nothing restarted it.
    const purge = () => {
        if (!config.feedbackRetentionDays && !config.analyticsRetentionDays) return;
        try {
            const n = db.purgeOldRows(
                config.feedbackRetentionDays || 1e6,
                config.analyticsRetentionDays || 1e6
            );
            if (n.feedback || n.analytics) {
                console.log(`[retention] purged ${n.feedback} feedback, ${n.analytics} analytics rows`);
            }
        } catch (e) {
            console.error(`[retention] purge failed: ${e.message}`);
        }
    };
    purge();
    setInterval(purge, 24 * 60 * 60 * 1000).unref();
    const server = app.listen(config.port, () => {
        console.log(`anjadhe-connect listening on :${config.port} — providers: ${router.available().join(', ') || 'NONE CONFIGURED'}`);
    });
    relay.attach(server);
    if (config.alertWebhookUrl) {
        setInterval(() => alerts.checkAndNotify(), 10 * 60 * 1000).unref();
        alerts.checkAndNotify();
    }
}

module.exports = app;
