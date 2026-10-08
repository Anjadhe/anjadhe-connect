// nenva Connect — hosted services for the nenva app (api.anjadhe.com).
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
const billing = require('./lib/billing');
const slackAnalysis = require('./lib/slack-analysis');
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
// LLM bodies were capped at 256 KB until 2026-10-08, sized for text: a chat
// with one photo (an image travels as a base64 data URL, and earlier
// photos ride again on every turn) came to ~626 KB and was refused, from
// the phone and the desktop alike. 4 MB holds several photos with the
// conversation; the cap still bounds what one request makes us parse, and
// the per-IP and per-key limiters still apply. Metering is by tokens, so
// the cap was never what bounded cost.
const jsonBody = express.json({ limit: '10kb' });
const jsonBodyAnalytics = express.json({ limit: '64kb' });
const jsonBodyLlm = express.json({ limit: '4mb' });
const jsonBodySlack = express.json({ limit: '16kb' });
// Stripe's webhook is verified over its exact bytes, so it gets the raw body.
// (type: any — a request with no Content-Type must still be read whole, or
// the check would run over an empty body.)
const rawBodyWebhook = express.raw({ type: () => true, limit: '256kb' });
app.use((req, res, next) => {
    if (req.path === '/v1/billing/webhook') return rawBodyWebhook(req, res, next);
    const parser = req.path === '/v1/analytics/events' ? jsonBodyAnalytics
        : req.path.startsWith('/v1/llm/') ? (req.get('x-nenva-feature') === 'slack-monitor' ? jsonBodySlack : jsonBodyLlm) : jsonBody;
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
function allowFeedbackHour(rawIp, map = _feedbackByIp) {
    const ip = ipBucket(rawIp);
    const now = Date.now();
    capLimiter(map, (v) => now - v.windowStart >= 3600000);
    const cur = map.get(ip);
    if (!cur || now - cur.windowStart >= 3600000) {
        map.set(ip, { windowStart: now, count: 1 });
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
    req.install = withPlan(row);
    next();
}

// Billing P3: an install attached to a paid code uses the code's plan while
// the code is in good standing (active, or past_due within the grace days
// after its paid-through date). Otherwise its own tier (free, or one set by
// hand). The tier is the only thing that changes; every limit below reads it.
function planFromCode(code, now = Date.now()) {
    if (!code) return null;
    const end = Date.parse(code.period_end || '') || 0;
    const grace = config.billingGraceDays * 86400000;
    if (code.status === 'active' && (!end || now <= end + grace)) return code.plan;
    if (code.status === 'past_due' && end && now <= end + grace) return code.plan;
    return null;
}
function withPlan(row) {
    // Who pays (billing P1/P3): a code shared by several Macs is one owner,
    // so its meters, top-ups and (with PLAN_ALLOWANCES) allowance are shared.
    const owner = row.plan_code ? 'c:' + row.plan_code : 'i:' + row.install_id;
    const code = row.plan_code ? db.planCodeGet(row.plan_code) : null;
    const plan = planFromCode(code);
    if (plan && Object.hasOwn(config.tierQuotas, plan)) {
        return { ...row, owner, tier: plan, plan_source: 'code', code_status: code.status, period_end: code.period_end };
    }
    // The trial (P4): a plan for a few days, once per registration.
    const trial = row.trial_sub ? db.trialGet(row.trial_sub) : null;
    if (trial && Date.parse(trial.ends_at) > Date.now() && Object.hasOwn(config.tierQuotas, trial.plan)) {
        return { ...row, owner, tier: trial.plan, plan_source: 'trial', code_status: code ? code.status : null, trial_ends: trial.ends_at };
    }
    return { ...row, owner, plan_source: 'tier', code_status: code ? code.status : (row.plan_code ? 'missing' : null) };
}

// Cost-weighted allowance (billing P2): only when PLAN_ALLOWANCES names the
// tier. { allowance, used: {chat, background}, bgCap } in micro-dollars.
function costAllowance(install) {
    const a = config.planAllowances[install.tier];
    if (!a || !Number.isFinite(a.aiMicros)) return null;
    const used = db.llmCostUsed(install.owner);
    const share = Number.isFinite(a.bgShare) ? Math.min(1, Math.max(0, a.bgShare)) : 0.4;
    return { allowance: a.aiMicros, used, bgCap: Math.floor(a.aiMicros * share) };
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
    if (config.commit) body.commit = config.commit;
    res.json(body);
});

// Which code is running. Keyless and cacheable: the point is that anyone
// (the app's Settings card, a skeptical reader of the public repo) can
// compare `commit` with github.com/Anjadhe/anjadhe-connect and know the
// privacy invariant they read is the one in production. `null` means the
// deploy did not stamp one (local dev) — never a fake value.
const STARTED_AT = new Date().toISOString();
app.get('/v1/version', (req, res) => {
    res.set('Cache-Control', 'public, max-age=300');
    res.json({
        commit: config.commit,
        env: config.envLabel,
        startedAt: STARTED_AT,
        source: 'https://github.com/Anjadhe/anjadhe-connect',
        privacy: 'https://github.com/Anjadhe/anjadhe-connect#privacy-verified'
    });
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
    // "test-…" ids are test installs (see db.js keys.test): flagged here,
    // the one moment the raw id is in hand.
    const isTest = /^test-/i.test(installId);
    db.createKey(idHash, hashKey(key), isTest);
    db.bumpMetric(isTest ? 'mint.test' : 'mint.new');
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
    // Past the month's allowance, a top-up pays for the search (billing P5).
    if (used >= quota && db.topupUseSearch(req.install.owner)) {
        db.bumpMetric('search.topup');
    } else if (used >= quota) {
        db.bumpMetric('search.quota');
        return res.status(429).json({
            error: `Monthly quota reached (${quota} searches on the ${tier} plan). Resets ${resetsAt()}.`,
            code: 'quota', used, quota, plan: tier, resetsAt: resetsAt()
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
        db.meterSearch({ owner: req.install.owner, provider: upstream, costMicros: config.providerPrices[upstream] || 0 });
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

// Current headlines for a batch of user-chosen topics (the nenva app's
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
    // Which sources answer (2026-09-10): ids from lib/news.js's registry;
    // unknown ids drop and nothing picked means Google News, so a client
    // from before sources existed is served exactly as before. Each item
    // comes back stamped `via` with the source that carried it.
    const sources = news.normalizeSources(req.body?.sources);
    const out = await Promise.all(topics.map(async (topic) => {
        try {
            const { items, served } = await news.topicNews(topic, sources);
            db.bumpMetric('news.topic_ok');
            for (const s of served) {
                // How often the second upstream is carrying Google: a
                // steady news.via_bing means Google has stopped answering.
                if (s.upstream === 'bing-fallback') db.bumpMetric('news.via_bing');
                // Uptake of the picked sources, service-wide counters only.
                if (s.source !== 'google') db.bumpMetric(`news.src.${s.source}`);
            }
            return { topic, items };
        } catch (e) {
            // Error details stay server-side; they could echo upstream URLs.
            // The failure CLASS is counted (news.upstream.http429, …) so the
            // dashboard can show that — and why — the upstream is refusing.
            db.bumpMetric('news.upstream_fail');
            db.bumpMetric(`news.upstream.${news.failureKind(e)}`);
            return { topic, items: [], error: 'unavailable' };
        }
    }));
    res.json({ topics: out, provider: 'anjadhe' });
});

// ── Brokerage, bank and card linking (/v1/brokerage, Plaid) ─────────────
// The app's Portfolio links a brokerage here, and since 2026-09-09 its
// Spending app links a bank or card the same way: /link hands back a Plaid
// Hosted Link URL the app opens in the browser, /link/:token is polled
// until the user finishes on the brokerage's own login page, and the data
// routes PROXY holdings and transactions for one linked Item. See
// lib/brokerage.js for the privacy shape (token sealed at rest, data never
// stored). Bounded two ways: linked Items per install by tier, and a
// service-wide ceiling (BROKERAGE_MAX_ITEMS — Plaid bills per Item).
const brokerage = require('./lib/brokerage');
const BROKERAGE_PER_MINUTE = 20;
const _brokerageByInstall = new Map();
function allowBrokerageMinute(installId) {
    const now = Date.now();
    capLimiter(_brokerageByInstall, (v) => now - v.windowStart >= 60000);
    const cur = _brokerageByInstall.get(installId);
    if (!cur || now - cur.windowStart >= 60000) {
        _brokerageByInstall.set(installId, { windowStart: now, count: 1 });
        return true;
    }
    if (cur.count >= BROKERAGE_PER_MINUTE) return false;
    cur.count++;
    return true;
}
// Link-status polling has its own, looser brake: the app polls every few
// seconds for as long as the user is on the brokerage's sign-in page, and a
// slow sign-in must not trip the data cap and abandon the link (it did —
// 2026-09-09, the first sandbox test).
const BROKERAGE_POLL_PER_MINUTE = 90;
const _brokeragePollByInstall = new Map();
function allowBrokeragePollMinute(installId) {
    const now = Date.now();
    capLimiter(_brokeragePollByInstall, (v) => now - v.windowStart >= 60000);
    const cur = _brokeragePollByInstall.get(installId);
    if (!cur || now - cur.windowStart >= 60000) {
        _brokeragePollByInstall.set(installId, { windowStart: now, count: 1 });
        return true;
    }
    if (cur.count >= BROKERAGE_POLL_PER_MINUTE) return false;
    cur.count++;
    return true;
}
function brokerageGate(req, res, next) {
    if (!brokerage.enabled()) {
        return res.status(503).json({ error: 'Brokerage linking is not enabled on this service.', code: 'disabled' });
    }
    const poll = req.method === 'GET' && /^\/v1\/brokerage\/link\//.test(req.path);
    if (!(poll ? allowBrokeragePollMinute : allowBrokerageMinute)(req.install.install_id)) {
        db.bumpMetric('brokerage.rate');
        return res.status(429).json({ error: 'Rate limit: too many brokerage requests this minute — retry shortly.', code: 'rate' });
    }
    next();
}
// One failure shape. Plaid's own message never travels (an error body can
// echo account data); the CODE does, because the app acts on it.
function brokerageFail(res, e, what) {
    const kind = brokerage.failureKind(e);
    db.bumpMetric('brokerage.fail');
    db.bumpMetric(`brokerage.fail.${kind}`);
    console.error(`[brokerage] ${what} failed: ${kind}`);
    if (brokerage.loginRequired(e)) {
        return res.status(409).json({ error: 'This brokerage needs you to sign in again.', code: 'login_required' });
    }
    if (kind === 'NOT_LINKED') return res.status(404).json({ error: 'No such linked institution.', code: 'not_found' });
    if (kind === 'timeout' || kind === 'net') {
        return res.status(502).json({ error: 'Plaid could not be reached right now.', code: 'upstream' });
    }
    return res.status(502).json({ error: 'Plaid returned an error.', code: kind });
}
const ITEM_ID_RX = /^[A-Za-z0-9_-]{4,80}$/;
const DATE_RX = /^\d{4}-\d{2}-\d{2}$/;

app.post('/v1/brokerage/link', auth, brokerageGate, async (req, res) => {
    const itemId = req.body?.itemId ? String(req.body.itemId) : null;
    if (itemId && !ITEM_ID_RX.test(itemId)) return res.status(400).json({ error: 'itemId malformed' });
    const products = Array.isArray(req.body?.products) ? req.body.products : null;
    if (products && (products.length > 4 || products.some(p => !brokerage.PRODUCTS.includes(String(p).toLowerCase())))) {
        return res.status(400).json({ error: `products must be from: ${brokerage.PRODUCTS.join(', ')}` });
    }
    if (!itemId) {
        const tier = req.install.tier || 'free';
        const cap = config.brokerageTierItems[tier] ?? config.brokerageTierItems.free;
        if (db.brokerageItemCountFor(req.install.install_id) >= cap) {
            db.bumpMetric('brokerage.cap.install');
            return res.status(429).json({ error: `Your plan allows ${cap} linked institution${cap === 1 ? '' : 's'}. Unlink one to add another.`, code: 'cap', cap });
        }
        if (config.brokerageMaxItems && db.brokerageItemCount() >= config.brokerageMaxItems) {
            db.bumpMetric('brokerage.cap.service');
            return res.status(503).json({ error: 'Account linking is at capacity right now. Try again later.', code: 'capacity' });
        }
    }
    try {
        const r = await brokerage.startLink(req.install.install_id, { itemId, products });
        db.bumpMetric(itemId ? 'brokerage.relink' : 'brokerage.link');
        if (!itemId) db.bumpMetric(`brokerage.link.${brokerage.parseProducts(products)[0]}`);
        res.json(r);
    } catch (e) { brokerageFail(res, e, 'link'); }
});

app.get('/v1/brokerage/link/:token', auth, brokerageGate, async (req, res) => {
    const token = String(req.params.token || '');
    if (!/^[A-Za-z0-9_-]{8,200}$/.test(token)) return res.status(400).json({ error: 'token malformed' });
    try {
        const r = await brokerage.linkStatus(req.install.install_id, token);
        if (r.status === 'done') db.bumpMetric('brokerage.linked');
        res.json(r);
    } catch (e) { brokerageFail(res, e, 'link status'); }
});

app.get('/v1/brokerage/items', auth, (req, res) => {
    res.json({ enabled: brokerage.enabled(), items: brokerage.enabled() ? brokerage.items(req.install.install_id) : [] });
});

app.post('/v1/brokerage/accounts', auth, brokerageGate, async (req, res) => {
    const itemId = String(req.body?.itemId || '');
    if (!ITEM_ID_RX.test(itemId)) return res.status(400).json({ error: 'itemId required' });
    try {
        const r = await brokerage.accounts(req.install.install_id, itemId);
        db.bumpMetric('brokerage.accounts');
        res.json(r);
    } catch (e) { brokerageFail(res, e, 'accounts'); }
});

// Bank/card spending, cursor-based (Plaid Transactions). The cursor is the
// app's to keep; Connect stores nothing between calls.
app.post('/v1/brokerage/transactions/sync', auth, brokerageGate, async (req, res) => {
    const itemId = String(req.body?.itemId || '');
    const cursor = req.body?.cursor ? String(req.body.cursor) : null;
    if (!ITEM_ID_RX.test(itemId)) return res.status(400).json({ error: 'itemId required' });
    if (cursor && cursor.length > 1024) return res.status(400).json({ error: 'cursor malformed' });
    try {
        const r = await brokerage.syncTransactions(req.install.install_id, itemId, cursor);
        db.bumpMetric('brokerage.sync');
        res.json(r);
    } catch (e) { brokerageFail(res, e, 'transactions sync'); }
});

app.post('/v1/brokerage/holdings', auth, brokerageGate, async (req, res) => {
    const itemId = String(req.body?.itemId || '');
    if (!ITEM_ID_RX.test(itemId)) return res.status(400).json({ error: 'itemId required' });
    try {
        const r = await brokerage.holdings(req.install.install_id, itemId);
        db.bumpMetric('brokerage.holdings');
        res.json(r);
    } catch (e) { brokerageFail(res, e, 'holdings'); }
});

app.post('/v1/brokerage/transactions', auth, brokerageGate, async (req, res) => {
    const itemId = String(req.body?.itemId || '');
    const start = String(req.body?.startDate || '');
    const end = String(req.body?.endDate || db.day());
    if (!ITEM_ID_RX.test(itemId)) return res.status(400).json({ error: 'itemId required' });
    if (!DATE_RX.test(start) || !DATE_RX.test(end) || start > end) {
        return res.status(400).json({ error: 'startDate/endDate must be YYYY-MM-DD with startDate <= endDate' });
    }
    try {
        const r = await brokerage.transactions(req.install.install_id, itemId, start, end);
        db.bumpMetric('brokerage.transactions');
        res.json(r);
    } catch (e) { brokerageFail(res, e, 'transactions'); }
});

app.post('/v1/brokerage/unlink', auth, brokerageGate, async (req, res) => {
    const itemId = String(req.body?.itemId || '');
    if (!ITEM_ID_RX.test(itemId)) return res.status(400).json({ error: 'itemId required' });
    try {
        const r = await brokerage.unlink(req.install.install_id, itemId);
        db.bumpMetric('brokerage.unlink');
        res.json(r);
    } catch (e) { brokerageFail(res, e, 'unlink'); }
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

app.get('/v1/llm/slack-monitor-policy', (_req, res) => res.json({ version: 1, requestBytes: 16384, outputTokens: 1024 }));

app.post('/v1/llm/chat/completions', auth, async (req, res) => {
    if (req.get('x-nenva-feature') === 'slack-monitor') {
        const denial = slackAnalysis.check(req.body, req.get('x-nenva-slack-account'), req.install.owner, db.reserveSlack);
        if (denial) return res.status(denial.status).json({ error: denial.error, code: denial.code });
        // A tagged background request never consumes a chat top-up.
        req.headers['x-nenva-work'] = 'background';
    }
    const models = llm.available();
    if (!models.length) {
        return res.status(503).json({ error: 'LLM inference is not configured on this deployment', code: 'unconfigured' });
    }
    // An old id (an alias) resolves to the model it was renamed to; the
    // error lists current ids only, never aliases.
    const model = llm.resolve(String(req.body?.model || ''));
    if (!model) {
        return res.status(400).json({ error: `Unknown model — one of: ${models.join(', ')}`, code: 'model', models });
    }
    if (!Array.isArray(req.body?.messages) || !req.body.messages.length) {
        return res.status(400).json({ error: 'messages required', code: 'request' });
    }
    // Images only to a model marked as reading them; otherwise the upstream
    // answers 400 and the person sees "AI request failed — retry shortly."
    if (llm.hasImages(req.body.messages) && !llm.readsImages(model)) {
        db.bumpMetric('llm.vision_refused');
        return res.status(400).json({ error: 'This nenva cloud model cannot read images.', code: 'vision' });
    }

    const { install_id: installId, tier } = req.install;
    const quota = llmQuotaFor(tier);
    const used = db.llmUsed(installId);
    const work = String(req.get('x-nenva-work') || '').toLowerCase() === 'background' ? 'background' : 'chat';
    // Over the month's allowance? Cost-weighted when PLAN_ALLOWANCES names
    // this tier (P2: background held to its share), else today's request +
    // token limits. A top-up with tokens left carries the person past it
    // (P5); background work never spends a top-up.
    const cost = costAllowance(req.install);
    const bgOut = cost && work === 'background' && cost.used.background >= cost.bgCap;
    const over = cost ? (cost.used.chat + cost.used.background >= cost.allowance)
        : (used.requests >= quota.requests || used.tokens >= quota.tokens);
    let viaTopup = false;
    if (over && !bgOut && work === 'chat' && db.topupBalance(req.install.owner).tokens > 0) viaTopup = true;
    if (bgOut) {
        db.bumpMetric('llm.quota_background');
        return res.status(429).json({
            error: `This month's share for background work is used on the ${tier} plan. Resets ${resetsAt()}.`,
            code: 'quota', work: 'background', plan: tier, resetsAt: resetsAt()
        });
    }
    if (over && !viaTopup) {
        db.bumpMetric('llm.quota');
        return res.status(429).json({
            error: `Monthly AI quota reached on the ${tier} plan. Resets ${resetsAt()}.`,
            code: 'quota', plan: tier,
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
    // `work` (above): what the call is for, from the app's X-Nenva-Work
    // header (billing P1). Absent counts as chat, which is how every call
    // counted before the header existed.
    const meter = { owner: req.install.owner, viaTopup };
    try {
        if (stream) {
            // chatStream owns the response from here (SSE passthrough).
            const { usage } = await llm.chatStream(model, req.body, res);
            meterLlm(installId, usage, used, quota, model, work, meter);
            if (usage.estimated) db.bumpMetric('llm.stream.estimated');
        } else {
            const { json, usage } = await llm.chat(model, req.body);
            meterLlm(installId, usage, used, quota, model, work, meter);
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
function meterLlm(installId, usage, before, quota, model, work, meter = {}) {
    db.bumpLlmUsage(installId, usage.prompt_tokens || 0, usage.completion_tokens || 0);
    // The cost meter (billing P1): the same tokens, priced at the model's
    // current rate, by model and by what the call was for, to the owner
    // that pays (the code when this Mac is on a paid plan).
    if (model) {
        const tin = usage.prompt_tokens || 0, tout = usage.completion_tokens || 0;
        db.meterLlm({ owner: meter.owner || 'i:' + installId, model, work, tokensIn: tin, tokensOut: tout,
            costMicros: db.llmCostMicros(model, tin, tout), estimated: !!usage.estimated });
        // A call made past the allowance on a top-up draws its tokens (P5).
        if (meter.viaTopup) { db.topupUseTokens(meter.owner, tin + tout); db.bumpMetric('llm.topup'); }
    }
    db.bumpMetric('llm.ok');
    const total = (usage.prompt_tokens || 0) + (usage.completion_tokens || 0);
    if (total) db.bumpMetricBy('llm.tokens', total);
    if (before && quota) {
        const crossed = llm.quotaCrossing(before, { requests: before.requests + 1, tokens: before.tokens + total }, quota);
        if (crossed) db.bumpMetric(`llm.quota_${crossed}`);
    }
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

// ── Website analytics (nenva.co) ─────────────────────────────────────────
// The website counts its own visitors here instead of running a third-party
// script. The browser never calls this: it posts to the site's own /api/e,
// whose server route adds the visitor's IP, user agent and Vercel's country
// header and forwards with WEB_ANALYTICS_TOKEN. What happens to each (see
// lib/web.js): IP + user agent become a salted hash whose salt dies at the
// end of the UTC day, and are otherwise dropped on the floor; the rest is
// normalized against a closed vocabulary and folded into daily counters.
const web = require('./lib/web');
// Per visitor-IP brake. Keyed by the IP the SITE saw (every request here
// arrives from Vercel's addresses, so req.ip would be one bucket for the
// whole world). A person reading the site makes a handful of events a
// minute; 60 absorbs a shared office.
const WEB_PER_MINUTE = 60;
const _webByIp = new Map();
function allowWebMinute(rawIp) {
    const ip = ipBucket(rawIp);
    const now = Date.now();
    capLimiter(_webByIp, (v) => now - v.windowStart >= 60000);
    const cur = _webByIp.get(ip);
    if (!cur || now - cur.windowStart >= 60000) {
        _webByIp.set(ip, { windowStart: now, count: 1 });
        return true;
    }
    if (cur.count >= WEB_PER_MINUTE) return false;
    cur.count++;
    return true;
}

app.post('/v1/web/events', (req, res) => {
    if (!config.webAnalyticsToken) {
        return res.status(503).json({ error: 'Website analytics is not enabled on this service.', code: 'disabled' });
    }
    const given = crypto.createHash('sha256').update(req.get('x-web-token') || '').digest();
    const want = crypto.createHash('sha256').update(config.webAnalyticsToken).digest();
    if (!crypto.timingSafeEqual(given, want)) {
        db.bumpMetric('web.auth_fail');
        return res.status(401).json({ error: 'Bad token' });
    }
    const ip = String(req.body?.ip || '').trim().slice(0, 64);
    const ua = String(req.body?.ua || '').slice(0, 400);
    if (!ip || web.isBot(ua)) {
        db.bumpMetric('web.bot');
        return res.json({ counted: false });
    }
    const ev = web.normalize(req.body);
    if (!ev) {
        db.bumpMetric('web.reject');
        return res.json({ counted: false });
    }
    if (!allowWebMinute(ip)) {
        db.bumpMetric('web.rate');
        return res.status(429).json({ error: 'Rate limit', code: 'rate' });
    }
    const counted = db.recordWeb(ev, web.visitorId(db.webSalt(), ip, ua), config.webMaxRowsPerDay);
    db.bumpMetric(counted ? 'web.ok' : 'web.cap');
    res.json({ counted });
});

// Everything /admin/website draws. Optional filters (path, referrer,
// source, country, device) narrow the counters; see db.webReport for why the
// unique-visitor numbers are only ever service-wide.
app.get('/v1/admin/web', adminAuth, (req, res) => {
    const days = rangeDays(req);
    const filters = {};
    for (const dim of db.webDims) {
        if (typeof req.query[dim] === 'string') filters[dim] = req.query[dim].slice(0, 120);
    }
    res.json({ day: db.day(), days, filters, ...db.webReport(db.daysAgo(days - 1), filters) });
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

// ── Release-notes subscribers ────────────────────────────────────────────
// The website's download page posts here ("Get release notes — email only,
// unsubscribe anytime"). The address is the entire record: keyless, no
// install id, no IP at rest, no name, no tags, and it exists for one
// purpose — one email per release, sent by the operator. Since 2026-09-30
// a license claim that agreed to contact also lands here (source
// 'license': release news and important notices; see App licenses). Unsubscribing
// deletes the row outright. The response never says whether an address
// was already on the list (a repeat signup is the same success), so the
// endpoint cannot be used to test membership. A real browser origin is
// involved this time, so the CORS grant is the site's own hosts.
const SITE_ORIGINS = new Set([
    'https://anjadhe.ai', 'https://www.anjadhe.ai', 'https://anjadhe.com', 'https://www.anjadhe.com',
    ...(process.env.SUBSCRIBE_ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean)
]);
function siteCors(req, res) {
    const origin = req.get('origin');
    res.set('Vary', 'Origin');
    if (!origin || !SITE_ORIGINS.has(origin)) return;
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Content-Type');
    res.set('Access-Control-Max-Age', '86400');
}
const _subscribeByIp = new Map();
const EMAIL_RX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
// What this endpoint can and cannot defend. It is keyless because the site
// is static — any token in its JS would be public — so a determined actor
// with curl can post; CORS governs browsers only, and Origin is spoofable
// outside one. The brakes are layered rather than absolute: an Origin from
// the site's own hosts is REQUIRED (stops naive scripts and any other
// site's visitors), a per-IP hourly cap, a honeypot, address validation +
// dedupe, and a service-wide daily cap on new rows so a distributed flood
// bounds the damage at a few hundred junk addresses that the admin page
// can remove. Nothing here mails anyone — the list is read by a person.
let _subscribeDay = '';
let _subscribeToday = 0;
function allowSubscribeToday() {
    if (!config.subscribePerDay) return true;
    const day = new Date().toISOString().slice(0, 10);
    if (day !== _subscribeDay) { _subscribeDay = day; _subscribeToday = 0; }
    return _subscribeToday < config.subscribePerDay;
}

app.options('/v1/subscribe', (req, res) => {
    siteCors(req, res);
    res.sendStatus(204);
});

app.post('/v1/subscribe', (req, res) => {
    siteCors(req, res);
    const origin = req.get('origin');
    if (!origin || !SITE_ORIGINS.has(origin)) {
        db.bumpMetric('subscribe.origin');
        return res.status(403).json({ error: 'Signups are accepted from nenva.co only.', code: 'origin' });
    }
    const email = String(req.body?.email || '').trim().toLowerCase();
    if (email.length > 200 || !EMAIL_RX.test(email)) {
        return res.status(400).json({ error: 'That does not look like an email address.', code: 'email' });
    }
    // The honeypot: a hidden field bots fill and people never see.
    if (String(req.body?.website || '')) return res.json({ success: true });
    const source = String(req.body?.source || '').trim().slice(0, 40) || null;
    if (!allowFeedbackHour(req.ip, _subscribeByIp)) {
        db.bumpMetric('subscribe.rate');
        return res.status(429).json({ error: 'Too many signups from this address this hour — please retry later.', code: 'rate' });
    }
    if (!allowSubscribeToday()) {
        db.bumpMetric('subscribe.cap');
        return res.status(503).json({ error: 'The signup list is closed for today — please try again tomorrow.', code: 'cap' });
    }
    if (db.addSubscriber(email, source)) { _subscribeToday++; db.bumpMetric('subscribe.ok'); }
    res.json({ success: true });
});

// The one-click link at the bottom of every release email. GET, because
// that is what a mail client opens; the token is unguessable (192 bits)
// and single-purpose, and the only effect is deleting the address that
// asked for it. A plain page, not JSON — a person is reading it.
app.get('/v1/unsubscribe', (req, res) => {
    const token = String(req.query.t || '');
    const ok = /^[A-Za-z0-9_-]{16,64}$/.test(token) && db.unsubscribe(token);
    if (ok) db.bumpMetric('subscribe.unsub');
    res.type('html').send(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>nenva release notes</title>
<style>body{font-family:-apple-system,system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1.5rem;color:#111;line-height:1.6}h1{font-weight:600;font-size:1.25rem}a{color:inherit}@media(prefers-color-scheme:dark){body{background:#111;color:#eee}}</style></head>
<body>${ok
        ? '<h1>You are unsubscribed.</h1><p>Your address has been deleted from the release-notes list. Nothing else was kept.</p>'
        : '<h1>Nothing to do.</h1><p>This link has already been used, or the address was never on the list.</p>'}
<p><a href="https://github.com/Anjadhe/Anjadhe/releases">Every release stays public on GitHub.</a></p></body></html>`);
});

app.get('/v1/admin/subscribers', adminAuth, (req, res) => {
    res.json({ count: db.subscriberCount(), items: db.subscribersList() });
});

app.post('/v1/admin/subscribers/remove', adminAuth, (req, res) => {
    const id = parseInt(req.body?.id, 10);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'id required' });
    if (!db.removeSubscriber(id)) return res.status(404).json({ error: 'Unknown subscriber id' });
    res.json({ success: true, id });
});

// ── App licenses ─────────────────────────────────────────────────────────
// The app's license (BUSINESS_MODEL.md in the app repo) is an Ed25519-signed
// string the app verifies OFFLINE with a baked-in public key — see
// lib/license.js. Since 2026-09-30 nenva's core is free for good and the
// license is how a person REGISTERS: the self-serve claim below is open to
// everyone, always (class 'alpha' while the alpha is open, 'free' after),
// and the admin mint remains for a paid key by hand. A license is issued to
// an EMAIL ADDRESS, typed by the person into the app: re-claiming with the
// same address returns the same key, so the address is how a re-install
// recovers it.
//
// Contact is CONSENT, carried per claim: the app sends `contact: true` only
// from the screen that says the address is how nenva reaches you (release
// news and important notices, unsubscribe in every email). That adds the
// address to the release-notes list (subscribers, source 'license'), whose
// per-address unsubscribe link already exists; unsubscribing leaves the
// license alone. Claims made before 2026-09-30 were told the address only
// put "free for good" on record, so they are never on the list.
const license = require('./lib/license');
let _licenseKey = null;
if (config.licenseSigningKey) {
    try {
        _licenseKey = license.privateKeyFromSeed(config.licenseSigningKey);
        console.log(`[license] signing enabled; public key ${license.publicKeyRaw(_licenseKey).toString('base64')}`);
    } catch (e) {
        console.error(`[license] LICENSE_SIGNING_KEY rejected: ${e.message} — licensing disabled`);
    }
} else {
    console.warn('[license] LICENSE_SIGNING_KEY unset — /v1/license endpoints answer 503');
}
const _licenseByIp = new Map();
function licenseAlphaOpen() {
    return !config.licenseAlphaClosesAt || new Date().toISOString().slice(0, 10) < config.licenseAlphaClosesAt;
}
function issueLicense({ cls, email, updatesUntil, source, appVersion }) {
    // A free license is one per person whichever name it was minted under:
    // someone who claimed during the alpha gets that key back after it.
    const existing = license.FREE_CLASSES.has(cls)
        ? (db.licenseFor(email, 'alpha') || db.licenseFor(email, 'free'))
        : db.licenseFor(email, cls);
    if (existing) return { row: existing, created: false };
    const { key, payload } = license.mint(_licenseKey, { cls, email, updatesUntil });
    db.addLicense({ id: payload.id, cls, email, subHash: payload.sub, updatesUntil, license: key, source, appVersion });
    return { row: db.licenseFor(email, cls), created: true };
}
function licenseJson(row) {
    return {
        license: row.license, class: row.class, id: row.id,
        issuedAt: row.created_at.slice(0, 10), updatesUntil: row.updates_until || null
    };
}

// Keyless, nothing about the caller: whether a license can be claimed.
// claimOpen is what current apps read; alphaOpen stays for apps before
// 0.1.0-alpha.102, which offer the claim only while it is true.
app.get('/v1/license/status', (req, res) => {
    res.json({
        enabled: !!_licenseKey,
        claimOpen: !!_licenseKey,
        alphaOpen: !!_licenseKey && licenseAlphaOpen(),
        alphaClosesAt: config.licenseAlphaClosesAt
    });
});

app.options(['/v1/license/claim', '/v1/license/alpha'], (req, res) => {
    analyticsCors(req, res);
    res.sendStatus(204);
});

// /v1/license/alpha is the path apps before 0.1.0-alpha.102 call; both
// paths are the one claim.
app.post(['/v1/license/claim', '/v1/license/alpha'], (req, res) => {
    analyticsCors(req, res);
    if (!_licenseKey) return res.status(503).json({ error: 'Licensing is not enabled on this server.', code: 'disabled' });
    const cls = licenseAlphaOpen() ? 'alpha' : 'free';
    const email = String(req.body?.email || '').trim().toLowerCase();
    if (email.length > 200 || !EMAIL_RX.test(email)) {
        return res.status(400).json({ error: 'That does not look like an email address.', code: 'email' });
    }
    const appVersion = String(req.body?.appVersion || '').trim().slice(0, 40) || null;
    if (!allowFeedbackHour(req.ip, _licenseByIp)) {
        db.bumpMetric('license.rate');
        return res.status(429).json({ error: 'Too many requests from this address this hour — please retry later.', code: 'rate' });
    }
    const known = db.licenseFor(email, 'alpha') || db.licenseFor(email, 'free');
    if (!known && config.licensePerDay && db.licensesToday() >= config.licensePerDay) {
        db.bumpMetric('license.cap');
        return res.status(503).json({ error: 'No more licenses can be issued today — please try again tomorrow.', code: 'cap' });
    }
    const { row, created } = issueLicense({ cls, email, updatesUntil: null, source: 'app', appVersion });
    db.bumpMetric(created ? `license.${row.class}` : `license.${row.class}_repeat`);
    // Only an explicit true, only from the screen that asked (see above).
    const contact = req.body?.contact === true;
    if (contact && db.addSubscriber(email, 'license')) db.bumpMetric('subscribe.license');
    res.json({ success: true, created, contact, ...licenseJson(row) });
});

app.get('/v1/admin/licenses', adminAuth, (req, res) => {
    res.json({
        enabled: !!_licenseKey,
        publicKey: _licenseKey ? license.publicKeyRaw(_licenseKey).toString('base64') : null,
        alphaOpen: !!_licenseKey && licenseAlphaOpen(),
        alphaClosesAt: config.licenseAlphaClosesAt,
        counts: db.licenseCounts(),
        items: db.licensesList()
    });
});

// The operator mints a license by hand: a paid key, or a free one for
// someone who wrote in. `updatesUntil` defaults to a year out for paid;
// alpha and free are always forever. Never adds anyone to the mailing list. Returns the key so the
// operator can send it — this server never emails anyone.
app.post('/v1/admin/licenses', adminAuth, (req, res) => {
    if (!_licenseKey) return res.status(503).json({ error: 'LICENSE_SIGNING_KEY is not set', code: 'disabled' });
    const email = String(req.body?.email || '').trim().toLowerCase();
    if (email.length > 200 || !EMAIL_RX.test(email)) return res.status(400).json({ error: 'email required' });
    const cls = String(req.body?.class || 'paid');
    if (!license.CLASSES.has(cls)) return res.status(400).json({ error: 'class must be alpha, free or paid' });
    let updatesUntil = null;
    if (cls === 'paid') {
        updatesUntil = String(req.body?.updatesUntil || '').trim().slice(0, 10)
            || new Date(Date.now() + 366 * 86400000).toISOString().slice(0, 10);
        if (!/^\d{4}-\d{2}-\d{2}$/.test(updatesUntil)) return res.status(400).json({ error: 'updatesUntil must be YYYY-MM-DD' });
    }
    const { row, created } = issueLicense({ cls, email, updatesUntil, source: 'admin', appVersion: null });
    db.bumpMetric(created ? 'license.admin' : 'license.admin_repeat');
    res.json({ success: true, created, item: row });
});

app.post('/v1/admin/licenses/remove', adminAuth, (req, res) => {
    const id = String(req.body?.id || '');
    if (!/^[a-f0-9]{16}$/.test(id)) return res.status(400).json({ error: 'id required' });
    if (!db.removeLicense(id)) return res.status(404).json({ error: 'Unknown license id' });
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
    const searchesUsed = db.getUsed(installId);
    // Usage v2 (billing P2 groundwork, anjadhe-app docs/BILLING.md): what
    // the app shows, never raw tokens (law B2). AI is the larger of the two
    // limits that apply today (requests, tokens) as a whole percentage,
    // split by chat vs background in proportion to each one's tokens from
    // the cost meter. The old fields stay for apps that read them.
    const pct = (used, quota) => quota > 0 ? Math.min(100, Math.floor((used / quota) * 100)) : 0;
    // With a cost-weighted allowance (P2) the percentage is cost over the
    // allowance; otherwise the larger of today's request and token limits,
    // split by each purpose's tokens.
    const cost = costAllowance(req.install);
    let aiPercent, backgroundPercent;
    if (cost) {
        aiPercent = pct(cost.used.chat + cost.used.background, cost.allowance);
        backgroundPercent = Math.min(aiPercent, pct(cost.used.background, cost.allowance));
    } else {
        aiPercent = Math.max(pct(llmUsed.requests, llmQuota.requests), pct(llmUsed.tokens, llmQuota.tokens));
        const split = db.llmWorkSplit(req.install.owner);
        const splitTotal = split.chat + split.background;
        backgroundPercent = splitTotal ? Math.round(aiPercent * split.background / splitTotal) : 0;
    }
    const topup = db.topupBalance(req.install.owner);
    res.json({
        tier,
        used: searchesUsed,
        quota: quotaFor(tier),
        llm: {
            requests: llmUsed.requests,
            requestQuota: llmQuota.requests,
            tokens: llmUsed.tokens,
            tokenQuota: llmQuota.tokens
        },
        plan: tier,
        // Billing P3: where the plan comes from ('code' = a purchase),
        // when it renews, and whether Manage can open the portal.
        billing: {
            available: billing.enabled(),
            source: req.install.plan_source || 'tier',
            status: req.install.code_status || null,
            renews: req.install.period_end ? String(req.install.period_end).slice(0, 10) : null,
            manage: req.install.plan_source === 'code',
            trial: req.install.plan_source === 'trial' ? { endsAt: String(req.install.trial_ends).slice(0, 10) } : null,
            trialAvailable: config.trialDays > 0 && !req.install.trial_sub && req.install.plan_source !== 'code',
            // What top-ups this owner holds (counts, never money) and the
            // packs on sale (sizes from config; prices are Stripe's).
            topup: { searches: topup.searches, cloud: topup.tokens > 0 },
            packs: billing.enabled() ? Object.keys(config.stripeTopups).map(id => billing.topupPack(id)).filter(Boolean)
                .map(p => ({ id: p.id, searches: p.searches || 0, cloud: p.tokens > 0 })) : [],
            // What can be bought, from the server's own config (law B6): each
            // plan, the billing intervals on sale, and its search allowance.
            // Prices are Stripe's and shown on its checkout page.
            plans: billing.enabled() ? (() => {
                const by = {};
                for (const k of Object.keys(config.stripePrices)) {
                    const [p, iv] = k.split(':');
                    if (!Object.hasOwn(config.tierQuotas, p)) continue;
                    (by[p] = by[p] || { id: p, intervals: [], searches: config.tierQuotas[p] }).intervals.push(iv);
                }
                return Object.values(by);
            })() : []
        },
        ai: { percent: aiPercent, chatPercent: Math.max(0, aiPercent - backgroundPercent), backgroundPercent },
        searches: { used: searchesUsed, allowance: quotaFor(tier) },
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
        aliases: db.llmAliasesAll(),
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
    const vision = req.body?.vision === undefined ? undefined : !!req.body.vision;
    // Billing P1: the provider's rate, US$ per million tokens. Absent keeps
    // the stored rate; a value must be a finite number from 0 to 100.
    const price = (v) => {
        if (v === undefined || v === null || v === '') return undefined;
        const n = Number(v);
        return Number.isFinite(n) && n >= 0 && n <= 100 ? n : NaN;
    };
    const priceIn = price(req.body?.priceIn), priceOut = price(req.body?.priceOut);
    if (Number.isNaN(priceIn) || Number.isNaN(priceOut)) {
        return res.status(400).json({ error: 'prices are US$ per million tokens, a number from 0 to 100' });
    }
    const alias = db.llmAliasGet(id);
    if (alias) {
        return res.status(400).json({ error: `"${id}" is an old id of ${alias.target} and still answers for it — remove the alias first` });
    }
    db.llmModelUpsert({ id, upstream, label, description, enabled, vision, priceIn, priceOut });
    res.json({ success: true, ...llmModelsPayload() });
});

app.post('/v1/admin/llm-models/delete', adminAuth, (req, res) => {
    const id = String(req.body?.id || '').trim();
    if (!db.llmModelDelete(id)) return res.status(404).json({ error: 'Unknown model id' });
    res.json({ success: true, ...llmModelsPayload() });
});

// Rename: the id is the API, so a rename leaves the old id behind as an
// alias — installs that stored it keep working, and it is never listed.
app.post('/v1/admin/llm-models/rename', adminAuth, (req, res) => {
    const from = String(req.body?.from || '').trim();
    const to = String(req.body?.to || '').trim();
    if (!LLM_MODEL_ID_RX.test(to)) {
        return res.status(400).json({ error: 'id must be lowercase letters, digits, dots or dashes (max 64)' });
    }
    if (!db.llmModelGet(from)) return res.status(404).json({ error: 'Unknown model id' });
    if (db.llmModelGet(to)) return res.status(400).json({ error: `"${to}" is already a model` });
    db.llmModelRename(from, to);
    res.json({ success: true, ...llmModelsPayload() });
});

// Remove an alias: installs still on that old id get "Unknown model".
app.post('/v1/admin/llm-models/alias/delete', adminAuth, (req, res) => {
    const alias = String(req.body?.alias || '').trim();
    if (!db.llmAliasDelete(alias)) return res.status(404).json({ error: 'Unknown alias' });
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

// Billing P1 (anjadhe-app docs/BILLING.md): what the service cost this
// month, by model and purpose, by search provider, by plan, and the 20
// costliest owners (hash prefixes only). Report only: nothing here limits
// anyone. ?period=YYYY-MM for an earlier month.
app.get('/v1/admin/billing', adminAuth, (req, res) => {
    const p = String(req.query.period || '').trim();
    if (p && !/^\d{4}-\d{2}$/.test(p)) return res.status(400).json({ error: 'period must be YYYY-MM' });
    res.json({ ...db.billingReport(p || undefined), providerPrices: config.providerPrices,
        models: db.llmModelsAll().map(m => ({ id: m.id, priceIn: m.price_in, priceOut: m.price_out, rateVersion: m.rate_version })) });
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
    // `q` narrows to a hex prefix of the stored id — the grid is otherwise a
    // top-N by volume, so a quiet install could not be looked up at all. Same
    // shape and validation as /v1/admin/installs.
    const q = String(req.query.q || '').trim().toLowerCase();
    if (q && !/^[0-9a-f]{1,64}$/.test(q)) {
        return res.status(400).json({ error: 'q must be a hex prefix of a stored (SHA-256) install id' });
    }
    const installs = db.analyticsByInstall(db.daysAgo(days - 1), limit, q);
    res.json({ day: db.day(), days, limit, q, installs });
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
    const includeTest = req.query.test === '1';
    const page = db.installPage({ sort, dir, limit, offset, q, includeTest });
    if (!page) return res.status(400).json({ error: 'unknown sort key', sortKeys: db.installSortKeys });
    res.json({ day: db.day(), sort, dir, limit, offset, includeTest, ...page });
});

// Mark or unmark an install as a test (for ones minted before the "test-"
// prefix existed, like operator probes). Takes the stored (hashed) id.
app.post('/v1/admin/installs/test', adminAuth, (req, res) => {
    const id = String(req.body?.installId || '').trim();
    if (!/^[0-9a-f]{64}$/.test(id)) return res.status(400).json({ error: 'installId must be a stored (SHA-256) install id' });
    if (!db.setKeyTest(id, req.body?.test !== false)) return res.status(404).json({ error: 'Unknown install id' });
    res.json({ success: true, installId: id, test: req.body?.test !== false });
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
        brokerage: brokerage.stats(),
        tierQuotas: config.tierQuotas,
        llmTierQuotas: config.llmTierQuotas,
        feedback: db.feedbackCounts(),
        subscribers: db.subscriberCount(),
        alerts: alerts.evaluate(),
        webhookConfigured: !!config.alertWebhookUrl
    });
});

app.post('/v1/admin/alerts/test', adminAuth, async (req, res) => {
    try {
        await alerts.sendTest();
        res.json({ success: true });
    } catch (e) {
        res.status(502).json({ error: `Webhook send failed: ${String(e.message).slice(0, 120)}` });
    }
});

// ── Paid plans (/v1/billing) — billing P3, anjadhe-app docs/BILLING.md ──
// Stripe is spoken only in lib/billing.js. The flow:
//   1. the app asks for a checkout (POST /v1/billing/checkout) and opens the
//      returned URL in the person's own browser, keeping the claim id;
//   2. Stripe's webhook (checkout.session.completed) mints the code;
//   3. the app polls the claim (GET /v1/billing/claim/:claim), receives the
//      code once, keeps it in the Keychain, and its install is attached;
//   4. the browser lands on /billing/done, which shows the same code for
//      use on another Mac ("I have a code": POST /v1/billing/attach).
// Codes are stored only as hashes; a plain code waits in billing_claims for
// about a day, then is erased. No email is read from any Stripe event.

const _billingByInstall = new Map(); // installId -> {windowStart, count}
function billingAllow(installId, perHour = 20) {
    const now = Date.now();
    capLimiter(_billingByInstall, (v) => now - v.windowStart >= 3600000);
    const cur = _billingByInstall.get(installId);
    if (!cur || now - cur.windowStart >= 3600000) { _billingByInstall.set(installId, { windowStart: now, count: 1 }); return true; }
    if (cur.count >= perHour) return false;
    cur.count++;
    return true;
}
const CLAIM_RX = /^[A-Za-z0-9_-]{32,64}$/;
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

app.post('/v1/billing/checkout', auth, async (req, res) => {
    if (!billing.enabled()) return res.status(503).json({ error: 'Buying a plan is not available yet.', code: 'unavailable' });
    const plan = String(req.body?.plan || '').trim();
    const interval = String(req.body?.interval || 'month').trim();
    const price = billing.priceFor(plan, interval);
    if (!price || !Object.hasOwn(config.tierQuotas, plan)) {
        return res.status(400).json({ error: 'Unknown plan', code: 'plan', plans: Object.keys(config.stripePrices) });
    }
    if (!billingAllow(req.install.install_id)) return res.status(429).json({ error: 'Too many checkout attempts. Try again later.', code: 'rate' });
    const claim = crypto.randomBytes(24).toString('base64url');
    try {
        const session = await billing.createCheckout({
            price, claim,
            successUrl: `${config.publicUrl}/billing/done?session_id={CHECKOUT_SESSION_ID}`,
            cancelUrl: `${config.publicUrl}/billing/canceled`
        });
        db.claimInsert({ claimHash: sha256(claim), installId: req.install.install_id, plan, interval, sessionId: session.id });
        db.bumpMetric('billing.checkout');
        res.json({ url: session.url, claim });
    } catch (e) {
        db.bumpMetric('billing.checkout_fail');
        console.error(`[billing] checkout failed: ${e.message}`);
        res.status(502).json({ error: 'Could not open checkout. Try again in a moment.', code: 'upstream' });
    }
});

// A one-time top-up (P5): extra searches or extra cloud use, bought in the
// browser like a plan, drawn only after the month's allowance is spent.
app.post('/v1/billing/topup', auth, async (req, res) => {
    if (!billing.enabled()) return res.status(503).json({ error: 'Top-ups are not available yet.', code: 'unavailable' });
    const pack = billing.topupPack(String(req.body?.pack || ''));
    if (!pack) return res.status(400).json({ error: 'Unknown top-up', code: 'pack', packs: Object.keys(config.stripeTopups) });
    if (!billingAllow(req.install.install_id)) return res.status(429).json({ error: 'Too many checkout attempts. Try again later.', code: 'rate' });
    const claim = crypto.randomBytes(24).toString('base64url');
    try {
        const session = await billing.createCheckout({ price: pack.price, claim, mode: 'payment',
            successUrl: `${config.publicUrl}/billing/done?session_id={CHECKOUT_SESSION_ID}`,
            cancelUrl: `${config.publicUrl}/billing/canceled` });
        db.claimInsert({ claimHash: sha256(claim), installId: req.install.install_id, plan: 'topup:' + pack.id, interval: 'once', sessionId: session.id });
        db.bumpMetric('billing.topup_checkout');
        res.json({ url: session.url, claim });
    } catch (e) {
        console.error(`[billing] top-up checkout failed: ${e.message}`);
        res.status(502).json({ error: 'Could not open checkout. Try again in a moment.', code: 'upstream' });
    }
});

// The trial (P4): the app asks once after registering; the answer is the
// same trial for the same email on any Mac or reinstall, never a second one.
app.post('/v1/billing/trial', auth, (req, res) => {
    if (!config.trialDays) return res.json({ trial: false, reason: 'off' });
    if (!_licenseKey) return res.json({ trial: false, reason: 'unavailable' });
    if (req.install.plan_source === 'code') return res.json({ trial: false, reason: 'paid' });
    const checked = license.verify(String(req.body?.license || ''), license.publicKeyRaw(_licenseKey));
    if (!checked || !checked.ok) return res.status(400).json({ error: 'A registered license is needed for the trial.', code: 'license' });
    const payload = checked.payload;
    let t = db.trialGet(payload.sub);
    if (!t) { t = db.trialStart(payload.sub, config.trialPlan, config.trialDays); db.bumpMetric('billing.trial_started'); }
    db.setInstallTrial(req.install.install_id, payload.sub);
    const active = Date.parse(t.ends_at) > Date.now();
    res.json({ trial: active, plan: t.plan, endsAt: t.ends_at.slice(0, 10) });
});

// The app polls this after opening checkout. 'pending' until the webhook
// lands; then the code, once, and this install is attached to it.
app.get('/v1/billing/claim/:claim', auth, (req, res) => {
    const claim = String(req.params.claim || '');
    if (!CLAIM_RX.test(claim)) return res.status(400).json({ error: 'Bad claim', code: 'request' });
    const row = db.claimGet(sha256(claim));
    if (!row || row.install_id !== req.install.install_id) return res.status(404).json({ error: 'Unknown claim', code: 'unknown' });
    if (row.status === 'pending') return res.json({ status: 'pending' });
    if (String(row.plan).startsWith('topup:')) {
        db.claimTaken(sha256(claim));
        return res.json({ status: 'paid', topup: row.plan.slice(6) });
    }
    const code = db.planCodeGet(row.code_hash);
    db.setInstallPlanCode(req.install.install_id, row.code_hash);
    db.claimTaken(sha256(claim));
    db.bumpMetric('billing.claimed');
    res.json({ status: 'paid', code: row.code || null, plan: code ? code.plan : row.plan });
});

// "I have a code": attach this install to a paid code (another Mac, a
// reinstall, a code from the receipt page).
app.post('/v1/billing/attach', auth, (req, res) => {
    if (!billingAllow(req.install.install_id, 10)) return res.status(429).json({ error: 'Too many tries. Try again later.', code: 'rate' });
    const code = billing.normalizeCode(req.body?.code);
    if (!code) return res.status(400).json({ error: 'That doesn’t look like a nenva code.', code: 'format' });
    const row = db.planCodeGet(billing.hashCode(code));
    if (!row) { db.bumpMetric('billing.attach_unknown'); return res.status(404).json({ error: 'That code isn’t known.', code: 'unknown' }); }
    if (req.install.plan_code !== row.code_hash && db.installsOnCode(row.code_hash) >= config.billingMaxInstalls) {
        return res.status(409).json({ error: `This code is already in use on ${config.billingMaxInstalls} Macs. Remove it from one of them first.`, code: 'full' });
    }
    db.setInstallPlanCode(req.install.install_id, row.code_hash);
    db.bumpMetric('billing.attached');
    // The code in its written form, so the Mac saves what it can show again.
    res.json({ success: true, code, plan: row.plan, status: row.status, active: !!planFromCode(row) });
});

app.post('/v1/billing/detach', auth, (req, res) => {
    db.setInstallPlanCode(req.install.install_id, null);
    res.json({ success: true });
});

// Manage: Stripe's customer portal for this install's code.
app.post('/v1/billing/portal', auth, async (req, res) => {
    if (!billing.enabled()) return res.status(503).json({ error: 'Not available yet.', code: 'unavailable' });
    const row = req.install.plan_code ? db.planCodeGet(req.install.plan_code) : null;
    if (!row || !row.customer_ref) return res.status(404).json({ error: 'This Mac has no plan to manage.', code: 'none' });
    if (!billingAllow(req.install.install_id)) return res.status(429).json({ error: 'Too many tries. Try again later.', code: 'rate' });
    try {
        const { url } = await billing.createPortal({ customer: row.customer_ref, returnUrl: `${config.publicUrl}/billing/managed` });
        res.json({ url });
    } catch (e) {
        console.error(`[billing] portal failed: ${e.message}`);
        res.status(502).json({ error: 'Could not open the billing page. Try again in a moment.', code: 'upstream' });
    }
});

// Stripe's webhook. Verified, handled once per event id, and nothing but
// ids, the price, the status and the period end is read from it.
app.post('/v1/billing/webhook', async (req, res) => {
    if (!billing.verifySignature(req.body, req.get('stripe-signature'))) {
        db.bumpMetric('billing.webhook_badsig');
        return res.status(400).json({ error: 'bad signature' });
    }
    let event;
    try { event = JSON.parse(req.body.toString('utf8')); } catch { return res.status(400).json({ error: 'bad body' }); }
    if (!event || !event.id || !event.type) return res.status(400).json({ error: 'bad event' });
    if (db.billingEventSeen(event.id)) return res.json({ received: true, duplicate: true });
    try {
        await handleBillingEvent(event);
        db.billingEventAdd(event.id);
        res.json({ received: true });
    } catch (e) {
        // A 5xx makes Stripe retry later; the event id is not recorded.
        console.error(`[billing] webhook ${event.type} failed: ${e.message}`);
        db.bumpMetric('billing.webhook_fail');
        res.status(500).json({ error: 'handler failed' });
    }
});

async function handleBillingEvent(event) {
    const obj = event.data && event.data.object || {};
    db.bumpMetric(`billing.event.${String(event.type).replace(/[^a-z_.]/g, '').slice(0, 60)}`);
    if (event.type === 'checkout.session.completed') {
        const claim = obj.metadata && obj.metadata.claim || obj.client_reference_id;
        const row = claim ? db.claimGet(sha256(claim)) : null;
        if (!row) return; // not ours (or already purged): nothing to do
        if (row.status !== 'pending') return;
        // A top-up (P5): add the pack to whoever pays for this Mac now.
        if (String(row.plan).startsWith('topup:')) {
            const pack = billing.topupPack(row.plan.slice(6));
            const key = db.getInstall(row.install_id);
            const owner = key && key.plan_code ? 'c:' + key.plan_code : 'i:' + row.install_id;
            if (pack) db.topupAdd({ owner, pack: pack.id, searches: pack.searches, tokens: pack.tokens,
                merchantRef: obj.payment_intent ? sha256(obj.payment_intent) : null });
            db.revenueAdd({ plan: 'topup', kind: 'topup', currency: obj.currency, cents: obj.amount_total || 0 });
            db.claimPaid(row.claim_hash, null, null);
            return;
        }
        if (db.planCodeBySub(obj.subscription)) return; // a replay after a crash
        const code = billing.mintCode();
        const codeHash = billing.hashCode(code);
        // The period end arrives with the subscription; fetch it once now so
        // the plan is right from the first minute (mock: one interval).
        let periodEnd = null, plan = row.plan, interval = row.interval;
        const sub = obj.subscription ? await billing.getSubscription(obj.subscription) : null;
        if (sub) {
            periodEnd = billing.periodEndOf(sub);
            const bought = billing.planForPrice(billing.priceOf(sub));
            if (bought) { plan = bought.plan; interval = bought.interval; }
        } else {
            periodEnd = new Date(Date.now() + (interval === 'year' ? 366 : 31) * 86400000).toISOString();
        }
        db.planCodeInsert({ codeHash, plan, interval, status: 'active', periodEnd,
            customerRef: obj.customer || null, subscriptionRef: obj.subscription || null });
        db.claimPaid(row.claim_hash, code, codeHash);
        return;
    }
    // Revenue for the admin's margin: every paid invoice of a plan.
    if (event.type === 'invoice.paid') {
        const row = obj.subscription ? db.planCodeBySub(obj.subscription) : null;
        db.revenueAdd({ plan: row ? row.plan : 'unknown', kind: 'subscription', currency: obj.currency, cents: obj.amount_paid || 0 });
        return;
    }
    // A refund or a dispute ends what was bought: a plan's code stops
    // working (status 'refunded'), a top-up's remaining balance is removed.
    if (event.type === 'charge.refunded' || event.type === 'charge.dispute.created') {
        const charge = event.type === 'charge.refunded' ? obj : { invoice: obj.invoice, payment_intent: obj.payment_intent, amount_refunded: obj.amount, currency: obj.currency };
        if (charge.payment_intent) db.topupRevoke(sha256(charge.payment_intent));
        let sub = null;
        if (charge.invoice) { const inv = await billing.getInvoice(charge.invoice); sub = inv && inv.subscription; }
        const row = sub ? db.planCodeBySub(sub) : null;
        if (row && (event.type === 'charge.dispute.created' || obj.refunded)) db.planCodeUpdate(row.code_hash, { status: 'refunded' });
        if (charge.amount_refunded) db.revenueAdd({ plan: row ? row.plan : 'topup', kind: 'refund', currency: charge.currency, cents: -charge.amount_refunded });
        return;
    }
    if (event.type === 'customer.subscription.created' || event.type === 'customer.subscription.updated'
        || event.type === 'customer.subscription.deleted') {
        const row = db.planCodeBySub(obj.id);
        if (!row) return; // created arrives before checkout.session.completed: the code is minted there
        const bought = billing.planForPrice(billing.priceOf(obj));
        db.planCodeUpdate(row.code_hash, {
            plan: bought && bought.plan, interval: bought && bought.interval,
            status: event.type === 'customer.subscription.deleted' ? 'canceled' : billing.mapStatus(obj.status),
            periodEnd: billing.periodEndOf(obj)
        });
    }
}

// Where Stripe sends the buyer back. Plain pages, no scripts; the code is
// shown once a day at most (it is erased from the database after that).
function billingPage(res, title, body) {
    const esc = (s) => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    res.set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'");
    res.set('Cache-Control', 'no-store');
    res.type('html').send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>
<style>body{font:15px/1.6 -apple-system,system-ui,sans-serif;background:#f5f5f3;color:#171717;margin:0;padding:64px 20px}main{max-width:520px;margin:0 auto}h1{font:400 30px/1.2 Charter,"Iowan Old Style",Georgia,serif;margin:0 0 12px}code{display:block;font:600 17px ui-monospace,Menlo,monospace;background:#fff;border:1px solid #e5e5e3;border-radius:8px;padding:14px 16px;margin:16px 0;word-break:break-all}p{color:#4a4a48}@media(prefers-color-scheme:dark){body{background:#131312;color:#ececea}code{background:#1b1b1a;border-color:#2a2a28}p{color:#b4b4b0}}</style>
</head><body><main><h1>${esc(title)}</h1>${body(esc)}</main></body></html>`);
}
app.get('/billing/done', (req, res) => {
    const sessionId = String(req.query.session_id || '');
    const row = /^cs_[A-Za-z0-9_]{6,200}$/.test(sessionId) ? db.claimBySession(sessionId) : null;
    if (!row) return billingPage(res, 'Thank you', () => '<p>Your plan is set up. Go back to nenva; it picks your plan up on its own.</p>');
    if (row.status === 'pending') {
        res.set('Refresh', '3');
        return billingPage(res, 'Finishing up…', () => '<p>Payment received, setting up your plan. This page refreshes on its own.</p>');
    }
    return billingPage(res, 'You’re all set', (esc) => row.code
        ? `<p>nenva on this Mac picks your plan up on its own. To use the same plan on another Mac, open Settings › Plan there and enter this code:</p><code>${esc(row.code)}</code><p>Keep it somewhere safe. It is shown only for about a day.</p>`
        : '<p>nenva on this Mac picks your plan up on its own.</p>');
});
app.get('/billing/canceled', (req, res) => billingPage(res, 'No change made', () => '<p>Checkout was closed before paying. Nothing was charged. You can go back to nenva.</p>'));
app.get('/billing/managed', (req, res) => billingPage(res, 'Done', () => '<p>Any changes you made apply right away. You can go back to nenva.</p>'));

// The admin pages. Multi-page since 2026-08-04 (one dashboard had grown
// every panel the service owns): /admin is service health, with analytics,
// installs and feedback as sibling pages sharing one shell (public/admin/).
// Serving them without auth is fine — the files contain no data (this repo
// is public anyway); every data fetch goes through adminAuth with the
// token the operator enters, and shared.js carries it between pages.
const ADMIN_PAGES = { '': 'overview', overview: 'overview', analytics: 'analytics', website: 'website', installs: 'installs', feedback: 'feedback', subscribers: 'subscribers', licenses: 'licenses', models: 'models', billing: 'billing' };
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
    // Retention sweep: once at boot, then daily. Cheap (three indexed
    // DELETEs), and running it at boot means a long-lived deployment can't
    // sit years past its stated retention because nothing restarted it.
    const purge = () => {
        try {
            const b = db.billingPurge();
            if (b.codes || b.claims || b.events) console.log(`[retention] erased ${b.codes} plain codes, ${b.claims} old claims, ${b.events} old billing events`);
        } catch (e) {
            console.error(`[retention] billing purge failed: ${e.message}`);
        }
        if (config.keyUnusedPurgeDays > 0) {
            try {
                const n = db.purgeUnusedKeys(config.keyUnusedPurgeDays);
                if (n) console.log(`[retention] purged ${n} never-used free keys older than ${config.keyUnusedPurgeDays}d`);
            } catch (e) {
                console.error(`[retention] key purge failed: ${e.message}`);
            }
        }
        if (!config.feedbackRetentionDays && !config.analyticsRetentionDays && !config.usageRetentionDays) return;
        try {
            const n = db.purgeOldRows(
                config.feedbackRetentionDays || 1e6,
                config.analyticsRetentionDays || 1e6,
                config.usageRetentionDays || 0
            );
            if (n.feedback || n.analytics || n.usage) {
                console.log(`[retention] purged ${n.feedback} feedback, ${n.analytics} analytics, ${n.usage} usage rows`);
            }
        } catch (e) {
            console.error(`[retention] purge failed: ${e.message}`);
        }
    };
    purge();
    setInterval(purge, 24 * 60 * 60 * 1000).unref();
    const server = app.listen(config.port, () => {
        console.log(`anjadhe-connect listening on :${config.port} — providers: ${router.available().join(', ') || 'NONE CONFIGURED'}`);
        console.log(brokerage.enabled()
            ? `[brokerage] linking ON (Plaid ${config.plaidMock ? 'mock' : config.plaidEnv}, cap ${config.brokerageMaxItems} items)`
            : '[brokerage] linking OFF — set PLAID_CLIENT_ID, PLAID_SECRET and BROKERAGE_TOKEN_KEY to enable');
    });
    relay.attach(server);
    if (config.alertWebhookUrl) {
        setInterval(() => alerts.checkAndNotify(), 10 * 60 * 1000).unref();
        alerts.checkAndNotify();
    }
}

module.exports = app;
