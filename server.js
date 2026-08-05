// Anjadhe Connect — hosted services for the Anjadhe app (api.anjadhe.com).
// First capability: /v1/search, a metered web-search API for agents. Future
// capabilities (sync relay, LLM inference) join as new /v1/* routes on the
// same key/tier/usage machinery.
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

const KEY_PREFIX = 'anck_';

const app = express();
app.set('trust proxy', 1); // Railway terminates TLS in front of us
// Analytics batches (up to 500 queued events from an offline machine) need
// more room than every other body; keep the tight cap for the rest.
const jsonBody = express.json({ limit: '10kb' });
const jsonBodyAnalytics = express.json({ limit: '64kb' });
app.use((req, res, next) =>
    (req.path === '/v1/analytics/events' ? jsonBodyAnalytics : jsonBody)(req, res, next));

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

// ── In-memory rate limiters ─────────────────────────────────────────────
// Single-instance service (Railway + volume), so process memory is the
// source of truth. A restart resets windows — acceptable at this scale.

const _mintByIp = new Map(); // ip -> {day, count}
function allowMint(ip) {
    if (_mintByIp.size > 10000) _mintByIp.clear();
    const day = new Date().toISOString().slice(0, 10);
    const cur = _mintByIp.get(ip);
    if (!cur || cur.day !== day) {
        _mintByIp.set(ip, { day, count: 1 });
        return true;
    }
    if (cur.count >= config.mintPerIpPerDay) return false;
    cur.count++;
    return true;
}

// News fetches are unmetered (server-side topic cache makes them nearly
// free), so a simple fixed per-minute window is the only brake needed.
const NEWS_PER_MINUTE = 12;
const _newsByInstall = new Map(); // installId -> {windowStart, count}
function allowNewsMinute(installId) {
    if (_newsByInstall.size > 10000) _newsByInstall.clear();
    const now = Date.now();
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
const _analyticsByIp = new Map(); // ip -> {windowStart, count}
function allowAnalyticsMinute(ip) {
    if (_analyticsByIp.size > 10000) _analyticsByIp.clear();
    const now = Date.now();
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
const _feedbackByIp = new Map(); // ip -> {windowStart, count}
function allowFeedbackHour(ip) {
    if (_feedbackByIp.size > 10000) _feedbackByIp.clear();
    const now = Date.now();
    const cur = _feedbackByIp.get(ip);
    if (!cur || now - cur.windowStart >= 3600000) {
        _feedbackByIp.set(ip, { windowStart: now, count: 1 });
        return true;
    }
    if (cur.count >= FEEDBACK_PER_HOUR) return false;
    cur.count++;
    return true;
}

const _searchByInstall = new Map(); // installId -> {windowStart, count}
function allowMinute(installId, tier) {
    if (_searchByInstall.size > 10000) _searchByInstall.clear();
    const limit = config.perMinute[tier] ?? config.perMinute.free;
    const now = Date.now();
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

function adminAuth(req, res, next) {
    if (!config.adminToken) return res.status(503).json({ error: 'Admin endpoints disabled (no ADMIN_TOKEN set)' });
    const given = Buffer.from(req.get('x-admin-token') || '');
    const want = Buffer.from(config.adminToken);
    if (given.length !== want.length || !crypto.timingSafeEqual(given, want)) {
        return res.status(401).json({ error: 'Bad admin token' });
    }
    next();
}

// ── Routes ──────────────────────────────────────────────────────────────

// `env` carries ENV_LABEL when the operator set one, so /admin can name the
// deployment it is showing before any token is entered — the point being that
// production and staging dashboards are otherwise identical.
app.get('/healthz', (req, res) => {
    const body = { ok: true, providers: router.available() };
    if (config.envLabel) body.env = config.envLabel;
    res.json(body);
});

// Mint (or rotate) the key for an installation. Since 2026-07-28 the app
// sends a random UUID as the install id (unguessable, so returning a fresh
// key for a known id is safe); ids minted before that are hostname-derived —
// guessable — which is why /v1/keys/migrate exists. The raw id is hashed
// here at the boundary and never stored. Rotation does NOT reset usage
// (usage keys off the install id), so re-minting can't refill a quota.
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
    const key = mintKey();
    const existing = db.getKeyByInstall(idHash);
    if (existing) db.rotateKey(idHash, hashKey(key));
    else db.createKey(idHash, hashKey(key));
    db.bumpMetric(existing ? 'mint.rotate' : 'mint.new');
    const tier = existing ? existing.tier : 'free';
    res.json({ apiKey: key, tier, monthlyQuota: quotaFor(tier), rotated: !!existing });
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
        res.status(502).json({ error: e.message || 'Search failed' });
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
    'agent.reply.feedback': ['rating'],
    'goal.status_updated': [],
    'schedule.task_completed': [],
    'journal.entry_written': [],
    'settings.analytics_enabled': [],
    'settings.analytics_disabled': []
};
const ANALYTICS_MAX_BATCH = 500; // matches the client's MAX_EVENTS buffer

// The app posts from the renderer, where CORS applies (the old Worker sent
// these same headers). Wide-open is fine: the endpoint only accepts counts.
function analyticsCors(res) {
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Content-Type');
    res.set('Access-Control-Max-Age', '86400');
}

app.options('/v1/analytics/events', (req, res) => {
    analyticsCors(res);
    res.sendStatus(204);
});

app.post('/v1/analytics/events', (req, res) => {
    analyticsCors(res);
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
        if (Number.isFinite(ts)) {
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
    analyticsCors(res);
    res.sendStatus(204);
});

app.post('/v1/feedback', (req, res) => {
    analyticsCors(res);
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
    res.json({
        tier,
        used: db.getUsed(installId),
        quota: quotaFor(tier),
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
    if (!(tier in config.tierQuotas)) {
        return res.status(400).json({ error: `Unknown tier — one of: ${Object.keys(config.tierQuotas).join(', ')}` });
    }
    // Accept either the stored (hashed) id — what the dashboard shows — or a
    // raw install id read off a user's Settings card.
    const stored = db.getKeyByInstall(installId) ? installId : db.hashInstallId(installId);
    if (!db.getKeyByInstall(stored)) return res.status(404).json({ error: 'Unknown installId' });
    db.setTier(stored, tier);
    res.json({ success: true, installId: stored, tier, monthlyQuota: quotaFor(tier) });
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

// Everything the /admin dashboard renders, in one call. Metrics are
// service-wide daily counters; the install list is the operator view needed
// for manual tier changes (install ids + counts, never IPs or content).
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
        relay: relay.stats(),
        tierQuotas: config.tierQuotas,
        installs: db.installList(200),
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
const ADMIN_PAGES = { '': 'overview', overview: 'overview', analytics: 'analytics', installs: 'installs', feedback: 'feedback' };
app.get(['/admin', '/admin/:page'], (req, res, next) => {
    const page = ADMIN_PAGES[req.params.page || ''];
    if (!page) return next();
    res.sendFile(path.join(__dirname, 'public', 'admin', page + '.html'));
});
app.use('/admin/assets', express.static(path.join(__dirname, 'public', 'admin', 'assets')));

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

if (require.main === module) {
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
