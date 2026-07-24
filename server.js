// Anjadhe Connect — hosted services for the Anjadhe app (api.anjadhe.com).
// First capability: /v1/search, a metered web-search API for agents. Future
// capabilities (sync relay, LLM inference) join as new /v1/* routes on the
// same key/tier/usage machinery.
//
// PRIVACY INVARIANT (this is the product): query text is never logged and
// never stored. Request logs carry method/path/status/latency only; SQLite
// holds counters keyed by install id — nothing about what was searched.
// Every change to this file must preserve that.
'use strict';
const crypto = require('crypto');
const express = require('express');
const config = require('./lib/config');
const db = require('./lib/db');
const router = require('./lib/router');

const KEY_PREFIX = 'anck_';

const app = express();
app.set('trust proxy', 1); // Railway terminates TLS in front of us
app.use(express.json({ limit: '10kb' }));

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
    if (!m) return res.status(401).json({ error: 'Missing or malformed API key' });
    const row = db.getKeyByHash(hashKey(m[1]));
    if (!row) return res.status(401).json({ error: 'Unknown API key' });
    req.install = row;
    next();
}

function adminAuth(req, res, next) {
    if (!config.adminToken) return res.status(503).json({ error: 'Admin endpoints disabled (no ADMIN_TOKEN set)' });
    if (req.get('x-admin-token') !== config.adminToken) return res.status(401).json({ error: 'Bad admin token' });
    next();
}

// ── Routes ──────────────────────────────────────────────────────────────

app.get('/healthz', (req, res) => {
    res.json({ ok: true, providers: router.available() });
});

// Mint (or rotate) the key for an installation. The install id is a UUID
// the app generates locally — unguessable, so returning a fresh key for a
// known id is safe. Rotation does NOT reset usage (usage keys off the
// install id), so re-minting can't refill a quota.
app.post('/v1/keys', (req, res) => {
    const installId = String(req.body?.installId || '').trim();
    if (!/^[A-Za-z0-9_-]{8,64}$/.test(installId)) {
        return res.status(400).json({ error: 'installId must be 8-64 chars of letters, digits, - or _' });
    }
    if (!allowMint(req.ip)) {
        return res.status(429).json({ error: 'Too many key requests from this address today' });
    }
    const key = mintKey();
    const existing = db.getKeyByInstall(installId);
    if (existing) db.rotateKey(installId, hashKey(key));
    else db.createKey(installId, hashKey(key), req.ip);
    const tier = existing ? existing.tier : 'free';
    res.json({ apiKey: key, tier, monthlyQuota: quotaFor(tier), rotated: !!existing });
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
        return res.status(429).json({
            error: `Monthly quota reached (${quota} searches on the ${tier} plan). Resets ${resetsAt()}.`,
            code: 'quota', used, quota, resetsAt: resetsAt()
        });
    }
    if (!allowMinute(installId, tier)) {
        return res.status(429).json({ error: 'Rate limit: too many searches this minute — retry shortly.', code: 'rate' });
    }

    try {
        const { results, upstream } = await router.search(query, maxResults);
        db.bumpUsage(installId);
        res.json({ results, provider: 'anjadhe', upstream, used: used + 1, quota });
    } catch (e) {
        res.status(502).json({ error: e.message || 'Search failed' });
    }
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
    if (!db.getKeyByInstall(installId)) return res.status(404).json({ error: 'Unknown installId' });
    db.setTier(installId, tier);
    res.json({ success: true, installId, tier, monthlyQuota: quotaFor(tier) });
});

app.get('/v1/admin/stats', adminAuth, (req, res) => {
    res.json(db.stats());
});

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

if (require.main === module) {
    app.listen(config.port, () => {
        console.log(`anjadhe-connect listening on :${config.port} — providers: ${router.available().join(', ') || 'NONE CONFIGURED'}`);
    });
}

module.exports = app;
