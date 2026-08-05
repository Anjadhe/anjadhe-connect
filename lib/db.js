// SQLite state on a Railway volume: API keys, per-install usage counters,
// per-provider usage counters.
//
// PRIVACY INVARIANT: no table stores query text — only counts. Keys are
// stored as SHA-256 hashes, so a DB leak leaks no usable credentials.
// Install ids are ALSO stored only as SHA-256 hashes (raw ids can be
// machine hostnames, i.e. personal names — the server hashes them at the
// API boundary and never writes the raw value anywhere). Mint IPs are not
// stored either. Usage is keyed by the hashed install id (not key hash) so
// rotating a key does NOT reset the month's quota.
'use strict';
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const config = require('./config');

// The at-rest form of an install id. Unsalted is fine: new ids are random
// UUIDs; legacy hostname-derived ids get guess-resistance, not secrecy.
function hashInstallId(installId) {
    return crypto.createHash('sha256').update(installId).digest('hex');
}

fs.mkdirSync(config.dataDir, { recursive: true });
const db = new Database(path.join(config.dataDir, 'connect.db'));
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS keys (
    install_id TEXT PRIMARY KEY,
    key_hash   TEXT UNIQUE NOT NULL,
    tier       TEXT NOT NULL DEFAULT 'free',
    created_at TEXT NOT NULL,
    mint_ip    TEXT
);
CREATE TABLE IF NOT EXISTS usage (
    install_id TEXT NOT NULL,
    period     TEXT NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (install_id, period)
);
CREATE TABLE IF NOT EXISTS provider_usage (
    provider TEXT NOT NULL,
    period   TEXT NOT NULL,
    used     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (provider, period)
);
CREATE TABLE IF NOT EXISTS metrics_daily (
    day  TEXT NOT NULL,
    name TEXT NOT NULL,
    n    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, name)
);
CREATE TABLE IF NOT EXISTS analytics_daily (
    day        TEXT NOT NULL,
    install_id TEXT NOT NULL,
    name       TEXT NOT NULL,
    n          INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, install_id, name)
);
CREATE TABLE IF NOT EXISTS alert_state (
    name          TEXT PRIMARY KEY,
    last_fired_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS feedback (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,
    kind        TEXT NOT NULL,
    message     TEXT NOT NULL,
    email       TEXT,
    app_version TEXT,
    platform    TEXT,
    status      TEXT NOT NULL DEFAULT 'new'
);
`);

// keys.last_seen_day is deliberately day-granularity (never a timestamp):
// enough to count active installs, too coarse to reconstruct a usage pattern.
// No migration machinery exists, so new columns are added via guarded ALTER.
if (!db.prepare('PRAGMA table_info(keys)').all().some(c => c.name === 'last_seen_day')) {
    db.exec('ALTER TABLE keys ADD COLUMN last_seen_day TEXT');
}

// One-time migration to hashed install ids (user_version 0 → 1): hash every
// stored id and null the legacy mint_ip column. Raw hostname-derived ids
// written by pre-hashing deploys are erased here, not just masked.
if (db.pragma('user_version', { simple: true }) < 1) {
    const renameKeys = db.prepare('UPDATE keys SET install_id = ?, mint_ip = NULL WHERE install_id = ?');
    const renameUsage = db.prepare('UPDATE usage SET install_id = ? WHERE install_id = ?');
    db.transaction(() => {
        for (const { install_id } of db.prepare('SELECT install_id FROM keys').all()) {
            renameKeys.run(hashInstallId(install_id), install_id);
            renameUsage.run(hashInstallId(install_id), install_id);
        }
        db.pragma('user_version = 1');
    })();
    // UPDATE alone leaves the old raw values recoverable in free pages and
    // the WAL — rebuild the file and truncate the log so they're actually
    // gone from disk, not just from the tables.
    db.exec('VACUUM');
    db.pragma('wal_checkpoint(TRUNCATE)');
}

// Calendar-month usage buckets, UTC — e.g. '2026-07'. Old rows are tiny and
// kept forever (they're the service's only usage history).
function period(now = new Date()) {
    return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
}

// UTC calendar day — e.g. '2026-07-28'. The bucket for metrics_daily and
// keys.last_seen_day.
function day(now = new Date()) {
    return now.toISOString().slice(0, 10);
}

function daysAgo(n) {
    return day(new Date(Date.now() - n * 86400000));
}

const stmt = {
    keyByInstall: db.prepare('SELECT * FROM keys WHERE install_id = ?'),
    keyByHash: db.prepare('SELECT * FROM keys WHERE key_hash = ?'),
    insertKey: db.prepare('INSERT INTO keys (install_id, key_hash, tier, created_at, mint_ip) VALUES (?, ?, ?, ?, ?)'),
    rotateKey: db.prepare('UPDATE keys SET key_hash = ? WHERE install_id = ?'),
    setTier: db.prepare('UPDATE keys SET tier = ? WHERE install_id = ?'),
    bumpUsage: db.prepare(`INSERT INTO usage (install_id, period, used) VALUES (?, ?, 1)
        ON CONFLICT(install_id, period) DO UPDATE SET used = used + 1`),
    getUsed: db.prepare('SELECT used FROM usage WHERE install_id = ? AND period = ?'),
    bumpProvider: db.prepare(`INSERT INTO provider_usage (provider, period, used) VALUES (?, ?, 1)
        ON CONFLICT(provider, period) DO UPDATE SET used = used + 1`),
    providerUsed: db.prepare('SELECT used FROM provider_usage WHERE provider = ? AND period = ?'),
    keyCount: db.prepare('SELECT COUNT(*) AS n FROM keys'),
    tierCounts: db.prepare('SELECT tier, COUNT(*) AS n FROM keys GROUP BY tier'),
    periodTotal: db.prepare('SELECT COALESCE(SUM(used), 0) AS n FROM usage WHERE period = ?'),
    providerTotals: db.prepare('SELECT provider, used FROM provider_usage WHERE period = ?'),
    bumpMetric: db.prepare(`INSERT INTO metrics_daily (day, name, n) VALUES (?, ?, 1)
        ON CONFLICT(day, name) DO UPDATE SET n = n + 1`),
    bumpAnalytics: db.prepare(`INSERT INTO analytics_daily (day, install_id, name, n) VALUES (?, ?, ?, ?)
        ON CONFLICT(day, install_id, name) DO UPDATE SET n = n + excluded.n`),
    analyticsDaily: db.prepare('SELECT day, SUM(n) AS n FROM analytics_daily WHERE day >= ? GROUP BY day ORDER BY day'),
    analyticsTop: db.prepare('SELECT name, SUM(n) AS n FROM analytics_daily WHERE day >= ? GROUP BY name ORDER BY SUM(n) DESC LIMIT ?'),
    analyticsActive: db.prepare('SELECT COUNT(DISTINCT install_id) AS n FROM analytics_daily WHERE day >= ?'),
    analyticsInstalls: db.prepare(`SELECT install_id, SUM(n) AS n, COUNT(DISTINCT day) AS days,
            MIN(day) AS first_day, MAX(day) AS last_day
        FROM analytics_daily WHERE day >= ?
        GROUP BY install_id ORDER BY SUM(n) DESC, install_id LIMIT ?`),
    // Same top-N install set as above (identical ORDER BY), one row per
    // (install, day) — the cells of the dashboard's install × day grid.
    analyticsCells: db.prepare(`SELECT install_id, day, SUM(n) AS n FROM analytics_daily
        WHERE day >= ? AND install_id IN (
            SELECT install_id FROM analytics_daily WHERE day >= ?
            GROUP BY install_id ORDER BY SUM(n) DESC, install_id LIMIT ?)
        GROUP BY install_id, day`),
    analyticsInstallEvents: db.prepare(`SELECT day, name, n FROM analytics_daily
        WHERE install_id = ? AND day >= ? ORDER BY day DESC, n DESC, name`),
    metricsSince: db.prepare('SELECT day, name, n FROM metrics_daily WHERE day >= ? ORDER BY day'),
    metricToday: db.prepare('SELECT n FROM metrics_daily WHERE day = ? AND name = ?'),
    touchSeen: db.prepare('UPDATE keys SET last_seen_day = ? WHERE install_id = ?'),
    activeSince: db.prepare('SELECT COUNT(*) AS n FROM keys WHERE last_seen_day >= ?'),
    installList: db.prepare(`SELECT k.install_id, k.tier, k.created_at, k.last_seen_day,
            COALESCE(u.used, 0) AS used
        FROM keys k LEFT JOIN usage u ON u.install_id = k.install_id AND u.period = ?
        ORDER BY used DESC, k.created_at DESC LIMIT ?`),
    renameKey: db.prepare('UPDATE keys SET install_id = ? WHERE install_id = ?'),
    renameUsage: db.prepare('UPDATE usage SET install_id = ? WHERE install_id = ?'),
    alertState: db.prepare('SELECT last_fired_at FROM alert_state WHERE name = ?'),
    alertFired: db.prepare(`INSERT INTO alert_state (name, last_fired_at) VALUES (?, ?)
        ON CONFLICT(name) DO UPDATE SET last_fired_at = excluded.last_fired_at`),
    insertFeedback: db.prepare(`INSERT INTO feedback (created_at, kind, message, email, app_version, platform)
        VALUES (?, ?, ?, ?, ?, ?)`),
    feedbackAll: db.prepare('SELECT * FROM feedback ORDER BY id DESC LIMIT ?'),
    feedbackByStatus: db.prepare('SELECT * FROM feedback WHERE status = ? ORDER BY id DESC LIMIT ?'),
    feedbackStatus: db.prepare('UPDATE feedback SET status = ? WHERE id = ?'),
    feedbackCounts: db.prepare('SELECT status, COUNT(*) AS n FROM feedback GROUP BY status')
};

module.exports = {
    period,
    day,
    daysAgo,
    hashInstallId,
    getKeyByInstall: (installId) => stmt.keyByInstall.get(installId),
    getKeyByHash: (hash) => stmt.keyByHash.get(hash),
    // mint_ip is deliberately NULL — no IP addresses at rest.
    createKey: (installId, hash) =>
        stmt.insertKey.run(installId, hash, 'free', new Date().toISOString(), null),
    rotateKey: (installId, hash) => stmt.rotateKey.run(hash, installId),
    setTier: (installId, tier) => stmt.setTier.run(tier, installId),

    // Rename an install (key + all usage periods move with it) — the
    // migration path off legacy hostname-derived install ids. Caller must
    // ensure the new id is unused.
    migrateInstall: db.transaction((oldId, newId) => {
        stmt.renameKey.run(newId, oldId);
        stmt.renameUsage.run(newId, oldId);
    }),
    bumpUsage: (installId) => stmt.bumpUsage.run(installId, period()),
    getUsed: (installId) => (stmt.getUsed.get(installId, period()) || { used: 0 }).used,
    bumpProviderUsage: (provider) => stmt.bumpProvider.run(provider, period()),
    providerUsed: (provider) => (stmt.providerUsed.get(provider, period()) || { used: 0 }).used,

    // App analytics: opt-in usage counters from the desktop app, keyed by a
    // hashed analytics id that is a DIFFERENT id space from Connect keys —
    // rows here can never be joined against search usage. Per (day, install,
    // event) counters only: the raw events (and their timestamps) are folded
    // away at the API boundary and never stored.
    recordAnalytics: db.transaction((installHash, rows) => {
        for (const r of rows) stmt.bumpAnalytics.run(r.day, installHash, r.name, r.count);
    }),
    analyticsDaily: (sinceDay) => stmt.analyticsDaily.all(sinceDay),
    analyticsTop: (sinceDay, limit = 40) => stmt.analyticsTop.all(sinceDay, limit),
    analyticsActives: () => ({
        today: stmt.analyticsActive.get(day()).n,
        last7d: stmt.analyticsActive.get(daysAgo(6)).n,
        last30d: stmt.analyticsActive.get(daysAgo(29)).n
    }),

    // Busiest installs in the window, each with its per-day event totals —
    // the install × day grid on /admin. Still counters: an install is a
    // hashed analytics id, a day is a UTC day, a cell is a count.
    analyticsByInstall: (sinceDay, limit = 100) => {
        const rows = stmt.analyticsInstalls.all(sinceDay, limit);
        const byId = new Map(rows.map((r) => [r.install_id, {
            installId: r.install_id,
            total: r.n,
            activeDays: r.days,
            firstDay: r.first_day,
            lastDay: r.last_day,
            byDay: {}
        }]));
        for (const c of stmt.analyticsCells.all(sinceDay, sinceDay, limit)) {
            const inst = byId.get(c.install_id);
            if (inst) inst.byDay[c.day] = c.n;
        }
        return [...byId.values()];
    },

    // One install's counters, broken out by day and event name.
    analyticsInstall: (installHash, sinceDay) => {
        const events = stmt.analyticsInstallEvents.all(installHash, sinceDay);
        const byDay = {};
        let total = 0;
        for (const e of events) {
            byDay[e.day] = (byDay[e.day] || 0) + e.n;
            total += e.n;
        }
        return { total, byDay, events };
    },

    // Observability counters: service-wide daily totals ('search.ok',
    // 'provider.serper.fail', 'search.ms.lt500', …). Never keyed by install,
    // never carrying request content — safe under the privacy invariant.
    bumpMetric: (name) => stmt.bumpMetric.run(day(), name),
    metricsSince: (sinceDay) => stmt.metricsSince.all(sinceDay),
    metricToday: (name) => (stmt.metricToday.get(day(), name) || { n: 0 }).n,

    // Called at most once per install per day (auth path checks first).
    touchSeen: (installId) => stmt.touchSeen.run(day(), installId),
    actives: () => ({
        today: stmt.activeSince.get(day()).n,
        last7d: stmt.activeSince.get(daysAgo(6)).n,
        last30d: stmt.activeSince.get(daysAgo(29)).n
    }),
    installList: (limit = 200) => stmt.installList.all(period(), limit),

    alertLastFired: (name) => (stmt.alertState.get(name) || {}).last_fired_at || null,
    markAlertFired: (name) => stmt.alertFired.run(name, new Date().toISOString()),

    // User feedback / support requests (POST /v1/feedback). The one table
    // that stores user-written TEXT — deliberately, because the user wrote
    // it TO the operator and pressing Send is the consent. Everything
    // around it keeps the invariant: no install id, no key, no IP on the
    // row, so a message can never be joined to search or analytics usage.
    // created_at is a full timestamp (unlike telemetry's day buckets):
    // support needs ordering, and the field describes a voluntary act.
    addFeedback: ({ kind, message, email, appVersion, platform }) =>
        stmt.insertFeedback.run(new Date().toISOString(), kind, message,
            email || null, appVersion || null, platform || null).lastInsertRowid,
    feedbackList: (status, limit = 200) =>
        status && status !== 'all'
            ? stmt.feedbackByStatus.all(status, limit)
            : stmt.feedbackAll.all(limit),
    setFeedbackStatus: (id, status) => stmt.feedbackStatus.run(status, id).changes > 0,
    feedbackCounts: () => {
        const out = { new: 0, read: 0, closed: 0, total: 0 };
        for (const r of stmt.feedbackCounts.all()) {
            out[r.status] = r.n;
            out.total += r.n;
        }
        return out;
    },
    stats: () => ({
        keys: stmt.keyCount.get().n,
        tiers: stmt.tierCounts.all(),
        period: period(),
        searchesThisPeriod: stmt.periodTotal.get(period()).n,
        providersThisPeriod: stmt.providerTotals.all(period())
    })
};
