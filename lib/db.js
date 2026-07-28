// SQLite state on a Railway volume: API keys, per-install usage counters,
// per-provider usage counters.
//
// PRIVACY INVARIANT: no table stores query text — only counts. Keys are
// stored as SHA-256 hashes, so a DB leak leaks no usable credentials.
// Usage is keyed by install_id (not key hash) so rotating a key does NOT
// reset the month's quota.
'use strict';
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const config = require('./config');

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
CREATE TABLE IF NOT EXISTS alert_state (
    name          TEXT PRIMARY KEY,
    last_fired_at TEXT NOT NULL
);
`);

// keys.last_seen_day is deliberately day-granularity (never a timestamp):
// enough to count active installs, too coarse to reconstruct a usage pattern.
// No migration machinery exists, so new columns are added via guarded ALTER.
if (!db.prepare('PRAGMA table_info(keys)').all().some(c => c.name === 'last_seen_day')) {
    db.exec('ALTER TABLE keys ADD COLUMN last_seen_day TEXT');
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
    metricsSince: db.prepare('SELECT day, name, n FROM metrics_daily WHERE day >= ? ORDER BY day'),
    metricToday: db.prepare('SELECT n FROM metrics_daily WHERE day = ? AND name = ?'),
    touchSeen: db.prepare('UPDATE keys SET last_seen_day = ? WHERE install_id = ?'),
    activeSince: db.prepare('SELECT COUNT(*) AS n FROM keys WHERE last_seen_day >= ?'),
    installList: db.prepare(`SELECT k.install_id, k.tier, k.created_at, k.last_seen_day,
            COALESCE(u.used, 0) AS used
        FROM keys k LEFT JOIN usage u ON u.install_id = k.install_id AND u.period = ?
        ORDER BY used DESC, k.created_at DESC LIMIT ?`),
    alertState: db.prepare('SELECT last_fired_at FROM alert_state WHERE name = ?'),
    alertFired: db.prepare(`INSERT INTO alert_state (name, last_fired_at) VALUES (?, ?)
        ON CONFLICT(name) DO UPDATE SET last_fired_at = excluded.last_fired_at`)
};

module.exports = {
    period,
    day,
    daysAgo,
    getKeyByInstall: (installId) => stmt.keyByInstall.get(installId),
    getKeyByHash: (hash) => stmt.keyByHash.get(hash),
    createKey: (installId, hash, ip) =>
        stmt.insertKey.run(installId, hash, 'free', new Date().toISOString(), ip),
    rotateKey: (installId, hash) => stmt.rotateKey.run(hash, installId),
    setTier: (installId, tier) => stmt.setTier.run(tier, installId),
    bumpUsage: (installId) => stmt.bumpUsage.run(installId, period()),
    getUsed: (installId) => (stmt.getUsed.get(installId, period()) || { used: 0 }).used,
    bumpProviderUsage: (provider) => stmt.bumpProvider.run(provider, period()),
    providerUsed: (provider) => (stmt.providerUsed.get(provider, period()) || { used: 0 }).used,

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
    stats: () => ({
        keys: stmt.keyCount.get().n,
        tiers: stmt.tierCounts.all(),
        period: period(),
        searchesThisPeriod: stmt.periodTotal.get(period()).n,
        providersThisPeriod: stmt.providerTotals.all(period())
    })
};
