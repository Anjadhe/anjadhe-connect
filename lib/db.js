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
`);

// Calendar-month usage buckets, UTC — e.g. '2026-07'. Old rows are tiny and
// kept forever (they're the service's only usage history).
function period(now = new Date()) {
    return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
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
    providerTotals: db.prepare('SELECT provider, used FROM provider_usage WHERE period = ?')
};

module.exports = {
    period,
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
    stats: () => ({
        keys: stmt.keyCount.get().n,
        tiers: stmt.tierCounts.all(),
        period: period(),
        searchesThisPeriod: stmt.periodTotal.get(period()).n,
        providersThisPeriod: stmt.providerTotals.all(period())
    })
};
