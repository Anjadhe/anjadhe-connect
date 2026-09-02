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
CREATE TABLE IF NOT EXISTS llm_usage (
    install_id TEXT NOT NULL,
    period     TEXT NOT NULL,
    requests   INTEGER NOT NULL DEFAULT 0,
    tokens_in  INTEGER NOT NULL DEFAULT 0,
    tokens_out INTEGER NOT NULL DEFAULT 0,
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
CREATE TABLE IF NOT EXISTS subscribers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    token       TEXT NOT NULL UNIQUE,
    source      TEXT,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS licenses (
    id            TEXT PRIMARY KEY,
    created_at    TEXT NOT NULL,
    class         TEXT NOT NULL,
    email         TEXT NOT NULL COLLATE NOCASE,
    sub_hash      TEXT NOT NULL,
    updates_until TEXT,
    license       TEXT NOT NULL,
    source        TEXT,
    app_version   TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS licenses_email_class ON licenses (email, class);
CREATE TABLE IF NOT EXISTS llm_models (
    id          TEXT PRIMARY KEY,
    upstream    TEXT NOT NULL,
    label       TEXT NOT NULL,
    description TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1,
    position    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
`);

// keys.last_seen_day is deliberately day-granularity (never a timestamp):
// enough to count active installs, too coarse to reconstruct a usage pattern.
// No migration machinery exists, so new columns are added via guarded ALTER.
if (!db.prepare('PRAGMA table_info(keys)').all().some(c => c.name === 'last_seen_day')) {
    db.exec('ALTER TABLE keys ADD COLUMN last_seen_day TEXT');
}

// Feedback diagnostics (2026-08-04): an app-details line the card shows
// before sending, and — only when the user ticked its default-off checkbox —
// the SHA-256 of their analytics id, the same form analytics_daily uses, so
// a report can be matched with that install's usage. Never the raw id.
for (const col of ['diagnostics', 'analytics_hash']) {
    if (!db.prepare('PRAGMA table_info(feedback)').all().some(c => c.name === col)) {
        db.exec(`ALTER TABLE feedback ADD COLUMN ${col} TEXT`);
    }
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

// The LLM model catalog is MANAGED DATA (admin console › Models) since
// 2026-08-19 — the table is what /v1/llm serves and validates against. The
// legacy LLM_MODELS env seeds an EMPTY table once, so an existing deploy
// upgrades onto its own lineup; after that the env is inert and the admin
// page is the only writer. Both env value shapes are accepted (bare
// upstream id, or {upstream, label, description}); key order becomes
// position, which is the order the app's picker shows (first = preselect).
if (db.prepare('SELECT COUNT(*) AS n FROM llm_models').get().n === 0
    && Object.keys(config.llmModels).length) {
    const now = new Date().toISOString();
    const ins = db.prepare(`INSERT INTO llm_models (id, upstream, label, description, enabled, position, created_at, updated_at)
        VALUES (?, ?, ?, ?, 1, ?, ?, ?)`);
    db.transaction(() => {
        Object.entries(config.llmModels).forEach(([id, v], i) => {
            const meta = (v && typeof v === 'object') ? v : { upstream: v };
            if (!meta.upstream) return;
            ins.run(id, String(meta.upstream),
                String(meta.label || (id === 'anjadhe-cloud' ? 'Anjadhe Cloud' : id)),
                meta.description ? String(meta.description) : null, i, now, now);
        });
    })();
    console.log(`[llm-models] seeded ${db.prepare('SELECT COUNT(*) AS n FROM llm_models').get().n} model(s) from LLM_MODELS env — the table is the source of truth from here on`);
}

// Calendar-month usage buckets, UTC — e.g. '2026-07'. Old rows are tiny;
// they age out on USAGE_RETENTION_DAYS (purgeOldRows).
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
    bumpLlm: db.prepare(`INSERT INTO llm_usage (install_id, period, requests, tokens_in, tokens_out)
        VALUES (?, ?, 1, ?, ?)
        ON CONFLICT(install_id, period) DO UPDATE SET
            requests = requests + 1,
            tokens_in = tokens_in + excluded.tokens_in,
            tokens_out = tokens_out + excluded.tokens_out`),
    llmUsed: db.prepare('SELECT requests, tokens_in, tokens_out FROM llm_usage WHERE install_id = ? AND period = ?'),
    llmPeriodTotals: db.prepare(`SELECT COALESCE(SUM(requests), 0) AS requests,
        COALESCE(SUM(tokens_in + tokens_out), 0) AS tokens FROM llm_usage WHERE period = ?`),
    renameLlmUsage: db.prepare('UPDATE llm_usage SET install_id = ? WHERE install_id = ?'),
    bumpProvider: db.prepare(`INSERT INTO provider_usage (provider, period, used) VALUES (?, ?, 1)
        ON CONFLICT(provider, period) DO UPDATE SET used = used + 1`),
    providerUsed: db.prepare('SELECT used FROM provider_usage WHERE provider = ? AND period = ?'),
    keyCount: db.prepare('SELECT COUNT(*) AS n FROM keys'),
    tierCounts: db.prepare('SELECT tier, COUNT(*) AS n FROM keys GROUP BY tier'),
    periodTotal: db.prepare('SELECT COALESCE(SUM(used), 0) AS n FROM usage WHERE period = ?'),
    providerTotals: db.prepare('SELECT provider, used FROM provider_usage WHERE period = ?'),
    bumpMetric: db.prepare(`INSERT INTO metrics_daily (day, name, n) VALUES (?, ?, 1)
        ON CONFLICT(day, name) DO UPDATE SET n = n + 1`),
    bumpMetricBy: db.prepare(`INSERT INTO metrics_daily (day, name, n) VALUES (?, ?, ?)
        ON CONFLICT(day, name) DO UPDATE SET n = n + excluded.n`),
    bumpAnalytics: db.prepare(`INSERT INTO analytics_daily (day, install_id, name, n) VALUES (?, ?, ?, ?)
        ON CONFLICT(day, install_id, name) DO UPDATE SET n = n + excluded.n`),
    analyticsNameCount: db.prepare('SELECT COUNT(*) AS n FROM analytics_daily WHERE day = ? AND install_id = ?'),
    analyticsHasName: db.prepare('SELECT 1 AS x FROM analytics_daily WHERE day = ? AND install_id = ? AND name = ?'),
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
    keyCountPrefix: db.prepare(`SELECT COUNT(*) AS n FROM keys WHERE install_id LIKE ? || '%'`),
    keyPurgeUnused: db.prepare(`DELETE FROM keys WHERE last_seen_day IS NULL AND tier = 'free' AND created_at < ?`),
    renameKey: db.prepare('UPDATE keys SET install_id = ? WHERE install_id = ?'),
    renameUsage: db.prepare('UPDATE usage SET install_id = ? WHERE install_id = ?'),
    alertState: db.prepare('SELECT last_fired_at FROM alert_state WHERE name = ?'),
    alertFired: db.prepare(`INSERT INTO alert_state (name, last_fired_at) VALUES (?, ?)
        ON CONFLICT(name) DO UPDATE SET last_fired_at = excluded.last_fired_at`),
    insertFeedback: db.prepare(`INSERT INTO feedback (created_at, kind, message, email, app_version, platform, diagnostics, analytics_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
    feedbackAll: db.prepare('SELECT * FROM feedback ORDER BY id DESC LIMIT ?'),
    feedbackByStatus: db.prepare('SELECT * FROM feedback WHERE status = ? ORDER BY id DESC LIMIT ?'),
    feedbackStatus: db.prepare('UPDATE feedback SET status = ? WHERE id = ?'),
    feedbackPurge: db.prepare('DELETE FROM feedback WHERE created_at < ?'),
    analyticsPurge: db.prepare('DELETE FROM analytics_daily WHERE day < ?'),
    usagePurge: db.prepare('DELETE FROM usage WHERE period < ?'),
    llmUsagePurge: db.prepare('DELETE FROM llm_usage WHERE period < ?'),
    feedbackCounts: db.prepare('SELECT status, COUNT(*) AS n FROM feedback GROUP BY status'),
    insertSubscriber: db.prepare(`INSERT OR IGNORE INTO subscribers (email, token, source, created_at) VALUES (?, ?, ?, ?)`),
    subscriberByToken: db.prepare('SELECT id FROM subscribers WHERE token = ?'),
    subscriberDeleteByToken: db.prepare('DELETE FROM subscribers WHERE token = ?'),
    subscriberDeleteById: db.prepare('DELETE FROM subscribers WHERE id = ?'),
    subscribersAll: db.prepare('SELECT id, email, token, source, created_at FROM subscribers ORDER BY id DESC'),
    subscriberCount: db.prepare('SELECT COUNT(*) AS n FROM subscribers'),
    insertLicense: db.prepare(`INSERT INTO licenses (id, created_at, class, email, sub_hash, updates_until, license, source, app_version)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
    licenseByEmailClass: db.prepare('SELECT * FROM licenses WHERE email = ? AND class = ?'),
    licensesAll: db.prepare('SELECT * FROM licenses ORDER BY created_at DESC'),
    licenseDelete: db.prepare('DELETE FROM licenses WHERE id = ?'),
    licenseCounts: db.prepare('SELECT class, COUNT(*) AS n FROM licenses GROUP BY class'),
    licensesToday: db.prepare("SELECT COUNT(*) AS n FROM licenses WHERE substr(created_at, 1, 10) = ?"),
    llmModelsAll: db.prepare('SELECT * FROM llm_models ORDER BY position, id'),
    llmModelsEnabled: db.prepare('SELECT * FROM llm_models WHERE enabled = 1 ORDER BY position, id'),
    llmModelGet: db.prepare('SELECT * FROM llm_models WHERE id = ?'),
    llmModelMaxPos: db.prepare('SELECT COALESCE(MAX(position), -1) AS p FROM llm_models'),
    llmModelInsert: db.prepare(`INSERT INTO llm_models (id, upstream, label, description, enabled, position, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
    llmModelUpdate: db.prepare(`UPDATE llm_models SET upstream = ?, label = ?, description = ?, enabled = ?, updated_at = ?
        WHERE id = ?`),
    llmModelDelete: db.prepare('DELETE FROM llm_models WHERE id = ?'),
    llmModelSetPos: db.prepare('UPDATE llm_models SET position = ? WHERE id = ?')
};

// The install table is server-sorted and paged (admin › Installs). ORDER BY
// can't take a bound parameter, so the sort column comes from this whitelist
// — user input picks a KEY here and is never interpolated into SQL.
const INSTALL_SORT_COLS = {
    usage: '(COALESCE(u.used, 0) + COALESCE(l.requests, 0))',
    searches: 'COALESCE(u.used, 0)',
    ai: 'COALESCE(l.requests, 0)',
    tokens: 'COALESCE(l.tokens_in + l.tokens_out, 0)',
    tier: 'k.tier',
    created: 'k.created_at',
    seen: `COALESCE(k.last_seen_day, '')` // never-seen sorts as oldest
};
const _installPageStmts = new Map(); // one prepared stmt per sort × dir × filtered
function installPageStmt(sortCol, dir, filtered) {
    const key = `${sortCol}|${dir}|${filtered}`;
    if (!_installPageStmts.has(key)) {
        _installPageStmts.set(key, db.prepare(`SELECT k.install_id, k.tier, k.created_at, k.last_seen_day,
                COALESCE(u.used, 0) AS used,
                COALESCE(l.requests, 0) AS llm_requests,
                COALESCE(l.tokens_in + l.tokens_out, 0) AS llm_tokens
            FROM keys k
            LEFT JOIN usage u ON u.install_id = k.install_id AND u.period = ?
            LEFT JOIN llm_usage l ON l.install_id = k.install_id AND l.period = ?
            ${filtered ? `WHERE k.install_id LIKE ? || '%'` : ''}
            ORDER BY ${sortCol} ${dir}, k.created_at DESC
            LIMIT ? OFFSET ?`));
    }
    return _installPageStmts.get(key);
}

module.exports = {
    // The privacy canary test scans the database FILE for request text; a
    // checkpoint first folds the WAL into it. Tests only.
    checkpoint: () => db.pragma('wal_checkpoint(TRUNCATE)'),
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
        stmt.renameLlmUsage.run(newId, oldId);
    }),
    bumpUsage: (installId) => stmt.bumpUsage.run(installId, period()),
    getUsed: (installId) => (stmt.getUsed.get(installId, period()) || { used: 0 }).used,

    // LLM metering: requests + tokens per install per month. Same privacy
    // shape as search usage — counters keyed by hashed install id, never a
    // word of what was asked or answered.
    bumpLlmUsage: (installId, tokensIn, tokensOut) =>
        stmt.bumpLlm.run(installId, period(), tokensIn | 0, tokensOut | 0),
    llmUsed: (installId) => {
        const r = stmt.llmUsed.get(installId, period()) || { requests: 0, tokens_in: 0, tokens_out: 0 };
        return { requests: r.requests, tokens: r.tokens_in + r.tokens_out };
    },
    llmPeriodTotals: () => stmt.llmPeriodTotals.get(period()),
    bumpProviderUsage: (provider) => stmt.bumpProvider.run(provider, period()),
    providerUsed: (provider) => (stmt.providerUsed.get(provider, period()) || { used: 0 }).used,

    // App analytics: opt-in usage counters from the desktop app, keyed by a
    // hashed analytics id that is a DIFFERENT id space from Connect keys —
    // rows here can never be joined against search usage. Per (day, install,
    // event) counters only: the raw events (and their timestamps) are folded
    // away at the API boundary and never stored.
    // Counter rows are keyed (day, install, name) and prop values feed into
    // the name, so an attacker-chosen value per event would otherwise mint a
    // new row per event, unbounded. Bumping an existing counter is always
    // allowed; CREATING one stops at the per-install-per-day cap.
    recordAnalytics: db.transaction((installHash, rows, maxNamesPerDay = 300) => {
        for (const r of rows) {
            if (!stmt.analyticsHasName.get(r.day, installHash, r.name)
                && stmt.analyticsNameCount.get(r.day, installHash).n >= maxNamesPerDay) continue;
            stmt.bumpAnalytics.run(r.day, installHash, r.name, r.count);
        }
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
    bumpMetricBy: (name, n) => stmt.bumpMetricBy.run(day(), name, n | 0),
    metricsSince: (sinceDay) => stmt.metricsSince.all(sinceDay),
    metricToday: (name) => (stmt.metricToday.get(day(), name) || { n: 0 }).n,

    // Called at most once per install per day (auth path checks first).
    touchSeen: (installId) => stmt.touchSeen.run(day(), installId),
    actives: () => ({
        today: stmt.activeSince.get(day()).n,
        last7d: stmt.activeSince.get(daysAgo(6)).n,
        last30d: stmt.activeSince.get(daysAgo(29)).n
    }),
    installSortKeys: Object.keys(INSTALL_SORT_COLS),
    // One page of the install table, server-sorted (admin › Installs).
    // `sort` must be a whitelisted key (null return = unknown); `q` is a
    // hex prefix of the STORED (hashed) id, validated by the route.
    installPage: ({ sort = 'usage', dir = 'desc', limit = 100, offset = 0, q = '' } = {}) => {
        const col = INSTALL_SORT_COLS[sort];
        if (!col) return null;
        const d = dir === 'asc' ? 'ASC' : 'DESC';
        const args = q ? [period(), period(), q, limit, offset]
                       : [period(), period(), limit, offset];
        return {
            installs: installPageStmt(col, d, !!q).all(...args),
            total: q ? stmt.keyCountPrefix.get(q).n : stmt.keyCount.get().n
        };
    },

    alertLastFired: (name) => (stmt.alertState.get(name) || {}).last_fired_at || null,
    markAlertFired: (name) => stmt.alertFired.run(name, new Date().toISOString()),

    // User feedback / support requests (POST /v1/feedback). The one table
    // that stores user-written TEXT — deliberately, because the user wrote
    // it TO the operator and pressing Send is the consent. Everything
    // around it keeps the invariant: no key, no IP, and no id on the row
    // UNLESS the user ticked the card's default-off checkbox to attach
    // their analytics id (arriving here already hashed by the route) so
    // the report can be matched with that install's usage — the join
    // exists only when the user performs it, per message.
    // created_at is a full timestamp (unlike telemetry's day buckets):
    // support needs ordering, and the field describes a voluntary act.
    addFeedback: ({ kind, message, email, appVersion, platform, diagnostics, analyticsHash }) =>
        stmt.insertFeedback.run(new Date().toISOString(), kind, message,
            email || null, appVersion || null, platform || null,
            diagnostics || null, analyticsHash || null).lastInsertRowid,
    // Release-notes subscribers (POST /v1/subscribe from the website's
    // download page). The second table holding something a person typed —
    // an email address, given for exactly one purpose: one email per
    // release. Keyless, no install id, no IP at rest, nothing else on the
    // row. Unsubscribing DELETES the row (there is no "unsubscribed" state
    // to keep — the address is the whole record, and its purpose is gone).
    // A repeat signup is a no-op that returns the same success, so the
    // endpoint never reveals whether an address is already on the list.
    addSubscriber: (email, source) => {
        const token = crypto.randomBytes(24).toString('base64url');
        const r = stmt.insertSubscriber.run(email, token, source || null, new Date().toISOString());
        return r.changes > 0; // false = already subscribed
    },
    unsubscribe: (token) => stmt.subscriberDeleteByToken.run(token).changes > 0,
    removeSubscriber: (id) => stmt.subscriberDeleteById.run(id).changes > 0,
    subscribersList: () => stmt.subscribersAll.all(),
    subscriberCount: () => stmt.subscriberCount.get().n,
    // App licenses (POST /v1/license/alpha, POST /v1/admin/licenses). The
    // THIRD table holding an email address, and the only one that holds it
    // for the life of the product: the address is how a person recovers
    // the key they were issued (a re-claim by the same address returns the
    // same license), and for a paid license it is the receipt. Given by
    // typing it into the License card, for that stated purpose. No install
    // id, no IP, no key hash on the row. The license string itself carries
    // only a hash of the address (lib/license.js).
    addLicense: ({ id, cls, email, subHash, updatesUntil, license, source, appVersion }) =>
        stmt.insertLicense.run(id, new Date().toISOString(), cls, email, subHash,
            updatesUntil || null, license, source || null, appVersion || null),
    licenseFor: (email, cls) => stmt.licenseByEmailClass.get(email, cls) || null,
    licensesList: () => stmt.licensesAll.all(),
    removeLicense: (id) => stmt.licenseDelete.run(id).changes > 0,
    licenseCounts: () => {
        const out = { alpha: 0, paid: 0 };
        for (const r of stmt.licenseCounts.all()) out[r.class] = r.n;
        return out;
    },
    licensesToday: () => stmt.licensesToday.get(new Date().toISOString().slice(0, 10)).n,
    feedbackList: (status, limit = 200) =>
        status && status !== 'all'
            ? stmt.feedbackByStatus.all(status, limit)
            : stmt.feedbackAll.all(limit),
    setFeedbackStatus: (id, status) => stmt.feedbackStatus.run(status, id).changes > 0,

    // Retention. Feedback is the only user-WRITTEN text the service holds,
    // so "we keep it until we don't" is not a policy anyone can rely on —
    // it now ages out on a stated clock, regardless of status (a closed
    // report and a forgotten one are the same liability). Analytics
    // counters age out too: they are the table an abusive client can grow,
    // and nothing reads a bucket older than the dashboard's window.
    purgeOldRows: (feedbackDays, analyticsDays, usageDays) => {
        const cutoff = new Date(Date.now() - feedbackDays * 86400000).toISOString();
        const feedback = stmt.feedbackPurge.run(cutoff).changes;
        const analytics = stmt.analyticsPurge.run(daysAgo(analyticsDays)).changes;
        // Usage buckets are calendar months ('2026-07'); a period sorts
        // before the cutoff day's own month iff it is strictly older.
        let usage = 0;
        if (usageDays) {
            const p = period(new Date(Date.now() - usageDays * 86400000));
            usage += stmt.usagePurge.run(p).changes;
            usage += stmt.llmUsagePurge.run(p).changes;
        }
        return { feedback, analytics, usage };
    },
    // Never-used keys age out: last_seen_day is stamped on an install's
    // FIRST authenticated call, so NULL means the key was minted and never
    // used once — the signature of sandbox/bot runs of a downloaded build.
    // free-tier only (an operator-upgraded key is never purged), and a real
    // user whose dormant key dies is fine: the app re-mints on 401 and the
    // vacated install id mints fresh.
    purgeUnusedKeys: (days) =>
        stmt.keyPurgeUnused.run(new Date(Date.now() - days * 86400000).toISOString()).changes,
    feedbackCounts: () => {
        const out = { new: 0, read: 0, closed: 0, total: 0 };
        for (const r of stmt.feedbackCounts.all()) {
            out[r.status] = r.n;
            out.total += r.n;
        }
        return out;
    },
    // LLM model catalog (admin-managed; see the seed block above). Rows
    // carry no user data — this is service configuration in the DB so the
    // operator manages it from /admin instead of Railway env edits.
    llmModelsAll: () => stmt.llmModelsAll.all(),
    llmModelsEnabled: () => stmt.llmModelsEnabled.all(),
    llmModelGet: (id) => stmt.llmModelGet.get(id),
    // Upsert keyed on id: an existing row keeps its position and created_at
    // (editing a model must not move it in the picker).
    llmModelUpsert: ({ id, upstream, label, description, enabled }) => {
        const now = new Date().toISOString();
        if (stmt.llmModelGet.get(id)) {
            stmt.llmModelUpdate.run(upstream, label, description, enabled ? 1 : 0, now, id);
        } else {
            stmt.llmModelInsert.run(id, upstream, label, description, enabled ? 1 : 0,
                stmt.llmModelMaxPos.get().p + 1, now, now);
        }
        return stmt.llmModelGet.get(id);
    },
    llmModelDelete: (id) => stmt.llmModelDelete.run(id).changes > 0,
    // Full-list reorder: one write, deterministic — the caller sends every
    // id in the wanted order (validated at the route).
    llmModelsReorder: db.transaction((ids) => {
        ids.forEach((id, i) => stmt.llmModelSetPos.run(i, id));
    }),

    stats: () => ({
        keys: stmt.keyCount.get().n,
        tiers: stmt.tierCounts.all(),
        period: period(),
        searchesThisPeriod: stmt.periodTotal.get(period()).n,
        providersThisPeriod: stmt.providerTotals.all(period()),
        llmThisPeriod: stmt.llmPeriodTotals.get(period())
    })
};
