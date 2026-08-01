// Picks an upstream for each search: the first provider in PROVIDER_ORDER
// that has a key, is under its monthly budget cap, and isn't cooling down
// after repeated failures. Failover walks down the list. This is where
// "spread the load and control cost" lives — cheap-first routing with hard
// budget backstops, NOT free-tier farming (one legitimate account per
// provider; multi-account farming violates provider ToS).
'use strict';
const config = require('./config');
const providers = require('./providers');
const db = require('./db');

const FAILS_TO_COOL = 3;
const COOLDOWN_MS = 5 * 60 * 1000;
const health = new Map(); // provider -> {fails, coolUntil}

// Per-provider pacing: calls to a paced upstream run one at a time with
// starts spaced providerPaceMs apart (Brave free tier is a hard 1 req/s —
// the app throttles per machine, but all machines share this one upstream
// key, so only the server can enforce the aggregate). Backlog is bounded:
// past ~10s of projected wait the caller fails over to the next provider
// immediately instead of stacking requests the app's own 30s client
// timeout would kill anyway. A backlog rejection is congestion, not
// provider illness — search() skips the health/cooldown bump for it.
const PACE_MAX_WAIT_MS = 10000;
const _pace = new Map(); // provider -> {tail, lastStart, waiting}

function paced(name, fn) {
    const interval = config.providerPaceMs[name] || 0;
    if (!interval) return fn();
    let p = _pace.get(name);
    if (!p) { p = { tail: Promise.resolve(), lastStart: 0, waiting: 0 }; _pace.set(name, p); }
    // waiting counts queued + in-flight; the projection undercounts when a
    // call runs longer than the interval, which only errs toward failing
    // over sooner under load.
    if (p.waiting * interval > PACE_MAX_WAIT_MS) {
        const e = new Error(`${name} rate-pacing backlog full`);
        e.backlog = true;
        return Promise.reject(e);
    }
    p.waiting++;
    const run = p.tail.then(async () => {
        const wait = p.lastStart + interval - Date.now();
        if (wait > 0) await new Promise(r => setTimeout(r, wait));
        p.lastStart = Date.now();
        try { return await fn(); } finally { p.waiting--; }
    });
    p.tail = run.catch(() => {});
    return run;
}

function available() {
    if (config.mock) return ['mock'];
    return config.providerOrder.filter(p => providers[p] && config.providerKeys[p]);
}

async function search(query, maxResults) {
    let lastErr = null;
    for (const name of available()) {
        const h = health.get(name);
        if (h && h.coolUntil > Date.now()) continue;
        const budget = config.providerBudgets[name];
        if (budget && db.providerUsed(name) >= budget) continue;
        try {
            const key = config.mock ? 'mock' : config.providerKeys[name];
            const results = await paced(name, () => providers[name](query, maxResults, key));
            db.bumpProviderUsage(name);
            db.bumpMetric(`provider.${name}.ok`);
            health.delete(name);
            return { results, upstream: name };
        } catch (e) {
            // e.message never contains the query (providers.js invariant).
            lastErr = e;
            if (e.backlog) {
                // Congested, not broken — fail over without poisoning the
                // provider's health (a cooldown would turn a burst into a
                // 5-minute outage of the healthiest upstream).
                db.bumpMetric(`provider.${name}.busy`);
                console.error(`[router] ${name} busy: ${e.message}`);
                continue;
            }
            db.bumpMetric(`provider.${name}.fail`);
            console.error(`[router] ${name} failed: ${e.message}`);
            const cur = health.get(name) || { fails: 0, coolUntil: 0 };
            cur.fails++;
            if (cur.fails >= FAILS_TO_COOL) {
                cur.coolUntil = Date.now() + COOLDOWN_MS;
                cur.fails = 0;
                console.error(`[router] ${name} cooling down for ${COOLDOWN_MS / 1000}s`);
            }
            health.set(name, cur);
        }
    }
    throw new Error(lastErr
        ? `All search providers failed (last: ${lastErr.message})`
        : 'No search provider available (none configured, or all over budget/cooling down)');
}

// Live status of each configured provider, for the admin dashboard and
// alert checks: current-month usage vs budget, and cooldown state.
function statusSnapshot() {
    return available().map((name) => {
        const h = health.get(name);
        const budget = config.providerBudgets[name] || null;
        const used = db.providerUsed(name);
        return {
            name,
            used,
            budget,
            overBudget: !!(budget && used >= budget),
            cooling: !!(h && h.coolUntil > Date.now()),
            coolUntil: h && h.coolUntil > Date.now() ? new Date(h.coolUntil).toISOString() : null,
            recentFails: h ? h.fails : 0
        };
    });
}

module.exports = { search, available, statusSnapshot };
