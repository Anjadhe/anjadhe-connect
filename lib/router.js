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
            const results = await providers[name](query, maxResults, key);
            db.bumpProviderUsage(name);
            health.delete(name);
            return { results, upstream: name };
        } catch (e) {
            // e.message never contains the query (providers.js invariant).
            lastErr = e;
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

module.exports = { search, available };
