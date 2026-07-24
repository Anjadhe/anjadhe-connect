// All deploy-time configuration comes from env vars (Railway service
// variables). Nothing here is per-user; user state lives in SQLite (db.js).
'use strict';

function intEnv(name, fallback) {
    const n = parseInt(process.env[name], 10);
    return Number.isFinite(n) ? n : fallback;
}

function jsonEnv(name, fallback) {
    try {
        return process.env[name] ? JSON.parse(process.env[name]) : fallback;
    } catch {
        console.error(`[config] ${name} is not valid JSON — ignoring`);
        return fallback;
    }
}

const config = {
    port: intEnv('PORT', 8080),
    // Railway sets RAILWAY_VOLUME_MOUNT_PATH when a volume is attached; the
    // DB must live there or every deploy wipes all keys and usage.
    dataDir: process.env.RAILWAY_VOLUME_MOUNT_PATH || process.env.DATA_DIR || './data',
    adminToken: process.env.ADMIN_TOKEN || null,

    // Monthly search quotas per tier. Tier assignment is manual for now
    // (POST /v1/admin/tier) — Stripe checkout/webhooks come later.
    tierQuotas: Object.assign({ free: 300, plus: 3000, pro: 15000 }, jsonEnv('TIER_QUOTAS', {})),

    // Per-key searches-per-minute — protects upstream keys from a runaway
    // agent loop regardless of how much monthly quota is left.
    perMinute: Object.assign({ free: 20, plus: 60, pro: 120 }, jsonEnv('TIER_PER_MINUTE', {})),

    // Keys one IP may mint per day. Several installs behind one NAT are
    // normal; hundreds are farming.
    mintPerIpPerDay: intEnv('MINT_PER_IP_PER_DAY', 20),

    // Upstream provider keys — any subset. providerOrder is the routing
    // preference, cheapest-adequate first.
    providerKeys: {
        serper: process.env.SERPER_API_KEY || null,
        brave: process.env.BRAVE_API_KEY || null,
        tavily: process.env.TAVILY_API_KEY || null
    },
    providerOrder: (process.env.PROVIDER_ORDER || 'serper,brave,tavily')
        .split(',').map(s => s.trim()).filter(Boolean),

    // Hard monthly caps per provider, in queries — the cost-control
    // backstop. {} = uncapped. Example: {"serper": 50000, "tavily": 1000}
    providerBudgets: jsonEnv('PROVIDER_BUDGETS', {}),

    // SEARCH_MOCK=1 swaps all upstreams for a canned-response provider so
    // the full mint→search→quota flow can run in dev/tests with no keys.
    mock: process.env.SEARCH_MOCK === '1'
};

module.exports = config;
