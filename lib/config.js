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

    // Names this deployment on /healthz and in the /admin banner, e.g.
    // 'production' / 'staging'. Unset = no banner, which is what a
    // single-deployment self-host wants.
    envLabel: (process.env.ENV_LABEL || '').trim().slice(0, 24) || null,

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

    // Minimum ms between call STARTS to an upstream, per provider — rate
    // protection for upstreams with hard req/s limits. Brave's free tier
    // is exactly 1 req/s, and every client machine shares this one key, so
    // clients pacing themselves individually still add up here. 1100 (not
    // 1000) because a 1s clock can still race the provider's. 0 = unpaced.
    providerPaceMs: Object.assign({ brave: 1100 }, jsonEnv('PROVIDER_PACE_MS', {})),

    // ── LLM inference (/v1/llm) ─────────────────────────────────────────
    // One OpenAI-compatible upstream under a zero-data-retention agreement
    // (DeepInfra / Together / Fireworks all speak this shape). The server is
    // a metering proxy: it never logs or stores prompt/completion text, and
    // the upstream sees Anjadhe's account, not the user.
    llmUpstreamUrl: (process.env.LLM_UPSTREAM_URL || '').replace(/\/$/, '') || null,
    llmUpstreamKey: process.env.LLM_UPSTREAM_KEY || null,

    // Public model name -> upstream model id. The public names are the API;
    // the upstream id can be swapped (better/cheaper weights) without any
    // app release. Example: {"anjadhe-cloud": "google/gemma-3-27b-it"}
    llmModels: jsonEnv('LLM_MODELS', {}),

    // Monthly per-install quotas: requests AND tokens (in+out), whichever
    // trips first. Requests are what the app's meter shows ("300 assistant
    // messages"); the token ceiling is the cost backstop behind it.
    llmTierQuotas: Object.assign({
        free: { requests: 300, tokens: 2500000 },
        plus: { requests: 3000, tokens: 25000000 },
        pro: { requests: 15000, tokens: 100000000 }
    }, jsonEnv('LLM_TIER_QUOTAS', {})),

    // Per-install brakes independent of monthly quota: a runaway agent loop
    // must not be able to burn a month of tokens in an afternoon.
    llmPerMinute: Object.assign({ free: 10, plus: 30, pro: 60 }, jsonEnv('LLM_PER_MINUTE', {})),
    llmMaxConcurrent: Object.assign({ free: 2, plus: 4, pro: 6 }, jsonEnv('LLM_MAX_CONCURRENT', {})),

    // Output clamp per request — a client asking for more gets this much.
    llmMaxOutputTokens: intEnv('LLM_MAX_OUTPUT_TOKENS', 2048),

    // Service-wide monthly token cap (in+out) — the cost-control backstop,
    // same idea as PROVIDER_BUDGETS. 0 = uncapped. When spent, /v1/llm
    // answers 503 until the 1st.
    llmBudgetTokens: intEnv('LLM_BUDGET_TOKENS', 0),

    // LLM_MOCK=1 swaps the upstream for a canned-response model so the full
    // mint→chat→quota flow can run in dev/tests with no keys.
    llmMock: process.env.LLM_MOCK === '1',

    // Optional alert push. Set ALERT_WEBHOOK_URL to receive alert
    // notifications (provider budget nearly spent, all upstreams down, mint
    // spikes, …). ALERT_WEBHOOK_KIND picks the payload shape: 'slack'
    // (default, {text}), 'discord' ({content}), or 'ntfy' (plain text body).
    // Alerts also always show on the /admin dashboard; the webhook is extra.
    alertWebhookUrl: process.env.ALERT_WEBHOOK_URL || null,
    alertWebhookKind: process.env.ALERT_WEBHOOK_KIND || 'slack',
    alertMintsPerDay: intEnv('ALERT_MINTS_PER_DAY', 50),
    alertResendHours: intEnv('ALERT_RESEND_HOURS', 6),

    // SEARCH_MOCK=1 swaps all upstreams for a canned-response provider so
    // the full mint→search→quota flow can run in dev/tests with no keys.
    mock: process.env.SEARCH_MOCK === '1'
};

module.exports = config;
