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

    // Keys the whole service will mint per day — the aggregate brake the
    // per-IP one can't be (per-IP scales with the attacker's address pool).
    // Sized far above organic install growth; raise it for a launch spike.
    mintPerDayGlobal: intEnv('MINT_PER_DAY_GLOBAL', 500),

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
    // backstop. Capped BY DEFAULT since 2026-08-05 (an uncapped deployment
    // used to be the default, i.e. no spend ceiling at all): override per
    // provider via env, explicit 0 uncaps that provider (warned at boot).
    // Example: PROVIDER_BUDGETS={"serper": 100000, "tavily": 0}
    providerBudgets: Object.assign(
        { serper: 50000, brave: 20000, tavily: 5000 },
        jsonEnv('PROVIDER_BUDGETS', {})
    ),

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

    // SEED ONLY since 2026-08-19: the model lineup lives in the llm_models
    // TABLE, managed at /admin/models — this env fills an EMPTY table once
    // (first boot / upgrade of an env-configured deploy) and is inert after
    // that. Values: upstream model id, or {upstream, label, description};
    // key order becomes the picker order. Keep public names on the
    // "anjadhe-cloud" prefix ("anjadhe-cloud-max"): app surfaces holding
    // only a bare model id recognize the engine by it. Examples:
    //   {"anjadhe-cloud": "google/gemma-3-27b-it"}
    //   {"anjadhe-cloud": {"upstream": "google/gemma-3-27b-it",
    //     "label": "Anjadhe Cloud", "description": "Fast all-rounder"}}
    llmModels: jsonEnv('LLM_MODELS', {}),

    // Monthly per-install quotas: requests AND tokens (in+out), whichever
    // trips first. Requests are what the app's meter shows; the token
    // ceiling is the cost backstop that actually bounds spend. Request caps
    // are deliberately generous relative to tokens: the app's ambient email
    // engine makes ~15 small calls/day on a metered brain (~450/mo), and a
    // request cap sized only for chat would let background work silently
    // exhaust the user's visible allowance mid-month.
    llmTierQuotas: Object.assign({
        free: { requests: 1000, tokens: 2500000 },
        plus: { requests: 10000, tokens: 25000000 },
        pro: { requests: 50000, tokens: 100000000 }
    }, jsonEnv('LLM_TIER_QUOTAS', {})),

    // Per-install brakes independent of monthly quota: a runaway agent loop
    // must not be able to burn a month of tokens in an afternoon. Sized
    // well above the worst LEGITIMATE burst — one agentic chat turn is up
    // to 16 requests (15 tool iterations + the synthesis pass) sharing the
    // window with background work (insight drain, memory extraction,
    // routines, and an inbox connect's queued insight calls) — so real use
    // clears without a 429 while a stuck loop still gets braked within a
    // minute or two. Spend is bounded by llmTierQuotas, not this.
    llmPerMinute: Object.assign({ free: 60, plus: 120, pro: 240 }, jsonEnv('LLM_PER_MINUTE', {})),
    // Concurrency is what protects the upstream from parallel fan-out —
    // streams hold a slot for their whole generation, so this cap is also
    // what a chat stream and a background drain share.
    llmMaxConcurrent: Object.assign({ free: 4, plus: 6, pro: 8 }, jsonEnv('LLM_MAX_CONCURRENT', {})),

    // Output clamp per request — a client asking for more gets this much.
    llmMaxOutputTokens: intEnv('LLM_MAX_OUTPUT_TOKENS', 2048),

    // Service-wide monthly token cap (in+out) — the cost-control backstop,
    // same idea as PROVIDER_BUDGETS. Non-zero BY DEFAULT since 2026-08-05
    // (the old default of 0 meant a fresh deployment had no spend ceiling);
    // explicit 0 = uncapped, warned at boot. When spent, /v1/llm answers
    // 503 until the 1st.
    llmBudgetTokens: intEnv('LLM_BUDGET_TOKENS', 250000000),

    // LLM_MOCK=1 swaps the upstream for a canned-response model so the full
    // mint→chat→quota flow can run in dev/tests with no keys.
    llmMock: process.env.LLM_MOCK === '1',

    // ── Retention ───────────────────────────────────────────────────────
    // Feedback is the only user-written text stored, so how long it is kept
    // is a promise, not an implementation detail — state it here and in the
    // README. Analytics counters age out on their own clock (the dashboard
    // never looks past ~90 days, and it's the table abuse can grow).
    // 0 disables either purge.
    feedbackRetentionDays: intEnv('FEEDBACK_RETENTION_DAYS', 365),
    analyticsRetentionDays: intEnv('ANALYTICS_RETENTION_DAYS', 400),
    // Keys that were minted but never authenticated once (sandbox VMs and
    // bots running a downloaded build mint a key and vanish) age out so
    // install counts keep meaning something. Safe for real users: the app
    // self-heals a dead key by re-minting on 401, and upgraded tiers are
    // never purged.
    keyUnusedPurgeDays: intEnv('KEY_UNUSED_PURGE_DAYS', 7),

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
