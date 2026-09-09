// Operational alerts, computed on demand from daily counters and provider
// state — nothing here reads or stores request content. Two consumers:
// the /admin dashboard (evaluate() runs on every overview fetch) and an
// optional webhook (checkAndNotify() on a timer, deduped via alert_state so
// a persisting condition re-fires at most every ALERT_RESEND_HOURS).
//
// PRIVACY INVARIANT: alert text contains service-wide numbers only — never
// an install id, IP, or anything a user typed.
'use strict';
const config = require('./config');
const db = require('./db');
const router = require('./router');

// Upstream failure rate only alarms with a real sample behind it.
const FAIL_RATE_MIN_REQUESTS = 20;
const FAIL_RATE_THRESHOLD = 0.2;
// News: topic fetches, not requests; a quiet day still has a few.
const NEWS_FAIL_MIN_TOPICS = 10;
const NEWS_FAIL_THRESHOLD = 0.5;

function evaluate() {
    const alerts = [];

    const providers = router.statusSnapshot();
    if (!providers.length) {
        alerts.push({
            id: 'no-providers', severity: 'critical', title: 'No search providers configured',
            detail: 'Every /v1/search call is failing. Check provider API keys.'
        });
    }
    const usable = providers.filter(p => !p.cooling && !p.overBudget);
    if (providers.length && !usable.length) {
        alerts.push({
            id: 'all-providers-down', severity: 'critical', title: 'All search providers unavailable',
            detail: providers.map(p => `${p.name}: ${p.overBudget ? 'over budget' : 'cooling down'}`).join(', ')
        });
    }
    for (const p of providers) {
        if (p.overBudget) {
            alerts.push({
                id: `budget-spent-${p.name}`, severity: 'critical',
                title: `Provider budget spent: ${p.name}`,
                detail: `${p.used}/${p.budget} queries this month — ${p.name} is out of rotation until the 1st.`
            });
        } else if (p.budget && p.used >= p.budget * 0.8) {
            alerts.push({
                id: `budget-80-${p.name}`, severity: 'warning',
                title: `Provider budget 80% spent: ${p.name}`,
                detail: `${p.used}/${p.budget} queries this month.`
            });
        }
        if (p.cooling) {
            alerts.push({
                id: `cooldown-${p.name}`, severity: 'warning',
                title: `Provider cooling down: ${p.name}`,
                detail: `Repeated failures — retrying after ${p.coolUntil}.`
            });
        }
    }

    const ok = providers.reduce((s, p) => s + db.metricToday(`provider.${p.name}.ok`), 0);
    const fail = providers.reduce((s, p) => s + db.metricToday(`provider.${p.name}.fail`), 0);
    if (ok + fail >= FAIL_RATE_MIN_REQUESTS && fail / (ok + fail) > FAIL_RATE_THRESHOLD) {
        alerts.push({
            id: 'upstream-fail-rate', severity: 'warning', title: 'High upstream failure rate today',
            detail: `${fail} of ${ok + fail} upstream calls failed (${Math.round(100 * fail / (ok + fail))}%).`
        });
    }

    // News upstream (Google News RSS, unmetered). Failures are not cached,
    // so when the upstream refuses the server every topic fails and the
    // rate climbs to 100% within minutes; the kind breakdown says why
    // (http429/http403 = refused, timeout/net = unreachable).
    const newsOk = db.metricToday('news.topic_ok');
    const newsFail = db.metricToday('news.upstream_fail');
    if (newsOk + newsFail >= NEWS_FAIL_MIN_TOPICS && newsFail / (newsOk + newsFail) > NEWS_FAIL_THRESHOLD) {
        const kinds = db.metricsTodayPrefix('news.upstream.')
            .map(r => `${r.name.slice('news.upstream.'.length)} ×${r.n}`).join(', ');
        alerts.push({
            id: 'news-upstream-fail', severity: 'warning', title: 'News upstream failing today',
            detail: `${newsFail} of ${newsOk + newsFail} topic fetches failed (${Math.round(100 * newsFail / (newsOk + newsFail))}%)${kinds ? ' — ' + kinds : ''}. Both upstreams (Google, Bing) refused; Connect users see no fresh headlines until this recovers.`
        });
    }

    const viaBing = db.metricToday('news.via_bing');
    if (viaBing >= NEWS_FAIL_MIN_TOPICS && viaBing >= newsOk * 0.5) {
        alerts.push({
            id: 'news-via-bing', severity: 'info', title: 'News is running on the Bing fallback',
            detail: `${viaBing} of ${newsOk} topic fetches today came from Bing after Google refused — headlines still flow, but Google is not answering this server.`
        });
    }

    // LLM token budget (service-wide monthly cap) — the one number that is
    // real money. Warn at 80%, go critical when /v1/llm starts refusing.
    if (config.llmBudgetTokens) {
        const { tokens } = db.llmPeriodTotals();
        if (tokens >= config.llmBudgetTokens) {
            alerts.push({
                id: 'llm-budget-spent', severity: 'critical', title: 'LLM token budget spent',
                detail: `${tokens.toLocaleString()}/${config.llmBudgetTokens.toLocaleString()} tokens this month — /v1/llm is refusing requests until the 1st.`
            });
        } else if (tokens >= config.llmBudgetTokens * 0.8) {
            alerts.push({
                id: 'llm-budget-80', severity: 'warning', title: 'LLM token budget 80% spent',
                detail: `${tokens.toLocaleString()}/${config.llmBudgetTokens.toLocaleString()} tokens this month.`
            });
        }
    }
    const llmQuotaHits = db.metricToday('llm.quota');
    if (llmQuotaHits > 0) {
        alerts.push({
            id: 'llm-quota-hits', severity: 'info', title: 'Installs hitting their monthly AI quota',
            detail: `${llmQuotaHits} AI requests blocked by quota today — upgrade demand, or one very busy install.`
        });
    }

    const mints = db.metricToday('mint.new') + db.metricToday('mint.rotate');
    if (mints > config.alertMintsPerDay) {
        alerts.push({
            id: 'mint-spike', severity: 'warning', title: 'Key-mint spike today',
            detail: `${mints} mints today (threshold ${config.alertMintsPerDay}) — possible abuse or a client re-mint loop.`
        });
    }
    const mintBlocked = db.metricToday('mint.rate');
    if (mintBlocked > 0) {
        alerts.push({
            id: 'mint-ip-capped', severity: 'info', title: 'Mint requests hit the per-IP cap today',
            detail: `${mintBlocked} mint attempts blocked — someone is minting hard from one address.`
        });
    }

    const quotaHits = db.metricToday('search.quota');
    if (quotaHits > 0) {
        alerts.push({
            id: 'quota-hits', severity: 'info', title: 'Installs hitting their monthly quota',
            detail: `${quotaHits} searches blocked by quota today — upgrade demand, or one very busy agent.`
        });
    }

    return alerts;
}

// Webhook push, deduped: an alert id re-notifies only after alertResendHours.
// info-severity alerts stay dashboard-only.
async function checkAndNotify() {
    if (!config.alertWebhookUrl) return;
    const cutoff = Date.now() - config.alertResendHours * 3600000;
    const due = evaluate().filter((a) => {
        if (a.severity === 'info') return false;
        const last = db.alertLastFired(a.id);
        return !last || Date.parse(last) < cutoff;
    });
    if (!due.length) return;
    const text = due.map(a => `[${a.severity}] ${a.title} — ${a.detail}`).join('\n');
    try {
        await send(`Anjadhe Connect:\n${text}`);
        due.forEach(a => db.markAlertFired(a.id));
    } catch (e) {
        console.error(`[alerts] webhook failed: ${e.message}`);
    }
}

async function send(text) {
    const kind = config.alertWebhookKind;
    const opts = kind === 'ntfy'
        ? { method: 'POST', body: text }
        : {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(kind === 'discord' ? { content: text } : { text })
        };
    const res = await fetch(config.alertWebhookUrl, opts);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
}

module.exports = { evaluate, checkAndNotify };
