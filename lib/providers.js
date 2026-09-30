// Upstream search adapters. Each returns [{title, url, snippet, age?}] —
// the exact shape the Anjadhe app already normalizes its BYOK providers
// to — or throws an Error whose message is safe to log (never contains
// the query). `age` is the upstream's freshness hint when it supplies one
// (e.g. "2 days ago" or a published date); the app's Discover pane uses
// it to skip stale stories.
//
// PRIVACY INVARIANT: the query passes through to the upstream and is never
// logged or stored here. Keep it out of every console.* and Error message.
'use strict';

const TIMEOUT_MS = 20000;
const SNIPPET_MAX = 400;
const AGE_MAX = 32;

// Rate-limit headers worth keeping on a refusal. Brave sends
// comma-separated pairs, per-second then per-month ("1, 2000"), so a 429
// with a monthly `remaining` of 0 is the quota, not the pace. Header values
// are numbers from the upstream — never anything derived from the query.
const RATE_HEADERS = ['x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset'];

// A non-2xx answer as an Error carrying `status` (the router counts
// failures by it) and, on a 429, whatever rate-limit headers came back.
function httpError(name, res) {
    let msg = `${name} HTTP ${res.status}`;
    if (res.status === 429) {
        const rl = RATE_HEADERS
            .map(h => [h.slice('x-ratelimit-'.length), res.headers.get(h)])
            .filter(([, v]) => v)
            .map(([k, v]) => `${k} ${String(v).slice(0, 40)}`);
        if (rl.length) msg += ` (${rl.join('; ')})`;
    }
    const e = new Error(msg);
    e.status = res.status;
    return e;
}

// Freshness hint, normalized: absent entirely when the upstream has none.
function age(value) {
    return value ? { age: String(value).slice(0, AGE_MAX) } : {};
}

async function serper(query, maxResults, apiKey) {
    const res = await fetch('https://google.serper.dev/search', {
        method: 'POST',
        headers: { 'X-API-KEY': apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ q: query, num: maxResults }),
        signal: AbortSignal.timeout(TIMEOUT_MS)
    });
    if (!res.ok) throw httpError('serper', res);
    const data = await res.json();
    return (data.organic || []).slice(0, maxResults).map(r => ({
        title: r.title || '',
        url: r.link || '',
        snippet: (r.snippet || '').slice(0, SNIPPET_MAX),
        ...age(r.date)
    }));
}

async function brave(query, maxResults, apiKey) {
    const params = new URLSearchParams({ q: query, count: String(maxResults) });
    const res = await fetch(`https://api.search.brave.com/res/v1/web/search?${params}`, {
        headers: { 'Accept': 'application/json', 'X-Subscription-Token': apiKey },
        signal: AbortSignal.timeout(TIMEOUT_MS)
    });
    if (!res.ok) throw httpError('brave', res);
    const data = await res.json();
    return (data?.web?.results || []).slice(0, maxResults).map(r => ({
        title: r.title || '',
        url: r.url || '',
        snippet: (r.description || '').slice(0, SNIPPET_MAX),
        // Brave's `age` is human-readable ("2 days ago"); page_age is an
        // ISO timestamp fallback.
        ...age(r.age || r.page_age)
    }));
}

async function tavily(query, maxResults, apiKey) {
    const res = await fetch('https://api.tavily.com/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
        // basic depth = 1 credit; advanced costs double and rarely helps for
        // agent snippet consumption.
        body: JSON.stringify({ query, search_depth: 'basic', max_results: maxResults }),
        signal: AbortSignal.timeout(TIMEOUT_MS)
    });
    if (!res.ok) throw httpError('tavily', res);
    const data = await res.json();
    return (data.results || []).slice(0, maxResults).map(r => ({
        title: r.title || '',
        url: r.url || '',
        snippet: (r.content || '').slice(0, SNIPPET_MAX),
        ...age(r.published_date)
    }));
}

// Canned provider for dev/tests (SEARCH_MOCK=1): exercises the whole
// mint→search→quota path without upstream keys or cost.
async function mock(query, maxResults) {
    return Array.from({ length: Math.min(maxResults, 3) }, (_, i) => ({
        title: `Mock result ${i + 1}`,
        url: `https://example.com/${i + 1}`,
        snippet: 'Canned result from the mock provider (SEARCH_MOCK=1).',
        // First result carries an age so the smoke test covers the
        // passthrough shape.
        ...age(i === 0 ? '2 hours ago' : '')
    }));
}

module.exports = { serper, brave, tavily, mock, httpError };
