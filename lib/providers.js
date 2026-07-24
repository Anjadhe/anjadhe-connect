// Upstream search adapters. Each returns [{title, url, snippet}] — the
// exact shape the Anjadhe app already normalizes its BYOK providers to —
// or throws an Error whose message is safe to log (never contains the
// query).
//
// PRIVACY INVARIANT: the query passes through to the upstream and is never
// logged or stored here. Keep it out of every console.* and Error message.
'use strict';

const TIMEOUT_MS = 20000;
const SNIPPET_MAX = 400;

async function serper(query, maxResults, apiKey) {
    const res = await fetch('https://google.serper.dev/search', {
        method: 'POST',
        headers: { 'X-API-KEY': apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ q: query, num: maxResults }),
        signal: AbortSignal.timeout(TIMEOUT_MS)
    });
    if (!res.ok) throw new Error(`serper HTTP ${res.status}`);
    const data = await res.json();
    return (data.organic || []).slice(0, maxResults).map(r => ({
        title: r.title || '',
        url: r.link || '',
        snippet: (r.snippet || '').slice(0, SNIPPET_MAX)
    }));
}

async function brave(query, maxResults, apiKey) {
    const params = new URLSearchParams({ q: query, count: String(maxResults) });
    const res = await fetch(`https://api.search.brave.com/res/v1/web/search?${params}`, {
        headers: { 'Accept': 'application/json', 'X-Subscription-Token': apiKey },
        signal: AbortSignal.timeout(TIMEOUT_MS)
    });
    if (!res.ok) throw new Error(`brave HTTP ${res.status}`);
    const data = await res.json();
    return (data?.web?.results || []).slice(0, maxResults).map(r => ({
        title: r.title || '',
        url: r.url || '',
        snippet: (r.description || '').slice(0, SNIPPET_MAX)
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
    if (!res.ok) throw new Error(`tavily HTTP ${res.status}`);
    const data = await res.json();
    return (data.results || []).slice(0, maxResults).map(r => ({
        title: r.title || '',
        url: r.url || '',
        snippet: (r.content || '').slice(0, SNIPPET_MAX)
    }));
}

// Canned provider for dev/tests (SEARCH_MOCK=1): exercises the whole
// mint→search→quota path without upstream keys or cost.
async function mock(query, maxResults) {
    return Array.from({ length: Math.min(maxResults, 3) }, (_, i) => ({
        title: `Mock result ${i + 1}`,
        url: `https://example.com/${i + 1}`,
        snippet: 'Canned result from the mock provider (SEARCH_MOCK=1).'
    }));
}

module.exports = { serper, brave, tavily, mock };
