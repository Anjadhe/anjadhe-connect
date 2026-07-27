// /v1/news upstream: Google News RSS per topic, parsed and cached in
// process memory. News is cheap (one upstream fetch serves every user who
// follows the same topic within the cache window), so it is NOT metered
// against the search quota.
//
// PRIVACY INVARIANT (same rule as search): topic text is never logged and
// never stored. Keep it out of every console.* and Error message. The
// in-memory cache keys are topics — process memory only, gone on restart,
// never written to disk.
'use strict';

const TIMEOUT_MS = 15000;
const CACHE_TTL_MS = 10 * 60 * 1000; // shared per-topic window (k-anonymity)
const CACHE_MAX = 5000;              // runaway guard, ~a few MB worst case
const MAX_ITEMS = 10;

const cache = new Map(); // normalized topic -> { at, items }

function decodeEntities(s) {
    return String(s || '')
        .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
        .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&apos;/g, "'")
        .replace(/&nbsp;/g, ' ')
        .trim();
}

// Minimal RSS <item> parser — Google/Bing news feeds are regular enough
// that a dependency isn't warranted in a repo kept lean for auditability.
function parseRss(xml) {
    const items = [];
    const blocks = String(xml || '').split(/<item(?:\s[^>]*)?>/).slice(1);
    for (const b of blocks) {
        const end = b.indexOf('</item>');
        const block = end === -1 ? b : b.slice(0, end);
        const tag = (name) => {
            const m = block.match(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, 'i'));
            return m ? decodeEntities(m[1]) : '';
        };
        let title = tag('title');
        const url = tag('link');
        const source = tag('source');
        const pub = Date.parse(tag('pubDate'));
        if (!title || !url) continue;
        // Google News titles carry a " - Publisher" suffix duplicating
        // <source>; strip it so clients show source once.
        if (source && title.toLowerCase().endsWith(' - ' + source.toLowerCase())) {
            title = title.slice(0, title.length - source.length - 3).trim();
        }
        items.push({
            title: title.slice(0, 300),
            url: url.slice(0, 2000),
            source: source.slice(0, 100),
            publishedAt: Number.isNaN(pub) ? null : new Date(pub).toISOString()
        });
        if (items.length >= MAX_ITEMS) break;
    }
    return items;
}

async function fetchTopic(topic) {
    // Canned results for dev/tests — exercises the route without upstream
    // traffic (mirrors the mock search provider).
    if (process.env.SEARCH_MOCK === '1') {
        return [{
            title: `Mock headline for ${topic}`,
            url: 'https://example.com/news/1',
            source: 'Mock Wire',
            publishedAt: new Date(Date.now() - 2 * 3600 * 1000).toISOString()
        }];
    }
    // en-US edition for now; locale params can become request fields later.
    const params = new URLSearchParams({ q: topic, hl: 'en-US', gl: 'US', ceid: 'US:en' });
    const res = await fetch(`https://news.google.com/rss/search?${params}`, {
        headers: { 'Accept': 'application/rss+xml, application/xml, text/xml', 'User-Agent': 'AnjadheConnect/1.0' },
        signal: AbortSignal.timeout(TIMEOUT_MS)
    });
    if (!res.ok) throw new Error(`news upstream HTTP ${res.status}`);
    return parseRss(await res.text());
}

async function topicNews(topic) {
    const key = String(topic).trim().toLowerCase();
    const hit = cache.get(key);
    if (hit && (Date.now() - hit.at) < CACHE_TTL_MS) return hit.items;
    const items = await fetchTopic(topic);
    if (cache.size >= CACHE_MAX) cache.clear();
    cache.set(key, { at: Date.now(), items });
    return items;
}

module.exports = { topicNews, parseRss };
