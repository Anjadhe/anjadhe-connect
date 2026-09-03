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
// 20 per topic (was 10): the app grew a per-topic drill-in and a headline
// search, and 10 rows starved both. The feed itself carries ~100.
const MAX_ITEMS = 20;

const cache = new Map(); // normalized topic -> { at, items }

function decodeEntities(s) {
    // &amp; decodes LAST: doing it first double-decodes (&amp;lt; -> <),
    // handing clients literal markup in what should be plain titles.
    return String(s || '')
        .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
        .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&apos;/g, "'")
        .replace(/&nbsp;/g, ' ')
        .replace(/&amp;/g, '&')
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
        let url = tag('link');
        // Google: <source url="…">Publisher</source>. Bing: <News:Source>.
        const source = tag('source') || tag('News:Source');
        const pub = Date.parse(tag('pubDate'));
        if (!title || !url) continue;
        // Bing wraps the article in a click-tracking redirect whose `url`
        // parameter is the publisher's page — hand that over instead, so
        // clients get the real article and not a tracker hop.
        const unwrapped = unwrapBingLink(url);
        if (unwrapped) url = unwrapped;
        // Google News titles carry a " - Publisher" suffix duplicating
        // <source>; strip it so clients show source once.
        if (source && title.toLowerCase().endsWith(' - ' + source.toLowerCase())) {
            title = title.slice(0, title.length - source.length - 3).trim();
        }
        // The <source> tag's url attribute is the publisher's site — the
        // item <link> is a news.google.com redirect, so this is the only
        // publisher domain in the feed (the app's favicon avatars).
        const srcM = block.match(/<source\s[^>]*url=(?:"([^"]*)"|'([^']*)')/i);
        let sourceUrl = decodeEntities(srcM ? (srcM[1] || srcM[2]) : '');
        // Bing carries no publisher site; the unwrapped article's origin is.
        if (!sourceUrl && unwrapped) { try { sourceUrl = new URL(unwrapped).origin; } catch { /* leave empty */ } }
        items.push({
            title: title.slice(0, 300),
            url: url.slice(0, 2000),
            source: source.slice(0, 100),
            sourceUrl: /^https?:\/\//i.test(sourceUrl) ? sourceUrl.slice(0, 300) : '',
            publishedAt: Number.isNaN(pub) ? null : new Date(pub).toISOString()
        });
        if (items.length >= MAX_ITEMS) break;
    }
    return items;
}

function unwrapBingLink(url) {
    try {
        const u = new URL(url);
        if (!/(^|\.)bing\.com$/i.test(u.hostname)) return null;
        const target = u.searchParams.get('url');
        return target && /^https?:\/\//i.test(target) ? target : null;
    } catch { return null; }
}

const UPSTREAM_HEADERS = { 'Accept': 'application/rss+xml, application/xml, text/xml', 'User-Agent': 'AnjadheConnect/1.0' };

async function fetchRss(url) {
    const res = await fetch(url, { headers: UPSTREAM_HEADERS, signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (!res.ok) { const e = new Error(`news upstream HTTP ${res.status}`); e.status = res.status; throw e; }
    return parseRss(await res.text());
}

async function fetchTopic(topic) {
    // Canned results for dev/tests — exercises the route without upstream
    // traffic (mirrors the mock search provider).
    if (process.env.SEARCH_MOCK === '1') {
        // '__fail__' exercises the failure path end to end (smoke test).
        if (topic === '__fail__') { const e = new Error('mock upstream'); e.status = 503; throw e; }
        return { upstream: 'google', items: [{
            title: `Mock headline for ${topic}`,
            url: 'https://example.com/news/1',
            source: 'Mock Wire',
            publishedAt: new Date(Date.now() - 2 * 3600 * 1000).toISOString()
        }] };
    }
    // en-US edition for now; locale params can become request fields later.
    // Google first; when it refuses this server (2026-09-03: every topic,
    // all day — a datacenter address it dislikes) Bing's news RSS answers
    // the same query. Resilience lives HERE on purpose: the app never
    // fetches around a Connect failure from the user's own address
    // (docs/DISCOVER.md in the app repo), so a second upstream on the
    // server is what keeps Connect users' headlines flowing. Both fail →
    // Google's error is the one reported (it is the primary).
    const google = new URLSearchParams({ q: topic, hl: 'en-US', gl: 'US', ceid: 'US:en' });
    try {
        return { items: await fetchRss(`https://news.google.com/rss/search?${google}`), upstream: 'google' };
    } catch (primary) {
        const bing = new URLSearchParams({ q: topic, format: 'rss', mkt: 'en-US' });
        try {
            return { items: await fetchRss(`https://www.bing.com/news/search?${bing}`), upstream: 'bing' };
        } catch { throw primary; }
    }
}

// The failure class of an upstream error, for a metric name: 'http429',
// 'http403', 'timeout', 'net'. Status and transport only — the metric is
// service-wide and must never carry the topic that failed. This is what
// lets /admin say WHY news is failing (Google refusing the server's IP
// looks like http429/http403; an outage looks like timeout/net) — before
// 2026-09-03 the route swallowed the error and the dashboard showed a
// healthy news line while every topic came back empty.
function failureKind(err) {
    if (err && Number.isInteger(err.status)) return `http${err.status}`;
    const name = err?.name || '';
    if (name === 'TimeoutError' || name === 'AbortError') return 'timeout';
    return 'net';
}

// → { items, upstream: 'google' | 'bing' | 'cache' }
async function topicNews(topic) {
    const key = String(topic).trim().toLowerCase();
    const hit = cache.get(key);
    if (hit && (Date.now() - hit.at) < CACHE_TTL_MS) return { items: hit.items, upstream: 'cache' };
    const { items, upstream } = await fetchTopic(topic);
    if (cache.size >= CACHE_MAX) cache.clear();
    cache.set(key, { at: Date.now(), items });
    return { items, upstream };
}

module.exports = { topicNews, parseRss, failureKind, unwrapBingLink };
