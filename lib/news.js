// /v1/news upstream: headlines per topic from the SOURCES the app asked
// for — Google News RSS (the default), Bing News RSS, Hacker News (the
// Algolia search API) — parsed and cached in process memory. News is
// cheap (one upstream fetch serves every user who follows the same topic
// on the same source within the cache window), so it is NOT metered
// against the search quota.
//
// This is the twin of the app's js/main/news-sources.js: same source ids,
// same item shape, same per-source cap. A source added here is added
// there in the same change.
//
// PRIVACY INVARIANT (same rule as search): topic text is never logged and
// never stored. Keep it out of every console.* and Error message. The
// in-memory cache keys are topics — process memory only, gone on restart,
// never written to disk.
'use strict';

const TIMEOUT_MS = 15000;
const CACHE_TTL_MS = 10 * 60 * 1000; // shared per-topic window (k-anonymity)
const CACHE_MAX = 5000;              // runaway guard, ~a few MB worst case
// 20 per SOURCE per topic (was 10): the app grew a per-topic drill-in and
// a headline search, and 10 rows starved both. The feed itself carries ~100.
const MAX_ITEMS = 20;
const HN_WINDOW_S = 48 * 60 * 60;    // the app's 48h story age, in seconds
// A story needs some traction before it is news: the feed sorts by date,
// and without a floor the newest rows were 1-point submissions nobody had
// read yet (seen 2026-09-10 on the first live run).
const HN_MIN_POINTS = 10;

const cache = new Map(); // `${source}:${normalized topic}` -> { at, items }

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

// Hacker News via the Algolia search API (JSON). A story's `url` is the
// article on its own site, so the PUBLISHER is that site's host and the
// HN thread rides separately as `discussionUrl`. A story with no link
// (Ask HN, Show HN text posts) IS its thread. `points` is community data,
// passed through as-is.
function hnItems(json) {
    let data = json;
    if (typeof json === 'string') {
        try { data = JSON.parse(json); } catch { return []; }
    }
    const hits = Array.isArray(data?.hits) ? data.hits : [];
    const items = [];
    for (const h of hits) {
        const id = String(h?.objectID || '');
        const title = String(h?.title || '').trim();
        if (!title || !/^\d{1,12}$/.test(id)) continue;
        const thread = `https://news.ycombinator.com/item?id=${id}`;
        const link = typeof h.url === 'string' && /^https?:\/\//i.test(h.url) ? h.url.trim() : '';
        let host = '';
        let origin = '';
        if (link) {
            try { const u = new URL(link); host = u.hostname.replace(/^www\./i, ''); origin = u.origin; }
            catch { /* unparsable link: fall through to the thread */ }
        }
        const pub = Date.parse(h.created_at || '');
        const points = Number(h.points);
        items.push({
            title: title.slice(0, 300),
            url: (host ? link : thread).slice(0, 2000),
            source: (host || 'Hacker News').slice(0, 100),
            sourceUrl: (host ? origin : 'https://news.ycombinator.com').slice(0, 300),
            publishedAt: Number.isNaN(pub) ? null : new Date(pub).toISOString(),
            discussionUrl: thread,
            ...(Number.isFinite(points) ? { points: Math.max(0, Math.round(points)) } : {})
        });
        if (items.length >= MAX_ITEMS) break;
    }
    return items;
}

// The source registry. Ids are the public contract (the app's settings
// carry them); `url` builds the one upstream request, `parse` reads it.
const SOURCES = [
    {
        id: 'google',
        url: (topic) => 'https://news.google.com/rss/search?'
            + new URLSearchParams({ q: topic, hl: 'en-US', gl: 'US', ceid: 'US:en' }),
        parse: parseRss
    },
    {
        id: 'bing',
        url: (topic) => 'https://www.bing.com/news/search?'
            + new URLSearchParams({ q: topic, format: 'rss', mkt: 'en-US' }),
        parse: parseRss
    },
    {
        id: 'hn',
        url: (topic, now = Date.now()) => 'https://hn.algolia.com/api/v1/search?'
            + new URLSearchParams({
                query: topic, tags: 'story', hitsPerPage: String(MAX_ITEMS),
                numericFilters: `created_at_i>${Math.floor(now / 1000) - HN_WINDOW_S},points>=${HN_MIN_POINTS}`
            }),
        parse: hnItems
    }
];
const SOURCE_IDS = SOURCES.map(s => s.id);
const DEFAULT_SOURCES = ['google'];

// The allowlist gate: unknown ids drop, duplicates fold, registry order,
// and nothing picked means Google News (every pre-sources client).
function normalizeSources(list) {
    const want = new Set((Array.isArray(list) ? list : [])
        .map(x => String(x || '').trim().toLowerCase())
        .filter(x => SOURCE_IDS.includes(x)));
    const out = SOURCE_IDS.filter(id => want.has(id));
    return out.length ? out : DEFAULT_SOURCES.slice();
}

const UPSTREAM_HEADERS = { 'Accept': 'application/rss+xml, application/xml, text/xml, application/json', 'User-Agent': 'AnjadheConnect/1.0' };

async function fetchUpstream(url, parse) {
    const res = await fetch(url, { headers: UPSTREAM_HEADERS, signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (!res.ok) { const e = new Error(`news upstream HTTP ${res.status}`); e.status = res.status; throw e; }
    return parse(await res.text());
}

// One topic from one source → { items, upstream }, where `upstream` names
// what actually answered: the source id, or 'bing-fallback' when Google
// refused and Bing carried it.
async function fetchTopic(topic, sourceId) {
    // Canned results for dev/tests — exercises the route without upstream
    // traffic (mirrors the mock search provider).
    if (process.env.SEARCH_MOCK === '1') {
        // '__fail__' exercises the failure path end to end (smoke test).
        if (topic === '__fail__') { const e = new Error('mock upstream'); e.status = 503; throw e; }
        const base = {
            title: `Mock ${sourceId} headline for ${topic}`,
            url: `https://example.com/news/${sourceId}/1`,
            source: 'Mock Wire',
            sourceUrl: 'https://example.com',
            publishedAt: new Date(Date.now() - 2 * 3600 * 1000).toISOString()
        };
        if (sourceId === 'hn') Object.assign(base, { source: 'example.com', discussionUrl: 'https://news.ycombinator.com/item?id=1', points: 42 });
        return { upstream: sourceId, items: [base] };
    }
    const src = SOURCES.find(s => s.id === sourceId);
    if (!src) { const e = new Error('unknown news source'); e.status = 400; throw e; }
    // en-US edition for now; locale params can become request fields later.
    try {
        return { items: await fetchUpstream(src.url(topic), src.parse), upstream: sourceId };
    } catch (primary) {
        // Google first; when it refuses this server (2026-09-03: every
        // topic, all day — a datacenter address it dislikes) Bing's news
        // RSS answers the same query. Resilience lives HERE on purpose: the
        // app never fetches around a Connect failure from the user's own
        // address (docs/DISCOVER.md in the app repo), so a second upstream
        // on the server is what keeps Connect users' headlines flowing.
        // Both fail → Google's error is the one reported (it is the primary).
        if (sourceId !== 'google') throw primary;
        const bing = SOURCES.find(s => s.id === 'bing');
        try {
            return { items: await fetchUpstream(bing.url(topic), bing.parse), upstream: 'bing-fallback' };
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

async function sourceNews(topic, sourceId) {
    const key = `${sourceId}:${String(topic).trim().toLowerCase()}`;
    const hit = cache.get(key);
    if (hit && (Date.now() - hit.at) < CACHE_TTL_MS) return { items: hit.items, upstream: 'cache' };
    const { items, upstream } = await fetchTopic(topic, sourceId);
    if (cache.size >= CACHE_MAX) cache.clear();
    cache.set(key, { at: Date.now(), items });
    return { items, upstream };
}

/**
 * One topic across the picked sources → { items, served, failed }.
 * `items` are every source's rows stamped `via`, newest first; `served`
 * lists [{ source, upstream }] for what answered (upstream: the source
 * id, 'bing-fallback', or 'cache'); `failed` the sources that did not.
 * Throws only when EVERY source failed — with the first source's error,
 * so the failure kind counted is the primary's — because a topic with
 * Google down and Hacker News up still has headlines to show.
 */
async function topicNews(topic, sources = DEFAULT_SOURCES) {
    const picked = normalizeSources(sources);
    const results = await Promise.all(picked.map(async (source) => {
        try { const r = await sourceNews(topic, source); return { source, ...r }; }
        catch (err) { return { source, err }; }
    }));
    const ok = results.filter(r => !r.err);
    if (!ok.length) throw results[0].err;
    const when = (it) => { const t = Date.parse(it?.publishedAt || ''); return Number.isNaN(t) ? 0 : t; };
    const items = ok.flatMap(r => r.items.map(it => ({ ...it, via: r.source })))
        .sort((a, b) => when(b) - when(a));
    return {
        items,
        served: ok.map(r => ({ source: r.source, upstream: r.upstream })),
        failed: results.filter(r => r.err).map(r => r.source)
    };
}

module.exports = { topicNews, parseRss, hnItems, failureKind, unwrapBingLink, normalizeSources, SOURCE_IDS, DEFAULT_SOURCES, MAX_ITEMS };
