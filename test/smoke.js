// End-to-end smoke test against the mock provider: mint → search → quota →
// admin upgrade → key rotation. No upstream keys or network needed.
// Run: npm test
'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.SEARCH_MOCK = '1';
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'connect-test-'));
process.env.ADMIN_TOKEN = 'test-admin';
process.env.TIER_QUOTAS = '{"free":3,"plus":5}';

const app = require('../server');

async function main() {
    const srv = app.listen(0);
    const base = `http://127.0.0.1:${srv.address().port}`;
    const j = async (res) => ({ status: res.status, body: await res.json() });
    const post = (p, body, headers = {}) => fetch(base + p, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body: JSON.stringify(body)
    }).then(j);
    const get = (p, headers = {}) => fetch(base + p, { headers }).then(j);

    // health
    let r = await get('/healthz');
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(r.body.providers, ['mock']);

    // mint rejects bad install ids
    r = await post('/v1/keys', { installId: 'no' });
    assert.strictEqual(r.status, 400);

    // mint
    r = await post('/v1/keys', { installId: 'test-install-0001' });
    assert.strictEqual(r.status, 200);
    assert.match(r.body.apiKey, /^anck_[a-f0-9]{48}$/);
    assert.strictEqual(r.body.tier, 'free');
    assert.strictEqual(r.body.monthlyQuota, 3);
    const key1 = r.body.apiKey;
    const bearer = (k) => ({ Authorization: `Bearer ${k}` });

    // bad key rejected
    r = await post('/v1/search', { query: 'x' }, bearer('anck_' + '0'.repeat(48)));
    assert.strictEqual(r.status, 401);

    // three searches succeed (free quota = 3)
    for (let i = 1; i <= 3; i++) {
        r = await post('/v1/search', { query: 'hello world', maxResults: 2 }, bearer(key1));
        assert.strictEqual(r.status, 200, JSON.stringify(r.body));
        assert.strictEqual(r.body.provider, 'anjadhe');
        assert.strictEqual(r.body.upstream, 'mock');
        assert.ok(Array.isArray(r.body.results) && r.body.results.length > 0);
        assert.ok(r.body.results[0].title && r.body.results[0].url);
        // Freshness hint passes through when the upstream supplies one
        // (and stays absent when it doesn't).
        assert.strictEqual(r.body.results[0].age, '2 hours ago');
        assert.ok(!('age' in r.body.results[1]));
        assert.strictEqual(r.body.used, i);
    }

    // fourth hits the monthly quota
    r = await post('/v1/search', { query: 'over quota' }, bearer(key1));
    assert.strictEqual(r.status, 429);
    assert.strictEqual(r.body.code, 'quota');

    // news is unmetered: works even at search quota, and leaves usage alone
    r = await post('/v1/news', { topics: ['cricket', 'ai'] }, bearer(key1));
    assert.strictEqual(r.status, 200, JSON.stringify(r.body));
    assert.strictEqual(r.body.topics.length, 2);
    const item = r.body.topics[0].items[0];
    assert.ok(item.title && item.url && item.source && item.publishedAt);
    r = await get('/v1/usage', bearer(key1));
    assert.strictEqual(r.body.used, 3);

    // news requires topics and auth
    r = await post('/v1/news', { topics: [] }, bearer(key1));
    assert.strictEqual(r.status, 400);
    r = await post('/v1/news', { topics: ['x'] });
    assert.strictEqual(r.status, 401);

    // RSS parser: entity decode, source-suffix strip, pubDate -> ISO
    const { parseRss } = require('../lib/news');
    const parsed = parseRss(`<rss><channel>
        <item><title>Rains hit city &amp; suburbs - The Daily</title>
        <link>https://d.example/a</link>
        <pubDate>Sun, 27 Jul 2026 08:00:00 GMT</pubDate>
        <source url="https://d.example">The Daily</source></item>
        <item><title><![CDATA[Second story]]></title><link>https://d.example/b</link></item>
    </channel></rss>`);
    assert.strictEqual(parsed[0].title, 'Rains hit city & suburbs');
    assert.strictEqual(parsed[0].source, 'The Daily');
    assert.ok(parsed[0].publishedAt.startsWith('2026-07-27'));
    assert.strictEqual(parsed[1].title, 'Second story');
    assert.strictEqual(parsed[1].publishedAt, null);

    // usage reflects it
    r = await get('/v1/usage', bearer(key1));
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body.used, 3);
    assert.strictEqual(r.body.quota, 3);

    // admin upgrade to plus (quota 5) unblocks
    r = await post('/v1/admin/tier', { installId: 'test-install-0001', tier: 'plus' }, { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.status, 200);
    r = await post('/v1/search', { query: 'post upgrade' }, bearer(key1));
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body.quota, 5);

    // admin auth enforced
    r = await post('/v1/admin/tier', { installId: 'test-install-0001', tier: 'pro' }, { 'x-admin-token': 'wrong' });
    assert.strictEqual(r.status, 401);

    // re-mint rotates the key but preserves usage and tier
    r = await post('/v1/keys', { installId: 'test-install-0001' });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body.rotated, true);
    assert.strictEqual(r.body.tier, 'plus');
    const key2 = r.body.apiKey;
    r = await post('/v1/search', { query: 'old key' }, bearer(key1));
    assert.strictEqual(r.status, 401);
    r = await get('/v1/usage', bearer(key2));
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body.used, 4); // rotation did not reset the counter

    // stats
    r = await get('/v1/admin/stats', { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body.keys, 1);
    assert.strictEqual(r.body.searchesThisPeriod, 4);

    // observability: daily counters, actives, provider status, alerts —
    // all aggregate, nothing per-request
    r = await get('/v1/admin/overview?days=7', { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.status, 200);
    const m = {};
    for (const row of r.body.metrics) m[row.name] = (m[row.name] || 0) + row.n;
    assert.strictEqual(m['search.ok'], 4);
    assert.strictEqual(m['search.quota'], 1);
    assert.strictEqual(m['mint.new'], 1);
    assert.strictEqual(m['mint.rotate'], 1);
    assert.ok(m['auth.fail'] >= 2); // bad key + rotated-away key
    assert.strictEqual(m['provider.mock.ok'], 4);
    assert.ok(m['search.ms.lt500'] >= 1);
    assert.strictEqual(r.body.actives.today, 1);
    assert.strictEqual(r.body.providers[0].name, 'mock');
    assert.strictEqual(r.body.providers[0].used, 4);
    assert.strictEqual(r.body.installs[0].install_id, 'test-install-0001');
    assert.strictEqual(r.body.installs[0].used, 4);
    assert.ok(r.body.alerts.some(a => a.id === 'quota-hits'));
    // alert text carries service-wide numbers only — never an install id or IP
    for (const a of r.body.alerts) {
        assert.ok(!JSON.stringify(a).includes('test-install-0001'));
    }

    // the dashboard shell is served (data-free — auth happens per fetch)
    const page = await fetch(base + '/admin');
    assert.strictEqual(page.status, 200);
    assert.ok((await page.text()).includes('Anjadhe Connect'));

    srv.close();
    console.log('smoke: all assertions passed');
}

main().catch((e) => { console.error(e); process.exit(1); });
