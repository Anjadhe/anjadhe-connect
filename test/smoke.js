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
        assert.strictEqual(r.body.used, i);
    }

    // fourth hits the monthly quota
    r = await post('/v1/search', { query: 'over quota' }, bearer(key1));
    assert.strictEqual(r.status, 429);
    assert.strictEqual(r.body.code, 'quota');

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

    srv.close();
    console.log('smoke: all assertions passed');
}

main().catch((e) => { console.error(e); process.exit(1); });
