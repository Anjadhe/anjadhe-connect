// End-to-end smoke test against the mock provider: mint → search → quota →
// admin upgrade → key rotation. No upstream keys or network needed.
// Run: npm test
'use strict';
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

process.env.SEARCH_MOCK = '1';
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'connect-test-'));
process.env.ADMIN_TOKEN = 'test-admin';
process.env.TIER_QUOTAS = '{"free":3,"plus":5}';

const app = require('../server');
const relay = require('../lib/relay');

async function main() {
    const srv = app.listen(0);
    relay.attach(srv);
    const base = `http://127.0.0.1:${srv.address().port}`;
    const wsBase = `ws://127.0.0.1:${srv.address().port}`;
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
    r = await post('/v1/news', { topics: ['baseball', 'ai'] }, bearer(key1));
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

    // migrate to a UUID-style install id: tier + usage travel, key keeps working
    r = await post('/v1/keys/migrate', { newInstallId: 'no' }, bearer(key2));
    assert.strictEqual(r.status, 400);
    r = await post('/v1/keys/migrate', { newInstallId: 'uuid-1111-2222-3333' }, bearer(key2));
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body.installId, 'uuid-1111-2222-3333');
    r = await get('/v1/usage', bearer(key2));
    assert.strictEqual(r.body.used, 4);   // usage moved with the rename
    assert.strictEqual(r.body.tier, 'plus');
    // the old id is free again; a new install there can't take the migrated one
    r = await post('/v1/keys', { installId: 'test-install-0001' });
    assert.strictEqual(r.body.rotated, false);
    assert.strictEqual(r.body.tier, 'free');
    const key3 = r.body.apiKey;
    r = await post('/v1/keys/migrate', { newInstallId: 'uuid-1111-2222-3333' }, bearer(key3));
    assert.strictEqual(r.status, 409);

    // ── app analytics: keyless, vocabulary-bound, aggregated on ingest ──
    r = await post('/v1/analytics/events', { installId: 'no', events: [] });
    assert.strictEqual(r.status, 400);
    const now = Date.now();
    const fiveDaysAgo = now - 5 * 86400000;
    r = await post('/v1/analytics/events', {
        installId: 'analytics-uuid-0001',
        generatedAt: now,
        events: [
            { name: 'app.opened', ts: now, props: { app: 'email' } },
            { name: 'app.opened', ts: now, props: { app: 'email' } },
            { name: 'app.opened', ts: fiveDaysAgo, props: { app: 'notes' } },
            { name: 'agent.query.sent', ts: now, props: { model: 'qwen3:14b', junk: 'dropped' } },
            { name: 'schedule.task_completed', ts: now - 400 * 86400000 },  // ancient ts → today
            { name: 'not.in.vocabulary', ts: now },                          // dropped
            { name: 'app.opened', ts: now, props: { app: 'x|y&z' } }         // value sanitized
        ]
    });
    assert.strictEqual(r.status, 200, JSON.stringify(r.body));
    assert.strictEqual(r.body.accepted, 6);
    assert.strictEqual(r.body.dropped, 1);

    r = await get('/v1/admin/overview?days=7', { 'x-admin-token': 'test-admin' });
    const an = r.body.analytics;
    assert.strictEqual(an.daily.reduce((s, d) => s + d.n, 0), 6);
    assert.strictEqual(an.daily.length, 2); // today + the 5-days-ago bucket
    const top = Object.fromEntries(an.top.map(t => [t.name, t.n]));
    assert.strictEqual(top['app.opened|app=email'], 2);
    assert.strictEqual(top['app.opened|app=notes'], 1);
    assert.strictEqual(top['agent.query.sent|model=qwen3:14b'], 1); // junk prop dropped
    assert.strictEqual(top['schedule.task_completed'], 1);
    assert.strictEqual(top['app.opened|app=x_y_z'], 1);
    assert.ok(!('not.in.vocabulary' in top));
    assert.strictEqual(an.actives.today, 1);

    // CORS preflight (the app posts from the Electron renderer)
    const pre = await fetch(base + '/v1/analytics/events', { method: 'OPTIONS' });
    assert.strictEqual(pre.status, 204);
    assert.strictEqual(pre.headers.get('access-control-allow-origin'), '*');

    // observability: daily counters, actives, provider status, alerts —
    // all aggregate, nothing per-request
    r = await get('/v1/admin/overview?days=7', { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.status, 200);
    const m = {};
    for (const row of r.body.metrics) m[row.name] = (m[row.name] || 0) + row.n;
    assert.strictEqual(m['search.ok'], 4);
    assert.strictEqual(m['search.quota'], 1);
    assert.strictEqual(m['mint.new'], 2);    // original + re-mint of the vacated id
    assert.strictEqual(m['mint.rotate'], 1);
    assert.strictEqual(m['mint.migrate'], 1);
    assert.ok(m['auth.fail'] >= 2); // bad key + rotated-away key
    assert.strictEqual(m['provider.mock.ok'], 4);
    assert.ok(m['search.ms.lt500'] >= 1);
    assert.strictEqual(r.body.actives.today, 2);
    assert.strictEqual(r.body.providers[0].name, 'mock');
    assert.strictEqual(r.body.providers[0].used, 4);
    // install ids at rest are SHA-256 hashes of what the client sent — the
    // raw id (a hostname on legacy installs) is never stored or exposed
    assert.strictEqual(r.body.installs[0].install_id, sha('uuid-1111-2222-3333'));
    assert.strictEqual(r.body.installs[0].used, 4);
    for (const k of r.body.installs) {
        assert.match(k.install_id, /^[0-9a-f]{64}$/);
        assert.ok(!('mint_ip' in k));
    }
    assert.ok(r.body.alerts.some(a => a.id === 'quota-hits'));
    // alert text carries service-wide numbers only — never an install id or IP
    for (const a of r.body.alerts) {
        assert.ok(!JSON.stringify(a).includes('test-install-0001'));
    }

    // admin tier accepts the stored hash (what the dashboard sends) as well
    // as the raw id (tested earlier)
    r = await post('/v1/admin/tier', { installId: sha('uuid-1111-2222-3333'), tier: 'free' }, { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.status, 200);
    r = await get('/v1/usage', bearer(key2));
    assert.strictEqual(r.body.tier, 'free');

    // ── relay: hello/welcome, bidirectional forwarding, host-state ──────
    // Plain HTTP on the relay path is a client mistake
    r = await fetch(base + '/v1/relay/some-routing-id').then(j);
    assert.strictEqual(r.status, 426);

    // Every message is queued as it arrives, so asserts can't race the relay.
    const wsOpen = (path) => new Promise((res, rej) => {
        const ws = new WebSocket(wsBase + path);
        ws.inbox = [];
        ws.waiters = [];
        ws.addEventListener('message', (ev) => {
            const msg = JSON.parse(ev.data);
            const w = ws.waiters.shift();
            if (w) w(msg); else ws.inbox.push(msg);
        });
        ws.addEventListener('open', () => res(ws));
        ws.addEventListener('error', () => rej(new Error('ws connect failed: ' + path)));
    });
    const recv = (ws) => ws.inbox.length
        ? Promise.resolve(ws.inbox.shift())
        : new Promise((res, rej) => {
            ws.waiters.push(res);
            setTimeout(() => rej(new Error('relay recv timeout')), 5000).unref();
        });
    const ROUTING = 'smoke-routing-id';

    const host = await wsOpen('/v1/relay/' + ROUTING);
    host.send(JSON.stringify({ t: 'hello', routingId: ROUTING, role: 'host' }));
    assert.strictEqual((await recv(host)).t, 'welcome');

    const phone = await wsOpen('/v1/relay/' + ROUTING);
    phone.send(JSON.stringify({ t: 'hello', routingId: ROUTING, role: 'client' }));
    const welcome = await recv(phone);
    assert.strictEqual(welcome.t, 'welcome');
    assert.match(welcome.clientId, /^[0-9a-f]{16}$/);
    assert.deepStrictEqual(await recv(phone), { t: 'host-state', online: true });
    assert.deepStrictEqual(await recv(host), { t: 'peer-join', clientId: welcome.clientId });

    // phone -> host carries from; host -> phone routes by clientId
    phone.send(JSON.stringify({ t: 'data', payload: 'deadbeef' }));
    assert.deepStrictEqual(await recv(host), { t: 'data', from: welcome.clientId, payload: 'deadbeef' });
    host.send(JSON.stringify({ t: 'data', to: welcome.clientId, payload: 'cafef00d' }));
    assert.deepStrictEqual(await recv(phone), { t: 'data', payload: 'cafef00d' });

    // a big-but-legal frame (chunk-sized) forwards intact
    const bigPayload = 'ab'.repeat(450_000); // 900k chars, under the 1 MiB frame cap
    host.send(JSON.stringify({ t: 'data', to: welcome.clientId, payload: bigPayload }));
    assert.strictEqual((await recv(phone)).payload, bigPayload);

    // host drop notifies the phone
    host.close();
    assert.deepStrictEqual(await recv(phone), { t: 'host-state', online: false });
    phone.close();

    // bad hello is rejected
    const bad = await wsOpen('/v1/relay/x');
    bad.send(JSON.stringify({ t: 'hello', routingId: 'x', role: 'admin' }));
    assert.strictEqual((await recv(bad)).t, 'error');
    bad.close();

    // non-relay upgrade path is refused
    await assert.rejects(wsOpen('/v1/search'));

    // relay observability: live gauges + daily counters in the overview
    r = await get('/v1/admin/overview?days=7', { 'x-admin-token': 'test-admin' });
    for (const k of ['rooms', 'hosts', 'clients']) assert.strictEqual(typeof r.body.relay[k], 'number');
    const rm = {};
    for (const row of r.body.metrics) rm[row.name] = (rm[row.name] || 0) + row.n;
    assert.strictEqual(rm['relay.connect.host'], 1);
    assert.strictEqual(rm['relay.connect.client'], 1);
    assert.strictEqual(rm['relay.frames'], 3); // deadbeef + cafef00d + the big one
    assert.strictEqual(rm['relay.reject.hello'], 1);

    // the dashboard shell is served (data-free — auth happens per fetch)
    const page = await fetch(base + '/admin');
    assert.strictEqual(page.status, 200);
    assert.ok((await page.text()).includes('Anjadhe Connect'));

    srv.close();
    console.log('smoke: all assertions passed');
}

main().catch((e) => { console.error(e); process.exit(1); });
