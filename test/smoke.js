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
process.env.LLM_MOCK = '1'; // every mock chat call: 10 tokens in, 5 out
// Seeds the llm_models table on first boot (the table is the source of
// truth; this env is inert after the seed) — asserted below.
process.env.LLM_MODELS = '{"anjadhe-cloud":{"upstream":"google/gemma-3-27b-it","label":"Anjadhe Cloud","description":"Fast all-rounder"}}';
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'connect-test-'));
process.env.ADMIN_TOKEN = 'test-admin';
process.env.TIER_QUOTAS = '{"free":3,"plus":5}';
process.env.LLM_TIER_QUOTAS = '{"free":{"requests":2,"tokens":1000},"plus":{"requests":50,"tokens":1000}}';
process.env.LLM_BUDGET_TOKENS = '60'; // trips after the 4th mock call (4 × 15)
process.env.PROVIDER_PACE_MS = '{"mock":150}';

const app = require('../server');
const relay = require('../lib/relay');
const db = require('../lib/db'); // same process, same SQLite handle — for day() in assertions

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

    // re-minting a known install id is refused — knowing an id must never be
    // enough to revoke the owner's key (legacy hostname ids are guessable)
    r = await post('/v1/keys', { installId: 'test-install-0001' });
    assert.strictEqual(r.status, 409);
    assert.strictEqual(r.body.code, 'already-registered');
    r = await get('/v1/usage', bearer(key1));
    assert.strictEqual(r.status, 200); // owner's key untouched by the attempt

    // rotation requires the current key, preserves usage and tier
    r = await post('/v1/keys/rotate', {}, bearer(key1));
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
            { name: 'model.added', ts: now, props: { engine: 'anjadhe', source: 'wizard' } },
            { name: 'schedule.task_completed', ts: now - 400 * 86400000 },  // ancient ts → today
            { name: 'not.in.vocabulary', ts: now },                          // dropped
            { name: 'app.opened', ts: now, props: { app: 'x|y&z' } }         // value sanitized
        ]
    });
    assert.strictEqual(r.status, 200, JSON.stringify(r.body));
    assert.strictEqual(r.body.accepted, 7);
    assert.strictEqual(r.body.dropped, 1);

    r = await get('/v1/admin/overview?days=7', { 'x-admin-token': 'test-admin' });
    const an = r.body.analytics;
    assert.strictEqual(an.daily.reduce((s, d) => s + d.n, 0), 7);
    assert.strictEqual(an.daily.length, 2); // today + the 5-days-ago bucket
    const top = Object.fromEntries(an.top.map(t => [t.name, t.n]));
    assert.strictEqual(top['app.opened|app=email'], 2);
    assert.strictEqual(top['app.opened|app=notes'], 1);
    assert.strictEqual(top['agent.query.sent|model=qwen3:14b'], 1); // junk prop dropped
    assert.strictEqual(top['model.added|engine=anjadhe|source=wizard'], 1);
    assert.strictEqual(top['schedule.task_completed'], 1);
    assert.strictEqual(top['app.opened|app=x_y_z'], 1);
    assert.ok(!('not.in.vocabulary' in top));
    assert.strictEqual(an.actives.today, 1);

    // a second machine, so the per-install grid has something to separate
    r = await post('/v1/analytics/events', {
        installId: 'analytics-uuid-0002',
        events: [{ name: 'journal.entry_written', ts: now }]
    });
    assert.strictEqual(r.body.accepted, 1);

    // per-install slice: busiest first, per-day cells, own id space
    r = await get('/v1/admin/analytics?days=7', { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.status, 200);
    const grid = r.body.installs;
    assert.strictEqual(grid.length, 2);
    assert.strictEqual(grid[0].installId, sha('analytics-uuid-0001'));
    assert.strictEqual(grid[0].total, 7);
    assert.strictEqual(grid[0].activeDays, 2);
    assert.strictEqual(grid[0].byDay[db.day()], 6);              // 6 today, 1 five days back
    assert.strictEqual(grid[0].byDay[db.daysAgo(5)], 1);
    assert.strictEqual(grid[1].total, 1);
    // analytics ids are their own id space — never a Connect install id
    const conn = await get('/v1/admin/installs', { 'x-admin-token': 'test-admin' });
    const connectIds = new Set(conn.body.installs.map(k => k.install_id));
    for (const g of grid) {
        assert.match(g.installId, /^[0-9a-f]{64}$/);
        assert.ok(!connectIds.has(g.installId));
    }

    // drill-down: one install's counters by day and event name
    r = await get('/v1/admin/analytics/install?id=' + sha('analytics-uuid-0001') + '&days=7',
        { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body.total, 7);
    assert.strictEqual(r.body.events.length, 6);                 // 6 distinct counters
    assert.strictEqual(r.body.events[0].day, db.day());           // newest day first
    assert.ok(r.body.events.some(e => e.name === 'app.opened|app=notes' && e.n === 1));
    // a raw (unhashed) id is not a lookup key here — nothing raw is at rest
    r = await get('/v1/admin/analytics/install?id=analytics-uuid-0001&days=7', { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.status, 400);
    r = await get('/v1/admin/analytics?days=7', { 'x-admin-token': 'wrong' });
    assert.strictEqual(r.status, 401);

    // CORS preflight. The app posts from the Electron renderer, which loads
    // over file:// and so sends Origin: null — that is granted. Any other
    // browser origin gets NO allow-origin header, so a random website can't
    // make its visitors write here (these bodies are JSON, hence preflighted).
    const pre = await fetch(base + '/v1/analytics/events', {
        method: 'OPTIONS', headers: { Origin: 'null' }
    });
    assert.strictEqual(pre.status, 204);
    assert.strictEqual(pre.headers.get('access-control-allow-origin'), 'null');

    const evil = await fetch(base + '/v1/analytics/events', {
        method: 'OPTIONS', headers: { Origin: 'https://evil.example' }
    });
    assert.strictEqual(evil.headers.get('access-control-allow-origin'), null);

    // A native client sends no Origin at all — CORS never applies to it, so
    // the absence of the header must not stop the request itself.
    const native = await post('/v1/analytics/events',
        { installId: 'analytics-uuid-0001', events: [] });
    assert.strictEqual(native.status, 200);

    // observability: daily counters, actives, provider status, alerts —
    // all aggregate, nothing per-request
    r = await get('/v1/admin/overview?days=7', { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.status, 200);
    const m = {};
    for (const row of r.body.metrics) m[row.name] = (m[row.name] || 0) + row.n;
    assert.strictEqual(m['search.ok'], 4);
    assert.strictEqual(m['search.quota'], 1);
    assert.strictEqual(m['mint.new'], 2);    // original + mint of the vacated id
    assert.strictEqual(m['mint.rotate'], 1);
    assert.strictEqual(m['mint.blocked'], 1); // the refused known-id re-mint
    assert.strictEqual(m['mint.migrate'], 1);
    assert.ok(m['auth.fail'] >= 2); // bad key + rotated-away key
    assert.strictEqual(m['provider.mock.ok'], 4);
    assert.ok(m['search.ms.lt500'] >= 1);
    assert.strictEqual(r.body.actives.today, 2);
    assert.strictEqual(r.body.providers[0].name, 'mock');
    assert.strictEqual(r.body.providers[0].used, 4);
    assert.ok(r.body.alerts.some(a => a.id === 'quota-hits'));
    // alert text carries service-wide numbers only — never an install id or IP
    for (const a of r.body.alerts) {
        assert.ok(!JSON.stringify(a).includes('test-install-0001'));
    }

    // install table: its own server-sorted, paged endpoint (the overview no
    // longer bundles it). Ids at rest are SHA-256 hashes of what the client
    // sent — the raw id (a hostname on legacy installs) is never stored or
    // exposed.
    r = await get('/v1/admin/installs', { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body.installs[0].install_id, sha('uuid-1111-2222-3333')); // busiest first by default
    assert.strictEqual(r.body.installs[0].used, 4);
    assert.strictEqual(r.body.total, r.body.installs.length);
    for (const k of r.body.installs) {
        assert.match(k.install_id, /^[0-9a-f]{64}$/);
        assert.ok(!('mint_ip' in k));
    }
    // sort keys are a whitelist; dir flips; paging slices the same ordering
    r = await get('/v1/admin/installs?sort=searches&dir=asc', { 'x-admin-token': 'test-admin' });
    const ascUsed = r.body.installs.map(k => k.used);
    assert.deepStrictEqual(ascUsed, [...ascUsed].sort((a, b) => a - b));
    assert.ok(ascUsed.length >= 2);
    r = await get('/v1/admin/installs?sort=searches&dir=asc&limit=1&offset=1', { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.body.installs.length, 1);
    assert.strictEqual(r.body.installs[0].used, ascUsed[1]);
    // q narrows by hex prefix of the STORED hash; junk input is refused
    r = await get('/v1/admin/installs?q=' + sha('uuid-1111-2222-3333').slice(0, 12), { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.body.total, 1);
    assert.strictEqual(r.body.installs[0].install_id, sha('uuid-1111-2222-3333'));
    r = await get('/v1/admin/installs?sort=nope', { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.status, 400);
    r = await get('/v1/admin/installs?q=not-hex', { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.status, 400);
    r = await get('/v1/admin/installs', { 'x-admin-token': 'wrong' });
    assert.strictEqual(r.status, 401);

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

    // every admin page + the shared assets are served (data-free — auth
    // happens per fetch inside the pages)
    for (const p of ['/admin', '/admin/analytics', '/admin/installs', '/admin/feedback']) {
        const page = await fetch(base + p);
        assert.strictEqual(page.status, 200, p);
        assert.ok((await page.text()).includes('Connect Admin'), p);
    }
    assert.strictEqual((await fetch(base + '/admin/assets/shared.js')).status, 200);
    assert.strictEqual((await fetch(base + '/admin/nope')).status, 404);

    // ── feedback: ingest → admin list → status flow ─────────────────────
    // Rejects: empty and over-long messages.
    r = await post('/v1/feedback', { message: '' });
    assert.strictEqual(r.status, 400);
    r = await post('/v1/feedback', { message: 'x'.repeat(4001) });
    assert.strictEqual(r.status, 400);

    // Accepts a support request with optional fields; unknown kind files
    // as 'feedback'.
    r = await post('/v1/feedback', {
        message: 'The sync between my Macs stopped working after the update.',
        kind: 'support', email: 'user@example.com', appVersion: '0.1.0-alpha.25', platform: 'darwin arm64'
    });
    assert.strictEqual(r.status, 200);
    const fbId = r.body.id;
    r = await post('/v1/feedback', { message: 'Love the new Email AI page!', kind: 'bogus' });
    assert.strictEqual(r.status, 200);

    // Admin list: both rows, newest first, counts correct, no auth = 401.
    assert.strictEqual((await fetch(base + '/v1/admin/feedback')).status, 401);
    r = await get('/v1/admin/feedback?status=all', { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.body.counts.new, 2);
    assert.strictEqual(r.body.items.length, 2);
    assert.strictEqual(r.body.items[1].kind, 'support');
    assert.strictEqual(r.body.items[1].email, 'user@example.com');
    assert.strictEqual(r.body.items[0].kind, 'feedback');
    assert.strictEqual(r.body.items[0].email, null);
    // No id of any kind on a row — the not-joinable promise, as a test.
    assert.ok(!('install_id' in r.body.items[0]));

    // Status flow: close → shows under closed, drops from new; bad id 404s.
    r = await post('/v1/admin/feedback/status', { id: fbId, status: 'closed' }, { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.status, 200);
    r = await get('/v1/admin/feedback?status=new', { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.body.items.length, 1);
    assert.strictEqual(r.body.counts.closed, 1);
    r = await post('/v1/admin/feedback/status', { id: 999999, status: 'read' }, { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.status, 404);

    // Overview carries the counts (the nav badge + tile read them).
    r = await get('/v1/admin/overview?days=7', { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.body.feedback.new, 1);
    assert.strictEqual(r.body.feedback.total, 2);

    // ── LLM inference: metered OpenAI-compatible proxy ──────────────────
    // healthz names the public models
    r = await get('/healthz');
    assert.deepStrictEqual(r.body.llmModels, ['anjadhe-cloud']);

    // /v1/llm/models: the keyless catalog the app's model picker renders
    // (mock mode serves the fixed mock model regardless of the table)
    r = await get('/v1/llm/models');
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(r.body.models, [{ id: 'anjadhe-cloud', label: 'Anjadhe Cloud' }]);

    // ── LLM model catalog: admin-managed table, env is only the seed ────
    // The LLM_MODELS env at the top of this file seeded one row on boot.
    r = await get('/v1/admin/llm-models', { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body.mock, true);
    assert.strictEqual(r.body.upstreamConfigured, false);
    assert.strictEqual(r.body.models.length, 1);
    assert.strictEqual(r.body.models[0].id, 'anjadhe-cloud');
    assert.strictEqual(r.body.models[0].upstream, 'google/gemma-3-27b-it');
    assert.strictEqual(r.body.models[0].label, 'Anjadhe Cloud');
    assert.strictEqual(r.body.models[0].description, 'Fast all-rounder');
    assert.strictEqual(r.body.models[0].enabled, 1);

    // create (validation first), edit keeps position, reorder, disable
    r = await post('/v1/admin/llm-models', { id: 'Bad Id!', upstream: 'x' }, { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.status, 400);
    r = await post('/v1/admin/llm-models', { id: 'anjadhe-cloud-max', upstream: 'qwen/qwen3-32b', label: 'Anjadhe Cloud Max', description: 'Bigger, slower' }, { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(r.body.models.map(m => m.id), ['anjadhe-cloud', 'anjadhe-cloud-max']);

    r = await post('/v1/admin/llm-models/order', { ids: ['anjadhe-cloud-max'] }, { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.status, 400); // must name every row exactly once
    r = await post('/v1/admin/llm-models/order', { ids: ['anjadhe-cloud-max', 'anjadhe-cloud'] }, { 'x-admin-token': 'test-admin' });
    assert.deepStrictEqual(r.body.models.map(m => m.id), ['anjadhe-cloud-max', 'anjadhe-cloud']);

    r = await post('/v1/admin/llm-models', { id: 'anjadhe-cloud-max', upstream: 'qwen/qwen3-32b', label: 'Anjadhe Cloud Max', description: 'Bigger, slower', enabled: false }, { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.body.models[0].enabled, 0); // edit kept position 0

    // With the mock off, /v1/llm reads the TABLE: enabled rows in position
    // order, upstream resolved per row, disabled rows invisible.
    {
        const cfg = require('../lib/config');
        const llmLib = require('../lib/llm');
        const saved = { llmMock: cfg.llmMock, llmUpstreamUrl: cfg.llmUpstreamUrl, llmUpstreamKey: cfg.llmUpstreamKey };
        try {
            cfg.llmMock = false;
            cfg.llmUpstreamUrl = 'http://upstream.test';
            cfg.llmUpstreamKey = 'k';
            assert.deepStrictEqual(llmLib.available(), ['anjadhe-cloud']);
            assert.deepStrictEqual(llmLib.catalog(),
                [{ id: 'anjadhe-cloud', label: 'Anjadhe Cloud', description: 'Fast all-rounder' }]);
            // a disabled row resolves no upstream (the route's available()
            // check rejects it first; this is the belt to that suspender)
            assert.strictEqual(llmLib.buildBody({ messages: [] }, 'anjadhe-cloud-max', false).model, undefined);
            const built = llmLib.buildBody({ messages: [{ role: 'user', content: 'x' }] }, 'anjadhe-cloud', false);
            assert.strictEqual(built.model, 'google/gemma-3-27b-it');
            r = await get('/v1/llm/models');
            assert.deepStrictEqual(r.body.models,
                [{ id: 'anjadhe-cloud', label: 'Anjadhe Cloud', description: 'Fast all-rounder' }]);
        } finally {
            Object.assign(cfg, saved);
        }
    }

    // delete: unknown 404s, real one goes, the seeded row survives
    r = await post('/v1/admin/llm-models/delete', { id: 'nope' }, { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.status, 404);
    r = await post('/v1/admin/llm-models/delete', { id: 'anjadhe-cloud-max' }, { 'x-admin-token': 'test-admin' });
    assert.deepStrictEqual(r.body.models.map(m => m.id), ['anjadhe-cloud']);

    const chatBody = { model: 'anjadhe-cloud', messages: [{ role: 'user', content: 'hi' }] };
    // auth + validation
    r = await post('/v1/llm/chat/completions', chatBody);
    assert.strictEqual(r.status, 401);
    r = await post('/v1/llm/chat/completions', { ...chatBody, model: 'gpt-4' }, bearer(key2));
    assert.strictEqual(r.status, 400);
    assert.strictEqual(r.body.code, 'model');
    r = await post('/v1/llm/chat/completions', { model: 'anjadhe-cloud', messages: [] }, bearer(key2));
    assert.strictEqual(r.status, 400);

    // non-stream: OpenAI shape through, usage metered (15 tokens)
    r = await post('/v1/llm/chat/completions', chatBody, bearer(key2));
    assert.strictEqual(r.status, 200, JSON.stringify(r.body));
    assert.ok(r.body.choices[0].message.content.length > 0);
    assert.strictEqual(r.body.usage.total_tokens, 15);
    r = await get('/v1/usage', bearer(key2));
    assert.strictEqual(r.body.llm.requests, 1);
    assert.strictEqual(r.body.llm.tokens, 15);
    assert.strictEqual(r.body.llm.requestQuota, 2);

    // stream: SSE passthrough, usage chunk still metered
    const sse = await fetch(base + '/v1/llm/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...bearer(key2) },
        body: JSON.stringify({ ...chatBody, stream: true })
    });
    assert.strictEqual(sse.status, 200);
    assert.match(sse.headers.get('content-type'), /text\/event-stream/);
    const sseText = await sse.text();
    assert.ok(sseText.includes('"content":"Canned "'));
    assert.ok(sseText.includes('[DONE]'));
    r = await get('/v1/usage', bearer(key2));
    assert.strictEqual(r.body.llm.requests, 2);
    assert.strictEqual(r.body.llm.tokens, 30);

    // third call hits the free request quota (2)
    r = await post('/v1/llm/chat/completions', chatBody, bearer(key2));
    assert.strictEqual(r.status, 429);
    assert.strictEqual(r.body.code, 'quota');
    assert.ok(r.body.resetsAt);

    // upgrade unblocks the install…
    r = await post('/v1/admin/tier', { installId: 'uuid-1111-2222-3333', tier: 'plus' }, { 'x-admin-token': 'test-admin' });
    assert.strictEqual(r.status, 200);
    r = await post('/v1/llm/chat/completions', chatBody, bearer(key2)); // 45 tokens
    assert.strictEqual(r.status, 200);
    r = await post('/v1/llm/chat/completions', chatBody, bearer(key2)); // 60 tokens
    assert.strictEqual(r.status, 200);

    // …but the service-wide token budget (60) is the hard ceiling
    r = await post('/v1/llm/chat/completions', chatBody, bearer(key2));
    assert.strictEqual(r.status, 503);
    assert.strictEqual(r.body.code, 'budget');

    // the upstream body is BUILT from a whitelist, never passed through:
    // the app's think-off hint survives, smuggled upstream knobs (logprobs,
    // user tags) are dropped, and max_tokens is clamped to the deploy cap
    {
        const { buildBody } = require('../lib/llm');
        const built = buildBody({
            messages: [{ role: 'user', content: 'x' }],
            chat_template_kwargs: { enable_thinking: false },
            temperature: 0.2,
            logprobs: true, user: 'tracking-tag', max_tokens: 999999
        }, 'anjadhe-cloud', false);
        assert.deepStrictEqual(built.chat_template_kwargs, { enable_thinking: false });
        assert.strictEqual(built.temperature, 0.2);
        assert.ok(!('logprobs' in built) && !('user' in built));
        assert.strictEqual(built.max_tokens, 2048); // LLM_MAX_OUTPUT_TOKENS default
    }

    // observability: period totals, daily counters, budget alert — and
    // nothing anywhere carrying what was asked
    r = await get('/v1/admin/overview?days=7', { 'x-admin-token': 'test-admin' });
    assert.deepStrictEqual(r.body.llm, { models: ['anjadhe-cloud'], requests: 4, tokens: 60, budgetTokens: 60 });
    assert.strictEqual(r.body.llmTierQuotas.free.requests, 2);
    const lm = {};
    for (const row of r.body.metrics) lm[row.name] = (lm[row.name] || 0) + row.n;
    assert.strictEqual(lm['llm.ok'], 4);
    assert.strictEqual(lm['llm.tokens'], 60);
    assert.strictEqual(lm['llm.quota'], 1);
    assert.strictEqual(lm['llm.budget'], 1);
    assert.ok(lm['llm.ms.lt2000'] >= 1);
    assert.ok(r.body.alerts.some(a => a.id === 'llm-budget-spent'));
    r = await get('/v1/admin/stats', { 'x-admin-token': 'test-admin' });
    assert.deepStrictEqual(r.body.llmThisPeriod, { requests: 4, tokens: 60 });

    // the install list carries per-install LLM usage beside search usage
    // (how the operator spots one install eating the token budget)
    r = await get('/v1/admin/installs', { 'x-admin-token': 'test-admin' });
    const llmInstall = r.body.installs.find(k => k.install_id === sha('uuid-1111-2222-3333'));
    assert.strictEqual(llmInstall.llm_requests, 4);
    assert.strictEqual(llmInstall.llm_tokens, 60);
    assert.ok(r.body.installs.every(k => 'llm_requests' in k && 'llm_tokens' in k));

    // ── router pacing: PROVIDER_PACE_MS spaces upstream call starts ─────
    // (config was loaded with {"mock":150} — see env at the top.) Three
    // concurrent searches must serialize: starts ≥150ms apart, so the
    // batch takes ≥300ms end to end. Direct router calls — key quotas
    // live at the route layer and must not be spent here.
    {
        const router = require('../lib/router');
        const t0 = Date.now();
        const batch = await Promise.all([
            router.search('pace probe 1', 1),
            router.search('pace probe 2', 1),
            router.search('pace probe 3', 1)
        ]);
        const elapsed = Date.now() - t0;
        assert.ok(batch.every(b => b.upstream === 'mock'));
        assert.ok(elapsed >= 300, `paced batch finished in ${elapsed}ms — pacing not applied`);
    }

    // ── never-used key purge ────────────────────────────────────────────
    // A minted-but-never-authenticated free key ages out; anything ever
    // seen, and any operator-upgraded tier, survives. Runs LAST — a
    // negative cutoff ("older than -1 days" = everything) sweeps every
    // unused key this test left behind, which is the point.
    {
        r = await post('/v1/keys', { installId: 'purge-test-victim-01' });
        assert.strictEqual(r.status, 200);
        r = await post('/v1/keys', { installId: 'purge-test-upgraded-1' });
        assert.strictEqual(r.status, 200);
        r = await post('/v1/admin/tier', { installId: 'purge-test-upgraded-1', tier: 'plus' }, { 'x-admin-token': 'test-admin' });
        assert.strictEqual(r.status, 200);

        assert.strictEqual(db.purgeUnusedKeys(7), 0); // both are minutes old — the real cutoff spares them
        const swept = db.purgeUnusedKeys(-1);
        assert.ok(swept >= 1, `expected the unused free key to be purged, swept ${swept}`);

        r = await get('/v1/admin/installs?q=' + sha('purge-test-victim-01').slice(0, 16), { 'x-admin-token': 'test-admin' });
        assert.strictEqual(r.body.total, 0);          // never-used free key: gone
        r = await get('/v1/admin/installs?q=' + sha('purge-test-upgraded-1').slice(0, 16), { 'x-admin-token': 'test-admin' });
        assert.strictEqual(r.body.total, 1);          // upgraded tier: never purged
        r = await get('/v1/admin/installs?q=' + sha('uuid-1111-2222-3333').slice(0, 16), { 'x-admin-token': 'test-admin' });
        assert.strictEqual(r.body.total, 1);          // ever-seen key: never purged

        // the vacated install id can mint fresh — the app's 401 self-heal path
        r = await post('/v1/keys', { installId: 'purge-test-victim-01' });
        assert.strictEqual(r.status, 200);
        assert.strictEqual(r.body.tier, 'free');
    }

    srv.close();
    console.log('smoke: all assertions passed');
}

main().catch((e) => { console.error(e); process.exit(1); });
