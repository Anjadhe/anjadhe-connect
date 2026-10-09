// Named keys (/admin/keys, 2026-10-09): the operator mints a key by hand,
// names it, and reads its usage by that name. On its own server so its AI
// calls never move test/smoke.js's exact budget counts.
//
//   node test/named-keys.js

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.SEARCH_MOCK = '1';
process.env.LLM_MOCK = '1';                 // every mock call: 10 tokens in, 5 out
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'connect-named-keys-'));
process.env.ADMIN_TOKEN = 'test-admin';
process.env.LLM_MODELS = '{"nenva-cloud-lite":{"upstream":"x/lite","label":"nenva cloud lite"}}';
process.env.TIER_QUOTAS = '{"free":1,"plus":5}';
process.env.LLM_TIER_QUOTAS = '{"free":{"requests":1,"tokens":1000},"plus":{"requests":100,"tokens":100000}}';
process.env.LLM_BUDGET_TOKENS = '100000';
process.env.PROVIDER_PACE_MS = '{"mock":0}';
const PROMPT_CANARY = 'named-key-prompt-canary-3c9e';

const db = require('../lib/db');
const app = require('../server');

async function main() {
    const srv = app.listen(0);
    const base = `http://127.0.0.1:${srv.address().port}`;
    const call = async (p, { body, headers = {}, method = body ? 'POST' : 'GET' } = {}) => {
        const res = await fetch(base + p, { method, headers: { 'Content-Type': 'application/json', ...headers }, ...(body ? { body: JSON.stringify(body) } : {}) });
        return { status: res.status, body: await res.json() };
    };
    const admin = { 'x-admin-token': 'test-admin' };
    const bearer = (k) => ({ Authorization: `Bearer ${k}` });
    const before = db.stats ? db.stats() : null;

    // Only the operator can make or list one.
    let r = await call('/v1/admin/keys', { body: { label: 'x' } });
    assert.strictEqual(r.status, 401);
    r = await call('/v1/admin/keys', { body: { label: '  ', tier: 'plus' }, headers: admin });
    assert.strictEqual(r.status, 400, 'a key needs a name');
    r = await call('/v1/admin/keys', { body: { label: 'x', tier: 'toString' }, headers: admin });
    assert.strictEqual(r.status, 400, 'an unknown tier is refused');

    // Made: shown once, a real key at the chosen tier.
    r = await call('/v1/admin/keys', { body: { label: 'coach eval, cloud lite', tier: 'plus' }, headers: admin });
    assert.strictEqual(r.status, 200);
    assert.match(r.body.apiKey, /^anck_[a-f0-9]{48}$/);
    const key = r.body.apiKey, id = r.body.item.install_id;
    assert.match(id, /^[0-9a-f]{64}$/);

    // It works like any key, and its calls are metered under its name.
    for (let i = 0; i < 2; i++) {
        r = await call('/v1/llm/chat/completions', { body: { model: 'nenva-cloud-lite', messages: [{ role: 'user', content: PROMPT_CANARY }] }, headers: { ...bearer(key), 'X-Nenva-Work': 'background' } });
        assert.strictEqual(r.status, 200, JSON.stringify(r.body));
    }
    r = await call('/v1/search', { body: { query: 'named key search' }, headers: bearer(key) });
    assert.strictEqual(r.status, 200);

    r = await call('/v1/admin/keys', { headers: admin });
    assert.strictEqual(r.status, 200);
    assert.ok(r.body.tiers.includes('free') && r.body.tiers.includes('plus'), 'the tiers to choose from');
    const item = r.body.items.find(k => k.install_id === id);
    assert.strictEqual(item.label, 'coach eval, cloud lite');
    assert.strictEqual(item.tier, 'plus');
    const llm = item.llm.find(x => x.period === r.body.period && x.work === 'background');
    assert.ok(llm, JSON.stringify(item.llm));
    assert.strictEqual(llm.requests, 2);
    assert.strictEqual(llm.tokens_in + llm.tokens_out, 30, 'two mock calls, 15 tokens each');
    assert.strictEqual(item.search.reduce((n, x) => n + x.searches, 0), 1);
    assert.ok(item.last_seen_day, 'used today');

    // A named key is a test install: it never counts as a real one, and the
    // never-used purge leaves a fresh named key alone.
    if (before) assert.strictEqual(db.stats().keys, before.keys, 'real install count unchanged');
    r = await call('/v1/admin/keys', { body: { label: 'never used', tier: 'free' }, headers: admin });
    const unused = r.body.item.install_id;
    if (db.purgeUnusedKeys) {
        db.purgeUnusedKeys(-1);   // a cutoff in the future: every never-used free key qualifies
        assert.ok(db.getKeyByInstall(unused), 'a named key is never purged as unused');
    }

    // Rename, then revoke: the key stops, its numbers stay.
    r = await call('/v1/admin/keys/rename', { body: { installId: id, label: 'coach eval run 1' }, headers: admin });
    assert.strictEqual(r.status, 200);
    r = await call('/v1/admin/keys/revoke', { body: { installId: id }, headers: admin });
    assert.strictEqual(r.status, 200);
    r = await call('/v1/admin/keys/revoke', { body: { installId: id }, headers: admin });
    assert.strictEqual(r.status, 404, 'already revoked');
    r = await call('/v1/llm/chat/completions', { body: { model: 'nenva-cloud-lite', messages: [{ role: 'user', content: 'x' }] }, headers: bearer(key) });
    assert.strictEqual(r.status, 401);
    assert.strictEqual(r.body.code, 'revoked');
    r = await call('/v1/admin/keys', { headers: admin });
    const after = r.body.items.find(k => k.install_id === id);
    assert.strictEqual(after.label, 'coach eval run 1');
    assert.ok(after.revoked_at);
    assert.strictEqual(after.llm.reduce((n, x) => n + x.requests, 0), 2, 'usage kept after revoke');

    // An ordinary install's key cannot be renamed or revoked from here.
    r = await call('/v1/keys', { body: { installId: 'plain-install-0001' } });
    const plain = db.hashInstallId('plain-install-0001');
    r = await call('/v1/admin/keys/revoke', { body: { installId: plain }, headers: admin });
    assert.strictEqual(r.status, 404);

    // Never the prompt: not in the database.
    db.checkpoint();
    for (const f of fs.readdirSync(process.env.DATA_DIR)) {
        assert.ok(!fs.readFileSync(path.join(process.env.DATA_DIR, f), 'latin1').includes(PROMPT_CANARY), `prompt text found in ${f}`);
    }

    srv.close();
    console.log('named-keys: create, meter by name, rename, revoke, never purged, never the prompt — passed');
}

main().catch((e) => { console.error(e); process.exit(1); });
