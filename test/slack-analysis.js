'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'nenva-slack-quota-'));
process.env.LLM_MOCK = '1';
process.env.LLM_MODELS = JSON.stringify({ fixture: { upstream: 'fixture' } });
const { check } = require('../lib/slack-analysis');
const db = require('../lib/db');
const account = 'a'.repeat(64), owner = 'i:fixture';
const body = { model: 'nenva-cloud-lite', stream: false, max_tokens: 1024, messages: [{ role: 'user', content: 'Synthetic excerpt' }] };
assert.equal(check(body, account, owner, db.reserveSlack), null);
for (let i = 1; i < 12; i++) assert.equal(check(body, account, 'i:device' + i, db.reserveSlack), null);
assert.equal(check(body, account, 'i:new-device', db.reserveSlack).status, 429, 'account cap spans installations');
assert.equal(check({ ...body, tools: [] }, account, owner, db.reserveSlack).status, 400);
assert.equal(check({ ...body, max_tokens: 1025 }, account, owner, db.reserveSlack).status, 400);
assert.equal(check({ ...body, messages: [{ role: 'user', content: 'x'.repeat(17000) }] }, account, owner, db.reserveSlack).status, 413);
assert.equal(check({ ...body, messages: [{ role: 'user', content: [{ type: 'image_url' }] }] }, account, owner, db.reserveSlack).status, 400);
assert.equal(check(body, 'not-an-account', owner, db.reserveSlack).status, 400);
assert.equal(db.reserveSlack('i:rollback', account, 100, 0), false, 'clock rollback cannot reset a quota');
console.log('Slack server quotas: cross-device attempts, body/output caps, payload whitelist and rollback passed');

(async () => {
    const app = require('../server');
    const server = app.listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    try {
        const policy = await fetch(base + '/v1/llm/slack-monitor-policy').then(r => r.json());
        assert.equal(policy.version, 1);
        const minted = await fetch(base + '/v1/keys', { method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ installId: 'slack-synthetic-install' }) }).then(r => r.json());
        assert.ok(minted.apiKey);
        const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${minted.apiKey}`,
            'X-Nenva-Feature': 'slack-monitor', 'X-Nenva-Slack-Account': account };
        const post = value => fetch(base + '/v1/llm/chat/completions', { method: 'POST', headers, body: JSON.stringify(value) });
        assert.equal((await post(body)).status, 429, 'HTTP route enforces account quota from another install');
        headers['X-Nenva-Slack-Account'] = 'b'.repeat(64);
        assert.equal((await post({ ...body, tools: [] })).status, 400);
        assert.equal((await post({ ...body, messages: [{ role: 'user', content: 'x'.repeat(20000) }] })).status, 413);
        const canary = 'private-slack-canary-never-store-19c20a';
        const response = await post({ ...body, messages: [{ role: 'user', content: canary }] });
        assert.equal(response.status, 200, await response.text());
        db.checkpoint();
        assert.ok(!fs.readFileSync(path.join(process.env.DATA_DIR, 'connect.db')).includes(Buffer.from(canary)));
        console.log('Slack HTTP: capability, authentication, cross-install quota, parser cap and privacy canary passed');
    } finally { await new Promise(resolve => server.close(resolve)); }
})().catch(e => { console.error(e); process.exitCode = 1; });
