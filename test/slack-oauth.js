'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'nenva-slack-oauth-'));
process.env.LLM_MOCK = '1';
process.env.SEARCH_MOCK = '1';
const { CALLBACK_PATH, LOOPBACK_URI } = require('../lib/slack-oauth');
const lines = [];
const originals = {};
for (const method of ['log', 'warn', 'error', 'info', 'debug']) {
    originals[method] = console[method];
    console[method] = (...args) => lines.push(args.map(String).join(' '));
}
const app = require('../server');
const db = require('../lib/db');

(async () => {
    const server = app.listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    const base = `http://127.0.0.1:${server.address().port}${CALLBACK_PATH}`;
    const state = 'private-slack-state-canary'.padEnd(43, 'x');
    const code = 'private-slack-code-canary.123';
    const query = new URLSearchParams({ state, code, iss: 'https://mcp.slack.com' });
    const get = (q, options = {}) => fetch(base + (q ? '?' + q : ''), { redirect: 'manual', ...options });
    const secure = res => {
        assert.equal(res.headers.get('cache-control'), 'no-store');
        assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
        assert.match(res.headers.get('content-security-policy'), /default-src 'none'/);
        assert.equal(res.headers.get('set-cookie'), null);
    };
    try {
        let response = await get('');
        assert.equal(response.status, 200);
        assert.equal(response.headers.get('location'), null);
        secure(response);
        response = await get(query);
        secure(response);
        assert.equal(response.status, 302);
        const target = new URL(response.headers.get('location'));
        assert.equal(target.origin + target.pathname, LOOPBACK_URI);
        assert.equal(target.searchParams.get('code'), code);
        assert.equal(target.searchParams.get('state'), state);
        assert.equal(target.searchParams.get('iss'), 'https://mcp.slack.com');
        assert.doesNotMatch(await response.text(), /private-slack/);

        const extras = new URLSearchParams(query);
        extras.set('redirect_uri', 'https://evil.test/steal');
        extras.set('return_to', 'https://evil.test/steal');
        extras.set('port', '9999');
        extras.set('access_token', 'private-slack-token-canary');
        response = await get(extras);
        assert.equal(response.headers.get('location'), target.href, 'untrusted targets and tokens are never forwarded');

        response = await get(new URLSearchParams({ state, error: 'user_denied', error_description: code }));
        assert.equal(response.status, 302);
        const denied = new URL(response.headers.get('location'));
        assert.equal(denied.searchParams.get('error'), 'access_denied');
        assert.equal(denied.searchParams.has('error_description'), false);
        assert.equal(denied.searchParams.get('state'), state);

        for (const bad of [
            'code=' + code, 'state=' + state, query + '&state=' + state,
            query + '&code=another', query + '&error=access_denied',
            query + '&iss=https://evil.test',
            new URLSearchParams({ state, code, iss: 'https://evil.test' }),
            new URLSearchParams({ state, code, iss: '' }),
            new URLSearchParams({ state, code: '' }),
            new URLSearchParams({ state: 'wrong', code }),
            new URLSearchParams({ state, code: 'x'.repeat(2049) }),
            new URLSearchParams({ state, code: 'value\r\nLocation:evil' }),
            new URLSearchParams({ state, error: '' }),
            new URLSearchParams({ state, error: '<script>' }),
            query + '&padding=' + 'x'.repeat(8200)
        ]) {
            response = await get(bad);
            assert.equal(response.status, 400);
            assert.equal(response.headers.get('location'), null);
            secure(response);
            assert.doesNotMatch(await response.text(), /private-slack|evil/);
        }
        for (const method of ['POST', 'HEAD', 'PUT']) {
            response = await get(query, { method });
            assert.equal(response.status, 405);
            assert.equal(response.headers.get('location'), null);
            secure(response);
        }
        db.checkpoint();
        assert.doesNotMatch(lines.join('\n'), /private-slack|evil\.test|state=|code=/);
        for (const file of fs.readdirSync(process.env.DATA_DIR)) {
            if (fs.statSync(path.join(process.env.DATA_DIR, file)).isFile()) {
                assert.ok(!fs.readFileSync(path.join(process.env.DATA_DIR, file)).includes(Buffer.from('private-slack')));
            }
        }
    } finally {
        await new Promise(resolve => server.close(resolve));
        for (const [method, original] of Object.entries(originals)) console[method] = original;
    }
    console.log('Slack OAuth: fixed browser handoff, denial, malformed input, no-store and log/database privacy passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
