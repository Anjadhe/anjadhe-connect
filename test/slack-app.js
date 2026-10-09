// nenva in Slack (lib/slack-app.js) against a local stub of Slack's API:
// sign-in (start, callback, claim, refresh), the direct install link,
// signed events and interactions, the inbox long-poll, replies confined to
// the person's own DM, bot-token rotation, uninstall/revocation, and the
// privacy canary — no DM text, reply text or token in a log line or in the
// database files. Run: node test/slack-app.js
'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

const CANARY_DM = 'canary-slack-dm-4e8b1f0a-do-not-log';
const CANARY_SHORTCUT = 'canary-slack-shortcut-7c2d9e3b-do-not-log';
const CANARY_REPLY = 'canary-slack-reply-1a6f5d2c-do-not-log';
const USER_TOKEN = 'xoxp-canary-user-token-0b9e';
const USER_REFRESH = 'xoxe-1-canary-user-refresh-3d7a';
const BOT_TOKEN = 'xoxb-canary-bot-token-5f21';
const BOT_TOKEN_2 = 'xoxb-canary-bot-token-rotated-8c44';
const BOT_REFRESH = 'xoxe-1-canary-bot-refresh-9a13';
const SECRET = 'test-signing-secret';
const TEAM = 'T0TEAM01', USER = 'U0PERSON1', OTHER = 'U0OTHER02', DM = 'D0DMCHAN1', CHAN = 'C0CHANNEL';

// ── Slack stub ───────────────────────────────────────────────────────────
const calls = [];
let botExpiresIn = 43200;
const stub = http.createServer((req, res) => {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
        const method = req.url.replace(/^\/api\//, '').replace(/^\//, '');
        const params = (req.headers['content-type'] || '').includes('json')
            ? JSON.parse(body || '{}') : Object.fromEntries(new URLSearchParams(body));
        calls.push({ method, params, auth: req.headers.authorization || '' });
        const send = (o) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(o)); };
        if (method === 'oauth.v2.access') {
            if (params.client_secret !== 'test-client-secret') return send({ ok: false, error: 'invalid_client' });
            if (params.grant_type === 'refresh_token') {
                if (params.refresh_token === BOT_REFRESH) return send({ ok: true, access_token: BOT_TOKEN_2, refresh_token: BOT_REFRESH, expires_in: 43200, token_type: 'bot' });
                if (params.refresh_token === USER_REFRESH) return send({ ok: true, access_token: USER_TOKEN + '-2', refresh_token: USER_REFRESH, expires_in: 43200, token_type: 'user' });
                return send({ ok: false, error: 'invalid_refresh_token' });
            }
            if (params.code === 'bad-code') return send({ ok: false, error: 'invalid_code' });
            return send({ ok: true, access_token: BOT_TOKEN, refresh_token: BOT_REFRESH, expires_in: botExpiresIn,
                token_type: 'bot', bot_user_id: 'U0BOT0001', team: { id: TEAM, name: 'Canary Workspace' },
                authed_user: { id: USER, access_token: USER_TOKEN, refresh_token: USER_REFRESH, expires_in: 43200,
                    scope: 'channels:read,im:history', token_type: 'user' } });
        }
        if (method === 'chat.postMessage' || method === 'chat.update') return send({ ok: true, ts: '1760000000.000100', channel: params.channel });
        if (method === 'auth.revoke') return send({ ok: true, revoked: true });
        if (method.startsWith('hooks/')) return res.end('ok');
        send({ ok: false, error: 'unknown_method' });
    });
});

(async () => {
    await new Promise(r => stub.listen(0, '127.0.0.1', r));
    const stubBase = `http://127.0.0.1:${stub.address().port}`;
    process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'nenva-slack-app-'));
    process.env.SEARCH_MOCK = '1';
    process.env.LLM_MOCK = '1';
    process.env.SLACK_CLIENT_ID = '1111.2222';
    process.env.SLACK_CLIENT_SECRET = 'test-client-secret';
    process.env.SLACK_SIGNING_SECRET = SECRET;
    process.env.SLACK_TOKEN_KEY = crypto.randomBytes(32).toString('base64');
    process.env.SLACK_API_BASE = stubBase + '/api';
    process.env.SLACK_HOOKS_PREFIX = stubBase + '/hooks/';
    process.env.SLACK_INSTALLED_URL = 'https://nenva.test/slack/installed';

    const lines = [];
    for (const m of ['log', 'warn', 'error', 'info', 'debug']) {
        console[m] = (...a) => lines.push(a.map(String).join(' '));
    }
    const app = require('../server');
    const slackApp = require('../lib/slack-app');
    const server = app.listen(0, '127.0.0.1');
    await new Promise(r => server.once('listening', r));
    const base = `http://127.0.0.1:${server.address().port}`;
    const wait = (ms) => new Promise(r => setTimeout(r, ms));
    const settle = () => wait(60);

    const call = async (method, p, body, key, headers = {}) => {
        const res = await fetch(base + p, { method, redirect: 'manual',
            headers: { ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
                ...(key ? { authorization: `Bearer ${key}` } : {}), ...headers },
            body: body !== undefined ? JSON.stringify(body) : undefined });
        const text = await res.text();
        let json = null;
        try { json = JSON.parse(text); } catch {}
        return { status: res.status, json, text, location: res.headers.get('location') };
    };
    const signed = (p, raw, { contentType = 'application/json', secret = SECRET, ts = Math.floor(Date.now() / 1000) } = {}) => {
        const sig = 'v0=' + crypto.createHmac('sha256', secret).update(`v0:${ts}:${raw}`).digest('hex');
        return fetch(base + p, { method: 'POST', body: raw, headers: { 'content-type': contentType,
            'x-slack-request-timestamp': String(ts), 'x-slack-signature': sig } });
    };
    let eventN = 0;
    const event = (ev, extra = {}) => signed('/v1/slack/events', JSON.stringify({ type: 'event_callback',
        team_id: TEAM, event_id: 'Ev' + (++eventN), event: ev, ...extra }));
    const dm = (text, user = USER) => event({ type: 'message', channel_type: 'im', channel: DM, user, text, ts: `176000000${eventN}.000200` });
    const interact = (payload) => signed('/v1/slack/interactivity',
        new URLSearchParams({ payload: JSON.stringify(payload) }).toString(), { contentType: 'application/x-www-form-urlencoded' });
    const posts = () => calls.filter(c => c.method === 'chat.postMessage');

    try {
        // Keys for two Macs.
        let r = await call('POST', '/v1/keys', { installId: 'slack-mac-0001' });
        const key = r.json.apiKey;
        r = await call('POST', '/v1/keys', { installId: 'slack-mac-0002' });
        const otherKey = r.json.apiKey;

        // ── Sign-in ─────────────────────────────────────────────────────
        assert.equal((await call('POST', '/v1/slack/install/start', {})).status, 401, 'start needs a key');
        r = await call('POST', '/v1/slack/install/start', {}, key);
        assert.equal(r.status, 200);
        const auth = new URL(r.json.url);
        const state = r.json.state;
        assert.equal(auth.searchParams.get('client_id'), '1111.2222');
        assert.equal(auth.searchParams.get('scope'), 'im:history,chat:write,commands');
        assert.equal(auth.searchParams.get('user_scope').split(',').length, 9);
        assert.equal(auth.searchParams.get('state'), state);
        assert.equal(auth.searchParams.has('client_secret'), false);

        r = await call('POST', '/v1/slack/install/claim', { state }, key);
        assert.equal(r.status, 202, 'not yet authorized');
        r = await call('POST', '/v1/slack/install/claim', { state }, otherKey);
        assert.equal(r.status, 404, 'another Mac cannot claim this sign-in');

        botExpiresIn = 60; // within five minutes: the first bot use refreshes
        r = await call('GET', `/v1/slack/oauth/callback?code=good-code&state=${state}`);
        assert.equal(r.status, 302);
        assert.equal(r.location, 'https://nenva.test/slack/installed?result=connected');
        const exchange = calls.find(c => c.method === 'oauth.v2.access' && c.params.code === 'good-code');
        assert.equal(exchange.params.redirect_uri, 'https://api.nenva.co/v1/slack/oauth/callback');
        r = await call('GET', `/v1/slack/oauth/callback?code=good-code&state=${state}`);
        assert.equal(r.location, 'https://nenva.test/slack/installed?result=expired', 'a state is used once');

        r = await call('POST', '/v1/slack/install/claim', { state }, key);
        assert.equal(r.status, 200);
        assert.deepEqual(r.json, { teamId: TEAM, userId: USER, accessToken: USER_TOKEN, refreshToken: USER_REFRESH,
            expiresIn: 43200, scope: 'channels:read,im:history' });
        assert.equal((await call('POST', '/v1/slack/install/claim', { state }, key)).status, 404, 'claimed once');

        r = await call('GET', '/v1/slack/bindings', undefined, key);
        assert.deepEqual(r.json.bindings, [{ teamId: TEAM, userId: USER, chatReady: false }]);

        // Denial and a failed exchange land on the confirmation page, honestly.
        r = await call('POST', '/v1/slack/install/start', {}, key);
        let s2 = r.json.state;
        r = await call('GET', `/v1/slack/oauth/callback?error=access_denied&state=${s2}`);
        assert.equal(r.location, 'https://nenva.test/slack/installed?result=denied');
        assert.deepEqual((await call('POST', '/v1/slack/install/claim', { state: s2 }, key)).json, { error: 'denied' });
        r = await call('POST', '/v1/slack/install/start', {}, key);
        s2 = r.json.state;
        r = await call('GET', `/v1/slack/oauth/callback?code=bad-code&state=${s2}`);
        assert.equal(r.location, 'https://nenva.test/slack/installed?result=failed');

        // Token refresh through the client secret; Macs with no binding are refused.
        r = await call('POST', '/v1/slack/token/refresh', { refreshToken: USER_REFRESH }, key);
        assert.equal(r.status, 200);
        assert.equal(r.json.accessToken, USER_TOKEN + '-2');
        r = await call('POST', '/v1/slack/token/refresh', { refreshToken: USER_REFRESH }, otherKey);
        assert.equal(r.status, 403);
        r = await call('POST', '/v1/slack/token/refresh', { refreshToken: 'xoxe-1-unknown-refresh' }, key);
        assert.equal(r.status, 401);

        // ── Signatures ──────────────────────────────────────────────────
        const challenge = JSON.stringify({ type: 'url_verification', challenge: 'chal-123' });
        r = await signed('/v1/slack/events', challenge);
        assert.deepEqual(await r.json(), { challenge: 'chal-123' });
        assert.equal((await signed('/v1/slack/events', challenge, { secret: 'wrong' })).status, 401);
        assert.equal((await signed('/v1/slack/events', challenge, { ts: Math.floor(Date.now() / 1000) - 600 })).status, 401, 'stale request');
        assert.equal((await fetch(base + '/v1/slack/events', { method: 'POST', body: challenge })).status, 401, 'unsigned');

        // ── A DM while the Mac is away: told at once, nothing kept ───────
        await dm(CANARY_DM);
        await settle();
        let last = posts().at(-1);
        assert.equal(last.params.channel, DM);
        assert.equal(last.params.text, slackApp.COPY.away);
        assert.equal(last.auth, `Bearer ${BOT_TOKEN_2}`, 'the expiring bot token was rotated before use');
        assert.ok(calls.some(c => c.method === 'oauth.v2.access' && c.params.refresh_token === BOT_REFRESH));
        r = await call('GET', '/v1/slack/bindings', undefined, key);
        assert.equal(r.json.bindings[0].chatReady, true, 'the DM channel is learned from the first message');

        // ── The Mac polls: a DM is handed over, once ────────────────────
        const poll = call('GET', '/v1/slack/inbox?wait=5', undefined, key);
        await wait(50);
        const sent = { type: 'event_callback', team_id: TEAM, event_id: 'EvDup1',
            event: { type: 'message', channel_type: 'im', channel: DM, user: USER, text: CANARY_DM, ts: '1760000001.000300' } };
        await signed('/v1/slack/events', JSON.stringify(sent));
        await signed('/v1/slack/events', JSON.stringify(sent)); // Slack's retry
        r = await poll;
        assert.equal(r.json.items.length, 1);
        const item = r.json.items[0];
        assert.equal(item.kind, 'message');
        assert.equal(item.text, CANARY_DM);
        assert.equal(item.teamId, TEAM);
        assert.equal(item.userId, USER);
        assert.equal(item.channel, DM);
        assert.equal(item.expires, undefined);
        r = await call('GET', '/v1/slack/inbox', undefined, key);
        assert.deepEqual(r.json.items, [], 'the retry was not delivered twice');
        r = await call('GET', '/v1/slack/inbox', undefined, otherKey);
        assert.deepEqual(r.json.items, [], 'another Mac sees nothing');

        // Bots, edits and other channels are not the person's words.
        await event({ type: 'message', channel_type: 'im', channel: DM, user: USER, text: 'x', bot_id: 'B1' });
        await event({ type: 'message', subtype: 'message_changed', channel_type: 'im', channel: DM, user: USER, text: 'x' });
        await event({ type: 'message', channel_type: 'channel', channel: CHAN, user: USER, text: 'x' });
        await settle();
        assert.deepEqual((await call('GET', '/v1/slack/inbox', undefined, key)).json.items, []);

        // Unclaimed for the hold: dropped, and the person told.
        const before = posts().length;
        await dm(CANARY_DM); // the Mac polled moments ago, so it is held
        await settle();
        assert.equal(posts().length, before, 'held, not refused');
        slackApp._test.sweepInbox(Date.now() + slackApp._test.HOLD_MS + 1);
        await settle();
        assert.equal(posts().at(-1).params.text, slackApp.COPY.away);
        assert.deepEqual((await call('GET', '/v1/slack/inbox', undefined, key)).json.items, []);

        // ── Someone who has not set nenva up ────────────────────────────
        const n0 = posts().length;
        await dm('hello', OTHER);
        await dm('hello again', OTHER);
        await settle();
        assert.equal(posts().length, n0 + 1, 'the set-up line, once');
        assert.equal(posts().at(-1).params.text, slackApp.COPY.setUp);

        // ── Replies: only into the person's own DM ──────────────────────
        r = await call('POST', '/v1/slack/reply', { teamId: TEAM, text: CANARY_REPLY, threadTs: '1760000001.000300' }, key);
        assert.equal(r.status, 200);
        assert.equal(r.json.ts, '1760000000.000100');
        last = posts().at(-1);
        assert.equal(last.params.channel, DM);
        assert.equal(last.params.text, CANARY_REPLY);
        assert.equal(last.params.thread_ts, '1760000001.000300');
        r = await call('POST', '/v1/slack/reply', { teamId: TEAM, text: 'approve?', blocks: [
            { type: 'section', text: { type: 'mrkdwn', text: 'Allow this?' } },
            { type: 'actions', elements: [{ type: 'button', action_id: 'allow', value: 'ask-1', text: { type: 'plain_text', text: 'Allow' } }] }] }, key);
        assert.equal(r.status, 200);
        r = await call('POST', '/v1/slack/reply', { teamId: TEAM, text: 'done', updateTs: '1760000000.000100' }, key);
        assert.equal(calls.at(-1).method, 'chat.update');
        assert.equal((await call('POST', '/v1/slack/reply', { teamId: TEAM, text: CANARY_REPLY }, otherKey)).status, 403);
        assert.equal((await call('POST', '/v1/slack/reply', { teamId: TEAM, text: 'x', channel: CHAN }, key)).json?.ts,
            '1760000000.000100', 'a channel in the body is ignored');
        assert.equal(posts().at(-1).params.channel, DM);
        assert.equal((await call('POST', '/v1/slack/reply', { teamId: TEAM, text: 'x', blocks: [{ type: 'image' }] }, key)).status, 400);
        assert.equal((await call('POST', '/v1/slack/reply', { teamId: TEAM, text: '' }, key)).status, 400);

        // ── Buttons and the shortcut ────────────────────────────────────
        await call('GET', '/v1/slack/inbox', undefined, key); // the Mac is here
        await interact({ type: 'block_actions', team: { id: TEAM }, user: { id: USER }, channel: { id: DM },
            container: { message_ts: '1760000000.000100' }, response_url: stubBase + '/hooks/1',
            actions: [{ action_id: 'allow', value: 'ask-1' }] });
        await interact({ type: 'message_action', callback_id: 'send_to_nenva', team: { id: TEAM }, user: { id: USER },
            channel: { id: CHAN }, message_ts: '1760000002.000400',
            message: { ts: '1760000002.000400', text: CANARY_SHORTCUT }, response_url: stubBase + '/hooks/2' });
        await settle();
        const items = (await call('GET', '/v1/slack/inbox', undefined, key)).json.items;
        assert.deepEqual(items.map(i => i.kind), ['action', 'shortcut']);
        assert.equal(items[0].actionId, 'allow');
        assert.equal(items[0].value, 'ask-1');
        assert.equal(items[1].channel, CHAN);
        assert.equal(items[1].ts, '1760000002.000400');
        assert.equal(items[1].text, undefined, 'a shortcut carries a pointer, never the text');
        assert.ok(!JSON.stringify(items).includes(CANARY_SHORTCUT));
        const hook = calls.find(c => c.method === 'hooks/2');
        assert.equal(hook.params.text, slackApp.COPY.sent);
        assert.equal(hook.params.response_type, 'ephemeral');
        await interact({ type: 'message_action', callback_id: 'send_to_nenva', team: { id: TEAM }, user: { id: OTHER },
            channel: { id: CHAN }, message_ts: '1760000002.000400', message: { ts: '1760000002.000400', text: CANARY_SHORTCUT },
            response_url: stubBase + '/hooks/3' });
        await settle();
        assert.equal(calls.find(c => c.method === 'hooks/3').params.text, slackApp.COPY.setUp);
        await interact({ type: 'message_action', callback_id: 'send_to_nenva', team: { id: TEAM }, user: { id: USER },
            channel: { id: CHAN }, message_ts: '1760000002.000400', response_url: 'https://evil.test/hook' });
        await settle();
        assert.ok(!lines.some(l => l.includes('evil.test')));

        // ── The direct install link (no Mac waiting) ────────────────────
        r = await call('GET', '/v1/slack/install');
        assert.equal(r.status, 302);
        const direct = new URL(r.location).searchParams.get('state');
        r = await call('GET', `/v1/slack/oauth/callback?code=good-code&state=${direct}`);
        assert.equal(r.location, 'https://nenva.test/slack/installed?result=installed');
        await settle();
        const revoke = calls.find(c => c.method === 'auth.revoke');
        assert.equal(revoke.auth, `Bearer ${USER_TOKEN}`, 'an unclaimable user token is revoked, not held');

        // The keyless link has its own cap and cannot crowd out a Mac's sign-in.
        let refused = 0;
        for (let i = 0; i < 305; i++) if ((await call('GET', '/v1/slack/install')).status === 503) refused++;
        assert.ok(refused >= 5, 'keyless sign-ins are capped');
        assert.equal((await call('POST', '/v1/slack/install/start', {}, key)).status, 200, 'a Mac can still sign in');

        // ── Revocation and uninstall ────────────────────────────────────
        await event({ type: 'tokens_revoked', tokens: { oauth: [USER], bot: [] } });
        await settle();
        assert.deepEqual((await call('GET', '/v1/slack/bindings', undefined, key)).json.bindings, []);
        await event({ type: 'app_uninstalled' });
        await settle();
        assert.equal(require('../lib/db').slackTeam(TEAM), undefined);

        // ── Privacy canary ──────────────────────────────────────────────
        const secrets = [CANARY_DM, CANARY_SHORTCUT, CANARY_REPLY, USER_TOKEN, USER_REFRESH, BOT_TOKEN, BOT_TOKEN_2, BOT_REFRESH, 'Canary Workspace'];
        for (const l of lines) for (const s of secrets) assert.ok(!l.includes(s), `log line leaked ${s}: ${l}`);
        const dir = process.env.DATA_DIR;
        for (const f of fs.readdirSync(dir)) {
            const bytes = fs.readFileSync(path.join(dir, f)).toString('latin1');
            for (const s of secrets) assert.ok(!bytes.includes(s), `${f} holds ${s}`);
        }
        console.info = console.log = () => {};
        process.stdout.write('Slack app: sign-in, claim, refresh, direct install, signatures, inbox, replies, buttons, shortcut, rotation, uninstall and privacy canary passed\n');
    } finally {
        server.close();
        stub.close();
    }
    process.exit(0);
})().catch((e) => { process.stderr.write(String(e?.stack || e) + '\n'); process.exit(1); });
