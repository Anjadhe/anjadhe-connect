// /v1/slack — nenva in Slack: the public Marketplace app (anjadhe-app
// docs/SLACK_MARKETPLACE.md). A person DMs nenva's bot in Slack and their
// own nenva answers from their Mac; buttons approve its asks; the "Send to
// nenva" shortcut hands one message to their Mac.
//
// Why this lives on the server: Slack's Marketplace refuses Socket Mode, so
// Slack must reach a public URL, and a bot is ONE per workspace — a bot
// token on each Mac would let one person's Mac read another person's DMs
// with nenva. So Connect is the confidential client: it exchanges the code
// with the client secret, keeps the bot token SEALED (SLACK_TOKEN_KEY,
// AES-256-GCM, the brokerage recipe), and hands the person's own user token
// to their Mac, which reads their chosen conversations with it directly.
//
// PRIVACY INVARIANT (the search rule, applied to Slack): Connect is a pipe,
// never a store. A DM's text, a reply, a token in an exchange or refresh,
// and a button click pass through process memory only — never a log line,
// never a database row. The shortcut keeps no text at all: only a pointer
// (team, user, channel, message ts) the Mac rereads with its own token.
// What is at rest: each workspace's sealed bot token and the binding
// (Slack team id, Slack user id, hashed install id, the bot's DM channel id).
// Slack's error CODES may be logged; response bodies never are.
//
// Laws (docs/SLACK_MARKETPLACE.md S-M2, S-M3): a message reaches a Mac only
// through a binding made from Slack's own exchange response for the key that
// started the sign-in; a bot token never leaves this process; the Mac may
// post only into the DM between the bot and its own bound person.
'use strict';
const crypto = require('crypto');
const express = require('express');
const config = require('./config');
const db = require('./db');

const BOT_SCOPES = ['im:history', 'chat:write', 'commands'];
const USER_SCOPES = ['channels:read', 'groups:read', 'im:read', 'mpim:read',
    'channels:history', 'groups:history', 'im:history', 'mpim:history', 'users:read'];

const TIMEOUT_MS = 10000;
const RESPONSE_MAX = 256 * 1024;      // bytes read from any Slack response
const PENDING_TTL_MS = 10 * 60 * 1000; // a sign-in must be claimed within this
const PENDING_MAX = 2000;
const PENDING_PER_INSTALL = 3;
const PENDING_KEYLESS_MAX = 300;     // the direct install link, kept apart so it cannot crowd out a Mac's sign-in
const HOLD_MS = 60 * 1000;            // a message waits this long for its Mac
const POLL_FRESH_MS = 90 * 1000;      // a Mac that polled this recently is "here"
const INBOX_MAX = 20;                 // items waiting per install
const WAIT_MAX_S = 25;                // longest inbox long-poll
const TEXT_MAX = 12000;               // chars of one DM handed to a Mac
const REPLY_TEXT_MAX = 12000;
const BLOCKS_MAX_BYTES = 16 * 1024;
const BLOCK_TYPES = new Set(['section', 'actions', 'context', 'divider', 'header']);
const SIG_SKEW_S = 5 * 60;
const SEEN_MAX = 5000;                // event ids remembered against Slack retries
const NOTE_EVERY_MS = 60 * 60 * 1000; // the "set it up" line, once an hour a person

const ID = { team: /^T[A-Z0-9]{2,31}$/, user: /^[UW][A-Z0-9]{2,31}$/,
    dm: /^D[A-Z0-9]{2,31}$/, channel: /^[CDG][A-Z0-9]{2,31}$/ };
const TS = /^\d{10}\.\d{6}$/;
const STATE = /^[A-Za-z0-9_-]{43}$/;

const COPY = {
    setUp: 'This is nenva, a personal AI that runs on your own Mac. To talk to it here, connect Slack in nenva on your Mac: https://nenva.co/slack',
    away: "nenva can't reach your Mac right now, so this message wasn't delivered. Send it again once nenva is running on your Mac.",
    busy: 'nenva is still working through your earlier messages. Send this again in a minute.',
    sent: 'nenva will look at this on your Mac.',
    shortcutAway: "nenva can't reach your Mac right now. Try again once nenva is running on your Mac."
};

function enabled() {
    return !!(config.slackClientId && config.slackClientSecret && config.slackSigningSecret && tokenKey(false));
}

// ── Token sealing (lib/brokerage.js's recipe, its own key) ──────────────
let _key = null;
function tokenKey(strict = true) {
    if (_key) return _key;
    const k = Buffer.from(String(config.slackTokenKey || ''), 'base64');
    if (k.length !== 32) {
        if (strict) throw new Error('SLACK_TOKEN_KEY must be the base64 of 32 random bytes');
        return null;
    }
    _key = k;
    return k;
}
function seal(plain) {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', tokenKey(), iv);
    const ct = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
    return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
}
function open(sealed) {
    const buf = Buffer.from(String(sealed), 'base64');
    const d = crypto.createDecipheriv('aes-256-gcm', tokenKey(), buf.subarray(0, 12));
    d.setAuthTag(buf.subarray(12, 28));
    return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8');
}

// ── Slack Web API ────────────────────────────────────────────────────────
class SlackError extends Error {
    constructor(method, code) {
        super(`slack ${method} ${code}`);
        this.name = 'SlackError';
        this.code = String(code || 'failed').replace(/[^a-z0-9_]/gi, '').slice(0, 64) || 'failed';
    }
}

async function readCapped(res) {
    const reader = res.body?.getReader();
    if (!reader) return '';
    const chunks = [];
    let size = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > RESPONSE_MAX) { reader.cancel().catch(() => {}); throw new Error('too_large'); }
        chunks.push(value);
    }
    return Buffer.concat(chunks).toString('utf8');
}

// form: application/x-www-form-urlencoded (oauth.*); otherwise JSON with the
// bearer token. Returns Slack's parsed answer or throws SlackError(code).
async function slack(method, params, { token, form = false } = {}) {
    const headers = {};
    let body;
    if (form) {
        headers['content-type'] = 'application/x-www-form-urlencoded';
        body = new URLSearchParams(params).toString();
    } else {
        headers['content-type'] = 'application/json; charset=utf-8';
        body = JSON.stringify(params);
    }
    if (token) headers.authorization = `Bearer ${token}`;
    let res, data;
    try {
        res = await fetch(`${config.slackApiBase}/${method}`, {
            method: 'POST', headers, body, redirect: 'error', signal: AbortSignal.timeout(TIMEOUT_MS)
        });
        data = JSON.parse(await readCapped(res));
    } catch (e) {
        throw new SlackError(method, e?.name === 'TimeoutError' ? 'timeout' : 'unreachable');
    }
    if (res.status === 429) throw new SlackError(method, 'ratelimited');
    if (!data || data.ok !== true) throw new SlackError(method, data?.error || `http${res.status}`);
    return data;
}

function oauthParams(extra) {
    return { client_id: config.slackClientId, client_secret: config.slackClientSecret, ...extra };
}

// ── Bot tokens: sealed per workspace, refreshed single-flight ───────────
const _refreshing = new Map(); // team -> Promise<token>

function saveTeam(teamId, botUserId, access, refresh, expiresIn) {
    const expires = Number.isFinite(expiresIn) && expiresIn > 0
        ? new Date(Date.now() + expiresIn * 1000).toISOString() : null;
    db.slackUpsertTeam(teamId, botUserId, seal(access), refresh ? seal(refresh) : null, expires);
}

async function botToken(teamId) {
    const row = db.slackTeam(teamId);
    if (!row) return null;
    const due = row.bot_expires_at && Date.parse(row.bot_expires_at) - Date.now() < 5 * 60 * 1000;
    if (!due || !row.bot_refresh_enc) return open(row.bot_token_enc);
    if (_refreshing.has(teamId)) return _refreshing.get(teamId);
    const run = (async () => {
        try {
            const data = await slack('oauth.v2.access', oauthParams({
                grant_type: 'refresh_token', refresh_token: open(row.bot_refresh_enc) }), { form: true });
            saveTeam(teamId, row.bot_user_id, data.access_token, data.refresh_token, data.expires_in);
            return data.access_token;
        } catch (e) {
            if (e.code === 'invalid_refresh_token' || e.code === 'token_revoked') db.slackForgetTeam(teamId);
            console.error(`[slack] bot refresh failed: ${e.code}`);
            return null;
        } finally {
            _refreshing.delete(teamId);
        }
    })();
    _refreshing.set(teamId, run);
    return run;
}

async function post(teamId, params) {
    const token = await botToken(teamId);
    if (!token) throw new SlackError('chat.postMessage', 'not_installed');
    return slack(params.ts ? 'chat.update' : 'chat.postMessage', params, { token });
}

// Fire-and-forget notes to a person (away, set-up). Failures are counted,
// never retried: the person can always send again.
function note(teamId, channel, text) {
    post(teamId, { channel, text }).catch((e) => {
        db.bumpMetric('slack.note.fail');
        console.error(`[slack] note failed: ${e.code}`);
    });
}

async function respond(responseUrl, text) {
    if (typeof responseUrl !== 'string' || !responseUrl.startsWith(config.slackHooksPrefix)) return;
    try {
        await fetch(responseUrl, { method: 'POST', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ response_type: 'ephemeral', text }), redirect: 'error',
            signal: AbortSignal.timeout(TIMEOUT_MS) });
    } catch {
        db.bumpMetric('slack.respond.fail');
    }
}

// ── Sign-ins waiting to be claimed (memory only) ────────────────────────
const _pending = new Map(); // state -> { installId|null, at, result, error }

function sweepPending(now = Date.now()) {
    for (const [state, p] of _pending) if (now - p.at > PENDING_TTL_MS) _pending.delete(state);
}

function newState(installId) {
    sweepPending();
    if (installId) {
        const mine = [..._pending].filter(([, p]) => p.installId === installId).sort((a, b) => a[1].at - b[1].at);
        while (mine.length >= PENDING_PER_INSTALL) _pending.delete(mine.shift()[0]);
    }
    if (!installId && [..._pending.values()].filter(p => !p.installId).length >= PENDING_KEYLESS_MAX) return null;
    if (_pending.size >= PENDING_MAX + PENDING_KEYLESS_MAX) return null;
    const state = crypto.randomBytes(32).toString('base64url');
    _pending.set(state, { installId, at: Date.now(), result: null, error: null });
    return state;
}

function authorizeUrl(state) {
    const u = new URL(config.slackAuthorizeUrl);
    u.searchParams.set('client_id', config.slackClientId);
    u.searchParams.set('scope', BOT_SCOPES.join(','));
    u.searchParams.set('user_scope', USER_SCOPES.join(','));
    u.searchParams.set('redirect_uri', config.slackRedirectUri);
    u.searchParams.set('state', state);
    return u.href;
}

function landing(res, result) {
    const u = new URL(config.slackInstalledUrl);
    u.searchParams.set('result', result);
    res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
    return res.redirect(302, u.href);
}

async function callback(req, res) {
    const q = req.query;
    const one = (k) => (typeof q[k] === 'string' ? q[k] : null);
    const state = one('state');
    const p = state && STATE.test(state) ? _pending.get(state) : null;
    if (!p || Date.now() - p.at > PENDING_TTL_MS || p.result || p.error) return landing(res, 'expired');
    if (one('error') || !one('code')) {
        p.error = 'denied';
        return landing(res, 'denied');
    }
    const code = one('code');
    if (!/^[\x21-\x7e]{1,512}$/.test(code)) { p.error = 'failed'; return landing(res, 'failed'); }
    let data;
    try {
        data = await slack('oauth.v2.access', oauthParams({ code, redirect_uri: config.slackRedirectUri }), { form: true });
    } catch (e) {
        p.error = 'failed';
        db.bumpMetric('slack.install.fail');
        console.error(`[slack] exchange failed: ${e.code}`);
        return landing(res, 'failed');
    }
    const teamId = data.team?.id, user = data.authed_user || {};
    if (!ID.team.test(teamId || '') || !ID.user.test(user.id || '') || typeof data.access_token !== 'string') {
        p.error = 'failed';
        console.error('[slack] exchange answered without a workspace, person or bot token');
        return landing(res, 'failed');
    }
    saveTeam(teamId, data.bot_user_id, data.access_token, data.refresh_token, data.expires_in);
    db.bumpMetric('slack.install');
    if (!p.installId) {
        // The direct install link: nobody's Mac is waiting, so the person's
        // user token has nowhere to go. Revoke it rather than hold it; they
        // authorize again from nenva on their Mac.
        if (typeof user.access_token === 'string') {
            slack('auth.revoke', {}, { token: user.access_token }).catch(() => {});
        }
        _pending.delete(state);
        return landing(res, 'installed');
    }
    if (typeof user.access_token !== 'string') { p.error = 'failed'; return landing(res, 'failed'); }
    db.slackBind(teamId, user.id, p.installId);
    p.result = {
        teamId, userId: user.id, accessToken: user.access_token,
        refreshToken: typeof user.refresh_token === 'string' ? user.refresh_token : null,
        expiresIn: Number.isFinite(user.expires_in) ? user.expires_in : null,
        scope: typeof user.scope === 'string' ? user.scope : ''
    };
    return landing(res, 'connected');
}

// ── Inbox: what waits for a Mac (memory only) ───────────────────────────
const _inbox = new Map(); // installId -> { items, waiter, lastPoll }

function box(installId) {
    let b = _inbox.get(installId);
    if (!b) { b = { items: [], waiter: null, lastPoll: 0 }; _inbox.set(installId, b); }
    return b;
}

function flush(b) {
    if (!b.waiter || !b.items.length) return;
    const { res, timer } = b.waiter;
    b.waiter = null;
    clearTimeout(timer);
    const items = b.items.splice(0).map(({ expires, ...item }) => item);
    res.json({ items });
}

// 'delivered' | 'away' | 'busy'. Nothing is held for a Mac that has not
// polled recently: telling the person at once beats a silent minute.
function deliver(installId, item) {
    const b = box(installId);
    if (Date.now() - b.lastPoll > POLL_FRESH_MS && !b.waiter) return 'away';
    if (b.items.length >= INBOX_MAX) return 'busy';
    b.items.push({ id: crypto.randomBytes(8).toString('hex'), at: new Date().toISOString(),
        ...item, expires: Date.now() + HOLD_MS });
    flush(b);
    return 'delivered';
}

// Unclaimed messages are dropped after HOLD_MS, and the person told.
function sweepInbox(now = Date.now()) {
    for (const [installId, b] of _inbox) {
        const keep = [];
        for (const item of b.items) {
            if (item.expires > now) { keep.push(item); continue; }
            db.bumpMetric('slack.message.away');
            if (item.kind === 'message') note(item.teamId, item.channel, COPY.away);
        }
        b.items = keep;
        if (!b.items.length && !b.waiter && now - b.lastPoll > PENDING_TTL_MS) _inbox.delete(installId);
    }
}

// ── Slack's requests: signature, retries ────────────────────────────────
function verified(req) {
    const ts = req.get('x-slack-request-timestamp') || '';
    const sig = req.get('x-slack-signature') || '';
    if (!/^\d{1,12}$/.test(ts) || Math.abs(Date.now() / 1000 - Number(ts)) > SIG_SKEW_S) return false;
    if (!/^v0=[a-f0-9]{64}$/.test(sig) || !Buffer.isBuffer(req.body)) return false;
    const mac = crypto.createHmac('sha256', config.slackSigningSecret);
    mac.update(`v0:${ts}:`);
    mac.update(req.body);
    const want = Buffer.from('v0=' + mac.digest('hex'));
    return crypto.timingSafeEqual(want, Buffer.from(sig));
}

const _seen = new Map(); // event_id -> at
function firstTime(eventId) {
    if (typeof eventId !== 'string' || !eventId) return true;
    if (_seen.has(eventId)) return false;
    if (_seen.size >= SEEN_MAX) _seen.delete(_seen.keys().next().value);
    _seen.set(eventId, Date.now());
    return true;
}

const _noted = new Map(); // team:user -> at
function noteOnce(teamId, userId, channel) {
    const k = `${teamId}:${userId}`;
    const last = _noted.get(k) || 0;
    if (Date.now() - last < NOTE_EVERY_MS) return;
    if (_noted.size >= SEEN_MAX) _noted.delete(_noted.keys().next().value);
    _noted.set(k, Date.now());
    note(teamId, channel, COPY.setUp);
}

function handleEvent(body) {
    const teamId = body.team_id;
    const ev = body.event || {};
    if (!ID.team.test(teamId || '')) return;
    if (ev.type === 'app_uninstalled') {
        db.slackForgetTeam(teamId);
        db.bumpMetric('slack.uninstall');
        return;
    }
    if (ev.type === 'tokens_revoked') {
        if (Array.isArray(ev.tokens?.bot) && ev.tokens.bot.length) db.slackForgetTeam(teamId);
        for (const u of Array.isArray(ev.tokens?.oauth) ? ev.tokens.oauth : []) {
            if (ID.user.test(u)) db.slackUnbind(teamId, u);
        }
        return;
    }
    // A person's own words to the bot, in the bot's DM. Edits, joins, files
    // and anything a bot wrote (including our own replies) are not.
    if (ev.type !== 'message' || ev.channel_type !== 'im' || ev.subtype || ev.bot_id) return;
    if (!ID.user.test(ev.user || '') || !ID.dm.test(ev.channel || '') || typeof ev.text !== 'string') return;
    const binding = db.slackBinding(teamId, ev.user);
    if (!binding) { db.bumpMetric('slack.unbound'); return noteOnce(teamId, ev.user, ev.channel); }
    if (binding.dm_channel !== ev.channel) db.slackSetDm(teamId, ev.user, ev.channel);
    db.bumpMetric('slack.message.in');
    const outcome = deliver(binding.install_id, {
        kind: 'message', teamId, userId: ev.user, channel: ev.channel,
        ts: TS.test(ev.ts || '') ? ev.ts : null,
        threadTs: TS.test(ev.thread_ts || '') ? ev.thread_ts : null,
        text: ev.text.slice(0, TEXT_MAX)
    });
    if (outcome !== 'delivered') {
        db.bumpMetric(`slack.message.${outcome}`);
        note(teamId, ev.channel, outcome === 'busy' ? COPY.busy : COPY.away);
    }
}

function handleInteraction(p) {
    const teamId = p.team?.id, userId = p.user?.id;
    if (!ID.team.test(teamId || '') || !ID.user.test(userId || '')) return;
    const binding = db.slackBinding(teamId, userId);
    if (p.type === 'message_action' && p.callback_id === 'send_to_nenva') {
        if (!binding) return respond(p.response_url, COPY.setUp);
        const channel = p.channel?.id, ts = p.message_ts || p.message?.ts;
        if (!ID.channel.test(channel || '') || !TS.test(ts || '')) return;
        const thread = p.message?.thread_ts;
        // The pointer only. The message text in this payload goes no further.
        const outcome = deliver(binding.install_id, { kind: 'shortcut', teamId, userId, channel, ts,
            threadTs: TS.test(thread || '') ? thread : null });
        db.bumpMetric(`slack.shortcut.${outcome}`);
        return respond(p.response_url, outcome === 'delivered' ? COPY.sent : outcome === 'busy' ? COPY.busy : COPY.shortcutAway);
    }
    if (p.type === 'block_actions') {
        if (!binding) return respond(p.response_url, COPY.setUp);
        const a = Array.isArray(p.actions) ? p.actions[0] : null;
        const channel = p.channel?.id || p.container?.channel_id;
        const messageTs = p.container?.message_ts || p.message?.ts;
        if (!a || typeof a.action_id !== 'string' || !ID.dm.test(channel || '') || channel !== binding.dm_channel) return;
        const outcome = deliver(binding.install_id, { kind: 'action', teamId, userId, channel,
            messageTs: TS.test(messageTs || '') ? messageTs : null,
            actionId: a.action_id.slice(0, 255), value: typeof a.value === 'string' ? a.value.slice(0, 2000) : null });
        db.bumpMetric(`slack.action.${outcome}`);
        if (outcome !== 'delivered') return respond(p.response_url, COPY.shortcutAway);
    }
}

// ── Reply validation ─────────────────────────────────────────────────────
function cleanBlocks(blocks) {
    if (blocks == null) return undefined;
    if (!Array.isArray(blocks) || blocks.length > 20) return null;
    if (!blocks.every(b => b && typeof b === 'object' && BLOCK_TYPES.has(b.type))) return null;
    if (Buffer.byteLength(JSON.stringify(blocks)) > BLOCKS_MAX_BYTES) return null;
    return blocks;
}

// ── Router ───────────────────────────────────────────────────────────────
// `auth` is server.js's key check (sets req.install). Raw bodies for the two
// signed routes are parsed in server.js before this runs.
function router(auth) {
    const r = express.Router();
    const off = (req, res, next) => (enabled() ? next()
        : res.status(503).json({ error: 'nenva in Slack is not set up on this server.' }));
    r.use(off);

    // The Mac begins a sign-in. The state is bound to its key.
    r.post('/install/start', auth, (req, res) => {
        const state = newState(req.install.install_id);
        if (!state) return res.status(503).json({ error: 'Too many sign-ins in progress. Try again shortly.' });
        res.json({ url: authorizeUrl(state), state, expiresIn: PENDING_TTL_MS / 1000 });
    });

    // The Marketplace's direct install link (no Mac, no key).
    r.get('/install', (req, res) => {
        const state = newState(null);
        if (!state) return res.status(503).type('text/plain').send('Try again shortly.');
        res.set('Cache-Control', 'no-store');
        res.redirect(302, authorizeUrl(state));
    });

    r.get('/oauth/callback', (req, res) => {
        callback(req, res).catch((e) => {
            console.error(`[slack] callback failed: ${e?.name || 'error'}`);
            if (!res.headersSent) landing(res, 'failed');
        });
    });

    // The Mac collects the person's own tokens, once.
    r.post('/install/claim', auth, (req, res) => {
        const state = req.body?.state;
        const p = typeof state === 'string' && STATE.test(state) ? _pending.get(state) : null;
        if (!p || p.installId !== req.install.install_id || Date.now() - p.at > PENDING_TTL_MS) {
            return res.status(404).json({ error: 'expired' });
        }
        if (p.error) { _pending.delete(state); return res.json({ error: p.error }); }
        if (!p.result) return res.status(202).json({ pending: true });
        _pending.delete(state);
        res.set('Cache-Control', 'no-store');
        res.json(p.result);
    });

    // Refreshing a person's rotating user token needs the client secret.
    r.post('/token/refresh', auth, async (req, res) => {
        const refresh = req.body?.refreshToken;
        if (typeof refresh !== 'string' || !/^xoxe-[\x21-\x7e]{8,500}$/.test(refresh)) {
            return res.status(400).json({ error: 'invalid_refresh_token' });
        }
        if (!db.slackBindingsFor(req.install.install_id).length) return res.status(403).json({ error: 'not_connected' });
        try {
            const data = await slack('oauth.v2.access', oauthParams({ grant_type: 'refresh_token', refresh_token: refresh }), { form: true });
            res.set('Cache-Control', 'no-store');
            res.json({ accessToken: data.access_token, refreshToken: data.refresh_token || null,
                expiresIn: Number.isFinite(data.expires_in) ? data.expires_in : null });
        } catch (e) {
            db.bumpMetric('slack.refresh.fail');
            res.status(e.code === 'invalid_refresh_token' || e.code === 'token_revoked' ? 401 : 502).json({ error: e.code });
        }
    });

    // Which Slack accounts this Mac is bound to (ids only).
    r.get('/bindings', auth, (req, res) => {
        res.json({ bindings: db.slackBindingsFor(req.install.install_id)
            .map(b => ({ teamId: b.team_id, userId: b.user_id, chatReady: !!b.dm_channel })) });
    });

    r.post('/disconnect', auth, (req, res) => {
        const teamId = req.body?.teamId;
        if (!ID.team.test(teamId || '')) return res.status(400).json({ error: 'invalid_team' });
        res.json({ removed: db.slackUnbindInstall(teamId, req.install.install_id) });
    });

    // The Mac's long-poll. One waiter per install; a newer poll ends the older.
    r.get('/inbox', auth, (req, res) => {
        const b = box(req.install.install_id);
        b.lastPoll = Date.now();
        if (b.waiter) {
            const old = b.waiter;
            b.waiter = null;
            clearTimeout(old.timer);
            old.res.json({ items: [] });
        }
        const wait = Math.min(WAIT_MAX_S, Math.max(0, parseInt(req.query.wait, 10) || 0));
        if (b.items.length || !wait) {
            const items = b.items.splice(0).map(({ expires, ...item }) => item);
            return res.json({ items });
        }
        const waiter = { res, timer: setTimeout(() => {
            if (b.waiter !== waiter) return;
            b.waiter = null;
            b.lastPoll = Date.now();
            res.json({ items: [] });
        }, wait * 1000) };
        b.waiter = waiter;
        req.on('close', () => {
            if (b.waiter === waiter) { b.waiter = null; clearTimeout(waiter.timer); }
        });
    });

    // The Mac answers. Only into the DM between the bot and its own person.
    r.post('/reply', auth, async (req, res) => {
        const { teamId, text, blocks, threadTs, updateTs } = req.body || {};
        if (!ID.team.test(teamId || '')) return res.status(400).json({ error: 'invalid_team' });
        const binding = db.slackBindingsFor(req.install.install_id).find(b => b.team_id === teamId);
        if (!binding) return res.status(403).json({ error: 'not_connected' });
        if (!binding.dm_channel) return res.status(409).json({ error: 'no_dm' });
        if (typeof text !== 'string' || !text.trim() || text.length > REPLY_TEXT_MAX) return res.status(400).json({ error: 'invalid_text' });
        const clean = cleanBlocks(blocks);
        if (clean === null) return res.status(400).json({ error: 'invalid_blocks' });
        for (const ts of [threadTs, updateTs]) if (ts != null && !TS.test(ts)) return res.status(400).json({ error: 'invalid_ts' });
        const params = { channel: binding.dm_channel, text };
        if (clean) params.blocks = clean;
        if (updateTs) params.ts = updateTs;
        else if (threadTs) params.thread_ts = threadTs;
        try {
            const data = await post(teamId, params);
            db.bumpMetric('slack.reply');
            res.json({ ts: TS.test(data.ts || '') ? data.ts : null });
        } catch (e) {
            db.bumpMetric('slack.reply.fail');
            res.status(e.code === 'not_installed' ? 409 : 502).json({ error: e.code });
        }
    });

    // Slack's Events API. Acknowledge first (3 s), then act.
    r.post('/events', (req, res) => {
        if (!verified(req)) return res.status(401).end();
        let body;
        try { body = JSON.parse(req.body.toString('utf8')); } catch { return res.status(400).end(); }
        if (body.type === 'url_verification' && typeof body.challenge === 'string') {
            return res.json({ challenge: body.challenge.slice(0, 256) });
        }
        res.status(200).end();
        if (body.type !== 'event_callback' || !firstTime(body.event_id)) return;
        try { handleEvent(body); } catch (e) { console.error(`[slack] event failed: ${e?.name || 'error'}`); }
    });

    // Buttons and the "Send to nenva" shortcut.
    r.post('/interactivity', (req, res) => {
        if (!verified(req)) return res.status(401).end();
        let p;
        try { p = JSON.parse(new URLSearchParams(req.body.toString('utf8')).get('payload') || ''); } catch { return res.status(400).end(); }
        res.status(200).end();
        Promise.resolve().then(() => handleInteraction(p))
            .catch((e) => console.error(`[slack] interaction failed: ${e?.name || 'error'}`));
    });

    return r;
}

function start() {
    setInterval(() => { sweepPending(); sweepInbox(); }, 5000).unref();
}

function stats() {
    return { enabled: enabled(), ...db.slackCounts(), waiting: _pending.size, macs: _inbox.size };
}

module.exports = { router, start, stats, enabled, BOT_SCOPES, USER_SCOPES, COPY,
    _test: { sweepInbox, sweepPending, _pending, _inbox, HOLD_MS } };
