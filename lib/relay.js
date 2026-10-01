// Zero-knowledge mobile-sync relay (/v1/relay/<routingId>) — the hosted
// deployment of the app repo's relay/server.js, replacing the anjadhe-relay
// Cloudflare Worker. It matches a user's Mac ("host") with their paired
// phones ("client") by an opaque routing ID and forwards frames between
// them.
//
// PRIVACY INVARIANT (same discipline as the rest of Connect):
//   - the relay never holds an encryption key and never inspects payloads —
//     they are end-to-end encrypted with a Noise session established
//     directly between the Mac and the phone; only the small routing
//     envelope (frame type + destination id) is read;
//   - routing ids live in process memory only — never written to the DB or
//     logs. Observability is service-wide daily counters, nothing per-room;
//   - keyless by design: tying connections to anck_ keys would let relay
//     activity be joined against a machine's search usage.
//
// Protocol (all frames are JSON text — unchanged from relay/server.js):
//   hello       peer  -> relay    { t:'hello', routingId, role:'host'|'client',
//                                   hostKey? }   hostKey (hosts only, ≤128
//                                   chars): continuity proof — a live keyed
//                                   host is only replaced by the same key
//   welcome     relay -> host     { t:'welcome' }
//   welcome     relay -> client   { t:'welcome', clientId }
//   peer-join   relay -> host     { t:'peer-join', clientId }
//   peer-leave  relay -> host     { t:'peer-leave', clientId }
//   host-state  relay -> client   { t:'host-state', online:boolean }
//   data        client -> relay   { t:'data', payload }
//   data        host   -> relay   { t:'data', to:clientId, payload }
//   data        relay  -> host    { t:'data', from:clientId, payload }
//   data        relay  -> client  { t:'data', payload }
//   error       relay  -> peer    { t:'error', message }
//
// Unlike the Worker (per-room Durable Objects), every room shares this one
// Node process — hence the 1 MiB frame cap: parsing a frame's JSON envelope
// happens on the same event loop that serves /v1/search, so frames must be
// small. The app's channel layer chunks large sync payloads to fit
// (channel-endpoint.mjs); the relay forwards chunk frames like any other
// opaque payload.
'use strict';
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const db = require('./db');
const { capLimiter, ipBucket } = require('./limiter');

const MAX_FRAME_BYTES = 1024 * 1024;
const MAX_ROUTING_ID = 128;
const HELLO_TIMEOUT_MS = 10000;   // connected but silent — drop
const HEARTBEAT_MS = 30000;       // ws ping; also reaps dead sockets
const MAX_ROOMS = 5000;
const MAX_CLIENTS_PER_ROOM = 8;   // one user's phones, not a crowd
const CONNECTS_PER_IP_PER_MIN = 30;
const MAX_SOCKETS_PER_IP = 20;    // live connections, not connects/min — one
                                  // user's Mac + phones, never a socket farm
// Per-connection forwarding budget per minute. Sized for a chunked full
// data sync (tens of ~1 MiB frames) with lots of headroom, while making
// the relay useless as a general-purpose proxy.
const FRAMES_PER_MIN = 1200;
const BYTES_PER_MIN = 256 * 1024 * 1024;
// Service-wide forwarding ceiling — the per-connection budget bounds one
// socket, but sockets × budget was unbounded (an egress-bill attack). Far
// above what a fleet of real users syncing needs; an emergency brake only.
const GLOBAL_BYTES_PER_MIN = 4 * 1024 * 1024 * 1024;
let _globalBytes = { windowStart: 0, bytes: 0 };

// routingId -> { host: ws|null, hostKey: string|null, clients: Map<clientId, ws> }
const rooms = new Map();

function getRoom(id) {
    let r = rooms.get(id);
    if (!r) { r = { host: null, hostKey: null, clients: new Map() }; rooms.set(id, r); }
    return r;
}
function pruneRoom(id) {
    const r = rooms.get(id);
    if (r && !r.host && r.clients.size === 0) rooms.delete(id);
}
function send(ws, obj) {
    if (ws && ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
}

// Live sockets per IP — a hard cap on concurrent connections, on top of the
// per-minute connect window (30 connects/min for a minute-long-lived socket
// would still allow thousands live at once).
const _socketsByIp = new Map(); // ip -> live socket count

// Origins that may open a browser-context connection. Native clients send
// no Origin header; the Capacitor/Ionic WebViews send their local shell.
const ORIGIN_OK = /^(capacitor|ionic):\/\/localhost$|^https?:\/\/localhost(:\d+)?$/;
function allowOrigin(origin) {
    if (ORIGIN_OK.test(origin)) return true;
    return (process.env.RELAY_ALLOWED_ORIGINS || '')
        .split(',').map((s) => s.trim()).filter(Boolean).includes(origin);
}

const _connectsByIp = new Map(); // ip -> {windowStart, count}
function allowConnect(ip) {
    const now = Date.now();
    capLimiter(_connectsByIp, (v) => now - v.windowStart >= 60000);
    const cur = _connectsByIp.get(ip);
    if (!cur || now - cur.windowStart >= 60000) {
        _connectsByIp.set(ip, { windowStart: now, count: 1 });
        return true;
    }
    if (cur.count >= CONNECTS_PER_IP_PER_MIN) return false;
    cur.count++;
    return true;
}

// Per-connection forwarding throttle; state lives on the socket.
function allowFrame(ws, bytes) {
    const now = Date.now();
    if (!ws.budget || now - ws.budget.windowStart >= 60000) {
        ws.budget = { windowStart: now, frames: 0, bytes: 0 };
    }
    ws.budget.frames++;
    ws.budget.bytes += bytes;
    return ws.budget.frames <= FRAMES_PER_MIN && ws.budget.bytes <= BYTES_PER_MIN;
}

function handleHello(ws, msg) {
    const okRole = msg.role === 'host' || msg.role === 'client';
    const okId = typeof msg.routingId === 'string'
        && msg.routingId.length > 0 && msg.routingId.length <= MAX_ROUTING_ID;
    if (msg.t !== 'hello' || !okRole || !okId) {
        db.bumpMetric('relay.reject.hello');
        send(ws, { t: 'error', message: 'expected valid hello' });
        return ws.close();
    }
    const room = rooms.get(msg.routingId) || null;
    if (!room && rooms.size >= MAX_ROOMS) {
        db.bumpMetric('relay.reject.rooms');
        send(ws, { t: 'error', message: 'relay full' });
        return ws.close();
    }
    if (msg.role === 'host') {
        const r = getRoom(msg.routingId);
        // Host continuity (2026-08-05). This used to be last-writer-wins,
        // so anyone who learned a routing id could evict the user's Mac in
        // a loop — a permanent sync DoS. A host hello may now carry a
        // `hostKey` (the app derives it from its Noise static key); a LIVE
        // keyed host is only replaced by a peer presenting the same key.
        // A keyless live host keeps last-writer-wins (legacy apps), and an
        // empty host slot may always be claimed — the key protects a
        // connected Mac, it is not room ownership (phones still verify the
        // real Mac end-to-end via the Noise handshake).
        const givenKey = typeof msg.hostKey === 'string' && msg.hostKey.length <= 128
            ? msg.hostKey : null;
        if (r.host && r.host !== ws && r.hostKey && givenKey !== r.hostKey) {
            db.bumpMetric('relay.reject.hostkey');
            send(ws, { t: 'error', message: 'host slot held' });
            pruneRoom(msg.routingId);
            return ws.close();
        }
        if (r.host && r.host !== ws) { try { r.host.close(); } catch { /* already dead */ } }
        r.host = ws;
        r.hostKey = givenKey;
        ws.meta = { routingId: msg.routingId, role: 'host' };
        db.bumpMetric('relay.connect.host');
        send(ws, { t: 'welcome' });
        for (const clientId of r.clients.keys()) send(ws, { t: 'peer-join', clientId });
    } else {
        const r = getRoom(msg.routingId);
        if (r.clients.size >= MAX_CLIENTS_PER_ROOM) {
            db.bumpMetric('relay.reject.clients');
            send(ws, { t: 'error', message: 'room full' });
            pruneRoom(msg.routingId);
            return ws.close();
        }
        const clientId = crypto.randomBytes(8).toString('hex');
        r.clients.set(clientId, ws);
        ws.meta = { routingId: msg.routingId, role: 'client', clientId };
        db.bumpMetric('relay.connect.client');
        send(ws, { t: 'welcome', clientId });
        send(ws, { t: 'host-state', online: !!r.host });
        send(r.host, { t: 'peer-join', clientId });
    }
}

function unregister(ws) {
    if (!ws.meta) return;
    const { routingId, role, clientId } = ws.meta;
    const room = rooms.get(routingId);
    if (!room) return;
    if (role === 'host') {
        if (room.host === ws) {
            room.host = null;
            for (const c of room.clients.values()) send(c, { t: 'host-state', online: false });
        }
    } else {
        room.clients.delete(clientId);
        send(room.host, { t: 'peer-leave', clientId });
    }
    pruneRoom(routingId);
}

function forward(ws, msg, rawBytes) {
    if (typeof msg.payload !== 'string') return; // opaque ciphertext only
    const now = Date.now();
    if (now - _globalBytes.windowStart >= 60000) _globalBytes = { windowStart: now, bytes: 0 };
    _globalBytes.bytes += rawBytes;
    if (_globalBytes.bytes > GLOBAL_BYTES_PER_MIN) {
        db.bumpMetric('relay.reject.globalbytes');
        send(ws, { t: 'error', message: 'relay busy — retry shortly' });
        return ws.close();
    }
    if (!allowFrame(ws, rawBytes)) {
        db.bumpMetric('relay.reject.throttle');
        send(ws, { t: 'error', message: 'forwarding budget exceeded — slow down' });
        return ws.close();
    }
    db.bumpMetric('relay.frames');
    const { routingId, role, clientId } = ws.meta;
    const room = rooms.get(routingId);
    if (!room) return;
    if (role === 'client') {
        send(room.host, { t: 'data', from: clientId, payload: msg.payload });
    } else {
        send(room.clients.get(msg.to), { t: 'data', payload: msg.payload });
    }
}

function attach(server) {
    const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_FRAME_BYTES });

    server.on('upgrade', (req, socket, head) => {
        const path = (req.url || '').split('?')[0];
        if (!(path === '/v1/relay' || path.startsWith('/v1/relay/'))) {
            socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
            return socket.destroy();
        }
        // Browsers always send Origin on a WebSocket upgrade and CORS does
        // not apply to WebSockets, so without this any web page could turn
        // its visitors' browsers into relay traffic. Native clients — the
        // Mac app's ws, the Capacitor WebView — send no Origin or a
        // local-shell one; anything else must be allowlisted via env.
        const origin = String(req.headers.origin || '');
        if (origin && !allowOrigin(origin)) {
            db.bumpMetric('relay.reject.origin');
            socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
            return socket.destroy();
        }
        // Railway terminates TLS in front of us; the client IP is the first
        // hop in x-forwarded-for (same trust as Express's `trust proxy: 1`).
        const fwd = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
        const ip = ipBucket(fwd || req.socket.remoteAddress || '');
        if (!allowConnect(ip) || (_socketsByIp.get(ip) || 0) >= MAX_SOCKETS_PER_IP) {
            db.bumpMetric('relay.reject.ip');
            socket.write('HTTP/1.1 429 Too Many Requests\r\n\r\n');
            return socket.destroy();
        }
        wss.handleUpgrade(req, socket, head, (ws) => {
            ws.ip = ip;
            _socketsByIp.set(ip, (_socketsByIp.get(ip) || 0) + 1);
            wss.emit('connection', ws);
        });
    });

    wss.on('connection', (ws) => {
        ws.meta = null;      // set once the hello handshake succeeds
        ws.alive = true;
        const helloTimer = setTimeout(() => {
            if (!ws.meta) { try { ws.close(); } catch { /* already closed */ } }
        }, HELLO_TIMEOUT_MS);

        ws.on('pong', () => { ws.alive = true; });
        ws.on('message', (raw) => {
            let msg;
            try { msg = JSON.parse(raw.toString()); }
            catch { return send(ws, { t: 'error', message: 'bad json' }); }
            if (!ws.meta) return handleHello(ws, msg);
            if (msg.t === 'data') return forward(ws, msg, raw.length);
            // unknown post-handshake messages are ignored
        });
        ws.on('close', () => {
            clearTimeout(helloTimer);
            unregister(ws);
            if (ws.ip !== undefined) {
                const n = (_socketsByIp.get(ws.ip) || 1) - 1;
                if (n <= 0) _socketsByIp.delete(ws.ip);
                else _socketsByIp.set(ws.ip, n);
                ws.ip = undefined; // close can only decrement once
            }
        });
        ws.on('error', () => { try { ws.close(); } catch { /* already closed */ } });
    });

    // Protocol-level heartbeat: keeps NAT mappings warm for the always-on
    // Mac connections and reaps sockets that died without a close frame.
    const heartbeat = setInterval(() => {
        for (const ws of wss.clients) {
            if (!ws.alive) { try { ws.terminate(); } catch { /* gone */ } continue; }
            ws.alive = false;
            try { ws.ping(); } catch { /* closing */ }
        }
    }, HEARTBEAT_MS);
    heartbeat.unref();

    return wss;
}

// Live gauges for /v1/admin/overview — counts only, no routing ids.
function stats() {
    let hosts = 0, clients = 0;
    for (const r of rooms.values()) {
        if (r.host) hosts++;
        clients += r.clients.size;
    }
    return { rooms: rooms.size, hosts, clients };
}

module.exports = { attach, stats };
