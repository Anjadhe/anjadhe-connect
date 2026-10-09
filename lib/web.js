// Website analytics (nenva.co) — the site's own visitor counts, in place of
// a third-party analytics script (Vercel Analytics was removed 2026-09-25).
//
// The shape is Plausible's: no cookie, nothing in the browser's storage, and
// a visitor is sha256(daily salt + IP + user agent). The salt is random, one
// per UTC day, and deleted when the day ends — so a visitor can be counted
// once today, but no one (the operator included) can link today's visitor
// to yesterday's. The IP and user agent exist only in the request; neither
// is ever written anywhere (the smoke test's canary scans the database file
// for both).
//
// Everything a row can hold is normalized HERE, against a closed vocabulary:
// three event names, a site path, a referring HOST (never a URL), a
// utm_source word, a two-letter country, a device class. A value that does
// not fit is dropped or blanked, never stored as sent.
'use strict';
const crypto = require('crypto');

const EVENTS = new Set(['view', 'download', 'signup']);
const DEVICES = new Set(['mobile', 'tablet', 'desktop']);

// The site's own hosts — a referrer from one of these is navigation, not a
// source. Every domain the site has answered on.
const OWN_HOSTS = /(^|\.)(nenva\.co|anjadhe\.ai|anjadhe\.com)$/;

// Crawlers, link unfurlers, monitors and scripts. Vocabulary, not a
// verdict: anything that names itself one of these is not a visitor.
const BOT_RX = /bot\b|bot\/|crawl|spider|slurp|headless|lighthouse|pagespeed|prerender|preview|facebookexternalhit|embedly|whatsapp|telegram|curl\/|wget\/|python|httpclient|http-client|axios|node-fetch|undici|go-http|java\/|okhttp|monitor|uptime/i;

function isBot(ua) {
    return !ua || ua.length < 20 || BOT_RX.test(ua);
}

// A site path: leading slash, URL-safe characters only, no query or hash,
// no trailing slash (except the root). Anything else is not a page on the
// site and the event is dropped.
function normPath(raw) {
    let p = String(raw || '').split(/[?#]/)[0];
    if (p.length > 1) p = p.replace(/\/+$/, '');
    if (!/^\/[A-Za-z0-9/_.~-]{0,119}$/.test(p)) return null;
    return p;
}

// A referring host, lowercased, www. dropped. The site sends the host
// only; a URL, a path or the site's own host blanks it.
function normReferrer(raw) {
    let h = String(raw || '').trim().toLowerCase();
    if (!h) return '';
    if (!/^[a-z0-9.-]{1,80}$/.test(h)) return '';
    h = h.replace(/^www\./, '');
    if (OWN_HOSTS.test(h)) return '';
    return h;
}

// utm_source (or ?ref=): one short word.
function normSource(raw) {
    const s = String(raw || '').trim().toLowerCase();
    return /^[a-z0-9._-]{1,40}$/.test(s) ? s : '';
}

function normCountry(raw) {
    const c = String(raw || '').trim().toUpperCase();
    return /^[A-Z]{2}$/.test(c) && c !== 'XX' ? c : '';
}

// The body the site's /api/e route forwards. Returns the row dimensions, or
// null when the event is not one we count.
function normalize(body) {
    const event = String(body?.event || '');
    if (!EVENTS.has(event)) return null;
    const path = normPath(body?.path);
    if (!path) return null;
    const device = DEVICES.has(body?.device) ? body.device : '';
    // Where a visit came from is a property of the landing view only; the
    // clicks that follow carry no referrer or source.
    const landing = event === 'view';
    return {
        event,
        path,
        referrer: landing ? normReferrer(body?.referrer) : '',
        source: landing ? normSource(body?.source) : '',
        country: normCountry(body?.country),
        device
    };
}

function visitorId(salt, ip, ua) {
    return crypto.createHash('sha256').update(`${salt}|${ip}|${ua}`).digest('hex').slice(0, 32);
}

module.exports = { EVENTS, normalize, normPath, normReferrer, normSource, isBot, visitorId };
