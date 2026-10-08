'use strict';

// A browser handoff only. No token exchange, storage, logging, cookies, or
// outbound request. The Mac must still validate its pending state and PKCE.
const CALLBACK_PATH = '/v1/oauth/slack/callback';
const LOOPBACK_URI = 'http://localhost:42819/callback';
const ISSUER = 'https://mcp.slack.com';

function callback(req, res) {
    res.set({
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache',
        'Referrer-Policy': 'no-referrer',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    });
    res.type('text/plain');
    if (req.method !== 'GET') {
        res.set('Allow', 'GET');
        return res.status(405).send('Start Slack sign-in from nenva on your Mac.');
    }
    const invalid = () => res.status(400).send('Could not verify the sign-in response. Return to nenva and connect Slack again.');
    if (req.originalUrl.length > 8192) return invalid();
    const params = new URL(req.originalUrl, 'https://api.nenva.co').searchParams;
    if (![...params].length) return res.status(200).send('nenva Slack sign-in callback. Start sign-in from Settings > Connectors > Slack in nenva and keep the app running.');
    for (const key of ['state', 'code', 'error', 'iss']) {
        if (params.getAll(key).length > 1) return invalid();
    }
    const state = params.get('state');
    if (!state || !/^[A-Za-z0-9_-]{43}$/.test(state)) return invalid();
    const code = params.get('code'), error = params.get('error'), issuer = params.get('iss');
    if (params.has('code') === params.has('error')) return invalid();
    if (params.has('code') && (!code || !/^[\x21-\x7e]{1,2048}$/.test(code))) return invalid();
    if (params.has('error') && (!error || !/^[a-zA-Z0-9_]{1,128}$/.test(error))) return invalid();
    if (params.has('iss') && issuer !== ISSUER) return invalid();

    // Never accept a return URL, host or port from the request. Drop all
    // extra parameters (including descriptions, tokens and redirect targets).
    const target = new URL(LOOPBACK_URI);
    target.searchParams.set('state', state);
    if (code) target.searchParams.set('code', code);
    else target.searchParams.set('error', 'access_denied');
    if (issuer) target.searchParams.set('iss', issuer);
    res.set('Location', target.href);
    // Avoid Express redirect() reflecting the result into an HTML body.
    return res.status(302).send('Returning to nenva on this Mac. Keep nenva running to finish sign-in.');
}

module.exports = { CALLBACK_PATH, LOOPBACK_URI, callback };
