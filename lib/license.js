// License keys — the app's one-time license, verified OFFLINE by the app.
//
// A license is a short string the user can paste or keep as a file:
//
//     ANJ1.<payload b64url>.<signature b64url>
//
// payload = JSON {v:1, id, class:'alpha'|'paid', sub, issuedAt, updatesUntil}
//   id           16 hex chars, random — names the license in the admin list
//   class        'alpha' (free for good, updates forever) or 'paid'
//   sub          first 32 hex of SHA-256(lowercased email) — binds the key to
//                the person who claimed it WITHOUT carrying the address; the
//                app can show "issued to r***@example.com" only from the
//                address the user typed locally, never from the key
//   issuedAt     YYYY-MM-DD
//   updatesUntil YYYY-MM-DD, or null = forever (alpha)
// signature = Ed25519 over the raw payload bytes (what the b64url decodes to),
//             so there is no canonicalisation step to get wrong on either side.
//
// The private seed lives ONLY in LICENSE_SIGNING_KEY (base64 of the 32-byte
// Ed25519 seed); the matching public key is baked into the app
// (js/main/license-store.js). Nothing here can check a license against a
// server, and that is the point: the app's "no account" promise survives
// because verification needs the public key and nothing else. There is no
// revocation — the source is public, enforcement is honour-system by design
// (BUSINESS_MODEL.md in the app repo).
'use strict';
const crypto = require('crypto');

const PREFIX = 'ANJ1';
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const CLASSES = new Set(['alpha', 'paid']);
const DATE_RX = /^\d{4}-\d{2}-\d{2}$/;

function privateKeyFromSeed(seedB64) {
    const seed = Buffer.from(String(seedB64 || ''), 'base64');
    if (seed.length !== 32) throw new Error('LICENSE_SIGNING_KEY must be the base64 of a 32-byte Ed25519 seed');
    return crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' });
}

function publicKeyRaw(privateKey) {
    return crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(SPKI_PREFIX.length);
}

function subjectHash(email) {
    return crypto.createHash('sha256').update(String(email).trim().toLowerCase()).digest('hex').slice(0, 32);
}

function b64url(buf) { return Buffer.from(buf).toString('base64url'); }

// Mint a license. `updatesUntil` null means forever (the alpha class); a
// paid license gets a date. The payload is minimal on purpose — anything
// more (a name, the address) would make the key itself a record of the person.
function mint(privateKey, { cls, email, updatesUntil = null, issuedAt = null, id = null }) {
    if (!CLASSES.has(cls)) throw new Error('class must be alpha or paid');
    if (updatesUntil !== null && !DATE_RX.test(updatesUntil)) throw new Error('updatesUntil must be YYYY-MM-DD or null');
    const payload = {
        v: 1,
        id: id || crypto.randomBytes(8).toString('hex'),
        class: cls,
        sub: subjectHash(email),
        issuedAt: issuedAt || new Date().toISOString().slice(0, 10),
        updatesUntil
    };
    const bytes = Buffer.from(JSON.stringify(payload), 'utf8');
    const sig = crypto.sign(null, bytes, privateKey);
    return { key: `${PREFIX}.${b64url(bytes)}.${b64url(sig)}`, payload };
}

// Verify a license string against a raw 32-byte public key. Returns
// {ok, payload} or {ok:false, error}. The same logic ships in the app;
// keep the two in step (a test on each side pins the format).
function verify(key, publicKeyRaw) {
    try {
        const parts = String(key || '').trim().split('.');
        if (parts.length !== 3 || parts[0] !== PREFIX) return { ok: false, error: 'Not an Anjadhe license key' };
        const bytes = Buffer.from(parts[1], 'base64url');
        const sig = Buffer.from(parts[2], 'base64url');
        const pub = { key: Buffer.concat([SPKI_PREFIX, Buffer.from(publicKeyRaw)]), format: 'der', type: 'spki' };
        if (sig.length !== 64 || !crypto.verify(null, bytes, pub, sig)) return { ok: false, error: 'Signature does not match' };
        const p = JSON.parse(bytes.toString('utf8'));
        if (p.v !== 1 || !CLASSES.has(p.class) || !/^[a-f0-9]{16}$/.test(p.id || '')
            || !/^[a-f0-9]{32}$/.test(p.sub || '') || !DATE_RX.test(p.issuedAt || '')
            || (p.updatesUntil !== null && !DATE_RX.test(p.updatesUntil || ''))) {
            return { ok: false, error: 'License payload is malformed' };
        }
        return { ok: true, payload: p };
    } catch {
        return { ok: false, error: 'License key could not be read' };
    }
}

module.exports = { PREFIX, privateKeyFromSeed, publicKeyRaw, subjectHash, mint, verify, CLASSES };
