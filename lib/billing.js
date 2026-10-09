// Billing phase P3 (anjadhe-app docs/BILLING.md): paid plans through Stripe.
//
// Everything Stripe-shaped lives here, so moving to another processor (or
// to Stripe as merchant of record) touches this file and its config only.
// Stripe's REST API is called with plain fetch and form encoding (no SDK,
// in keeping with the rest of Connect).
//
// Laws (BILLING.md B4–B8):
//  - A CODE, NOT AN ACCOUNT. A completed checkout mints a random 128-bit
//    code; the database keeps only its SHA-256. Installs attach to it, so
//    two Macs (and the iPhone through its Mac) share one plan.
//  - The buyer's email stays at Stripe. Nothing here reads
//    `customer_details`, `customer_email` or any address from an event,
//    and the smoke test's canary checks the database file for one.
//  - What reaches Connect from Stripe: the customer id (cus_…, for the
//    "Manage" portal), the subscription id (sub_…, to follow its status),
//    the price that was bought, the period end and the status.
//
// STRIPE_MOCK=1 swaps the network for canned answers so the whole flow
// (checkout → webhook → claim → attach → portal) runs in tests with no key.

const crypto = require('crypto');
const config = require('./config');

const API = 'https://api.stripe.com/v1';
const CODE_PREFIX = 'nenva-';

function enabled() {
    return config.stripeMock || !!(config.stripeSecretKey && config.stripeWebhookSecret);
}

// "plus" + "month" → the configured Stripe price id, or null.
function priceFor(plan, interval) {
    return config.stripePrices[`${plan}:${interval}`] || null;
}

// The reverse, for a webhook naming the price that was bought.
function planForPrice(priceId) {
    for (const [k, v] of Object.entries(config.stripePrices)) {
        if (v === priceId) {
            const [plan, interval] = k.split(':');
            return { plan, interval };
        }
    }
    return null;
}

// Stripe takes form encoding with bracketed keys: line_items[0][price]=…
function form(obj, prefix = '', out = new URLSearchParams()) {
    for (const [k, v] of Object.entries(obj)) {
        if (v === undefined || v === null) continue;
        const key = prefix ? `${prefix}[${k}]` : k;
        if (typeof v === 'object') form(v, key, out);
        else out.append(key, String(v));
    }
    return out;
}

async function stripe(method, path, body, version = config.stripeApiVersion) {
    const res = await fetch(API + path, {
        method,
        headers: {
            Authorization: `Bearer ${config.stripeSecretKey}`,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Stripe-Version': version
        },
        body: body ? form(body).toString() : undefined,
        signal: AbortSignal.timeout(20000)
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) {
        // Stripe's message names fields and ids, never card data; still,
        // the client gets a fixed message and the operator the detail.
        const err = new Error(`stripe ${method} ${path}: ${res.status} ${json?.error?.message || ''}`.trim());
        err.status = res.status;
        throw err;
    }
    return json;
}

let _mockN = 0;

/**
 * A hosted Checkout page for a subscription. `claim` is the opaque id the
 * app polls with; it rides as metadata and client_reference_id so the
 * webhook can find it again. The install id never goes to Stripe.
 */
// mode 'subscription' (a plan) or 'payment' (a one-time top-up). Stripe
// emails the receipt; the email address never reaches Connect.
async function createCheckout({ price, claim, successUrl, cancelUrl, mode = 'subscription' }) {
    if (config.stripeMock) {
        const id = `cs_mock_${++_mockN}`;
        return { id, url: `https://checkout.stripe.test/${id}` };
    }
    const body = checkoutBody({ price, claim, successUrl, cancelUrl, mode });
    // Where nenva sells is decided in the app (PlanUsage.SELLS_IN) and, off
    // Managed Payments, by a Radar rule: BILLING.md "Stripe setup".
    const session = await stripe('POST', '/checkout/sessions', body,
        config.stripeManaged ? config.stripeCheckoutApiVersion : config.stripeApiVersion);
    return { id: session.id, url: session.url };
}

// The Checkout Session request, pure so the tests can pin it. Under
// Managed Payments Stripe owns tax and the address it needs: it refuses
// automatic_tax (and needs a basil-or-later API version, chosen above).
function checkoutBody({ price, claim, successUrl, cancelUrl, mode = 'subscription' }) {
    const body = {
        mode,
        line_items: [{ price, quantity: 1 }],
        client_reference_id: claim,
        metadata: { claim },
        success_url: successUrl,
        cancel_url: cancelUrl,
        allow_promotion_codes: 'true'
    };
    if (config.stripeManaged) {
        body.managed_payments = { enabled: 'true' };
    } else {
        body.automatic_tax = { enabled: config.stripeTax ? 'true' : 'false' };
        // Stripe Tax needs an address; Checkout collects only what tax needs.
        body.billing_address_collection = config.stripeTax ? 'required' : 'auto';
    }
    if (mode === 'subscription') body.subscription_data = { metadata: { claim } };
    else body.payment_intent_data = { metadata: { claim } };
    return body;
}

/** The invoice a charge paid (for refunds and disputes on a plan). */
const _mockInvoices = new Map();
async function getInvoice(id) {
    if (config.stripeMock) return _mockInvoices.get(id) || null;
    return stripe('GET', `/invoices/${encodeURIComponent(id)}`);
}
function setMockInvoice(id, invoice) { _mockInvoices.set(id, invoice); }

/** Stripe's customer portal (change plan, card, cancel, receipts). */
async function createPortal({ customer, returnUrl }) {
    if (config.stripeMock) return { url: `https://billing.stripe.test/p/${customer}` };
    const s = await stripe('POST', '/billing_portal/sessions', { customer, return_url: returnUrl });
    return { url: s.url };
}

/** The subscription as the webhook needs it (price, status, period end). */
async function getSubscription(id) {
    if (config.stripeMock) return null;
    return stripe('GET', `/subscriptions/${encodeURIComponent(id)}`);
}

/**
 * Verify Stripe's `Stripe-Signature` header over the RAW body: HMAC-SHA256
 * of "<t>.<body>" with the endpoint secret, compared in constant time
 * against every v1 signature, and refused when older than the tolerance.
 */
function verifySignature(rawBody, header, secret = config.stripeWebhookSecret, toleranceSec = 300, now = Date.now()) {
    if (!secret || !header || !Buffer.isBuffer(rawBody)) return false;
    const parts = {};
    for (const item of String(header).split(',')) {
        const [k, v] = item.split('=');
        if (!k || !v) continue;
        (parts[k.trim()] = parts[k.trim()] || []).push(v.trim());
    }
    const t = parseInt((parts.t || [])[0], 10);
    if (!Number.isFinite(t) || Math.abs(now / 1000 - t) > toleranceSec) return false;
    const expected = crypto.createHmac('sha256', secret).update(`${t}.`).update(rawBody).digest();
    return (parts.v1 || []).some(sig => {
        let got;
        try { got = Buffer.from(sig, 'hex'); } catch { return false; }
        return got.length === expected.length && crypto.timingSafeEqual(got, expected);
    });
}

/** For tests and the mock: a header Stripe would send for this body. */
function signForTest(rawBody, secret = config.stripeWebhookSecret, t = Math.floor(Date.now() / 1000)) {
    const sig = crypto.createHmac('sha256', secret).update(`${t}.`).update(rawBody).digest('hex');
    return `t=${t},v1=${sig}`;
}

/** A code a person can type: nenva-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-X (128 bits, Crockford base32). */
function mintCode() {
    const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    const bytes = crypto.randomBytes(17); // 136 bits, 26 chars ≥ 128 bits
    let bits = 0, value = 0, out = '';
    for (const b of bytes) {
        value = (value << 8) | b; bits += 8;
        while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
    }
    out = out.slice(0, 26);
    return CODE_PREFIX + out.match(/.{1,5}/g).join('-');
}

/** Normalize what a person typed (case, spaces, dashes, I/L/O look-alikes). */
function normalizeCode(input) {
    const raw = String(input || '').trim().toUpperCase().replace(/^NENVA[-\s]*/, '').replace(/[\s-]/g, '')
        .replace(/[IL]/g, '1').replace(/O/g, '0');
    if (!/^[0-9A-HJKMNP-TV-Z]{26}$/.test(raw)) return null;
    return CODE_PREFIX + raw.match(/.{1,5}/g).join('-');
}

function hashCode(code) {
    return crypto.createHash('sha256').update(String(code)).digest('hex');
}

// Stripe subscription status → ours. trialing counts as active; unpaid and
// incomplete_expired end the plan like a cancellation.
function mapStatus(s) {
    if (s === 'active' || s === 'trialing') return 'active';
    if (s === 'past_due' || s === 'incomplete') return 'past_due';
    return 'canceled';
}

// The period end moved from the subscription to its items in newer API
// versions; read either.
function periodEndOf(sub) {
    const t = sub?.current_period_end ?? sub?.items?.data?.[0]?.current_period_end;
    return Number.isFinite(t) ? new Date(t * 1000).toISOString() : null;
}

function priceOf(sub) {
    return sub?.items?.data?.[0]?.price?.id || null;
}

/** A top-up pack on sale: { id, price, searches?, tokens? } or null. */
function topupPack(id) {
    const p = config.stripeTopups[id];
    if (!p || !p.price) return null;
    return { id, price: p.price, searches: Math.max(0, parseInt(p.searches, 10) || 0), tokens: Math.max(0, parseInt(p.tokens, 10) || 0) };
}

module.exports = {
    enabled, priceFor, planForPrice, createCheckout, checkoutBody, createPortal, getSubscription, getInvoice, setMockInvoice, topupPack,
    verifySignature, signForTest, mintCode, normalizeCode, hashCode, mapStatus, periodEndOf, priceOf, form
};
