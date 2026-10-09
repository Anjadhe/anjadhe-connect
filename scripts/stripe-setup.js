// Sets up nenva's Stripe account (sandbox or live) for Connect's billing:
// products + prices (with the tax code Managed Payments needs), the customer
// portal, the webhook endpoint.
// Safe to re-run: prices are found by lookup_key, the webhook by URL.
//
//   node scripts/stripe-setup.js <file holding sk_test_… or sk_live_…>
//
// Prints the Railway env values at the end.

const fs = require('fs');
const key = fs.readFileSync(process.argv[2], 'utf8').trim();
if (!/^sk_(test|live)_/.test(key)) throw new Error('expected a secret key (sk_test_… / sk_live_…)');
const LIVE = key.startsWith('sk_live_');

const API = 'https://api.stripe.com/v1';
const VERSION = '2024-06-20'; // Connect's pinned STRIPE_API_VERSION
const WEBHOOK_URL = 'https://api.nenva.co/v1/billing/webhook';
const EVENTS = [
    'checkout.session.completed',
    'customer.subscription.created',
    'customer.subscription.updated',
    'customer.subscription.deleted',
    'invoice.paid',
    'charge.refunded',
    'charge.dispute.created'
];

// Managed Payments needs an eligible tax code on every product. nenva is a
// downloaded app working with cloud AI, sold to people for personal use:
// "AI as a Service - Cloud Based & Downloaded - Personal Use".
const TAX_CODE = 'txcd_10105003';

// Amounts in cents. Sandbox placeholders until the real prices are decided.
const PRODUCTS = [
    { id: 'plus', name: 'nenva Plus', prices: [
        { lookup: 'plus_month', amount: 500, interval: 'month' },
        { lookup: 'plus_year', amount: 5000, interval: 'year' }] },
    { id: 'pro', name: 'nenva Pro', prices: [
        { lookup: 'pro_month', amount: 1200, interval: 'month' },
        { lookup: 'pro_year', amount: 12000, interval: 'year' }] },
    { id: 'searches', name: '2,000 web searches', prices: [
        { lookup: 'searches_2000', amount: 500 }] },
    { id: 'cloud', name: 'More nenva cloud', prices: [
        { lookup: 'cloud_5m', amount: 500 }] }
];

function form(obj, prefix = '', out = new URLSearchParams()) {
    for (const [k, v] of Object.entries(obj)) {
        if (v === undefined || v === null) continue;
        const name = prefix ? `${prefix}[${k}]` : k;
        if (typeof v === 'object') form(v, name, out);
        else out.append(name, String(v));
    }
    return out;
}

async function stripe(method, path, body) {
    const isGet = method === 'GET';
    const qs = isGet && body ? '?' + form(body).toString() : '';
    const res = await fetch(API + path + qs, {
        method,
        headers: {
            Authorization: `Bearer ${key}`,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Stripe-Version': VERSION
        },
        body: !isGet && body ? form(body).toString() : undefined
    });
    const json = await res.json();
    if (!res.ok) throw new Error(`${method} ${path}: ${json.error?.message}`);
    return json;
}

async function main() {
    console.log(`Mode: ${LIVE ? 'LIVE' : 'sandbox'}\n`);
    const ids = {};
    const productIds = {};

    for (const p of PRODUCTS) {
        const productId = `nenva_${p.id}`;
        let product;
        try { product = await stripe('POST', `/products/${productId}`, { tax_code: TAX_CODE }); }
        catch { product = await stripe('POST', '/products', { id: productId, name: p.name, tax_code: TAX_CODE }); }
        productIds[p.id] = product.id;
        for (const pr of p.prices) {
            const found = await stripe('GET', '/prices', { lookup_keys: [pr.lookup], active: 'true' });
            let price = found.data[0];
            if (!price) {
                price = await stripe('POST', '/prices', {
                    product: product.id,
                    currency: 'usd',
                    unit_amount: pr.amount,
                    lookup_key: pr.lookup,
                    recurring: pr.interval ? { interval: pr.interval } : undefined
                });
                console.log(`created ${p.name} ${pr.interval || 'one-time'} ${price.id}`);
            } else {
                console.log(`exists  ${p.name} ${pr.interval || 'one-time'} ${price.id}`);
            }
            ids[pr.lookup] = price.id;
        }
    }

    // Customer portal: update the account's default configuration.
    const configs = await stripe('GET', '/billing_portal/configurations', { is_default: 'true', limit: 1 });
    const portal = {
        business_profile: {
            privacy_policy_url: 'https://nenva.co/privacy',
            terms_of_service_url: 'https://nenva.co/terms'
        },
        features: {
            invoice_history: { enabled: 'true' },
            payment_method_update: { enabled: 'true' },
            customer_update: { enabled: 'false' },
            subscription_cancel: { enabled: 'true', mode: 'at_period_end' },
            subscription_update: {
                enabled: 'true',
                default_allowed_updates: ['price'],
                proration_behavior: 'create_prorations',
                products: [
                    { product: productIds.plus, prices: [ids.plus_month, ids.plus_year], adjustable_quantity: { enabled: "false" } },
                    { product: productIds.pro, prices: [ids.pro_month, ids.pro_year], adjustable_quantity: { enabled: "false" } }
                ]
            }
        }
    };
    if (configs.data[0]) {
        await stripe('POST', `/billing_portal/configurations/${configs.data[0].id}`, portal);
        console.log(`\nportal  updated ${configs.data[0].id}`);
    } else {
        const c = await stripe('POST', '/billing_portal/configurations', portal);
        console.log(`\nportal  created ${c.id}`);
    }

    // Webhook endpoint (its secret is shown only when it is created).
    const hooks = await stripe('GET', '/webhook_endpoints', { limit: 100 });
    let secret = null;
    const existing = hooks.data.find((h) => h.url === WEBHOOK_URL);
    if (existing) {
        await stripe('POST', `/webhook_endpoints/${existing.id}`, { enabled_events: EVENTS });
        console.log(`webhook exists  ${existing.id} (secret: copy it from the dashboard)`);
    } else {
        const h = await stripe('POST', '/webhook_endpoints', {
            url: WEBHOOK_URL, enabled_events: EVENTS, api_version: VERSION,
            description: 'nenva Connect billing'
        });
        secret = h.secret;
        console.log(`webhook created ${h.id}`);
    }

    const prices = {
        'plus:month': ids.plus_month, 'plus:year': ids.plus_year,
        'pro:month': ids.pro_month, 'pro:year': ids.pro_year
    };
    const topups = {
        'searches-2000': { price: ids.searches_2000, searches: 2000 },
        'cloud-5m': { price: ids.cloud_5m, tokens: 5000000 }
    };
    console.log('\n--- Railway env ---');
    console.log(`STRIPE_PRICES=${JSON.stringify(prices)}`);
    console.log(`STRIPE_TOPUPS=${JSON.stringify(topups)}`);
    if (secret) console.log(`STRIPE_WEBHOOK_SECRET=${secret}`);
}

main().catch((e) => { console.error(e.message); process.exit(1); });
