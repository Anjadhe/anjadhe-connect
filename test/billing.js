// Billing P2–P5 (anjadhe-app docs/BILLING.md), on its own server so its AI
// calls never move test/smoke.js's exact budget counts: one plan shared by
// two Macs (one owner), top-ups past the month's limits, refunds and
// disputes, revenue, the trial (once per registration), and cost-weighted
// allowances with the background share.
//
//   node test/billing.js

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.SEARCH_MOCK = '1';
process.env.LLM_MOCK = '1';                 // every mock call: 10 tokens in, 5 out
process.env.STRIPE_MOCK = '1';
process.env.STRIPE_WEBHOOK_SECRET = 'whsec_billing_test';
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'connect-billing-'));
process.env.ADMIN_TOKEN = 'test-admin';
process.env.LLM_MODELS = '{"nenva-cloud-lite":{"upstream":"x/lite","label":"nenva cloud lite"}}';
process.env.TIER_QUOTAS = '{"free":1,"plus":2,"pro":2}';
process.env.LLM_TIER_QUOTAS = '{"free":{"requests":1,"tokens":1000},"plus":{"requests":1,"tokens":1000},"pro":{"requests":100,"tokens":100000}}';
process.env.LLM_BUDGET_TOKENS = '100000';
process.env.STRIPE_PRICES = '{"plus:month":"price_plus_m"}';
process.env.STRIPE_TOPUPS = '{"searches-3":{"price":"price_s3","searches":3},"cloud-20":{"price":"price_c20","tokens":20}}';
process.env.TRIAL_DAYS = '14';
process.env.TRIAL_PLAN = 'plus';
process.env.LICENSE_SIGNING_KEY = crypto.randomBytes(32).toString('base64');
// pro: cost-weighted, 8 micro-dollars a month, background at most half.
process.env.PLAN_ALLOWANCES = '{"pro":{"aiMicros":8,"bgShare":0.5}}';
process.env.PROVIDER_PACE_MS = '{"mock":0}';
const BUYER_EMAIL = 'billing-canary-' + Date.now() + '@example.com';

const billing = require('../lib/billing');
const license = require('../lib/license');
const db = require('../lib/db');
const app = require('../server');

async function main() {
    // ── The Checkout request: plain Stripe vs Managed Payments ──
    {
        const config = require('../lib/config');
        const args = { price: 'price_plus_m', claim: 'c1', successUrl: 'https://x/done', cancelUrl: 'https://x/no' };
        const was = config.stripeManaged;
        config.stripeManaged = false;
        let b = billing.checkoutBody(args);
        assert.deepStrictEqual(b.automatic_tax, { enabled: 'false' }, 'plain Stripe: tax off unless STRIPE_TAX');
        assert.strictEqual(b.managed_payments, undefined);
        config.stripeManaged = true;
        b = billing.checkoutBody(args);
        assert.deepStrictEqual(b.managed_payments, { enabled: 'true' }, 'Managed Payments on');
        assert.strictEqual(b.automatic_tax, undefined, 'Stripe refuses automatic_tax under Managed Payments');
        assert.strictEqual(b.billing_address_collection, undefined);
        assert.deepStrictEqual(b.subscription_data, { metadata: { claim: 'c1' } }, 'the claim still rides along');
        b = billing.checkoutBody({ ...args, mode: 'payment' });
        assert.deepStrictEqual(b.payment_intent_data, { metadata: { claim: 'c1' } });
        assert.ok(/^\d{4}-\d{2}-\d{2}\.\w+$/.test(config.stripeCheckoutApiVersion) && config.stripeCheckoutApiVersion >= '2025-03-31',
            'Managed Payments needs basil or later on the Checkout call');
        config.stripeManaged = was;
    }
    const srv = app.listen(0);
    await new Promise(r => srv.once('listening', r));
    const base = `http://127.0.0.1:${srv.address().port}`;
    const bearer = (k) => ({ Authorization: `Bearer ${k}` });
    const req = async (method, p, body, headers = {}) => {
        const res = await fetch(base + p, { method, headers: { 'Content-Type': 'application/json', ...headers }, body: body ? JSON.stringify(body) : undefined });
        return { status: res.status, body: await res.json().catch(() => null) };
    };
    const post = (p, body, h) => req('POST', p, body, h);
    const get = (p, h) => req('GET', p, null, h);
    const admin = { 'x-admin-token': 'test-admin' };
    const hook = async (event) => {
        const raw = Buffer.from(JSON.stringify(event));
        const res = await fetch(base + '/v1/billing/webhook', { method: 'POST', headers: { 'Stripe-Signature': billing.signForTest(raw) }, body: raw });
        return res.status;
    };
    const key = async (id) => bearer((await post('/v1/keys', { installId: id })).body.apiKey);
    const chat = (h, work) => post('/v1/llm/chat/completions', { model: 'nenva-cloud-lite', messages: [{ role: 'user', content: 'hi' }] },
        { ...h, ...(work ? { 'x-nenva-work': work } : {}) });
    const search = (h) => post('/v1/search', { query: 'billing test' }, h);
    let evt = 0;
    const buy = async (h, plan = 'plus') => {
        let r = await post('/v1/billing/checkout', { plan, interval: 'month' }, h);
        const claim = r.body.claim, session = r.body.url.split('/').pop(), n = ++evt;
        await hook({ id: `evt_buy_${n}`, type: 'checkout.session.completed', data: { object: { id: session, mode: 'subscription',
            metadata: { claim }, customer: `cus_${n}`, subscription: `sub_${n}`, customer_details: { email: BUYER_EMAIL } } } });
        r = await get('/v1/billing/claim/' + claim, h);
        return { code: r.body.code, sub: `sub_${n}` };
    };

    // price the model: 10 in × 0.1 + 5 out × 0.4 = 3 micro-dollars a call
    let r = await get('/v1/admin/llm-models', admin);
    const lite = r.body.models[0];
    r = await post('/v1/admin/llm-models', { id: lite.id, upstream: lite.upstream, label: lite.label, priceIn: 0.1, priceOut: 0.4 }, admin);
    assert.strictEqual(r.status, 200);

    // ── One plan, two Macs: one owner ──
    {
        const a = await key('bill-mac-a'), b = await key('bill-mac-b');
        const { code } = await buy(a);
        r = await post('/v1/billing/attach', { code }, b);
        assert.strictEqual(r.status, 200);
        await search(a); await search(b);
        r = await get('/v1/admin/billing', admin);
        const owners = r.body.top.filter(o => o.owner.startsWith('c:'));
        assert.strictEqual(owners.length, 1, 'two Macs on one code meter as one owner');
        assert.strictEqual(owners[0].searches, 2);
        assert.strictEqual(owners[0].tier, 'plus', 'a code owner reports its plan');
        r = await get('/v1/admin/billing', admin);
        assert.ok(r.body.plans.some(p => p.plan === 'plus' && p.status === 'active'));
    }

    // ── Top-ups: past the month's limits, never for background ──
    {
        const h = await key('bill-topup');
        r = await get('/v1/usage', h);
        assert.deepStrictEqual(r.body.billing.packs, [{ id: 'searches-3', searches: 3, cloud: false }, { id: 'cloud-20', searches: 0, cloud: true }]);
        assert.deepStrictEqual(r.body.billing.topup, { searches: 0, cloud: false });
        assert.strictEqual((await search(h)).status, 200);           // the free allowance (1)
        assert.strictEqual((await search(h)).status, 429, 'over the month without a top-up');
        r = await post('/v1/billing/topup', { pack: 'nope' }, h);
        assert.strictEqual(r.status, 400);
        for (const pack of ['searches-3', 'cloud-20']) {
            r = await post('/v1/billing/topup', { pack }, h);
            assert.strictEqual(r.status, 200);
            const claim = r.body.claim, session = r.body.url.split('/').pop(), n = ++evt;
            assert.strictEqual(await hook({ id: `evt_top_${n}`, type: 'checkout.session.completed', data: { object: { id: session, mode: 'payment',
                metadata: { claim }, payment_intent: `pi_${pack}`, amount_total: 500, currency: 'usd', customer_details: { email: BUYER_EMAIL } } } }), 200);
            r = await get('/v1/billing/claim/' + claim, h);
            assert.deepStrictEqual(r.body, { status: 'paid', topup: pack });
        }
        r = await get('/v1/usage', h);
        assert.deepStrictEqual(r.body.billing.topup, { searches: 3, cloud: true });
        assert.strictEqual((await search(h)).status, 200, 'a top-up pays for the search past the month');
        r = await get('/v1/usage', h);
        assert.strictEqual(r.body.billing.topup.searches, 2);
        // AI: free = 1 request. The second chat runs on the top-up's 20 tokens (15 used).
        assert.strictEqual((await chat(h)).status, 200);
        assert.strictEqual((await chat(h, 'background')).status, 429, 'background work never spends a top-up');
        assert.strictEqual((await chat(h)).status, 200, 'chat past the month on a top-up');
        assert.strictEqual((await chat(h)).status, 200, '5 tokens left still lets one more call start');
        assert.strictEqual((await chat(h)).status, 429, 'then the top-up is spent');
        // refunding the search pack removes what is left of it
        assert.strictEqual(await hook({ id: 'evt_refund_top', type: 'charge.refunded', data: { object: {
            payment_intent: 'pi_searches-3', refunded: true, amount_refunded: 500, currency: 'usd' } } }), 200);
        r = await get('/v1/usage', h);
        assert.strictEqual(r.body.billing.topup.searches, 0, 'a refunded top-up is removed');
    }

    // ── Refunds and disputes end a plan; revenue is recorded ──
    {
        const h = await key('bill-refund');
        const { sub } = await buy(h);
        assert.strictEqual(await hook({ id: 'evt_inv_paid', type: 'invoice.paid', data: { object: { subscription: sub, amount_paid: 500, currency: 'usd' } } }), 200);
        r = await get('/v1/usage', h);
        assert.strictEqual(r.body.plan, 'plus');
        billing.setMockInvoice('in_refund', { subscription: sub });
        assert.strictEqual(await hook({ id: 'evt_refund', type: 'charge.refunded', data: { object: {
            invoice: 'in_refund', refunded: true, amount_refunded: 500, currency: 'usd' } } }), 200);
        r = await get('/v1/usage', h);
        assert.strictEqual(r.body.plan, 'free', 'a refunded plan ends');
        assert.strictEqual(r.body.billing.status, 'refunded');

        const h2 = await key('bill-dispute');
        const second = await buy(h2);
        billing.setMockInvoice('in_dispute', { subscription: second.sub });
        assert.strictEqual(await hook({ id: 'evt_dispute', type: 'charge.dispute.created', data: { object: {
            invoice: 'in_dispute', amount: 500, currency: 'usd' } } }), 200);
        r = await get('/v1/usage', h2);
        assert.strictEqual(r.body.plan, 'free', 'a disputed plan ends');

        r = await get('/v1/admin/billing', admin);
        const rev = (kind) => r.body.revenue.filter(x => x.kind === kind).reduce((s, x) => s + x.cents, 0);
        assert.strictEqual(rev('subscription'), 500);
        assert.strictEqual(rev('topup'), 1000);
        assert.strictEqual(rev('refund'), -1500, 'refunds and disputes count against revenue');
    }

    // ── The trial: once per registration, never per install ──
    {
        const priv = license.privateKeyFromSeed(process.env.LICENSE_SIGNING_KEY);
        const { key: lic } = license.mint(priv, { cls: 'free', email: 'trial-person@example.com' });
        const h = await key('bill-trial-1');
        r = await get('/v1/usage', h);
        assert.strictEqual(r.body.billing.trialAvailable, true);
        r = await post('/v1/billing/trial', { license: 'nonsense' }, h);
        assert.strictEqual(r.status, 400);
        r = await post('/v1/billing/trial', { license: lic }, h);
        assert.strictEqual(r.body.trial, true);
        assert.strictEqual(r.body.plan, 'plus');
        r = await get('/v1/usage', h);
        assert.strictEqual(r.body.plan, 'plus');
        assert.ok(r.body.billing.trial && r.body.billing.trial.endsAt, 'the trial says when it ends');
        assert.strictEqual(r.body.billing.trialAvailable, false);
        // the same email on another Mac: the same trial, not a new one
        const h2 = await key('bill-trial-2');
        r = await post('/v1/billing/trial', { license: lic }, h2);
        assert.strictEqual(r.body.endsAt, (await get('/v1/usage', h)).body.billing.trial.endsAt);
        r = await get('/v1/admin/billing', admin);
        assert.strictEqual(r.body.trials.n, 1, 'one trial per registration');
        // an ended trial is not restarted
        const sub = license.subjectHash('trial-person@example.com');
        db.trialGet(sub); // exists
        require('better-sqlite3')(path.join(process.env.DATA_DIR, 'connect.db'))
            .prepare('UPDATE trials SET ends_at = ? WHERE license_sub = ?').run(new Date(Date.now() - 1000).toISOString(), sub);
        r = await post('/v1/billing/trial', { license: lic }, h);
        assert.strictEqual(r.body.trial, false, 'a finished trial does not start again');
        r = await get('/v1/usage', h);
        assert.strictEqual(r.body.plan, 'free');
    }

    // ── Cost-weighted allowance (PLAN_ALLOWANCES for pro): 8 µ$, bg half ──
    {
        const h = await key('bill-cost');
        r = await post('/v1/admin/tier', { installId: 'bill-cost', tier: 'pro' }, admin);
        assert.strictEqual(r.status, 200);
        assert.strictEqual((await chat(h, 'background')).status, 200);   // bg 3
        assert.strictEqual((await chat(h, 'background')).status, 200);   // bg 6 (cap 4 reached after)
        r = await chat(h, 'background');
        assert.strictEqual(r.status, 429);
        assert.strictEqual(r.body.work, 'background', 'background stops at its share');
        assert.strictEqual((await chat(h)).status, 200, 'chat keeps its own room');   // total 9 ≥ 8
        r = await chat(h);
        assert.strictEqual(r.status, 429, 'the whole allowance is spent');
        assert.strictEqual(r.body.code, 'quota');
        r = await get('/v1/usage', h);
        assert.strictEqual(r.body.ai.percent, 100);
        assert.strictEqual(r.body.ai.backgroundPercent, 75);
        assert.ok(!JSON.stringify(r.body).includes('Micros'), 'no cost reaches the app');
    }

    // ── Canary: the buyer's email from Stripe's events is stored nowhere ──
    db.checkpoint();
    for (const f of fs.readdirSync(process.env.DATA_DIR)) {
        assert.ok(!fs.readFileSync(path.join(process.env.DATA_DIR, f), 'latin1').includes(BUYER_EMAIL), `buyer email found in ${f}`);
    }

    srv.close();
    console.log('billing: shared plans, top-ups, refunds, revenue, trial and cost allowances passed');
}

main().catch((e) => { console.error(e); process.exit(1); });
