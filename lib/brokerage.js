// /v1/brokerage — linking a brokerage, bank or card through Plaid
// (Investments for holdings, Transactions for spending; 2026-09-09).
//
// Why this lives on the server at all: Plaid's client id + secret can never
// ship inside the app, and every Plaid call needs them. So the app talks to
// Connect, Connect talks to Plaid, and the user signs in on the BROKERAGE'S
// OWN page (Plaid Hosted Link, opened in the user's default browser) — no
// brokerage password ever touches the app or this server.
//
// PRIVACY INVARIANT (the search rule, applied to money): holdings, balances
// and transactions — investment trades AND bank/card spending — are PROXIED — normalised in memory and handed to the app,
// never written to disk, never logged. The ONE thing stored per link is the
// Plaid access token, sealed with BROKERAGE_TOKEN_KEY (AES-256-GCM) so the
// database volume alone is not a set of live tokens, plus the institution
// name (a bank, not a person) so the admin console can count broken links.
// Unlink calls Plaid's item-remove and deletes the row.
//
// Plaid errors are reported by CODE only (ITEM_LOGIN_REQUIRED, …). Response
// bodies from Plaid are never logged: an error body can echo account data.
'use strict';
const crypto = require('crypto');
const config = require('./config');
const db = require('./db');

const HOSTS = { sandbox: 'https://sandbox.plaid.com', production: 'https://production.plaid.com' };
const TIMEOUT_MS = 25000;
const LINK_TTL_S = 30 * 60;          // Hosted Link URL lifetime
const LINK_ROW_TTL_MS = 2 * 60 * 60 * 1000; // pending-link rows older than this are swept
const TXN_PAGE = 500;                // Plaid's max per /investments/transactions/get page
const TXN_MAX = 5000;                // sanity ceiling per request (10 pages)
const SYNC_PAGE = 500;               // Plaid's max per /transactions/sync page
const SYNC_PAGES = 20;               // pages per request; the app continues from the cursor
const PRODUCTS = ['investments', 'transactions'];

// A string unique to the mock data set: the smoke test's privacy canary
// asserts it never reaches a console line or a byte of the database.
const MOCK_CANARY = 'mock-security-9d2f7c1e-do-not-log';

function enabled() {
    if (config.plaidMock) return true;
    return !!(config.plaidClientId && config.plaidSecret && tokenKey(false));
}

// ── Token sealing ────────────────────────────────────────────────────────
let _key = null;
function tokenKey(strict = true) {
    if (_key) return _key;
    const k = Buffer.from(String(config.brokerageTokenKey || ''), 'base64');
    if (k.length !== 32) {
        if (strict) throw new Error('BROKERAGE_TOKEN_KEY must be the base64 of 32 random bytes');
        return null;
    }
    _key = k;
    return k;
}
function seal(plain) {
    const key = config.plaidMock && !tokenKey(false) ? Buffer.alloc(32, 7) : tokenKey();
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
    return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
}
function open(sealed) {
    const key = config.plaidMock && !tokenKey(false) ? Buffer.alloc(32, 7) : tokenKey();
    const buf = Buffer.from(String(sealed), 'base64');
    const d = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
    d.setAuthTag(buf.subarray(12, 28));
    return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8');
}

// ── Plaid client ─────────────────────────────────────────────────────────
class PlaidError extends Error {
    constructor(path, status, body) {
        super(`plaid ${path} ${status}`);
        this.name = 'PlaidError';
        this.status = status;
        this.code = String(body?.error_code || 'UPSTREAM').slice(0, 64);
        this.type = String(body?.error_type || '').slice(0, 64);
    }
}

// Investments data is not always ready the moment an Item is linked: Plaid
// answers PRODUCT_NOT_READY for a few seconds (sandbox included). Data
// calls wait it out here — 2s, 4s, 8s — inside the app's own timeout.
const NOT_READY_WAITS_MS = [2000, 4000, 8000];
async function plaidReady(path, body) {
    for (let i = 0; ; i++) {
        try { return await plaid(path, body); }
        catch (e) {
            if (!(e instanceof PlaidError) || e.code !== 'PRODUCT_NOT_READY' || i >= NOT_READY_WAITS_MS.length) throw e;
            await new Promise(r => setTimeout(r, NOT_READY_WAITS_MS[i]));
        }
    }
}

async function plaid(path, body) {
    if (config.plaidMock) return mock(path, body);
    const res = await fetch(HOSTS[config.plaidEnv] + path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_id: config.plaidClientId, secret: config.plaidSecret, ...body }),
        signal: AbortSignal.timeout(TIMEOUT_MS)
    });
    const text = await res.text();
    let data = null;
    try { data = JSON.parse(text); } catch { /* non-JSON: treated as upstream failure below */ }
    if (!res.ok || !data) throw new PlaidError(path, res.status, data);
    return data;
}

// The failure CLASS, for metrics and for the app's messaging. Never carries
// text from Plaid beyond its error code.
function failureKind(e) {
    if (e instanceof PlaidError) return e.code;
    if (e && e.name === 'TimeoutError') return 'timeout';
    if (e && (e.name === 'AbortError' || /fetch failed/i.test(e.message || ''))) return 'net';
    return 'error';
}

function loginRequired(e) {
    return e instanceof PlaidError && (e.code === 'ITEM_LOGIN_REQUIRED' || e.code === 'PENDING_EXPIRATION'
        || e.code === 'INVALID_ACCESS_TOKEN');
}

// ── Normalisation (the shape the app consumes; Plaid's names stay here) ─
function normAccount(a) {
    return {
        id: a.account_id,
        name: a.name || a.official_name || 'Account',
        officialName: a.official_name || null,
        mask: a.mask || null,
        type: a.type || null,
        subtype: a.subtype || null,
        balance: {
            current: a.balances?.current ?? null,
            available: a.balances?.available ?? null,
            currency: a.balances?.iso_currency_code || 'USD'
        }
    };
}
function normSecurity(s) {
    if (!s) return null;
    const oc = s.option_contract;
    return {
        id: s.security_id,
        ticker: s.ticker_symbol || null,
        name: s.name || null,
        type: s.type || null,
        cash: !!s.is_cash_equivalent || s.type === 'cash',
        option: oc ? {
            type: oc.contract_type || null,
            expiration: oc.expiration_date || null,
            strike: oc.strike_price ?? null,
            underlying: oc.underlying_security_ticker || null
        } : null,
        price: s.close_price ?? null,
        priceAsOf: s.close_price_as_of || null
    };
}
function securityMap(list) {
    const m = new Map();
    for (const s of list || []) if (s && s.security_id) m.set(s.security_id, normSecurity(s));
    return m;
}
function normHoldings(r) {
    const secs = securityMap(r.securities);
    return {
        accounts: (r.accounts || []).map(normAccount),
        holdings: (r.holdings || []).map(h => ({
            accountId: h.account_id,
            security: secs.get(h.security_id) || null,
            quantity: h.quantity ?? 0,
            costBasis: h.cost_basis ?? null,
            price: h.institution_price ?? null,
            priceAsOf: h.institution_price_as_of || null,
            value: h.institution_value ?? null,
            currency: h.iso_currency_code || 'USD'
        }))
    };
}
function normTransaction(t, secs) {
    return {
        id: t.investment_transaction_id,
        accountId: t.account_id,
        date: t.date,
        name: t.name || null,
        type: t.type || null,
        subtype: t.subtype || null,
        quantity: t.quantity ?? 0,
        amount: t.amount ?? 0,
        price: t.price ?? 0,
        fees: t.fees ?? 0,
        currency: t.iso_currency_code || 'USD',
        security: secs.get(t.security_id) || null
    };
}

// A bank/card transaction (Plaid Transactions). Plaid's sign convention
// is kept: positive = money leaving the account, negative = money in.
// Plaid's own category (personal_finance_category) rides along; the app
// lets the user override it and never asks a model to invent one.
function normBankTransaction(t) {
    const pfc = t.personal_finance_category || null;
    return {
        id: t.transaction_id,
        accountId: t.account_id,
        date: t.date,
        authorizedDate: t.authorized_date || null,
        name: t.name || null,
        merchant: t.merchant_name || null,
        amount: t.amount ?? 0,
        currency: t.iso_currency_code || 'USD',
        pending: !!t.pending,
        pendingId: t.pending_transaction_id || null,
        channel: t.payment_channel || null,
        category: pfc ? { primary: pfc.primary || null, detailed: pfc.detailed || null } : null
    };
}

function parseProducts(list) {
    const out = [];
    for (const p of Array.isArray(list) ? list : []) {
        const v = String(p || '').toLowerCase();
        if (PRODUCTS.includes(v) && !out.includes(v)) out.push(v);
    }
    return out.length ? out : ['investments'];
}
function rowProducts(row) {
    return parseProducts(String(row.products || 'investments').split(','));
}

// ── Public operations (each takes the caller's HASHED install id) ────────
function publicItem(row) {
    return {
        itemId: row.item_id,
        institutionId: row.institution_id || null,
        institution: row.institution_name || null,
        products: rowProducts(row),
        status: row.status,
        createdAt: row.created_at,
        updatedAt: row.updated_at
    };
}

async function startLink(installId, { itemId = null, products = null } = {}) {
    db.brokeragePurgeLinks(LINK_ROW_TTL_MS);
    let wanted = parseProducts(products);
    const body = {
        client_name: config.plaidClientName,
        language: 'en',
        country_codes: ['US'],
        user: { client_user_id: installId },
        hosted_link: { url_lifetime_seconds: LINK_TTL_S, is_mobile_app: false }
    };
    let row = null;
    if (itemId) {
        // Update mode: a link whose credentials expired is re-authorised
        // in place — same Item, same token, no exchange afterwards.
        row = db.brokerageItem(itemId, installId);
        if (!row) throw new PlaidError('/link/token/create', 404, { error_code: 'NOT_LINKED' });
        body.access_token = open(row.access_token_enc);
        wanted = rowProducts(row);
    } else {
        // The first product is what the user asked to link and filters
        // Plaid's institution picker; any further product is taken only
        // where the institution supports it (a bank login that also holds
        // a brokerage yields both) and never blocks the link. Nothing the
        // caller did not ask for is requested — each product is billed.
        body.products = [wanted[0]];
        if (wanted.length > 1) body.optional_products = wanted.slice(1);
    }
    if (wanted.includes('transactions') || !itemId) {
        body.transactions = { days_requested: config.brokerageHistoryDays };
    }
    const r = await plaid('/link/token/create', body);
    db.brokerageInsertLink(r.link_token, installId, itemId, wanted.join(','));
    return { linkToken: r.link_token, url: r.hosted_link_url, expiresAt: r.expiration || null };
}

async function linkStatus(installId, linkToken) {
    const row = db.brokerageLink(linkToken, installId);
    if (!row) return { status: 'unknown' };
    const r = await plaid('/link/token/get', { link_token: linkToken });
    const sessions = Array.isArray(r.link_sessions) ? r.link_sessions : [];
    // Hosted Link reports the completed session either under results
    // (current docs) or on_success (older shape); accept both.
    const finished = sessions.filter(s => s && s.finished_at);
    // Update mode (re-authorising an existing Item) adds nothing and
    // exchanges nothing: a finished session the user did not exit means
    // the credentials are good again.
    const success = row.item_id
        ? finished.find(s => !s.on_exit)
        : finished.find(s => (s.results?.item_add_results || []).length || s.on_success?.public_token);
    if (!success) {
        if (finished.some(s => s.on_exit)) {
            db.brokerageDeleteLink(linkToken);
            return { status: 'exited' };
        }
        const expired = r.expiration && Date.parse(r.expiration) < Date.now();
        if (expired) db.brokerageDeleteLink(linkToken);
        return { status: expired ? 'expired' : 'pending' };
    }
    if (row.item_id) {
        db.brokerageItemStatus(row.item_id, 'ok', null);
        db.brokerageDeleteLink(linkToken);
        const item = db.brokerageItem(row.item_id, installId);
        return { status: 'done', item: item ? publicItem(item) : null };
    }
    const add = (success.results?.item_add_results || [])[0] || null;
    const publicToken = add?.public_token || success.on_success?.public_token;
    const ex = await plaid('/item/public_token/exchange', { public_token: publicToken });
    const institution = add?.institution || success.on_success?.metadata?.institution || null;
    const existing = db.brokerageItem(ex.item_id, installId);
    if (existing) {
        db.brokerageItemToken(ex.item_id, seal(ex.access_token));
        db.brokerageItemStatus(ex.item_id, 'ok', null);
    } else {
        db.brokerageInsertItem(ex.item_id, installId, seal(ex.access_token),
            institution?.institution_id || null, institution?.name ? String(institution.name).slice(0, 80) : null,
            String(row.products || 'investments'));
    }
    db.brokerageDeleteLink(linkToken);
    return { status: 'done', item: publicItem(db.brokerageItem(ex.item_id, installId)) };
}

function items(installId) {
    return db.brokerageItems(installId).map(publicItem);
}

function itemFor(installId, itemId) {
    const row = db.brokerageItem(itemId, installId);
    // Our own 404 (no such link for this install) — distinct from Plaid's
    // ITEM_NOT_FOUND, which means the Item died on Plaid's side.
    if (!row) throw new PlaidError('item', 404, { error_code: 'NOT_LINKED' });
    return row;
}

// Marks the row when a call proves the link needs the user again, so the
// app (and the admin count) can say so without another Plaid round-trip.
function noteFailure(row, e) {
    if (loginRequired(e)) db.brokerageItemStatus(row.item_id, 'login_required', e.code);
    else if (e instanceof PlaidError) db.brokerageItemStatus(row.item_id, 'error', e.code);
}

async function holdings(installId, itemId) {
    const row = itemFor(installId, itemId);
    try {
        const r = await plaidReady('/investments/holdings/get', { access_token: open(row.access_token_enc) });
        if (row.status !== 'ok') db.brokerageItemStatus(row.item_id, 'ok', null);
        return normHoldings(r);
    } catch (e) { noteFailure(row, e); throw e; }
}

// Every account on the Item with its current balance — the picker after a
// bank link (no holdings to enumerate accounts from) and the balance
// refresh for cash accounts.
async function accounts(installId, itemId) {
    const row = itemFor(installId, itemId);
    try {
        const r = await plaidReady('/accounts/get', { access_token: open(row.access_token_enc) });
        if (row.status !== 'ok') db.brokerageItemStatus(row.item_id, 'ok', null);
        return { accounts: (r.accounts || []).map(normAccount) };
    } catch (e) { noteFailure(row, e); throw e; }
}

// Bank/card transactions, cursor-based: the app keeps Plaid's cursor and
// gets only what was added, changed or removed since (a pending charge
// settling arrives as removed + added, joined by pendingId). No cursor =
// the first pull, which walks the whole requested history; the walk is
// capped per request and `hasMore` + `cursor` let the app keep going. If
// Plaid mutates the set mid-walk, the walk restarts once from the caller's
// cursor, as Plaid requires.
async function syncTransactions(installId, itemId, cursor) {
    const row = itemFor(installId, itemId);
    const token = open(row.access_token_enc);
    const walk = async () => {
        const out = { added: [], modified: [], removed: [], accounts: [], cursor: cursor || null, hasMore: false };
        let next = cursor || null;
        for (let page = 0; page < SYNC_PAGES; page++) {
            const body = { access_token: token, count: SYNC_PAGE };
            if (next) body.cursor = next;
            const r = await plaidReady('/transactions/sync', body);
            for (const t of r.added || []) out.added.push(normBankTransaction(t));
            for (const t of r.modified || []) out.modified.push(normBankTransaction(t));
            for (const t of r.removed || []) out.removed.push({ id: t.transaction_id, accountId: t.account_id || null });
            if (Array.isArray(r.accounts) && r.accounts.length) out.accounts = r.accounts.map(normAccount);
            next = r.next_cursor || next;
            out.cursor = next;
            out.hasMore = !!r.has_more;
            if (!r.has_more) break;
        }
        return out;
    };
    try {
        let result;
        try { result = await walk(); }
        catch (e) {
            if (!(e instanceof PlaidError) || e.code !== 'TRANSACTIONS_SYNC_MUTATION_DURING_PAGINATION') throw e;
            result = await walk();
        }
        if (row.status !== 'ok') db.brokerageItemStatus(row.item_id, 'ok', null);
        return result;
    } catch (e) { noteFailure(row, e); throw e; }
}

async function transactions(installId, itemId, startDate, endDate) {
    const row = itemFor(installId, itemId);
    const token = open(row.access_token_enc);
    const out = [];
    let accounts = [];
    let total = 0;
    let secs = new Map();
    try {
        for (let offset = 0; offset < TXN_MAX; offset += TXN_PAGE) {
            const r = await plaidReady('/investments/transactions/get', {
                access_token: token, start_date: startDate, end_date: endDate,
                options: { count: TXN_PAGE, offset }
            });
            if (!accounts.length) accounts = (r.accounts || []).map(normAccount);
            for (const [k, v] of securityMap(r.securities)) secs.set(k, v);
            total = r.total_investment_transactions ?? total;
            const page = r.investment_transactions || [];
            for (const t of page) out.push(normTransaction(t, secs));
            if (page.length < TXN_PAGE || out.length >= total) break;
        }
        if (row.status !== 'ok') db.brokerageItemStatus(row.item_id, 'ok', null);
    } catch (e) { noteFailure(row, e); throw e; }
    return { accounts, transactions: out, total, truncated: out.length < total };
}

async function unlink(installId, itemId) {
    const row = itemFor(installId, itemId);
    // Tell Plaid first so billing stops even if the row delete raced; a
    // Plaid failure here (already removed, login dead) must not keep the
    // token around — the user asked to sever, so sever.
    try { await plaid('/item/remove', { access_token: open(row.access_token_enc) }); }
    catch (e) { if (!(e instanceof PlaidError)) throw e; }
    db.brokerageDeleteItem(itemId, installId);
    return { removed: true };
}

function stats() {
    const byProduct = {};
    for (const p of PRODUCTS) byProduct[p] = 0;
    for (const r of db.brokerageAllProducts()) for (const p of rowProducts(r)) byProduct[p] += r.n;
    return {
        enabled: enabled(),
        byProduct,
        env: config.plaidMock ? 'mock' : config.plaidEnv,
        maxItems: config.brokerageMaxItems,
        tierItems: config.brokerageTierItems,
        ...db.brokerageStats()
    };
}

// ── Mock Plaid (PLAID_MOCK=1) ────────────────────────────────────────────
// Just enough of the endpoints for the smoke test: a link that finishes on
// the second status poll, one brokerage account with three positions (a
// stock, an option, cash) and a page of trades, plus a checking account
// and a card with a two-page first sync and a settling pending charge.
const _mock = { links: new Map(), removed: new Set(), polls: new Map() };
function mock(path, body) {
    const day = (n) => new Date(Date.now() - n * 86400000).toISOString().slice(0, 10);
    switch (path) {
        case '/link/token/create': {
            const t = 'link-mock-' + crypto.randomBytes(8).toString('hex');
            _mock.links.set(t, { update: !!body.access_token, products: body.products || [] });
            return { link_token: t, hosted_link_url: 'https://secure.plaid.com/hl/' + t, expiration: new Date(Date.now() + 1800000).toISOString() };
        }
        case '/link/token/get': {
            const n = (_mock.polls.get(body.link_token) || 0) + 1;
            _mock.polls.set(body.link_token, n);
            const l = _mock.links.get(body.link_token);
            if (!l) throw new PlaidError(path, 400, { error_code: 'INVALID_LINK_TOKEN' });
            if (n < 2) return { link_sessions: [], expiration: new Date(Date.now() + 1800000).toISOString() };
            return {
                expiration: new Date(Date.now() + 1800000).toISOString(),
                link_sessions: [{
                    link_session_id: 'ls-mock', finished_at: new Date().toISOString(),
                    results: { item_add_results: l.update ? [] : [{
                        public_token: 'public-mock-' + body.link_token,
                        institution: { institution_id: 'ins_109508', name: 'First Platypus Bank' }
                    }] },
                    on_success: l.update ? { public_token: null } : null
                }]
            };
        }
        case '/item/public_token/exchange':
            return { access_token: 'access-mock-' + crypto.randomBytes(8).toString('hex'), item_id: 'item-mock-' + String(body.public_token).slice(-8) };
        case '/investments/holdings/get': {
            if (_mock.removed.has(body.access_token)) throw new PlaidError(path, 400, { error_code: 'ITEM_NOT_FOUND' });
            if (String(body.access_token).endsWith('login')) throw new PlaidError(path, 400, { error_code: 'ITEM_LOGIN_REQUIRED' });
            return {
                accounts: [{ account_id: 'acct-mock-1', name: 'Individual Brokerage', official_name: null, mask: '1234', type: 'investment', subtype: 'brokerage', balances: { current: 15250.5, available: 250.5, iso_currency_code: 'USD' } }],
                holdings: [
                    { account_id: 'acct-mock-1', security_id: 'sec-aapl', quantity: 10, cost_basis: 1500, institution_price: 210, institution_price_as_of: day(1), institution_value: 2100, iso_currency_code: 'USD' },
                    { account_id: 'acct-mock-1', security_id: 'sec-opt', quantity: 2, cost_basis: 900, institution_price: 5.5, institution_price_as_of: day(1), institution_value: 1100, iso_currency_code: 'USD' },
                    { account_id: 'acct-mock-1', security_id: 'sec-cash', quantity: 250.5, cost_basis: 250.5, institution_price: 1, institution_price_as_of: day(1), institution_value: 250.5, iso_currency_code: 'USD' }
                ],
                securities: [
                    { security_id: 'sec-aapl', ticker_symbol: 'AAPL', name: MOCK_CANARY, type: 'equity', close_price: 210, close_price_as_of: day(1) },
                    { security_id: 'sec-opt', ticker_symbol: 'AAPL261218C00250000', name: 'AAPL Dec 18 2026 250 Call', type: 'derivative', option_contract: { contract_type: 'call', expiration_date: '2026-12-18', strike_price: 250, underlying_security_ticker: 'AAPL' }, close_price: 5.5 },
                    { security_id: 'sec-cash', ticker_symbol: 'CUR:USD', name: 'US Dollar', type: 'cash', is_cash_equivalent: true, close_price: 1 }
                ]
            };
        }
        case '/investments/transactions/get': {
            if (_mock.removed.has(body.access_token)) throw new PlaidError(path, 400, { error_code: 'ITEM_NOT_FOUND' });
            const all = [
                { investment_transaction_id: 'itx-1', account_id: 'acct-mock-1', security_id: 'sec-aapl', date: day(3), name: 'BUY AAPL', type: 'buy', subtype: 'buy', quantity: 10, amount: 1500, price: 150, fees: 0, iso_currency_code: 'USD' },
                { investment_transaction_id: 'itx-2', account_id: 'acct-mock-1', security_id: 'sec-opt', date: day(2), name: 'BUY CALL', type: 'buy', subtype: 'buy', quantity: 2, amount: 900, price: 4.5, fees: 1.3, iso_currency_code: 'USD' },
                { investment_transaction_id: 'itx-3', account_id: 'acct-mock-1', security_id: 'sec-cash', date: day(1), name: MOCK_CANARY + ' dividend', type: 'cash', subtype: 'dividend', quantity: 0, amount: -12.34, price: 0, fees: 0, iso_currency_code: 'USD' },
                { investment_transaction_id: 'itx-4', account_id: 'acct-mock-1', security_id: null, date: day(1), name: 'Deposit', type: 'cash', subtype: 'deposit', quantity: 0, amount: -500, price: 0, fees: 0, iso_currency_code: 'USD' }
            ].filter(t => t.date >= body.start_date && t.date <= body.end_date);
            const offset = body.options?.offset || 0;
            const count = body.options?.count || TXN_PAGE;
            return {
                accounts: [{ account_id: 'acct-mock-1', name: 'Individual Brokerage', mask: '1234', type: 'investment', subtype: 'brokerage', balances: { current: 15250.5, available: 250.5 } }],
                investment_transactions: all.slice(offset, offset + count),
                securities: [
                    { security_id: 'sec-aapl', ticker_symbol: 'AAPL', name: MOCK_CANARY, type: 'equity' },
                    { security_id: 'sec-opt', ticker_symbol: 'AAPL261218C00250000', name: 'AAPL call', type: 'derivative', option_contract: { contract_type: 'call', expiration_date: '2026-12-18', strike_price: 250, underlying_security_ticker: 'AAPL' } },
                    { security_id: 'sec-cash', ticker_symbol: 'CUR:USD', name: 'US Dollar', type: 'cash', is_cash_equivalent: true }
                ],
                total_investment_transactions: all.length
            };
        }
        case '/accounts/get': {
            if (_mock.removed.has(body.access_token)) throw new PlaidError(path, 400, { error_code: 'ITEM_NOT_FOUND' });
            if (String(body.access_token).endsWith('login')) throw new PlaidError(path, 400, { error_code: 'ITEM_LOGIN_REQUIRED' });
            return {
                accounts: [
                    { account_id: 'acct-mock-1', name: 'Individual Brokerage', mask: '1234', type: 'investment', subtype: 'brokerage', balances: { current: 15250.5, available: 250.5, iso_currency_code: 'USD' } },
                    { account_id: 'acct-mock-chk', name: 'Plaid Checking', official_name: 'Plaid Gold Standard 0% Interest Checking', mask: '0000', type: 'depository', subtype: 'checking', balances: { current: 1105.7, available: 1000, iso_currency_code: 'USD' } },
                    { account_id: 'acct-mock-cc', name: 'Plaid Credit Card', mask: '3333', type: 'credit', subtype: 'credit card', balances: { current: 410.25, available: 4589.75, iso_currency_code: 'USD' } }
                ]
            };
        }
        case '/transactions/sync': {
            // Two pages on the first pull (no cursor), a settled pending
            // charge on the next pull, nothing after that.
            if (_mock.removed.has(body.access_token)) throw new PlaidError(path, 400, { error_code: 'ITEM_NOT_FOUND' });
            if (String(body.access_token).endsWith('login')) throw new PlaidError(path, 400, { error_code: 'ITEM_LOGIN_REQUIRED' });
            const accounts = [
                { account_id: 'acct-mock-chk', name: 'Plaid Checking', mask: '0000', type: 'depository', subtype: 'checking', balances: { current: 1105.7, available: 1000, iso_currency_code: 'USD' } },
                { account_id: 'acct-mock-cc', name: 'Plaid Credit Card', mask: '3333', type: 'credit', subtype: 'credit card', balances: { current: 410.25, available: 4589.75, iso_currency_code: 'USD' } }
            ];
            const tx = (id, acct, d, name, merchant, amount, primary, detailed, extra = {}) => ({
                transaction_id: id, account_id: acct, date: day(d), authorized_date: day(d + 1), name, merchant_name: merchant,
                amount, iso_currency_code: 'USD', pending: false, pending_transaction_id: null, payment_channel: 'in store',
                personal_finance_category: { primary, detailed, confidence_level: 'HIGH' }, ...extra
            });
            const cur = body.cursor || '';
            if (!cur) {
                return {
                    accounts,
                    added: [
                        tx('btx-1', 'acct-mock-cc', 4, 'SPARKFUN', MOCK_CANARY, 89.4, 'GENERAL_MERCHANDISE', 'GENERAL_MERCHANDISE_ELECTRONICS'),
                        tx('btx-2', 'acct-mock-chk', 3, 'United Airlines', 'United Airlines', 500, 'TRAVEL', 'TRAVEL_FLIGHTS'),
                        tx('btx-3', 'acct-mock-chk', 2, 'ACH Electronic CreditGUSTO PAY 123456', null, -2500, 'INCOME', 'INCOME_WAGES')
                    ],
                    modified: [], removed: [], next_cursor: 'cursor-mock-1', has_more: true
                };
            }
            if (cur === 'cursor-mock-1') {
                return {
                    accounts,
                    added: [tx('btx-4p', 'acct-mock-cc', 1, 'Starbucks', 'Starbucks', 4.33, 'FOOD_AND_DRINK', 'FOOD_AND_DRINK_COFFEE', { pending: true })],
                    modified: [], removed: [], next_cursor: 'cursor-mock-2', has_more: false
                };
            }
            if (cur === 'cursor-mock-2') {
                return {
                    accounts,
                    added: [tx('btx-4', 'acct-mock-cc', 1, 'Starbucks', 'Starbucks', 4.33, 'FOOD_AND_DRINK', 'FOOD_AND_DRINK_COFFEE', { pending_transaction_id: 'btx-4p' })],
                    modified: [tx('btx-2', 'acct-mock-chk', 3, 'United Airlines', 'United Airlines', 512.8, 'TRAVEL', 'TRAVEL_FLIGHTS')],
                    removed: [{ transaction_id: 'btx-4p', account_id: 'acct-mock-cc' }],
                    next_cursor: 'cursor-mock-3', has_more: false
                };
            }
            return { accounts, added: [], modified: [], removed: [], next_cursor: cur, has_more: false };
        }
        case '/item/remove':
            _mock.removed.add(body.access_token);
            return { removed: true };
        default:
            throw new PlaidError(path, 404, { error_code: 'INVALID_REQUEST' });
    }
}

module.exports = {
    enabled, startLink, linkStatus, items, accounts, holdings, transactions, syncTransactions, unlink, stats,
    failureKind, loginRequired, PlaidError, PRODUCTS, parseProducts,
    // exported for tests
    seal, open, normHoldings, normTransaction, normBankTransaction, securityMap, MOCK_CANARY
};
