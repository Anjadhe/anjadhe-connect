// LLM inference proxy (/v1/llm): one OpenAI-compatible upstream serving
// open-weight models under a zero-data-retention agreement. This file is a
// metering passthrough, not a router — one upstream, a whitelisted request
// body, and token usage read off the response so the route can meter it.
//
// PRIVACY INVARIANT (same as search): prompt and completion text pass
// through to the upstream and are never logged or stored here. Keep them
// out of every console.* and Error message — upstream errors are reduced
// to an HTTP status before they can echo request content back.
'use strict';
const config = require('./config');
const db = require('./db');

// Non-stream calls get a generous ceiling (a big context on a slow model);
// streams get an overall cap so an upstream that stalls mid-answer can't
// hold a connection (and a concurrency slot) forever.
const TIMEOUT_MS = 120000;
const STREAM_TIMEOUT_MS = 300000;

// Request fields forwarded verbatim when the client sent them. Everything
// else is dropped — the upstream body is BUILT, never passed through, so a
// client can't smuggle upstream-specific knobs (logprobs, user tags, …)
// through the proxy. chat_template_kwargs is the one non-OpenAI-standard
// entry: the vLLM/llama-server extension the Anjadhe app uses to turn off
// reasoning on capped background calls ({enable_thinking:false}) — without
// it a reasoning model spends those calls' token budgets thinking, which
// on this endpoint is quota and upstream spend. Harmless no-op on models
// and servers without it.
const PASSTHROUGH_FIELDS = [
    'temperature', 'top_p', 'stop', 'response_format',
    'tools', 'tool_choice', 'presence_penalty', 'frequency_penalty', 'seed',
    'chat_template_kwargs'
];

// The model lineup is the llm_models TABLE (admin console › Models) since
// 2026-08-19 — LLM_MODELS env only seeds an empty table on first boot (see
// db.js). Enabled rows in position order; nothing serves without upstream
// credentials, so a deploy missing them advertises no models either.
function available() {
    if (config.llmMock) return [MOCK_MODEL];
    if (!config.llmUpstreamUrl || !config.llmUpstreamKey) return [];
    return db.llmModelsEnabled().map((m) => m.id);
}

// The public id a request names, resolved: an enabled model's own id, or
// the model an old id (an alias, see db.js) now points at. null when
// neither — the route answers 400 listing available() only, so aliases
// never show up as choices.
function resolve(requested) {
    const ids = available();
    if (ids.includes(requested)) return requested;
    const alias = requested ? db.llmAliasGet(requested) : null;
    return (alias && ids.includes(alias.target)) ? alias.target : null;
}

function upstreamModel(publicName) {
    if (config.llmMock) return 'mock';
    const row = db.llmModelGet(publicName);
    return (row && row.enabled) ? row.upstream : undefined;
}

// Public catalog for the app's model picker: [{id, label, description?}]
// in position order (first = what the app preselects). Upstream ids
// deliberately never appear here — the public name is the API.
function catalog() {
    if (config.llmMock) return [{ id: MOCK_MODEL, label: 'nenva cloud lite' }];
    if (!config.llmUpstreamUrl || !config.llmUpstreamKey) return [];
    return db.llmModelsEnabled().map((m) => ({
        id: m.id,
        label: m.label,
        ...(m.description ? { description: m.description } : {})
    }));
}

// The body sent upstream: whitelisted fields plus a clamped max_tokens.
// stream_options.include_usage makes OpenAI-compatible upstreams append a
// final chunk carrying token counts — that chunk is what metering reads.
function buildBody(body, model, stream) {
    const out = { model: upstreamModel(model), messages: body.messages, stream };
    for (const k of PASSTHROUGH_FIELDS) {
        if (body[k] !== undefined) out[k] = body[k];
    }
    const want = Number(body.max_tokens) || config.llmMaxOutputTokens;
    out.max_tokens = Math.max(1, Math.min(config.llmMaxOutputTokens, want));
    if (stream) out.stream_options = { include_usage: true };
    return out;
}

async function callUpstream(body, stream, signal) {
    const res = await fetch(config.llmUpstreamUrl + '/chat/completions', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${config.llmUpstreamKey}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(body),
        signal
    });
    if (!res.ok) {
        // Never forward the upstream error body — it can echo request text.
        res.body?.cancel?.().catch(() => {});
        throw new Error(`llm upstream HTTP ${res.status}`);
    }
    return res;
}

// Non-streaming chat. Returns { json, usage } — json is forwarded to the
// client as-is (OpenAI shape), usage is {prompt_tokens, completion_tokens}.
async function chat(publicModel, body) {
    if (config.llmMock) return mockChat(publicModel);
    const res = await callUpstream(buildBody(body, publicModel, false), false,
        AbortSignal.timeout(TIMEOUT_MS));
    const json = await res.json();
    // The upstream names its own model; the client only ever sees the
    // public id it asked for (users see tiers, never models — 2026-09-30).
    if (json && typeof json === 'object') json.model = publicModel;
    return { json, usage: json.usage || {} };
}

// Rough chars-per-token for the estimate below. Deliberately LOW (real
// English averages ~4) so a disconnect-heavy client is never under-metered:
// the estimate is a floor on cost, not a measurement.
const CHARS_PER_TOKEN = 3;

function estimateUsage(body, outChars) {
    let inChars = 0;
    try { inChars = JSON.stringify(body.messages || []).length; } catch { /* unstringifiable */ }
    return {
        prompt_tokens: Math.ceil(inChars / CHARS_PER_TOKEN),
        completion_tokens: Math.ceil(outChars / CHARS_PER_TOKEN),
        estimated: true
    };
}

// Streaming chat: pipes upstream SSE bytes to the client response verbatim
// while scanning the decoded copy for the usage chunk. Resolves { usage }
// when the stream ends. A client that disconnects before the final chunk
// takes the usage chunk with it — that used to meter as 1 request and ZERO
// tokens, so the token ceiling (the thing that actually bounds spend) could
// be walked past by always disconnecting early. When the chunk is missing,
// usage is ESTIMATED from the prompt and the content actually streamed, and
// flagged `estimated` so the route can count it separately. Client
// disconnect still aborts the upstream call so an abandoned stream stops
// costing tokens.
async function chatStream(publicModel, body, clientRes) {
    if (config.llmMock) {
        sseHeaders(clientRes);
        return mockChatStream(publicModel, clientRes);
    }

    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), STREAM_TIMEOUT_MS);
    clientRes.on('close', () => abort.abort());
    try {
        // Upstream is called BEFORE any header goes out, so an upstream
        // failure still surfaces to the client as a clean 502 JSON error
        // instead of an empty event stream.
        const res = await callUpstream(buildBody(body, publicModel, true), true, abort.signal);
        sseHeaders(clientRes);
        const decoder = new TextDecoder();
        let usage = {};
        let tail = '';
        let outChars = 0; // streamed completion text, for the fallback estimate
        // Forwarded line by line rather than byte for byte: each `data:`
        // event is re-serialized with the PUBLIC model id, because the
        // upstream's own model name must never reach the client. The same
        // pass scans for the usage chunk. `tail` carries a line split
        // across network chunks to the next iteration.
        const rewrite = (line) => {
            if (!line.startsWith('data: ') || line.includes('[DONE]')) return line;
            try {
                const parsed = JSON.parse(line.slice(6));
                if (parsed.usage) usage = parsed.usage;
                const delta = parsed.choices?.[0]?.delta;
                if (typeof delta?.content === 'string') outChars += delta.content.length;
                if (parsed && typeof parsed === 'object' && 'model' in parsed) {
                    parsed.model = publicModel;
                    return 'data: ' + JSON.stringify(parsed);
                }
            } catch { /* partial or non-JSON keepalive — forwarded as is */ }
            return line;
        };
        for await (const chunk of res.body) {
            if (clientRes.writableEnded || clientRes.destroyed) break;
            tail += decoder.decode(chunk, { stream: true });
            const lines = tail.split('\n');
            tail = lines.pop();
            if (lines.length) clientRes.write(lines.map(rewrite).join('\n') + '\n');
        }
        tail += decoder.decode();
        if (tail && !clientRes.writableEnded && !clientRes.destroyed) clientRes.write(rewrite(tail));
        if (!usage.completion_tokens && !usage.prompt_tokens) usage = estimateUsage(body, outChars);
        return { usage };
    } finally {
        clearTimeout(timer);
        if (clientRes.headersSent && !clientRes.writableEnded) clientRes.end();
    }
}

function sseHeaders(clientRes) {
    clientRes.setHeader('Content-Type', 'text/event-stream');
    clientRes.setHeader('Cache-Control', 'no-cache');
    clientRes.setHeader('Connection', 'keep-alive');
    clientRes.flushHeaders();
}

// ── Mock model (LLM_MOCK=1) ─────────────────────────────────────────────
// Canned completions with fixed usage (10 in / 5 out) so tests can assert
// exact quota arithmetic without upstream keys or cost.

const MOCK_USAGE = { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 };
const MOCK_MODEL = 'nenva-cloud-lite';

function mockChat(publicModel) {
    return {
        json: {
            id: 'mock-completion', object: 'chat.completion', model: publicModel,
            choices: [{
                index: 0, finish_reason: 'stop',
                message: { role: 'assistant', content: 'Canned completion from the mock model (LLM_MOCK=1).' }
            }],
            usage: MOCK_USAGE
        },
        usage: MOCK_USAGE
    };
}

function mockChatStream(publicModel, clientRes) {
    const chunk = (delta, extra = {}) => 'data: ' + JSON.stringify({
        id: 'mock-completion', object: 'chat.completion.chunk', model: publicModel,
        choices: delta ? [{ index: 0, delta }] : [],
        ...extra
    }) + '\n\n';
    clientRes.write(chunk({ role: 'assistant', content: 'Canned ' }));
    clientRes.write(chunk({ content: 'stream.' }));
    clientRes.write(chunk(null, { usage: MOCK_USAGE }));
    clientRes.write('data: [DONE]\n\n');
    clientRes.end();
    return Promise.resolve({ usage: MOCK_USAGE });
}

// Which allowance line a request carried an install over, if any — 'near'
// at 80%, 'reached' at 100%, of requests or tokens, whichever is closer.
// Usage only grows within a month, so each install crosses each line at
// most once per period: server.js counts the crossings per day, and those
// counts (never an install id) are the operator alert in lib/alerts.js.
function quotaCrossing(before, after, quota) {
    const frac = (u) => Math.max(
        quota.requests ? u.requests / quota.requests : 0,
        quota.tokens ? u.tokens / quota.tokens : 0);
    const a = frac(before), b = frac(after);
    if (a < 1 && b >= 1) return 'reached';
    if (a < 0.8 && b >= 0.8) return 'near';
    return null;
}

// buildBody is exported for the smoke test only — it is the whitelist, and
// the mock path never exercises it.
module.exports = { available, resolve, catalog, chat, chatStream, buildBody, quotaCrossing };
