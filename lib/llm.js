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

function available() {
    if (config.llmMock) return ['anjadhe-cloud'];
    if (!config.llmUpstreamUrl || !config.llmUpstreamKey) return [];
    return Object.keys(config.llmModels);
}

function upstreamModel(publicName) {
    return config.llmMock ? 'mock' : config.llmModels[publicName];
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
    if (config.llmMock) return mockChat(body);
    const res = await callUpstream(buildBody(body, publicModel, false), false,
        AbortSignal.timeout(TIMEOUT_MS));
    const json = await res.json();
    return { json, usage: json.usage || {} };
}

// Streaming chat: pipes upstream SSE bytes to the client response verbatim
// while scanning the decoded copy for the usage chunk. Resolves { usage }
// when the stream ends (usage may be empty if the client disconnected
// before the final chunk — the route meters what it got and counts the
// request either way). Client disconnect aborts the upstream call so an
// abandoned stream stops costing tokens.
async function chatStream(publicModel, body, clientRes) {
    if (config.llmMock) {
        sseHeaders(clientRes);
        return mockChatStream(body, clientRes);
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
        for await (const chunk of res.body) {
            if (clientRes.writableEnded || clientRes.destroyed) break;
            clientRes.write(chunk);
            // Scan complete SSE lines for the usage chunk. `tail` carries a
            // line split across network chunks to the next iteration.
            tail += decoder.decode(chunk, { stream: true });
            const lines = tail.split('\n');
            tail = lines.pop();
            for (const line of lines) {
                if (!line.startsWith('data: ') || line.includes('[DONE]')) continue;
                try {
                    const parsed = JSON.parse(line.slice(6));
                    if (parsed.usage) usage = parsed.usage;
                } catch { /* partial or non-JSON keepalive — not the usage chunk */ }
            }
        }
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

function mockChat() {
    return {
        json: {
            id: 'mock-completion', object: 'chat.completion', model: 'anjadhe-cloud',
            choices: [{
                index: 0, finish_reason: 'stop',
                message: { role: 'assistant', content: 'Canned completion from the mock model (LLM_MOCK=1).' }
            }],
            usage: MOCK_USAGE
        },
        usage: MOCK_USAGE
    };
}

function mockChatStream(body, clientRes) {
    const chunk = (delta, extra = {}) => 'data: ' + JSON.stringify({
        id: 'mock-completion', object: 'chat.completion.chunk', model: 'anjadhe-cloud',
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

// buildBody is exported for the smoke test only — it is the whitelist, and
// the mock path never exercises it.
module.exports = { available, chat, chatStream, buildBody };
