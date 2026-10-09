// "Answer without thinking" fallback (lib/llm.js sendUpstream): the proxy
// learns which spelling each upstream model accepts. Fake fetch, no network.
'use strict';
const assert = require('assert');
process.env.LLM_UPSTREAM_URL = 'https://upstream.invalid/v1';
process.env.LLM_UPSTREAM_KEY = 'test';
const llm = require('../lib/llm');

let calls = [];
let accepts = () => true;          // (body) => true | status number
global.fetch = async (url, opts) => {
    const body = JSON.parse(opts.body);
    calls.push(body);
    const r = accepts(body);
    if (r === true) return { ok: true, status: 200, json: async () => ({ choices: [] }), body: null };
    return { ok: false, status: r, body: { cancel: async () => {} } };
};
const never = () => AbortSignal.timeout(5000);
const noThink = (model) => ({ model, messages: [{ role: 'user', content: 'x' }], chat_template_kwargs: { enable_thinking: false } });

(async () => {
    // 1. A model that takes the kwargs: one call, sent as is.
    calls = []; accepts = () => true;
    await llm._sendUpstream(noThink('m-kwargs'), false, never);
    assert.strictEqual(calls.length, 1);
    assert.deepStrictEqual(calls[0].chat_template_kwargs, { enable_thinking: false });

    // 2. A model that 400s on the kwargs but takes reasoning_effort 'none'.
    calls = []; accepts = (b) => (b.chat_template_kwargs ? 400 : (b.reasoning_effort === 'none' ? true : 400));
    await llm._sendUpstream(noThink('m-effort'), false, never);
    assert.strictEqual(calls.length, 2);
    assert.strictEqual(calls[1].reasoning_effort, 'none');
    assert.ok(!('chat_template_kwargs' in calls[1]));
    // ...and remembers it: the next call goes straight there.
    calls = [];
    await llm._sendUpstream(noThink('m-effort'), false, never);
    assert.strictEqual(calls.length, 1);
    assert.strictEqual(calls[0].reasoning_effort, 'none');

    // 3. A model that takes neither: falls through to a plain request.
    calls = []; accepts = (b) => (b.chat_template_kwargs || b.reasoning_effort ? 400 : true);
    await llm._sendUpstream(noThink('m-plain'), false, never);
    assert.strictEqual(calls.length, 4);
    assert.ok(!('chat_template_kwargs' in calls[3]) && !('reasoning_effort' in calls[3]));

    // 4. A non-400 failure is the request's own: no retries, it throws.
    calls = []; accepts = () => 503;
    await assert.rejects(llm._sendUpstream(noThink('m-down'), false, never), /HTTP 503/);
    assert.strictEqual(calls.length, 1);
    assert.ok(!llm._noThinkStyle.has('m-down'), 'a failure teaches nothing');

    // 5. Every spelling refused: the last 400 surfaces, nothing is cached.
    calls = []; accepts = () => 400;
    await assert.rejects(llm._sendUpstream(noThink('m-broken'), false, never), /HTTP 400/);
    assert.strictEqual(calls.length, 4);
    assert.ok(!llm._noThinkStyle.has('m-broken'));

    // 6. A request that did not ask for no-thinking is never rewritten or retried.
    calls = []; accepts = () => 400;
    await assert.rejects(llm._sendUpstream({ model: 'm-x', messages: [] }, false, never), /HTTP 400/);
    assert.strictEqual(calls.length, 1);

    console.log('llm-nothink: all assertions passed');
})().catch((e) => { console.error(e); process.exit(1); });
