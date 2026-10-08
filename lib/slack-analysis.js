'use strict';
// The client supplies a stable opaque Slack account hash, not a credential.
// This is an aggregate resource guard, not a claim to verify Slack identity.
function check(body, account, owner, reserve) {
    const bad = { status: 400, code: 'slack_request', error: 'Invalid bounded Slack analysis request.' };
    const keys = ['model', 'messages', 'stream', 'temperature', 'max_tokens', 'response_format', 'chat_template_kwargs'];
    if (!/^[a-f0-9]{64}$/.test(account || '') || !owner || !body || typeof body !== 'object'
        || Object.keys(body).some(k => !keys.includes(k)) || body.stream !== false
        || !Number.isInteger(body.max_tokens) || body.max_tokens < 1 || body.max_tokens > 1024
        || !Array.isArray(body.messages) || !body.messages.length || body.messages.length > 3
        || body.messages.some(m => !m || !['system', 'user'].includes(m.role) || typeof m.content !== 'string'
            || Object.keys(m).some(k => !['role', 'content'].includes(k)))
        || (body.temperature != null && body.temperature !== 0)
        || (body.response_format != null && JSON.stringify(body.response_format) !== '{"type":"json_object"}')
        || (body.chat_template_kwargs != null && JSON.stringify(body.chat_template_kwargs) !== '{"enable_thinking":false}')) return bad;
    const bytes = Buffer.byteLength(JSON.stringify(body));
    if (bytes > 16384) return { status: 413, code: 'slack_size', error: 'Slack analysis exceeds 16 KiB.' };
    if (!reserve(owner, account, bytes)) return { status: 429, code: 'slack_quota', error: 'Slack analysis limit reached. Coverage is incomplete.' };
    return null;
}
module.exports = { check };
