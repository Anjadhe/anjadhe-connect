// Bounded sweep for the in-memory rate-limit maps. They used to self-reset
// with map.clear() once they passed 10k entries, which meant a flood from
// >10k distinct sources (trivial over IPv6) wiped every active window —
// the attacker's included — turning the size cap into a limiter bypass.
// Stale windows are dropped first; if the map is somehow still over cap,
// oldest-inserted entries go. Active windows survive the sweep.
'use strict';

const DEFAULT_MAX = 10000;

function capLimiter(map, isStale, max = DEFAULT_MAX) {
    if (map.size <= max) return;
    for (const [k, v] of map) {
        if (isStale(v)) map.delete(k);
    }
    if (map.size <= max) return;
    for (const k of map.keys()) {
        if (map.size <= max) break;
        map.delete(k);
    }
}

// Rate-limit key for an IP. IPv4 passes through; IPv6 collapses to its /64
// prefix — providers hand a whole /64 to one subscriber, so per-address
// limiting is free to bypass over IPv6 (2^64 addresses per person).
function ipBucket(ip) {
    if (!ip || !ip.includes(':')) return ip;
    if (ip.startsWith('::ffff:')) return ip.slice(7); // v4-mapped IPv4
    const halves = ip.split('::');
    let groups = halves[0] ? halves[0].split(':') : [];
    if (halves.length === 2) {
        const tail = halves[1] ? halves[1].split(':') : [];
        while (groups.length + tail.length < 8) groups.push('0');
        groups = groups.concat(tail);
    }
    return groups.slice(0, 4).join(':');
}

module.exports = { capLimiter, ipBucket };
