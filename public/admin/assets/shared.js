// Anjadhe Connect admin — shared shell for every /admin page: the token
// gate, the environment banner, the page nav, the chart/table primitives,
// and the load/refresh loop. Each page defines `PAGE` (its nav id) and
// `loadPage()` (fetch + render) before including this file's init call.
'use strict';
const $ = (s, el = document) => el.querySelector(s);
const TOKEN_KEY = 'anjadhe-admin-token';
let rangeDays = 30;

const fmt = (n) => {
  if (n >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + 'M';
  if (n >= 1e4) return (n / 1e3).toFixed(n >= 1e5 ? 0 : 1) + 'K';
  return Number(n).toLocaleString('en-US');
};
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ── data plumbing ───────────────────────────────────────────────────────

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { 'x-admin-token': sessionStorage.getItem(TOKEN_KEY) || '', ...(opts.headers || {}) }
  });
  if (res.status === 401) { sessionStorage.removeItem(TOKEN_KEY); showGate('Bad admin token.'); throw new Error('unauthorized'); }
  if (res.status === 503) { showGate('Admin endpoints are disabled — set ADMIN_TOKEN on the service.'); throw new Error('disabled'); }
  if (!res.ok) throw new Error('HTTP ' + res.status);
  return res.json();
}

function showGate(err) {
  $('#dash').classList.add('hidden');
  $('#gate').classList.remove('hidden');
  $('#gate-err').textContent = err || '';
}

async function load() {
  $('#dash').classList.add('stale');
  try {
    await loadPage(); // defined by the page
  } catch { return; }
  $('#gate').classList.add('hidden');
  $('#dash').classList.remove('hidden', 'stale');
  const note = $('#refresh-note');
  if (note) note.textContent = 'refreshed ' + new Date().toLocaleTimeString();
}

// ── shared header ───────────────────────────────────────────────────────

const NAV_PAGES = [
  { id: 'overview', label: 'Overview', href: '/admin' },
  { id: 'analytics', label: 'Analytics', href: '/admin/analytics' },
  { id: 'installs', label: 'Installs', href: '/admin/installs' },
  { id: 'feedback', label: 'Feedback', href: '/admin/feedback' }
];

function renderNav() {
  const nav = $('#admin-nav');
  if (!nav) return;
  nav.innerHTML = NAV_PAGES.map(p =>
    `<a href="${p.href}" data-nav="${p.id}" class="${p.id === PAGE ? 'on' : ''}">${p.label}</a>`).join('');
}

// A fresh-feedback badge on the nav — small enough to be worth the one
// extra counter on every page's payload; pages pass what they know.
function navFeedbackBadge(newCount) {
  const link = $('#admin-nav a[data-nav="feedback"]');
  if (!link) return;
  const cur = link.querySelector('.nav-badge');
  if (cur) cur.remove();
  if (newCount > 0) link.insertAdjacentHTML('beforeend', `<span class="nav-badge">${fmt(newCount)}</span>`);
}

// Counters bucket on UTC days and always will — explain the offset in the
// viewer's own clock rather than pretending the buckets are local.
function renderClockNote(day, period) {
  const el = $('#hdr-clock');
  if (!el) return;
  const now = new Date();
  const zone = new Intl.DateTimeFormat('en-US', { timeZoneName: 'short' })
    .formatToParts(now).find((p) => p.type === 'timeZoneName')?.value || 'local time';
  const rollover = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1))
    .toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' });
  el.innerHTML = `<span class="sub">UTC day <b>${esc(day)}</b>${period ? ` · month ${esc(period)}` : ''} — day buckets advance at ${esc(rollover)} ${esc(zone)} on your clock.</span>`;
}

// ── chart/table primitives (inline SVG, no libraries) ───────────────────

function dayList(endDay) {
  const end = new Date(endDay + 'T00:00:00Z');
  return Array.from({ length: rangeDays }, (_, i) =>
    new Date(end - (rangeDays - 1 - i) * 86400000).toISOString().slice(0, 10));
}

const val = (byDay, day, name) => (byDay[day] && byDay[day][name]) || 0;

function columnChart(mount, days, series, byDay) {
  const W = 480, H = 190, padL = 34, padB = 18, padT = 8;
  const plotW = W - padL - 6, plotH = H - padT - padB;
  const totals = days.map(d => series.reduce((s, sr) => s + val(byDay, d, sr.name), 0));
  const max = Math.max(1, ...totals);
  const step = niceStep(max);
  const yMax = Math.ceil(max / step) * step;
  const band = plotW / days.length;
  const barW = Math.max(3, Math.min(24, band - 2));
  const y = (v) => padT + plotH * (1 - v / yMax);

  let g = '';
  for (let v = 0; v <= yMax; v += step) {
    g += `<line x1="${padL}" x2="${W - 6}" y1="${y(v)}" y2="${y(v)}" stroke="${v === 0 ? 'var(--baseline)' : 'var(--grid)'}" stroke-width="1"/>`
       + `<text x="${padL - 5}" y="${y(v) + 3.5}" text-anchor="end">${fmt(v)}</text>`;
  }
  const labelEvery = Math.ceil(days.length / 6);
  days.forEach((d, i) => {
    if (i % labelEvery === 0) {
      g += `<text x="${padL + i * band + band / 2}" y="${H - 4}" text-anchor="middle">${d.slice(5)}</text>`;
    }
  });

  let bars = '', hits = '';
  days.forEach((d, i) => {
    const x = padL + i * band + (band - barW) / 2;
    let acc = 0;
    const segs = series.map(sr => ({ ...sr, v: val(byDay, d, sr.name) })).filter(sg => sg.v > 0);
    segs.forEach((sg, si) => {
      const y1 = y(acc + sg.v), y0 = y(acc) - (si > 0 ? 2 : 0);
      const h = Math.max(1, y0 - y1);
      const isTop = si === segs.length - 1;
      bars += isTop
        ? `<path d="${roundedTop(x, y1, barW, h, Math.min(4, h / 2, barW / 2))}" fill="${sg.color}"/>`
        : `<rect x="${x}" y="${y1}" width="${barW}" height="${h}" fill="${sg.color}"/>`;
      acc += sg.v;
    });
    const tip = `<b>${d}</b><br>` + series.map(sr => `${esc(sr.label)}: ${fmt(val(byDay, d, sr.name))}`).join('<br>');
    hits += `<rect x="${padL + i * band}" y="${padT}" width="${band}" height="${plotH}" fill="transparent" data-tip="${esc(tip)}"/>`;
  });

  mount.innerHTML = `<svg viewBox="0 0 ${W} ${H}" style="width:100%; height:auto; display:block">${g}${bars}${hits}</svg>`;
  wireTooltips(mount);
}

function roundedTop(x, y, w, h, r) {
  return `M${x},${y + h} L${x},${y + r} Q${x},${y} ${x + r},${y} L${x + w - r},${y} Q${x + w},${y} ${x + w},${y + r} L${x + w},${y + h} Z`;
}

function niceStep(max) {
  const raw = max / 4;
  const mag = Math.pow(10, Math.floor(Math.log10(Math.max(1, raw))));
  for (const m of [1, 2, 5, 10]) if (m * mag >= raw) return m * mag;
  return 10 * mag;
}

function dataTable(mount, header, rows) {
  mount.innerHTML = `<table class="data-table"><tr>${header.map(h => `<th>${esc(h)}</th>`).join('')}</tr>`
    + rows.map(r => `<tr>${r.map(c => `<td>${esc(c)}</td>`).join('')}</tr>`).join('') + '</table>';
}

function wireTooltips(scope) {
  const tip = $('#tooltip');
  scope.querySelectorAll('[data-tip]').forEach((el) => {
    el.addEventListener('mousemove', (e) => {
      tip.innerHTML = el.dataset.tip;
      tip.style.display = 'block';
      const x = Math.min(e.clientX + 12, window.innerWidth - tip.offsetWidth - 8);
      tip.style.left = x + 'px';
      tip.style.top = (e.clientY - tip.offsetHeight - 10 < 0 ? e.clientY + 14 : e.clientY - tip.offsetHeight - 10) + 'px';
    });
    el.addEventListener('mouseleave', () => { tip.style.display = 'none'; });
  });
}

function wireChartToggles() {
  document.querySelectorAll('[data-toggle]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const card = btn.closest('.chart-card');
      const showingTable = !$('.table-wrap', card).classList.toggle('hidden');
      $('.plot', card).classList.toggle('hidden', showingTable);
      const legend = $('.legend', card);
      if (legend) legend.classList.toggle('hidden', showingTable);
      btn.textContent = showingTable ? 'chart' : 'table';
    });
  });
}

// ── environment banner ──────────────────────────────────────────────────

async function showEnvironment() {
  let env = null;
  try { env = (await (await fetch('/healthz')).json()).env || null; } catch { /* offline — no banner */ }
  if (!env) return;
  const isProd = /^prod/i.test(env);
  const banner = $('#env-banner');
  banner.innerHTML = esc(env)
    + (isProd ? ' <span class="what">real users, real numbers</span>'
              : ' <span class="what">test deployment, numbers here are not real usage</span>');
  banner.classList.toggle('is-prod', isProd);
  banner.classList.remove('hidden');
  document.title = document.title.replace(/\s*\(.*\)$/, '') + ` (${env})`;
}

// ── boot ────────────────────────────────────────────────────────────────

function initAdminShell() {
  renderNav();
  wireChartToggles();

  const range = $('#range-buttons');
  if (range) {
    range.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-days]');
      if (!btn) return;
      rangeDays = parseInt(btn.dataset.days, 10);
      range.querySelectorAll('button').forEach(b => b.classList.toggle('on', b === btn));
      load();
    });
  }

  const go = () => {
    const t = $('#token-input').value.trim();
    if (!t) return;
    sessionStorage.setItem(TOKEN_KEY, t);
    load();
  };
  $('#token-go').addEventListener('click', go);
  $('#token-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });

  showEnvironment();
  if (sessionStorage.getItem(TOKEN_KEY)) load(); else showGate();
  setInterval(() => { if (!$('#dash').classList.contains('hidden')) load(); }, 60000);
}
