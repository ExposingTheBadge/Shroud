/* ─────────────────────────────────────────────────────────────────────
 * SHROUD admin dashboard — v2.4.0
 *
 * Architecture notes:
 *   - One module, no build step, no framework. Vanilla DOM updates.
 *   - State lives in `state`. Render functions read from state and pour
 *     into the DOM. They are idempotent — calling render() twice produces
 *     the same HTML.
 *   - Each tab has its own /api/v1/admin/stats/<section> endpoint. Tabs
 *     refresh on the user-chosen interval; the time-critical panels
 *     (audit, errors, failed-logins) get pushed live over /ws/admin so
 *     they update the instant something happens, not on the next tick.
 *   - All POST/DELETE admin endpoints expect the X-CSRF-Token header set
 *     to the shroud_csrf cookie value (matches server check_csrf).
 * ───────────────────────────────────────────────────────────────────── */

'use strict';

/* ─── Global state ────────────────────────────────────────────────── */
const state = {
  tab:        'overview',
  regOn:      false,
  mntOn:      false,
  onionOn:    false,
  fileData:   [],
  audit:      [],
  failedLogins: [],
  recentErrors: [],
  refreshInterval: 8000,
  refreshTimer: null,
  ws: null,
  wsBackoff: 1000,
  pendingGoto: null,            /* `g` shortcut buffer */
  pendingGotoUntil: 0,
};

const LS_INTERVAL   = 'shroud.admin.interval';
const LS_LAST_TAB   = 'shroud.admin.lastTab';

/* ─── DOM helpers ─────────────────────────────────────────────────── */
function $(id) { return document.getElementById(id); }
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  })[c]);
}

/* ─── Icons ───────────────────────────────────────────────────────────
 * One small line-icon set, drawn here so there is no icon font, no CDN
 * and no emoji. Every glyph is a 24-unit path stroked in currentColor,
 * so it takes the theme and the state colour of whatever contains it. */
const ICONS = {
  shield:   '<path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/>',
  search:   '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>',
  refresh:  '<path d="M20 11a8 8 0 1 0-2.3 5.7"/><path d="M20 4v7h-7"/>',
  monitor:  '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
  sun:      '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon:     '<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/>',
  keyboard: '<rect x="2" y="6" width="20" height="12" rx="2"/><path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M7 14h10"/>',
  logout:   '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
  grid:     '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  users:    '<circle cx="9" cy="8" r="4"/><path d="M2 21c0-3.9 3.1-7 7-7s7 3.1 7 7M16 4.1a4 4 0 0 1 0 7.8M22 21c0-3-1.7-5.5-4.2-6.5"/>',
  user:     '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-8 8-8s8 3.6 8 8"/>',
  devices:  '<rect x="2" y="4" width="14" height="10" rx="1.5"/><path d="M5 18h8"/><rect x="17" y="8" width="5" height="12" rx="1.2"/>',
  key:      '<circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.7 12.3L20 3M16 7l3 3M14 9l2 2"/>',
  file:     '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>',
  list:     '<path d="M9 6h11M9 12h11M9 18h11M4 6h.01M4 12h.01M4 18h.01"/>',
  activity: '<path d="M3 12h4l3 8 4-16 3 8h4"/>',
  globe:    '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18"/>',
  ban:      '<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>',
  check:    '<circle cx="12" cy="12" r="9"/><path d="M8 12.5l2.7 2.7L16 9.5"/>',
  alert:    '<path d="M12 3.5l9 16H3z"/><path d="M12 10v4M12 17h.01"/>',
  warn:     '<circle cx="12" cy="12" r="9"/><path d="M12 7.5v5.5M12 16.5h.01"/>',
  info:     '<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5M12 7.5h.01"/>',
  copy:     '<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/>',
  trash:    '<path d="M3 6h18M8 6V4h8v2M6 6l1 15h10l1-15"/>',
  download: '<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>',
  power:    '<path d="M12 3v9M6.3 6.3a8 8 0 1 0 11.4 0"/>',
  lock:     '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  database: '<ellipse cx="12" cy="5.5" rx="8" ry="3"/><path d="M4 5.5v13c0 1.7 3.6 3 8 3s8-1.3 8-3v-13M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
  sync:     '<path d="M4 11a8 8 0 0 1 14-4.5M20 13a8 8 0 0 1-14 4.5"/><path d="M18 3v4h-4M6 21v-4h4"/>',
  up:       '<path d="M6 15l6-6 6 6"/>',
  down:     '<path d="M6 9l6 6 6-6"/>',
  arrow:    '<path d="M5 12h14M13 6l6 6-6 6"/>',
};
function icon(name) {
  return '<svg class="ic" viewBox="0 0 24 24" aria-hidden="true">' + (ICONS[name] || ICONS.info) + '</svg>';
}
/* Swap every <span data-icon="x"> placeholder in static markup for the
 * SVG, and give each tab its icon. */
function hydrateIcons(root) {
  (root || document).querySelectorAll('span[data-icon]').forEach(el => {
    el.insertAdjacentHTML('afterend', icon(el.dataset.icon));
    el.remove();
  });
  (root || document).querySelectorAll('[data-icon-tab]').forEach(el => {
    if (!el.querySelector('.ic')) el.insertAdjacentHTML('afterbegin', icon(el.dataset.iconTab));
  });
}

/* ─── Row actions without inline JavaScript ───────────────────────────
 * Rows used to be built as onclick="openUser('<esc(value)>')". esc()
 * turns ' into &#39;, but the HTML parser decodes that back to ' before
 * the handler runs, so a username like  x');alert(document.cookie)//
 * broke out of the string. Usernames are unrestricted, so any stranger
 * could register one and run script in the admin's browser the moment
 * the Users tab rendered — with the JS-readable CSRF token in reach.
 * Actions now carry their arguments as JSON in a data attribute, which
 * is only ever parsed, never executed. */
const ACTIONS = {};
function act(name, ...args) {
  return 'data-act="' + esc(name) + '" data-args="' + esc(JSON.stringify(args)) + '"';
}
function ctxAct(name, ...args) {
  return 'data-ctx="' + esc(name) + '" data-ctx-args="' + esc(JSON.stringify(args)) + '"';
}
document.addEventListener('click', e => {
  const cp = e.target.closest('.copy');
  if (cp && cp.dataset.copy) { e.stopPropagation(); copyText(cp.dataset.copy); return; }
  const el = e.target.closest('[data-act]');
  if (!el) return;
  const fn = ACTIONS[el.dataset.act];
  if (!fn) return;
  e.preventDefault();
  let args = [];
  try { args = JSON.parse(el.dataset.args || '[]'); } catch (_) { return; }
  fn(...args);
});
document.addEventListener('contextmenu', e => {
  const el = e.target.closest('[data-ctx]');
  const fn = el && ACTIONS[el.dataset.ctx];
  if (!fn) return;
  let args = [];
  try { args = JSON.parse(el.dataset.ctxArgs || '[]'); } catch (_) { return; }
  fn(e, ...args);
});

/* ─── Small render helpers ────────────────────────────────────────── */
/* Server timestamps are SQLite "YYYY-MM-DD HH:MM:SS" in UTC. */
function parseTs(ts) {
  if (!ts) return NaN;
  let t = String(ts).trim();
  if (/^\d{4}-\d\d-\d\d \d/.test(t)) t = t.replace(' ', 'T');
  if (/^\d{4}-\d\d-\d\dT/.test(t) && !/(z|[+-]\d\d:?\d\d)$/i.test(t)) t += 'Z';
  return Date.parse(t);
}
function ago(ms) {
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 45) return 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return m + ' min ago';
  const h = Math.round(m / 60);
  if (h < 24) return h + ' h ago';
  const d = Math.round(h / 24);
  if (d < 45) return d + (d === 1 ? ' day ago' : ' days ago');
  return new Date(ms).toISOString().slice(0, 10);
}
/* "3 min ago" with the exact local time on hover, and a sort key. */
function rel(ts, fallback) {
  const ms = parseTs(ts);
  if (isNaN(ms)) return '<span class="muted">' + esc(fallback || ts || '—') + '</span>';
  return '<span class="rel" data-ts="' + ms + '" data-sort="' + ms + '" title="' +
         esc(new Date(ms).toLocaleString()) + '">' + ago(ms) + '</span>';
}
function refreshRelTimes() {
  document.querySelectorAll('.rel[data-ts]').forEach(el => {
    el.textContent = ago(Number(el.dataset.ts));
  });
}
function copyCell(value, shown) {
  return '<span class="copy" data-copy="' + esc(value) + '" title="Click to copy ' + esc(value) + '">' +
         esc(shown == null ? value : shown) + '</span>';
}
function copyText(value, what) {
  const done = () => toast((what || 'Copied') + (what ? ' copied' : ''), 'ok');
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(value).then(done, () => window.prompt('Copy:', value));
  } else {
    window.prompt('Copy:', value);
  }
}
function emptyRow(cols, title, sub, ic) {
  return '<tr class="empty-row"><td colspan="' + cols + '"><div class="empty">' + icon(ic || 'info') +
         '<b>' + esc(title) + '</b>' + (sub ? '<span>' + esc(sub) + '</span>' : '') + '</div></td></tr>';
}

/* ─── Theme: system / light / dark ────────────────────────────────── */
const LS_THEME = 'shroud.admin.theme';
const THEMES = ['system', 'light', 'dark'];
function currentTheme() {
  try { return localStorage.getItem(LS_THEME) || 'system'; } catch (e) { return 'system'; }
}
function applyTheme(t) {
  if (t === 'system') delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = t;
  const b = $('themeBtn');
  if (b) {
    b.innerHTML = icon(t === 'light' ? 'sun' : t === 'dark' ? 'moon' : 'monitor');
    b.title = 'Theme: ' + (t === 'system' ? 'follows your system' : t) + ' (press t to change)';
  }
}
function cycleTheme() {
  const t = THEMES[(THEMES.indexOf(currentTheme()) + 1) % THEMES.length];
  try { localStorage.setItem(LS_THEME, t); } catch (e) {}
  applyTheme(t);
  toast('Theme: ' + (t === 'system' ? 'follows your system' : t), 'ok');
}

/* ─── Health summary ──────────────────────────────────────────────────
 * The overview is ~30 numbers. This line answers the question an
 * operator actually opens it with — is anything wrong? — in words, with
 * a link to where to look. Thresholds match the tile colouring. */
function renderHealth(d) {
  const el = $('health');
  if (!el) return;
  const errRate = d.requests_total ? (d.errors_total / d.requests_total) * 100 : 0;
  const diskFree = Number(d.disk_free_bytes) || 0;
  const issues = [];
  const add = (sev, text, link) => issues.push({ sev, text, link });
  const busy = (d.requests_total || 0) >= 50;
  if (d.maintenance_mode)
    add('warn', 'Maintenance mode is on, so clients cannot send messages.', ['Turn it off', 'confirmToggle', 'maintenance']);
  if (diskFree && diskFree < 512 * 1048576)
    add('alert', 'Only ' + fmtSize(diskFree) + ' of disk space left.', ['Purge old files', 'ctrlConfirm', 'purge-files', 'Purge Files', 'This deletes expired and already-downloaded files from disk.', 'warn']);
  else if (diskFree && diskFree < 2 * 1073741824)
    add('warn', 'Disk space is getting low (' + fmtSize(diskFree) + ' free).', ['Purge old files', 'ctrlConfirm', 'purge-files', 'Purge Files', 'This deletes expired and already-downloaded files from disk.', 'warn']);
  // Some 4xx is normal (wrong passwords, stale devices), so the bar for
  // calling it out here is higher than the tile's colouring.
  if (busy && errRate >= 25) add('alert', errRate.toFixed(1) + '% of requests are ending in an error.', ['See errors', 'goTab', 'audit']);
  else if (busy && errRate >= 10) add('warn', errRate.toFixed(1) + '% of requests are ending in an error.', ['See errors', 'goTab', 'audit']);
  if (d.failed_logins_24h >= 25) add('alert', d.failed_logins_24h + ' failed admin sign-ins in the last day. Someone may be guessing the password.', ['See who', 'goTab', 'audit']);
  else if (d.failed_logins_24h >= 5) add('warn', d.failed_logins_24h + ' failed admin sign-ins in the last day.', ['See who', 'goTab', 'audit']);
  if (d.undelivered >= 1000) add('alert', (d.undelivered).toLocaleString() + ' messages are waiting to be collected.', ['Open activity', 'goTab', 'activity']);
  else if (d.undelivered >= 100) add('warn', (d.undelivered).toLocaleString() + ' messages are waiting to be collected.', ['Open activity', 'goTab', 'activity']);
  if (busy && d.p95_req_ms >= 1000) add('alert', 'The relay is slow: 1 in 20 requests takes over ' + d.p95_req_ms + ' ms.');
  else if (busy && d.p95_req_ms >= 250) add('warn', 'The relay is slower than usual: 1 in 20 requests takes over ' + d.p95_req_ms + ' ms.');

  const facts = [
    (d.active_now || 0) + ' of ' + (d.total_devices || 0) + ' devices online now',
    'registration ' + (d.registration_enabled ? 'open' : 'closed'),
    d.onion_only ? 'Tor-only' : null,
    'up ' + (d.uptime_fmt || '—'),
  ].filter(Boolean).join(' · ');

  const worst = issues.some(i => i.sev === 'alert') ? 'alert' : issues.length ? 'warn' : '';
  el.className = 'health ' + worst;
  if (!issues.length) {
    el.innerHTML = '<div class="hi">' + icon('check') + '</div><div><h2>Everything looks healthy</h2><p>' +
                   esc(facts) + '</p></div>';
    return;
  }
  el.innerHTML = '<div class="hi">' + icon(worst === 'alert' ? 'alert' : 'warn') + '</div><div><h2>' +
    issues.length + (issues.length === 1 ? ' thing needs' : ' things need') + ' your attention</h2><p>' +
    esc(facts) + '</p><ul>' + issues.map(i =>
      '<li><span class="sev ' + i.sev + '">' + (i.sev === 'alert' ? 'Urgent' : 'Check') + '</span>' +
      '<span>' + esc(i.text) + '</span>' +
      (i.link ? '<a ' + act(i.link[1], ...i.link.slice(2)) + '>' + esc(i.link[0]) + '</a>' : '') + '</li>'
    ).join('') + '</ul></div>';
}

/* ─── Top-bar switches, with a plain-language confirmation for the
 * direction that can lock people out. ─────────────────────────────── */
const TOGGLES = {
  registration: {
    name: 'registration', on: () => state.regOn, risky: 'off',
    onText: 'New people will be able to create accounts on this relay and every federated relay.',
    offText: 'Nobody will be able to create a new account on this relay or anywhere in the federation. People who already have an account can still sign in.',
  },
  maintenance: {
    name: 'maintenance mode', on: () => state.mntOn, risky: 'on',
    onText: 'Clients will be refused while maintenance is on. Messages already queued are kept and delivered afterwards.',
    offText: 'The relay goes back to accepting messages.',
  },
  'onion-only': {
    name: 'Tor-only mode', on: () => state.onionOn, risky: 'on',
    onText: 'Every client request that does not arrive over Tor will be refused. Make sure Tor is running on this relay first, or your users lose access. This panel stays reachable.',
    offText: 'Clients can connect over the normal internet again.',
  },
};
async function confirmToggle(which) {
  const t = TOGGLES[which];
  const next = !t.on();
  if ((next ? 'on' : 'off') === t.risky) {
    const ok = await showModal({
      title: (next ? 'Turn on ' : 'Turn off ') + t.name + '?',
      body: esc(next ? t.onText : t.offText),
      confirmText: next ? 'Turn on' : 'Turn off', confirmClass: 'danger',
    });
    if (!ok) return;
  }
  toggleSetting(which, next);
}

/* ─── Tables: click a header to sort; filters and sort survive the
 * auto-refresh (they used to reset every few seconds, because each
 * refresh re-renders the rows). ───────────────────────────────────── */
const sortState = {};
function cellKey(td) {
  if (!td) return '';
  const k = td.querySelector('[data-sort]');
  if (k) return Number(k.dataset.sort);
  const t = td.textContent.trim();
  const n = Number(t.replace(/,/g, ''));
  return t !== '' && !isNaN(n) ? n : t.toLowerCase();
}
function applyView(tb) {
  const st = sortState[tb.id];
  if (st) {
    const rows = [...tb.rows].filter(r => !r.classList.contains('empty-row'));
    rows.sort((a, b) => {
      const x = cellKey(a.cells[st.col]), y = cellKey(b.cells[st.col]);
      const c = typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y));
      return st.dir === 'asc' ? c : -c;
    });
    rows.forEach(r => tb.appendChild(r));
  }
  const inp = document.querySelector('input.search[data-target="' + tb.id + '"]');
  if (inp && inp.value.trim()) applySearch(inp);
  if (tb._obs) tb._obs.takeRecords();
}
function wireTables() {
  document.querySelectorAll('table').forEach(tbl => {
    const tb = tbl.tBodies[0];
    if (!tb || !tb.id || tb._obs) return;
    tb._obs = new MutationObserver(() => applyView(tb));
    tb._obs.observe(tb, { childList: true });
    tbl.querySelectorAll('thead th').forEach((th, i) => {
      if (!th.textContent.trim()) return;
      th.classList.add('sortable');
      th.title = 'Sort by ' + th.textContent.trim().toLowerCase();
      th.insertAdjacentHTML('beforeend', '<span class="arr"></span>');
      th.addEventListener('click', () => {
        const cur = sortState[tb.id];
        const dir = !cur || cur.col !== i ? 'asc' : cur.dir === 'asc' ? 'desc' : null;
        tbl.querySelectorAll('th').forEach(h => { h.classList.remove('asc', 'desc'); const a = h.querySelector('.arr'); if (a) a.innerHTML = ''; });
        if (dir) {
          sortState[tb.id] = { col: i, dir };
          th.classList.add(dir);
          th.querySelector('.arr').innerHTML = icon(dir === 'asc' ? 'up' : 'down');
          applyView(tb);
        } else {
          delete sortState[tb.id];
          fetchTab(state.tab);   // restore the server's own order
        }
      });
    });
  });
}

/* ─── CSV export for any table ─────────────────────────────────────── */
function exportTable(tbodyId) {
  const tb = $(tbodyId);
  if (!tb) return;
  const tbl = tb.closest('table');
  const panel = tb.closest('.panel');
  const title = panel ? (panel.querySelector('.panel-hdr').firstChild.textContent || 'table').trim() : 'table';
  const cols = [...tbl.tHead.rows[0].cells].map(th => th.textContent.trim()).filter(Boolean);
  const valueOf = td => {
    const c = td.querySelector('[data-copy]');
    if (c) return c.dataset.copy;
    const t = td.querySelector('[data-ts]');
    if (t) return new Date(Number(t.dataset.ts)).toISOString();
    return td.textContent.trim();
  };
  const rows = [...tb.rows]
    .filter(r => r.style.display !== 'none' && !r.classList.contains('empty-row'))
    .map(r => [...r.cells].slice(0, cols.length).map(valueOf));
  if (!rows.length) { toast('Nothing to export', 'warn'); return; }
  const q = v => /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
  const csv = [cols, ...rows].map(r => r.map(q).join(',')).join('\r\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = 'shroud-' + title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') +
               '-' + new Date().toISOString().slice(0, 10) + '.csv';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  toast('Exported ' + rows.length + ' row' + (rows.length === 1 ? '' : 's'), 'ok');
}
function addExportButtons() {
  document.querySelectorAll('.panel').forEach(panel => {
    const tb = panel.querySelector('table tbody[id]');
    const hdr = panel.querySelector('.panel-hdr');
    if (!tb || !hdr || tb.id === 'auditTable') return;   // audit has a server-side export
    let actions = hdr.querySelector('.actions');
    if (!actions) { actions = document.createElement('div'); actions.className = 'actions'; hdr.appendChild(actions); }
    if (actions.querySelector('.csv-btn')) return;
    const b = document.createElement('button');
    b.className = 'csv-btn';
    b.title = 'Download the rows shown as a CSV file';
    b.innerHTML = icon('download') + ' CSV';
    b.addEventListener('click', () => exportTable(tb.id));
    actions.appendChild(b);
  });
}

/* ─── Command palette (Ctrl/Cmd + K) ──────────────────────────────── */
const TAB_META = [
  ['overview', 'Overview', 'grid'], ['users', 'Users', 'users'], ['devices', 'Devices', 'devices'],
  ['crypto', 'Crypto', 'key'], ['files', 'Files', 'file'], ['audit', 'Audit log', 'list'],
  ['activity', 'Activity', 'activity'], ['federation', 'Federation', 'globe'], ['bans', 'Bans', 'ban'],
];
const palette = { items: [], shown: [], sel: 0, loadedAt: 0 };
function paletteItems() {
  const items = TAB_META.map(([t, label, ic]) => ({ label: 'Go to ' + label, grp: 'Tab', ic, run: () => goTab(t) }));
  items.push(
    { label: 'Refresh now', grp: 'Action', ic: 'refresh', run: () => refresh(true) },
    { label: 'Switch theme', grp: 'Action', ic: 'sun', run: cycleTheme },
    { label: (state.regOn ? 'Close' : 'Open') + ' registration', grp: 'Action', ic: 'user', run: () => confirmToggle('registration') },
    { label: 'Turn maintenance ' + (state.mntOn ? 'off' : 'on'), grp: 'Action', ic: 'power', run: () => confirmToggle('maintenance') },
    { label: 'Turn Tor-only mode ' + (state.onionOn ? 'off' : 'on'), grp: 'Action', ic: 'lock', run: () => confirmToggle('onion-only') },
    { label: 'Add a ban', grp: 'Action', ic: 'ban', run: () => { goTab('bans'); setTimeout(() => $('banValueInput').focus(), 50); } },
    { label: 'Sync federation state now', grp: 'Action', ic: 'sync', run: forceFederationSync },
    { label: 'Purge old files', grp: 'Action', ic: 'trash', run: () => ctrlConfirm('purge-files', 'Purge Files', 'This deletes expired and already-downloaded files from disk.', 'warn') },
    { label: 'Compact the database (VACUUM)', grp: 'Action', ic: 'database', run: () => ctrlConfirm('vacuum', 'Vacuum DB', 'Reclaims disk space by repacking the SQLite database. Briefly locks the DB.', 'warn') },
    { label: 'Export audit log as CSV', grp: 'Action', ic: 'download', run: exportAuditCsv },
    { label: 'Keyboard shortcuts', grp: 'Help', ic: 'keyboard', run: showCheatsheet },
    { label: 'Sign out', grp: 'Action', ic: 'logout', run: logout },
  );
  for (const u of state.users || [])
    items.push({ label: u.username, grp: 'User · ' + u.devices + ' device' + (u.devices === 1 ? '' : 's'), ic: 'user', run: () => openUser(u.user_id) });
  for (const d of state.devices || [])
    items.push({ label: (d.name || 'Unnamed device') + ' · ' + d.id.slice(0, 8), grp: 'Device · ' + (PLATFORM[d.platform] || d.platform), ic: 'devices', run: () => openDevice(d.id) });
  return items;
}
async function openPalette() {
  $('paletteBg').classList.add('show');
  const inp = $('paletteInput');
  inp.value = '';
  palette.items = paletteItems();
  renderPalette();
  inp.focus();
  // Users and devices are fetched on demand so the palette can search
  // them from any tab; cached for a minute.
  if (Date.now() - palette.loadedAt > 60000) {
    palette.loadedAt = Date.now();
    try {
      const [u, d] = await Promise.all([api('GET', '/api/v1/admin/stats/users'), api('GET', '/api/v1/admin/stats/devices')]);
      state.users = (await u.json()).users || [];
      state.devices = (await d.json()).devices || [];
      if ($('paletteBg').classList.contains('show')) { palette.items = paletteItems(); renderPalette(); }
    } catch (e) { /* tabs and actions still work */ }
  }
}
function closePalette() { $('paletteBg').classList.remove('show'); }
function renderPalette() {
  const q = $('paletteInput').value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  palette.shown = palette.items.filter(it => {
    const hay = (it.label + ' ' + it.grp).toLowerCase();
    return q.every(t => hay.includes(t));
  }).slice(0, 50);
  palette.sel = Math.min(palette.sel, Math.max(0, palette.shown.length - 1));
  $('paletteRes').innerHTML = palette.shown.map((it, i) =>
    '<div class="it' + (i === palette.sel ? ' sel' : '') + '" data-i="' + i + '">' + icon(it.ic) +
    '<span>' + esc(it.label) + '</span><span class="grp">' + esc(it.grp) + '</span></div>'
  ).join('') || '<div class="none">No matches</div>';
  const sel = $('paletteRes').querySelector('.sel');
  if (sel) sel.scrollIntoView({ block: 'nearest' });
}
function runPalette(i) {
  const it = palette.shown[i];
  if (!it) return;
  closePalette();
  it.run();
}
$('paletteInput').addEventListener('input', () => { palette.sel = 0; renderPalette(); });
$('paletteInput').addEventListener('keydown', e => {
  if (e.key === 'ArrowDown') { e.preventDefault(); palette.sel = Math.min(palette.sel + 1, palette.shown.length - 1); renderPalette(); }
  else if (e.key === 'ArrowUp') { e.preventDefault(); palette.sel = Math.max(palette.sel - 1, 0); renderPalette(); }
  else if (e.key === 'Enter') { e.preventDefault(); runPalette(palette.sel); }
  else if (e.key === 'Escape') { e.preventDefault(); closePalette(); }
});
$('paletteRes').addEventListener('click', e => {
  const it = e.target.closest('.it');
  if (it) runPalette(Number(it.dataset.i));
});

/* ─── "Updated 5 s ago" ───────────────────────────────────────────── */
function tickFreshness() {
  const el = $('freshness');
  if (!el) return;
  if (state.lastErr && (!state.lastOk || state.lastErr > state.lastOk)) {
    el.textContent = 'cannot reach relay, retrying';
    el.classList.add('stale');
    return;
  }
  if (!state.lastOk) return;
  const s = Math.round((Date.now() - state.lastOk) / 1000);
  el.textContent = 'updated ' + (s < 2 ? 'just now' : s < 60 ? s + ' s ago' : Math.round(s / 60) + ' min ago');
  el.classList.toggle('stale', state.refreshInterval > 0 && s * 1000 > Math.max(60000, state.refreshInterval * 3));
}

function fmtSize(b) {
  if (!b && b !== 0) return '—';
  if (b < 1024)       return b + ' B';
  if (b < 1048576)    return (b/1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b/1048576).toFixed(1) + ' MB';
  return (b/1073741824).toFixed(2) + ' GB';
}
function fmtPct(part, total) {
  if (!total) return '0%';
  return ((part/total)*100).toFixed(1) + '%';
}
function getCookie(name) {
  const m = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : '';
}

/* ─── HTTP with CSRF on writes ──────────────────────────────────────
 *  Writes echo the shroud_csrf cookie back as X-CSRF-Token
 *  (double-submit). Any non-2xx response is thrown so the caller can
 *  show an honest failure toast — silently treating 403/503 as success
 *  is what made the v2.4.0 maintenance toggle appear to do nothing. */
async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (method !== 'GET') {
    const csrf = getCookie('shroud_csrf');
    if (csrf) opts.headers['X-CSRF-Token'] = csrf;
  }
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(path, opts);
  if (r.status === 401) { location = '/admin/login'; throw new Error('unauthorized'); }
  if (!r.ok) {
    let detail = r.status + ' ' + r.statusText;
    try {
      const j = await r.clone().json();
      if (j && j.detail) detail = j.detail;
    } catch (_) { /* response wasn't JSON */ }
    throw new Error(detail);
  }
  return r;
}

/* ─── Toast ───────────────────────────────────────────────────────── */
function toast(msg, level) {
  const t = document.createElement('div');
  t.className = 'toast ' + (level || '');
  const ic = level === 'danger' ? 'alert' : level === 'warn' ? 'warn' : level === 'ok' ? 'check' : 'info';
  t.innerHTML = icon(ic) + '<span></span>';
  t.lastChild.textContent = msg;
  $('toastStack').appendChild(t);
  setTimeout(() => {
    t.style.transition = 'opacity .3s';
    t.style.opacity = '0';
    setTimeout(() => t.remove(), 320);
  }, 3800);
}

/* ─── Modal ───────────────────────────────────────────────────────── */
let modalResolver = null;
function showModal({ title, body, impact, impactClass, confirmText, confirmClass, focus }) {
  $('modalTitle').textContent = title || 'Confirm';
  $('modalBody').innerHTML    = body || '';
  const imp = $('modalImpact');
  if (impact) {
    imp.textContent = impact;
    imp.className   = 'impact' + (impactClass ? ' ' + impactClass : '');
    imp.style.display = 'block';
  } else {
    imp.style.display = 'none';
  }
  const btn = $('modalConfirm');
  btn.textContent = confirmText || 'Confirm';
  btn.className   = confirmClass || 'primary';
  $('modalBg').classList.add('show');
  setTimeout(() => { const f = focus && $(focus); (f || btn).focus(); }, 30);
  return new Promise(res => { modalResolver = res; });
}
function closeModal(result) {
  $('modalBg').classList.remove('show');
  if (modalResolver) { modalResolver(result === true); modalResolver = null; }
}
$('modalConfirm').addEventListener('click', () => closeModal(true));
$('modalBg').addEventListener('click', e => { if (e.target.id === 'modalBg') closeModal(false); });
$('modalBg').addEventListener('keydown', e => {
  if (e.key === 'Enter' && e.target.matches('input')) { e.preventDefault(); closeModal(true); }
});

function showCheatsheet()  { $('cheatsheetBg').classList.add('show'); }
function closeCheatsheet() { $('cheatsheetBg').classList.remove('show'); }

/* ─── Tabs ────────────────────────────────────────────────────────── */
function goTab(name) {
  state.tab = name;
  document.querySelectorAll('.tab').forEach(t => {
    t.classList.toggle('active', t.dataset.tab === name);
  });
  document.querySelectorAll('.section').forEach(s => {
    s.classList.toggle('active', s.dataset.section === name);
  });
  history.replaceState(null, '', '#' + name);
  try { localStorage.setItem(LS_LAST_TAB, name); } catch (e) {}
  /* Trigger an immediate fetch for the tab we just entered, so the user
   * isn't waiting for the next tick. */
  fetchTab(name);
}

function currentTabFromHash() {
  const h = (location.hash || '').replace(/^#/, '');
  const valid = ['overview','users','devices','crypto','files','audit','activity','federation','bans'];
  if (valid.includes(h)) return h;
  try {
    const last = localStorage.getItem(LS_LAST_TAB);
    if (valid.includes(last)) return last;
  } catch (e) {}
  return 'overview';
}

/* ─── Per-tab fetchers ────────────────────────────────────────────── */
async function fetchOverview() {
  const r = await api('GET', '/api/v1/admin/stats/overview');
  const d = await r.json();
  renderOverview(d);
  renderTopBar(d);
  renderToggles(d);
}
async function fetchUsers() {
  const r = await api('GET', '/api/v1/admin/stats/users');
  const d = await r.json();
  renderUsers(d);
}
async function fetchDevices() {
  const r = await api('GET', '/api/v1/admin/stats/devices');
  const d = await r.json();
  renderDevices(d);
}
async function fetchCrypto() {
  const r = await api('GET', '/api/v1/admin/stats/crypto');
  const d = await r.json();
  renderCrypto(d);
}
async function fetchFiles() {
  const r = await api('GET', '/api/v1/admin/stats/files');
  const d = await r.json();
  state.fileData = d.files || [];
  renderFiles(d);
}
async function fetchAudit() {
  const q = new URLSearchParams();
  const a = $('auditFilterActor').value.trim();   if (a) q.set('actor', a);
  const ac = $('auditFilterAction').value.trim(); if (ac) q.set('action', ac);
  const tg = $('auditFilterTarget').value.trim(); if (tg) q.set('target', tg);
  const sn = $('auditFilterSince').value;         if (sn) q.set('since_hours', sn);
  const url = '/api/v1/admin/stats/audit' + (q.toString() ? '?' + q : '');
  const r = await api('GET', url);
  const d = await r.json();
  state.audit = d.audit_log || [];
  state.failedLogins = d.failed_logins || [];
  state.recentErrors = d.recent_errors || [];
  renderAudit(d);
}
async function fetchActivity() {
  const r = await api('GET', '/api/v1/admin/stats/activity');
  const d = await r.json();
  renderActivity(d);
}

/* ─── Tab dispatcher ──────────────────────────────────────────────── */
function fetchTab(name) {
  switch (name) {
    case 'overview': return fetchOverview();
    case 'users':    return fetchUsers();
    case 'devices':  return fetchDevices();
    case 'crypto':   return fetchCrypto();
    case 'files':    return fetchFiles();
    case 'audit':    return fetchAudit();
    case 'activity': return fetchActivity();
    case 'federation': return loadFederation();
    case 'bans':       return loadBans();
  }
}

/* ─── Bans ────────────────────────────────────────────────────────── */
async function banUserPrompt(username) {
  const ok = await showModal({
    title: 'Ban ' + username + '?',
    body: '<b>' + esc(username) + '</b> will be signed out and refused on every relay in the federation. ' +
          'Every hardware ID they have signed in from is banned too, so a new account on the same machine is refused.' +
          '<label class="lbl" for="modalReason">Reason shown to them (optional)</label>' +
          '<input class="field" id="modalReason" maxlength="500" placeholder="e.g. Spam">',
    confirmText: 'Ban ' + username, confirmClass: 'danger', focus: 'modalReason',
  });
  if (!ok) return;
  const reason = ($('modalReason') || {}).value || '';
  try {
    const r = await api('POST', '/api/v1/admin/bans', { kind: 'username', value: username, reason });
    const d = await r.json();
    const n = (d.hwids_banned || []).length;
    toast('Banned ' + username + ' and ' + n + ' hardware ID' + (n === 1 ? '' : 's'), 'ok');
    if (state.tab === 'bans') loadBans();
  } catch (e) {
    toast('Could not ban ' + username + ': ' + e.message, 'danger');
  }
}

function userContextMenu(ev, username, userId) {
  ev.preventDefault();
  const existing = document.getElementById('userCtxMenu');
  if (existing) existing.remove();
  const m = document.createElement('div');
  m.id = 'userCtxMenu';
  m.className = 'palette';
  m.style.cssText = 'position:fixed;z-index:160;width:auto;min-width:200px;padding:4px';
  m.style.left = Math.min(ev.clientX, innerWidth - 220) + 'px';
  m.style.top  = Math.min(ev.clientY, innerHeight - 140) + 'px';
  const item = (ic, label, fn, danger) => {
    const i = document.createElement('div');
    i.className = 'it';
    i.innerHTML = icon(ic) + '<span></span>';
    i.lastChild.textContent = label;
    if (danger) i.style.color = 'var(--danger)';
    i.onmouseenter = () => i.classList.add('sel');
    i.onmouseleave = () => i.classList.remove('sel');
    i.onclick = () => { m.remove(); fn(); };
    m.appendChild(i);
  };
  item('user', 'Open ' + username, () => openUser(userId));
  item('copy', 'Copy user ID', () => copyText(userId, 'User ID'));
  item('ban', 'Ban…', () => banUserPrompt(username), true);
  item('trash', 'Delete account…', () => delUser(userId, username, 0), true);
  document.body.appendChild(m);
  const dismiss = () => { m.remove(); document.removeEventListener('click', dismiss); };
  setTimeout(() => document.addEventListener('click', dismiss), 0);
}

async function loadBans() {
  try {
    const r = await api('GET', '/api/v1/admin/bans');
    renderBans(await r.json());
  } catch (e) {
    const t = $('banTable');
    if (t) t.innerHTML = emptyRow(7, 'Could not load bans', e.message, 'alert');
  }
}

const BAN_KIND = { username: 'Username', hwid: 'Hardware ID', ip: 'IP address' };

function renderBans(d) {
  const arr = d.bans || [];
  const tbl = $('banTable');
  if (!tbl) return;
  $('banCountPill').textContent = arr.length;
  $('banCountPill2').textContent = arr.length;
  tbl.innerHTML = arr.map(b =>
    '<tr>' +
    '<td class="who">' + esc(BAN_KIND[b.kind] || b.kind) + '</td>' +
    '<td>' + copyCell(b.value, b.value.length > 24 ? b.value.slice(0, 24) + '…' : b.value) + '</td>' +
    '<td class="who">' + (b.reason ? esc(b.reason) : '<span class="muted">No reason given</span>') + '</td>' +
    '<td class="muted">' + esc(b.banned_by || '') + '</td>' +
    '<td>' + rel(b.banned_at) + '</td>' +
    '<td class="who">' + esc(b.origin_user || '') + '</td>' +
    '<td class="acts">' +
      '<button class="b sm" ' + act('liftBan', b.id, b.kind, b.value) + '>Lift</button>' +
      (b.origin_user ?
        '<button class="b sm" title="Lift the username ban and every hardware ID banned with it" ' +
          act('liftUserCascade', b.origin_user) + '>Lift all for ' + esc(b.origin_user) + '</button>' : '') +
    '</td>' +
    '</tr>'
  ).join('') || emptyRow(7, 'No active bans', 'Everyone can register and sign in.', 'check');
}

async function liftBan(id, kind, value) {
  const ok = await showModal({
    title: 'Lift this ban?',
    body: 'The ' + esc((BAN_KIND[kind] || kind).toLowerCase()) + ' <b>' + esc(value) + '</b> will be allowed again on every relay.',
    confirmText: 'Lift ban',
  });
  if (!ok) return;
  try {
    await api('DELETE', '/api/v1/admin/bans/' + id);
    toast('Ban lifted', 'ok');
    loadBans();
  } catch (e) { toast('Could not lift ban: ' + e.message, 'danger'); }
}

async function liftUserCascade(username) {
  const ok = await showModal({
    title: 'Lift every ban for ' + username + '?',
    body: 'Removes the username ban and every hardware ID that was banned along with it.',
    confirmText: 'Lift all',
  });
  if (!ok) return;
  try {
    const r = await api('POST', '/api/v1/admin/bans/lift-user', { username });
    const d = await r.json();
    toast('Lifted ' + d.deleted + ' ban' + (d.deleted === 1 ? '' : 's') + ' for ' + username, 'ok');
    loadBans();
  } catch (e) { toast('Could not lift bans: ' + e.message, 'danger'); }
}

const BAN_PLACEHOLDER = { username: 'Username to ban', hwid: 'Hardware ID (hex)', ip: 'IP address, e.g. 203.0.113.7' };
function banKindChanged() {
  $('banValueInput').placeholder = BAN_PLACEHOLDER[$('banKindInput').value];
}

async function addBanCustom() {
  const kind  = $('banKindInput').value;
  const value = $('banValueInput').value.trim();
  const reason = $('banReasonInput').value.trim();
  if (!value) { toast('Enter a ' + BAN_KIND[kind].toLowerCase() + ' to ban', 'warn'); $('banValueInput').focus(); return; }
  try {
    const r = await api('POST', '/api/v1/admin/bans', { kind, value, reason });
    const d = await r.json().catch(() => ({}));
    $('banValueInput').value  = '';
    $('banReasonInput').value = '';
    const n = (d.hwids_banned || []).length;
    toast('Banned ' + value + (kind === 'username' ? ' and ' + n + ' hardware ID' + (n === 1 ? '' : 's') : ''), 'ok');
    loadBans();
  } catch (e) { toast('Could not add ban: ' + e.message, 'danger'); }
}

/* ─── Federation ──────────────────────────────────────────────────── */
async function forceFederationSync() {
  try {
    const r = await api('POST', '/api/v1/admin/federation/sync-now');
    const d = await r.json();
    let total = 0;
    const failed = (d.peers || []).filter(p => p.error);
    for (const p of (d.peers || [])) total += (p.applied || 0);
    toast('Synced with ' + ((d.peers || []).length - failed.length) + ' peer(s), ' + total + ' new event(s)' +
          (failed.length ? '. ' + failed.length + ' peer(s) failed.' : '.'), failed.length ? 'warn' : 'ok');
    loadFederation();
  } catch (e) {
    toast('Sync failed: ' + e.message, 'danger');
  }
}

async function loadFederation() {
  try {
    const r = await api('GET', '/api/v1/admin/federation');
    renderFederation(await r.json());
  } catch (e) {
    const grid = $('fedGrid');
    if (grid) grid.innerHTML = '<div class="empty">' + icon('alert') + '<b>Could not poll the federation</b><span>' + esc(e.message) + '</span></div>';
  }
}

function renderFederation(d) {
  const grid = $('fedGrid');
  if (!grid) return;
  const relays = d.relays || [];
  $('fedBadge').textContent = d.summary.reachable + '/' + d.summary.total;
  $('fedSummary').textContent = d.summary.reachable + ' of ' + d.summary.total + ' reachable';

  let reqTotal = 0, anonPending = 0, diagPending = 0, torCount = 0;
  grid.innerHTML = relays.map(r => {
    const s = r.stats || {};
    const t = s.traffic || {};
    if (r.reachable) {
      reqTotal    += t.requests_total || 0;
      anonPending += t.anon_messages_pending || 0;
      diagPending += t.diag_reports_pending || 0;
      if (s.tor && s.tor.enabled) torCount++;
    }
    const onion = (s.tor && s.tor.onion_address) || '';
    const disk = s.capacity && s.capacity.disk_used_pct >= 0 ? s.capacity.disk_used_pct : null;
    const diskCls = disk == null ? '' : disk >= 90 ? 'alert' : disk >= 75 ? 'warn' : '';
    const errPct = t.requests_total ? (t.errors_total || 0) / t.requests_total * 100 : 0;
    const head = '<div class="rh"><span class="tag ' + (r.reachable ? 'ok' : 'danger') + '">' +
      (r.reachable ? 'Online' : 'Down') + '</span><span class="ep" title="' + esc(r.endpoint) + '">' +
      esc(r.endpoint === 'self' ? 'This relay' : r.endpoint) + '</span></div>';
    if (!r.reachable) {
      return '<div class="relay-card down">' + head + '<div class="muted" style="font-size:12px">' +
        esc(r.error || 'Did not answer in time.') + '</div></div>';
    }
    return '<div class="relay-card">' + head + '<dl class="kv">' +
      '<dt>Version</dt><dd>' + esc(s.version || '?') + ' <span class="muted">' + esc((s.git_sha || '').slice(0, 7)) + '</span></dd>' +
      '<dt>Up for</dt><dd>' + fmtUptime(s.uptime_seconds || 0) + '</dd>' +
      '<dt>Peers</dt><dd>' + ((s.federation && s.federation.active_peers) || 0) + '</dd>' +
      '<dt>Requests</dt><dd>' + (t.requests_total || 0).toLocaleString() +
        ' <span class="' + (errPct >= 5 ? '' : 'muted') + '" style="' + (errPct >= 5 ? 'color:var(--warn)' : '') + '">(' + errPct.toFixed(1) + '% errors)</span></dd>' +
      '<dt>Queued</dt><dd>' + (t.anon_messages_pending ?? 0) + ' messages, ' + (t.diag_reports_pending ?? 0) + ' reports</dd>' +
      '<dt>Disk</dt><dd>' + (disk == null ? '—' : disk + '% used<div class="meter ' + diskCls + '"><i style="width:' + disk + '%"></i></div>') + '</dd>' +
      '<dt>Load</dt><dd>' + esc(((s.capacity && s.capacity.load_avg) || []).join('  ') || '—') + '</dd>' +
      '<dt>Tor</dt><dd>' + (onion ? '<span class="copy" data-copy="' + esc(onion) + '" style="color:var(--accent)">' + esc(onion) + '</span>' : '<span class="muted">Not enabled</span>') + '</dd>' +
      '</dl></div>';
  }).join('') || '<div class="empty">' + icon('globe') + '<b>No relays to show</b></div>';
  $('fedReachable').textContent = d.summary.reachable;
  $('fedTotal').textContent = 'of ' + d.summary.total + ' relays';
  $('fedTor').textContent = torCount;
  $('fedReqTotal').textContent = reqTotal.toLocaleString();
  $('fedAnonPending').textContent = anonPending.toLocaleString();
  $('fedDiagPending').textContent = diagPending.toLocaleString();
  renderAws(d.aws);
}

function renderAws(aws) {
  const body = document.getElementById('awsBody');
  const pill = document.getElementById('awsSummaryPill');
  const hint = document.getElementById('awsHint');
  if (!body || !pill || !hint) return;

  if (!aws || !aws.available) {
    pill.textContent = 'unavailable';
    pill.style.background = '#3a1010';
    pill.style.color = '#ff8a8a';
    hint.innerHTML = `<span style="color:#ff8a8a">${escapeHtml((aws && aws.error) || 'AWS inventory unavailable')}</span>`;
    body.innerHTML = '';
    return;
  }

  pill.style.background = '';
  pill.style.color = '';
  const s = aws.summary || {};
  pill.textContent = `${s.running}/${s.total} running`;
  hint.textContent = `${s.running} running · ${s.stopped} stopped · ${s.other || 0} other across ${s.regions_with_assets} region(s).`;

  const regions = Object.keys(aws.regions || {}).sort();
  if (regions.length === 0) {
    body.innerHTML = `<div style="padding:14px;color:var(--dim);font-size:12px">No EC2 instances found in any region.</div>`;
    return;
  }

  let html = '';
  for (const rg of regions) {
    const rgData = aws.regions[rg] || {};
    const items = rgData.instances || [];
    const err = rgData.error;
    html += `<div style="margin:14px 0 6px 0;display:flex;align-items:center;gap:8px">
      <div style="color:var(--accent);font-size:11px;letter-spacing:0.08em;text-transform:uppercase;font-weight:700">${escapeHtml(rg)}</div>
      <div style="color:var(--dim);font-size:11px">${items.length} instance${items.length === 1 ? '' : 's'}</div>
      ${err ? `<div style="color:#ff8a8a;font-size:11px">${escapeHtml(err)}</div>` : ''}
    </div>`;
    if (items.length === 0) continue;
    html += `<table class="aws-tbl">
      <thead><tr>
        <th>Name</th>
        <th>Instance ID</th>
        <th>State</th>
        <th>Type</th>
        <th>Public IP</th>
        <th>AZ</th>
        <th class="act">Actions</th>
      </tr></thead><tbody>`;
    for (const i of items) {
      const st = i.state;
      const stCls = st === 'running' ? 'run'
                  : st === 'stopped' ? 'stop'
                  : (st === 'pending' || st === 'stopping' || st === 'shutting-down' || st === 'rebooting') ? 'pend'
                  : 'bad';
      // is_self marks the instance this relay is running on. The server
      // refuses stop/reboot on it (Rule 0); disable rather than let the
      // button imply otherwise.
      const self = !!i.is_self;
      const a = (a_, label, cls, enabled) => enabled
        ? `<button class="aws-btn ${cls}" ${act('awsAction', a_, i.id, rg, i.name || '')}>${label}</button>`
        : `<button class="aws-btn ${cls}" disabled title="${self ? 'This is the relay serving the admin panel' : 'Not available in state: ' + escapeHtml(st)}">${label}</button>`;
      html += `<tr${self ? ' class="self"' : ''}>
        <td>${escapeHtml(i.name || '—')}${self ? '<span class="selftag">this relay</span>' : ''}</td>
        <td class="dim">${escapeHtml(i.id)}</td>
        <td><span class="st ${stCls}">${escapeHtml(st)}</span></td>
        <td>${escapeHtml(i.type)}</td>
        <td>${i.pub_ip ? escapeHtml(i.pub_ip) : '<span class="dim">—</span>'}</td>
        <td class="dim">${escapeHtml(i.az)}</td>
        <td class="act">
          ${a('start', 'Start', 'go', st === 'stopped')}
          ${a('stop', 'Stop', 'no', st === 'running' && !self)}
          ${a('reboot', 'Reboot', 'wr', st === 'running' && !self)}
        </td>
      </tr>`;
    }
    html += `</tbody></table>`;
  }
  body.innerHTML = html;
}

/* Start / stop / reboot an EC2 instance. Confirmed through the same
 * modal every other destructive control uses. The relay re-checks
 * everything server-side — including refusing to stop itself — so a
 * stale render can't be used to take the fleet down. */
async function awsAction(action, instanceId, region, name) {
  const verb = action === 'start' ? 'Start' : action === 'stop' ? 'Stop' : 'Reboot';
  const who = name ? `${name} (${instanceId})` : instanceId;
  const ok = await showModal({
    title: `${verb} EC2 instance?`,
    body: `<div style="font-family:Consolas,monospace;font-size:12px">${escapeHtml(who)}<br>` +
          `<span style="color:var(--dim)">region ${escapeHtml(region)}</span></div>`,
    impact: action === 'start'
      ? 'The instance will boot and start billing.'
      : `The instance will ${action}. If it hosts a relay, that relay leaves the federation until it returns.`,
    impactClass: action === 'start' ? 'warn' : 'danger',
    confirmText: verb,
    confirmClass: action === 'start' ? 'primary' : 'danger',
  });
  if (!ok) return;
  try {
    const r = await api('POST', '/api/v1/admin/aws/instance/action',
                        { action, instance_id: instanceId, region });
    const j = await r.json();
    toast(`${verb} ${instanceId}: ${j.prev_state || '?'} → ${j.curr_state || '?'}`, 'ok');
  } catch (e) {
    toast(`${verb} failed: ${e.message}`, 'err');
    return;
  }
  // EC2 state changes lag the API call; give it a beat before re-reading.
  setTimeout(loadFederation, 2500);
}

function fmtUptime(secs) {
  if (!secs || secs < 0) return '—';
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

async function refresh(manual) {
  /* Always refresh the top-bar overview metrics (cheap), plus the active
   * tab if it isn't already overview. */
  try {
    await fetchOverview();
    if (state.tab !== 'overview') await fetchTab(state.tab);
    /* Badges on the inactive tabs — pull tiny counts. */
    fetchBadges();
    state.lastOk = Date.now();
  } catch (e) {
    state.lastErr = Date.now();
    if (manual) toast('Refresh failed: ' + e.message, 'danger');
    console.error('refresh failed:', e);
  }
  tickFreshness();
}

async function fetchBadges() {
  try {
    const r = await api('GET', '/api/v1/admin/stats/badges');
    const d = await r.json();
    $('userBadge').textContent   = d.users != null   ? d.users   : '—';
    $('deviceBadge').textContent = d.devices != null ? d.devices : '—';
    $('fileBadge').textContent   = d.files != null   ? d.files   : '—';
    $('auditBadge').textContent  = d.audit != null   ? d.audit   : '—';
  } catch (e) {}
}

/* ─── Render: top bar + toggles ──────────────────────────────────── */
function renderTopBar(d) {
  $('metaUptime').textContent = 'uptime ' + d.uptime_fmt;
  $('metaUptime').title = 'Relay process running for ' + d.uptime_fmt + '. Server time ' + d.server_time_utc + ' UTC.';
  $('metaTime').textContent   = d.server_time_utc + ' UTC';
  $('metaVer').textContent    = 'v' + d.version;
}
function renderToggles(d) {
  state.regOn   = !!d.registration_enabled;
  state.mntOn   = !!d.maintenance_mode;
  state.onionOn = !!d.onion_only;
  $('regToggle').classList.toggle('on',  state.regOn);
  $('mntToggle').classList.toggle('on',  state.mntOn);
  $('onionToggle').classList.toggle('on', state.onionOn);
  $('regLbl').textContent   = 'Registration ' + (state.regOn   ? 'ON' : 'OFF');
  $('mntLbl').textContent   = 'Maintenance '  + (state.mntOn   ? 'ON' : 'OFF');
  $('onionLbl').textContent = 'Onion '         + (state.onionOn ? 'ON' : 'OFF');
}

/* ─── Render: Overview ───────────────────────────────────────────── */
/* Overview metric rendering.
 *
 * Two rules here, both learned from the version this replaces:
 *   1. Not every number deserves equal weight. Five headline figures go
 *      in the KPI row; the rest are grouped by subject underneath.
 *   2. Colour is a signal, not decoration. A cell is tinted only when
 *      its value warrants attention — `state` below returns '' for the
 *      normal case. Previously every tile had a hardcoded colour, so a
 *      red "Files: 3" sat next to a green "Undelivered: 400" and the
 *      palette told you nothing.
 */
function cell(value, label, state, tip) {
  return '<div class="cell ' + (state || '') + '"' + (tip ? ' title="' + esc(tip) + '"' : '') + '><div class="v">' +
         esc(value) + '</div><div class="k">' + esc(label) + '</div></div>';
}

function group(title, cells) {
  return '<div class="metric-group"><div class="gh">' + esc(title) +
         '</div><div class="cells">' + cells.join('') + '</div></div>';
}

function kpi(value, label, sub, state, tip) {
  return '<div class="kpi ' + (state || '') + '"' + (tip ? ' title="' + esc(tip) + '"' : '') + '><div class="val">' +
         esc(value) + '</div><div class="lbl">' + esc(label) + '</div>' +
         (sub ? '<div class="sub">' + esc(sub) + '</div>' : '') + '</div>';
}

// Threshold helper: over `bad` → alert, over `soft` → warn, else neutral.
function over(n, soft, bad) {
  n = Number(n) || 0;
  if (bad !== undefined && n >= bad) return 'alert';
  if (soft !== undefined && n >= soft) return 'warn';
  return '';
}

function renderOverview(d) {
  const num = v => (Number(v) || 0).toLocaleString();
  const errRate = d.requests_total ? (d.errors_total / d.requests_total) * 100 : 0;
  const diskFree = Number(d.disk_free_bytes) || 0;

  $('kpis').innerHTML = [
    kpi(num(d.total_messages), 'Total Messages',
        num(d.msgs_24h) + ' in the last 24h'),
    kpi(num(d.active_today), 'Active Today',
        d.active_now + ' now · ' + d.total_users + ' users', 'good'),
    kpi(num(d.requests_total), 'Requests Since Boot',
        errRate.toFixed(1) + '% errored',
        errRate >= 10 ? 'alert' : errRate >= 3 ? 'warn' : ''),
    kpi(d.p95_req_ms + 'ms', 'p95 Request',
        'avg ' + d.avg_req_ms + 'ms', over(d.p95_req_ms, 250, 1000),
        '95% of requests finished faster than this since the relay started.'),
    kpi(num(d.undelivered), 'Undelivered',
        'sealed messages queued', over(d.undelivered, 100, 1000),
        'Encrypted messages waiting for their recipient to come online and collect them.'),
  ].join('');

  $('groups').innerHTML = [
    group('Fleet', [
      cell(d.total_users, 'Users'),
      cell(d.total_devices, 'Devices'),
      cell(d.active_now, 'Active now (60s)', '', 'Devices that contacted the relay in the last minute.'),
      cell(d.active_1min, 'Active (5 min)', '', 'Devices that contacted the relay in the last five minutes.'),
      cell(d.os_windows + ' / ' + d.os_android + ' / ' + d.os_ios, 'Win / Android / iOS'),
      cell(d.total_groups, 'Groups'),
      cell(d.total_friendships, 'Friendships'),
    ]),
    group('Traffic', [
      cell(num(d.msgs_1h), 'Msgs / 1h'),
      cell(num(d.msgs_24h), 'Msgs / 24h'),
      cell(fmtSize(d.bytes_24h), 'Msg bytes / 24h'),
      cell(fmtSize(d.avg_msg_size), 'Avg msg size'),
      cell(d.avg_latency_ms + 'ms', 'Avg msg latency', over(d.avg_latency_ms, 500, 2000)),
      cell(num(d.cover_count), 'Cover messages', '', 'Dummy traffic clients send so real messages cannot be picked out by timing.'),
      cell(fmtSize(d.cover_bytes), 'Cover bytes', '', 'Total size of that dummy traffic.'),
      cell(d.onion_pct + '%', 'Reqs via onion', '', 'Share of requests that arrived over Tor rather than the open internet.'),
    ]),
    group('Storage', [
      cell(d.file_count, 'Files'),
      cell(fmtSize(d.file_total_bytes), 'Encrypted stored'),
      cell(fmtSize(d.files_dir_bytes), 'Files folder'),
      cell(fmtSize(d.db_size_bytes), 'Database'),
      cell(fmtSize(diskFree), 'Disk free',
           diskFree && diskFree < 512 * 1024 * 1024 ? 'alert'
           : diskFree && diskFree < 2 * 1024 * 1024 * 1024 ? 'warn' : ''),
    ]),
    group('Integrity', [
      cell(num(d.errors_total), 'Errors since boot', over(d.errors_total, 1, 500)),
      cell(d.failed_logins_24h, 'Failed logins 24h', over(d.failed_logins_24h, 5, 25)),
      cell(d.pending_friend_requests, 'Pending friend req'),
      cell(d.pending_group_invites, 'Pending group inv'),
      cell(d.ecdh_cache_size, 'ECDH cache', '', 'Short-lived key exchanges for sign-ins in progress. Safe to clear; clients just retry.'),
    ]),
  ].join('');

  renderHealth(d);

  /* Hourly chart */
  const hh = d.hourly_activity || [];
  const hMax = Math.max(1, ...hh.map(x => x.count));
  const hTotal = hh.reduce((a, b) => a + b.count, 0);
  $('hourlyTotal').textContent = hTotal.toLocaleString() + ' msgs';
  const buckets = [];
  for (let i = 23; i >= 0; i--) {
    const dt = new Date(Date.now() - i * 3600000);
    const k = dt.toISOString().slice(0, 13).replace('T', ' ') + ':00';
    const found = hh.find(x => x.hour === k);
    buckets.push({ hour: dt.getUTCHours() + ':00', count: found ? found.count : 0 });
  }
  // Peak label + hour ticks: the bars alone gave no way to read a
  // magnitude or a time without hovering every column.
  const scale = $('chartScale');
  if (scale) scale.innerHTML = '<span>peak ' + hMax.toLocaleString() +
    '/h</span><span>' + (hTotal / 24).toFixed(0) + '/h avg</span>';
  const xl = $('chartXLabels');
  if (xl) xl.innerHTML = [0, 6, 12, 18, 23]
    .map(i => '<span>' + esc(buckets[i].hour) + '</span>').join('');
  $('hourlyChart').innerHTML = buckets.map(b =>
    '<div class="bar" style="height:' + Math.max(2, b.count / hMax * 100) + '%">' +
    '<span class="tt">' + b.hour + ' — ' + b.count.toLocaleString() + '</span></div>'
  ).join('');

  /* Top endpoints */
  const ep = d.top_endpoints || [];
  const eMax = Math.max(1, ...ep.map(x => x.count));
  $('endpointList').innerHTML = ep.map(x =>
    '<div class="item"><span class="label" title="' + esc(x.path) + '">' + esc(x.path) +
    '</span><span class="track"><span class="fill" style="width:' +
    (x.count / eMax * 100) + '%"></span></span><span class="num">' +
    (Number(x.count) || 0).toLocaleString() +
    (x.errors ? ' <span style="color:var(--danger)">(' + x.errors + ')</span>' : '') +
    '</span></div>'
  ).join('') || '<div class="empty">no traffic yet</div>';
}

/* ─── Render: Users ──────────────────────────────────────────────── */
function renderUsers(d) {
  const users = d.users || [];
  state.users = users;
  $('userCountPill').textContent = users.length;
  $('userTable').innerHTML = users.map(u =>
    '<tr class="clickable" ' + act('openUser', u.user_id) + ' ' + ctxAct('userMenu', u.username, u.user_id) + '>' +
    '<td class="who">' + esc(u.username) + '</td>' +
    '<td>' + copyCell(u.user_id, u.user_id.substring(0, 16)) + '</td>' +
    '<td>' + u.devices + '</td>' +
    '<td>' + rel(u.created) + '</td>' +
    '<td class="acts">' +
      '<button class="b sm warn-o" ' + act('banUserPrompt', u.username) + '>Ban</button>' +
      '<button class="b sm danger-o" ' + act('delUser', u.user_id, u.username, u.devices) + '>Delete</button>' +
    '</td>' +
    '</tr>'
  ).join('') || emptyRow(5, 'No accounts yet', 'Accounts appear here as soon as someone registers.', 'users');

  const fr = d.friend_requests_pending || [];
  $('frPill').textContent = fr.length;
  $('frTable').innerHTML = fr.map(r =>
    '<tr><td class="who">' + esc(r.from) + '</td><td class="who">' + esc(r.to) + '</td>' +
    '<td class="who">' + esc(r.reason) + '</td><td>' + rel(r.created) + '</td></tr>'
  ).join('') || emptyRow(4, 'No pending friend requests');

  const gi = d.group_invites_pending || [];
  $('giPill').textContent = gi.length;
  $('giTable').innerHTML = gi.map(r =>
    '<tr><td class="who">' + esc(r.group) + '</td><td class="who">' + esc(r.from) + '</td>' +
    '<td class="who">' + esc(r.to) + '</td><td class="who">' + esc(r.reason) + '</td>' +
    '<td>' + rel(r.created) + '</td></tr>'
  ).join('') || emptyRow(5, 'No pending group invites');

  const ts = d.top_senders || [];
  const tsMax = Math.max(1, ...ts.map(x => x.count));
  $('topSenders').innerHTML = ts.map(x =>
    '<div class="item"><span class="label">' + esc(x.id) +
    '</span><span class="track"><span class="fill" style="width:' +
    (x.count / tsMax * 100) + '%"></span></span><span class="num">' + x.count +
    '</span></div>'
  ).join('') || '<div class="empty">—</div>';

  const tr = d.top_recipients || [];
  const trMax = Math.max(1, ...tr.map(x => x.count));
  $('topRecips').innerHTML = tr.map(x =>
    '<div class="item"><span class="label">' + esc(x.id) +
    '</span><span class="track"><span class="fill" style="width:' +
    (x.count / trMax * 100) + '%"></span></span><span class="num">' + x.count +
    '</span></div>'
  ).join('') || '<div class="empty">—</div>';
}

/* ─── Render: Devices ────────────────────────────────────────────── */
const PLATFORM = { windows: 'Windows', android: 'Android', ios: 'iOS' };
function renderDevices(d) {
  const devices = d.devices || [];
  state.devices = devices;
  $('deviceCountPill').textContent = devices.length;
  $('devTable').innerHTML = devices.map(dv =>
    '<tr class="clickable" ' + act('openDevice', dv.id) + '>' +
    '<td>' + copyCell(dv.id, dv.id.substring(0, 16)) + '</td>' +
    '<td class="who">' + esc(PLATFORM[dv.platform] || dv.platform) + '</td>' +
    '<td class="who">' + esc(dv.name) + '</td>' +
    '<td>' + rel(dv.registered) + '</td>' +
    '<td>' + rel(dv.last_seen, 'Never') + '</td>' +
    '<td class="acts"><button class="b sm danger-o" ' + act('delDev', dv.id, dv.name) + '>Delete</button></td>' +
    '</tr>'
  ).join('') || emptyRow(6, 'No devices yet', 'A device appears when someone signs in from an app.', 'devices');

  const grp = d.groups || [];
  $('grpCountPill').textContent = grp.length;
  $('grpTable').innerHTML = grp.map(g =>
    '<tr><td>' + copyCell(g.id, g.id.substring(0, 12)) + '</td>' +
    '<td class="who">' + esc(g.name) + '</td>' +
    '<td>' + g.members + '</td>' +
    '<td>' + rel(g.created) + '</td></tr>'
  ).join('') || emptyRow(4, 'No groups yet');
}

/* ─── Render: Crypto ─────────────────────────────────────────────── */
function renderCrypto(d) {
  $('idFp').textContent    = d.identity_fingerprint || '(unavailable)';
  $('idSuite').textContent = d.identity_suite || '(none)';
  $('pqSuite').textContent = d.pq_suite || '(unavailable)';

  const ageDays = ts => {
    if (!ts) return '—';
    const t = new Date(ts + (ts.endsWith('Z') ? '' : 'Z')).getTime();
    if (isNaN(t)) return '—';
    return Math.max(0, Math.floor((Date.now() - t) / 86400000)) + 'd';
  };

  const cards = [
    [d.pq_available ? 'ok' : 'danger',           d.pq_available ? 'READY' : 'OFF', 'PQ Hybrid'],
    [d.anon_creds_available ? 'ok' : 'danger',   d.anon_creds_available ? 'READY' : 'OFF', 'Anon Creds'],
    ['ok',                                       d.anon_creds_redeemed_total, 'Anon Creds Redeemed'],
    [d.srp_available ? 'ok' : 'danger',          d.srp_available ? 'READY' : 'OFF', 'SRP-6a PAKE'],
    ['ok',                                       d.srp_users, 'SRP Users'],
    [d.at_rest_available ? 'ok' : 'danger',      d.at_rest_available ? 'ON' : 'OFF', 'At-Rest Enc'],
    ['accent',                                   d.ratchet_devices, 'Ratchet Devices'],
    ['ok',                                       d.one_time_prekeys_total, 'One-Time Prekeys'],
    ['purple',                                   d.treekem_groups, 'TreeKEM Groups'],
    ['accent',                                   d.device_link_active, 'Active Device Links'],
    ['accent',                                   ageDays(d.identity_created_at), 'Identity Key Age'],
    ['accent',                                   ageDays(d.anon_creds_created_at), 'Anon-Creds Key Age'],
    ['accent',                                   ageDays(d.at_rest_created_at), 'At-Rest Key Age'],
  ];
  $('cryptoCards').innerHTML = cards.map(c =>
    '<div class="card ' + c[0] + '"><div class="val">' + esc(c[1]) +
    '</div><div class="lbl">' + esc(c[2]) + '</div></div>'
  ).join('');

  /* Padded-envelope bucket distribution */
  const pad = d.padding_distribution || [];
  const padTotal = pad.reduce((a, b) => a + b.count, 0);
  const padMax = Math.max(1, ...pad.map(x => x.count));
  $('padTotalPill').textContent = padTotal.toLocaleString() + ' msgs';
  $('padBuckets').innerHTML = pad.map(x =>
    '<div class="item"><span class="label">' + esc(x.bucket) +
    '</span><span class="track"><span class="fill" style="width:' +
    (x.count / padMax * 100) + '%"></span></span><span class="num">' +
    fmtPct(x.count, padTotal) + '</span></div>'
  ).join('') || '<div class="empty">no messages yet</div>';

  /* Low-prekey devices */
  const lp = d.low_prekey_devices || [];
  $('lowPrekeyPill').textContent = lp.length;
  $('lowPrekeyTable').innerHTML = lp.map(r =>
    '<tr class="clickable" ' + act('openDevice', r.device_id) + '>' +
    '<td>' + copyCell(r.device_id, r.device_id.substring(0, 16)) + '</td>' +
    '<td class="who">' + esc(r.username || '(no account)') + '</td>' +
    '<td><span class="tag ' + (r.prekeys === 0 ? 'danger' : 'warn') + '">' +
    r.prekeys + '</span></td>' +
    '<td>' + rel(r.last_seen, 'Never') + '</td></tr>'
  ).join('') || emptyRow(4, 'Every device has enough one-time prekeys', 'Devices show up here when they drop below 5.', 'check');
}

/* ─── Render: Files ──────────────────────────────────────────────── */
function renderFiles(d) {
  $('fileCountPill').textContent = (d.files || []).length;
  updateCountdowns();
}

/* ─── Render: Audit ──────────────────────────────────────────────── */
function renderAudit(d) {
  $('auditCountPill').textContent = (d.audit_log || []).length;
  $('auditTable').innerHTML = (d.audit_log || []).map(r =>
    '<tr><td>' + rel(r.ts) + '</td><td>' + esc(r.actor) +
    '</td><td><span class="tag dim">' + esc(r.action) + '</span></td>' +
    '<td>' + esc(r.target) + '</td><td class="who">' + esc(r.detail) + '</td></tr>'
  ).join('') || emptyRow(5, 'Nothing in the audit log for this filter', 'Admin actions are recorded here as they happen.', 'list');

  $('flPill').textContent = (d.failed_logins || []).length;
  $('flTable').innerHTML = (d.failed_logins || []).map(r =>
    '<tr><td>' + copyCell(r.ip, r.ip) + '</td><td>' + esc(r.hwid) + '</td>' +
    '<td>' + esc(r.fp) + '</td><td>' + rel(r.ts) + '</td></tr>'
  ).join('') || emptyRow(4, 'No failed admin logins', '', 'check');

  $('errPill').textContent = (d.recent_errors || []).length;
  $('errTable').innerHTML = (d.recent_errors || []).map(r =>
    '<tr><td>' + rel(r.ts) + '</td><td>' + esc(r.path) + '</td>' +
    '<td><span class="tag ' + (r.status >= 500 ? 'danger' : 'warn') + '">' +
    esc(r.status) + '</span></td><td class="who">' + esc(r.detail) + '</td></tr>'
  ).join('') || emptyRow(4, 'No recent errors', '', 'check');

  const sess = d.sessions || [];
  $('sessCountPill').textContent = sess.length;
  $('sessTable').innerHTML = sess.map(s =>
    '<tr><td>' + esc(s.id.substring(0, 12)) + '</td><td>' + esc(s.ip) +
    '</td><td>' + rel(s.login_at) + '</td><td>' + rel(s.last_activity) +
    '</td><td><span class="tag ' + (s.active ? 'ok' : 'dim') + '">' +
    (s.active ? 'Active' : 'Ended') + '</span></td>' +
    '<td class="acts">' + (s.active
      ? '<button class="b sm warn-o" ' + act('killSess', s.id) + '>Sign out</button>'
      : '') + '</td></tr>'
  ).join('') || emptyRow(6, 'No admin sessions');
}

/* ─── Render: Activity (time-series + recent messages) ───────────── */
function renderActivity(d) {
  const series = d.series || [];
  if (series.length) {
    const first = series[0];
    const last  = series[series.length - 1];
    $('seriesRangePill').textContent = first.bucket + ' → ' + last.bucket;
  }

  /* Sparkline cards: each metric gets its own SVG line chart. */
  const metrics = [
    { key: 'active_devices', title: 'Active devices (7d)',   color: 'var(--accent)' },
    { key: 'messages',       title: 'Messages/hour',         color: 'var(--ok)' },
    { key: 'failed_logins',  title: 'Failed logins/hour',    color: 'var(--danger)' },
    { key: 'errors',         title: 'Errors/hour',           color: 'var(--warn)' },
    { key: 'new_users',      title: 'New users/hour',        color: 'var(--purple)' },
    { key: 'storage_bytes',  title: 'Storage growth',        color: 'var(--accent)', fmt: fmtSize },
  ];
  $('seriesGrid').innerHTML = metrics.map(m => sparklineCard(m, series)).join('');

  /* Recent messages */
  $('msgTable').innerHTML = (d.recent_messages || []).map(m =>
    '<tr><td>' + rel(m.ts) + '</td>' +
    '<td>' + esc(m.sender.substring(0, 12)) + '</td>' +
    '<td>' + esc(m.recipient.substring(0, 12)) + '</td>' +
    '<td>' + m.size + 'B</td>' +
    '<td><span class="tag ' + (m.delivered ? 'ok' : 'warn') + '">' +
    (m.delivered ? 'Delivered' : 'Waiting') + '</span></td></tr>'
  ).join('') || emptyRow(5, 'No messages yet');

  /* Onion vs clearnet split */
  const total = (d.onion_requests || 0) + (d.clear_requests || 0);
  const onPct = total ? ((d.onion_requests / total) * 100) : 0;
  $('onionPct').textContent  = onPct.toFixed(1) + '%';
  $('clearPct').textContent  = (100 - onPct).toFixed(1) + '%';
  $('onionCount').textContent = (d.onion_requests || 0).toLocaleString() + ' reqs';
  $('clearCount').textContent = (d.clear_requests || 0).toLocaleString() + ' reqs';
  $('onionRatioBar').style.width = onPct + '%';
}

function sparklineCard(m, series) {
  const values = series.map(p => Number(p[m.key] || 0));
  const max = Math.max(1, ...values);
  const min = Math.min(0, ...values);
  const W = 280, H = 60, pad = 2;
  const n = values.length;
  let pts = '';
  if (n > 0) {
    for (let i = 0; i < n; i++) {
      const x = pad + (i / Math.max(1, n - 1)) * (W - 2 * pad);
      const y = H - pad - ((values[i] - min) / Math.max(1, max - min)) * (H - 2 * pad);
      pts += (i ? ' L' : 'M') + x.toFixed(1) + ',' + y.toFixed(1);
    }
  }
  /* Area fill underneath */
  const area = pts ? pts + ' L' + (W - pad) + ',' + (H - pad) + ' L' + pad + ',' + (H - pad) + ' Z' : '';
  const now = values.length ? values[values.length - 1] : 0;
  const nowFmt = m.fmt ? m.fmt(now) : now.toLocaleString();
  return '' +
    '<div class="sparkline-card">' +
    '<div class="title"><span>' + esc(m.title) + '</span><span class="now">' + esc(nowFmt) + '</span></div>' +
    '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none">' +
      (area ? '<path d="' + area + '" fill="' + m.color + '" opacity="0.12"/>' : '') +
      (pts  ? '<path d="' + pts  + '" fill="none" stroke="' + m.color + '" stroke-width="1.5"/>' : '') +
    '</svg>' +
    '<div class="axis"><span>' + esc(series[0]?.bucket || '') + '</span><span>' +
      esc(series[series.length - 1]?.bucket || '') + '</span></div>' +
    '</div>';
}

/* ─── File countdowns (50ms tick) ─────────────────────────────────── */
function updateCountdowns() {
  if (state.tab !== 'files') return;
  let h = '';
  const n = Date.now();
  for (const f of state.fileData) {
    if (!f.expires_at) continue;
    const e = new Date(f.expires_at + 'Z').getTime();
    const r = e - n;
    let label, color;
    if (f.downloaded) { label = 'DOWNLOADED'; color = 'var(--ok)'; }
    else if (r <= 0)   { label = 'EXPIRED';    color = 'var(--danger)'; }
    else {
      const hh = Math.floor(r / 3600000);
      const mm = Math.floor((r % 3600000) / 60000);
      const ss = Math.floor((r % 60000) / 1000);
      const ms = r % 1000;
      label = hh + ':' + String(mm).padStart(2, '0') + ':' +
              String(ss).padStart(2, '0') + '.' + String(ms).padStart(3, '0');
      color = r < 300000 ? 'var(--danger)' : r < 1800000 ? 'var(--warn)' : 'var(--ok)';
    }
    h += '<tr><td>' + esc(f.id.substring(0, 12)) + '</td>' +
         '<td>' + esc(f.sender) + '</td>' +
         '<td>' + esc(f.recipient) + '</td>' +
         '<td>' + fmtSize(f.orig_size) + '</td>' +
         '<td>' + fmtSize(f.enc_size) + '</td>' +
         '<td>' + esc(f.server_ts) + '</td>' +
         '<td style="color:' + color + ';font-weight:600">' + label + '</td>' +
         '<td>' + (f.downloaded
           ? '<span class="tag ok">Done</span>'
           : '<span class="tag warn">Waiting</span>') + '</td></tr>';
  }
  $('fileTable').innerHTML = h || emptyRow(8, 'No files waiting', 'Encrypted attachments appear here until they are downloaded or expire.', 'file');
}

/* ─── Search filtering (client-side, instant) ────────────────────── */
function wireSearchInputs() {
  document.querySelectorAll('input.search').forEach(inp => {
    inp.addEventListener('input', () => applySearch(inp));
  });
}
function applySearch(inp) {
  const targetId = inp.dataset.target;
  const q = inp.value.trim().toLowerCase();
  const tbody = $(targetId);
  if (!tbody) return;
  for (const row of tbody.querySelectorAll('tr')) {
    if (!q) { row.style.display = ''; continue; }
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  }
}

/* ─── Controls ───────────────────────────────────────────────────── */
async function ctrlConfirm(action, title, plainBody, impactClass) {
  /* Some destructive actions ask the server for an impact preview first. */
  let impact = null;
  if (action === 'clear-undelivered' || action === 'purge-files' || action === 'rotate-identity') {
    try {
      const r = await api('GET', '/api/v1/admin/control/' + action + '/preview');
      const p = await r.json();
      impact = p.message || null;
    } catch (e) {}
  }
  const body = plainBody || (
    action === 'clear-undelivered' ? 'Permanently delete every undelivered message in the database. This cannot be undone — once gone, the recipient device cannot pick them up.' :
    action === 'rotate-identity'   ? 'Generate a new server identity keypair. All previously-pinned clients will refuse to connect until they re-pin the new fingerprint.' :
    action === 'purge-files'       ? 'Delete expired and already-downloaded files from disk.' :
    'Run ' + action + '?'
  );
  const ok = await showModal({
    title, body, impact, impactClass: impactClass === 'danger' ? 'danger' : '',
    confirmText: impactClass === 'danger' ? 'Yes, do it' : 'Confirm',
    confirmClass: impactClass === 'danger' ? 'danger' : 'primary',
  });
  if (!ok) return;
  try {
    const r = await api('POST', '/api/v1/admin/control/' + action);
    const j = await r.json().catch(() => ({}));
    toast(title + ': ' + (j.message || 'done'), 'ok');
    refresh();
  } catch (e) {
    toast(title + ' failed: ' + e.message, 'danger');
  }
}
async function toggleSetting(which, enabled) {
  try {
    const r = await api('POST', '/api/v1/admin/control/' + which, { enabled });
    const j = await r.json().catch(() => ({}));
    // Read back the server's reported state so the toast can't lie when
    // the persistence step didn't happen. Different endpoints use
    // slightly different keys; check the obvious ones in order.
    const key = which === 'onion-only' ? 'onion_only'
              : which === 'maintenance' ? 'maintenance_mode'
              : which === 'registration' ? 'registration_enabled'
              : null;
    const actual = key && key in j ? !!j[key] : enabled;
    const NAMES = { registration: 'Registration', maintenance: 'Maintenance mode', 'onion-only': 'Tor-only mode' };
    toast((NAMES[which] || which) + ' is now ' + (actual ? 'on' : 'off'), 'ok');
    await refresh();
  } catch (e) {
    toast('Could not change ' + which + ': ' + (e && e.message ? e.message : 'unknown error'), 'danger');
  }
}
function copyFp() {
  const fp = $('idFp').textContent;
  if (navigator.clipboard) {
    navigator.clipboard.writeText(fp).then(() => toast('Fingerprint copied', 'ok'), () => prompt('Fingerprint:', fp));
  } else {
    prompt('Fingerprint:', fp);
  }
}
async function delDev(id, name) {
  const ok = await showModal({
    title: 'Delete device',
    body: 'Delete ' + (name ? '<b>' + esc(name) + '</b> ' : 'device ') + '<code>' + esc(id.substring(0, 16)) + '…</code>? It will need to sign in again.',
    impact: 'All messages to and from this device will be removed from the queue.',
    impactClass: 'warn',
    confirmText: 'Delete', confirmClass: 'danger',
  });
  if (!ok) return;
  try {
    await api('DELETE', '/api/v1/admin/devices/' + id);
    toast('Device deleted', 'ok');
  } catch (e) { toast('Could not delete device: ' + e.message, 'danger'); return; }
  refresh();
}
async function delUser(id, name, devices) {
  const ok = await showModal({
    title: 'Delete user',
    body: 'Delete <code>' + esc(name) + '</code> and ALL their data?',
    impact: devices + ' device(s), all messages, groups, friendships, and ' +
            'pending files will be wiped. Audit log retains the action.',
    impactClass: 'danger',
    confirmText: 'Yes, delete', confirmClass: 'danger',
  });
  if (!ok) return;
  try {
    await api('DELETE', '/api/v1/admin/users/' + id);
    toast('User deleted: ' + name, 'ok');
  } catch (e) {
    toast('Delete failed: ' + (e && e.message ? e.message : 'unknown'), 'danger');
    return;
  }
  refresh();
}
async function killSess(id) {
  const ok = await showModal({
    title: 'Kill admin session',
    body: 'Sign out session <code>' + esc(id.substring(0, 12)) + '…</code>?',
    confirmText: 'Sign out', confirmClass: 'danger',
  });
  if (!ok) return;
  try {
    await api('DELETE', '/api/v1/admin/sessions/' + id);
    toast('Session signed out', 'ok');
  } catch (e) { toast('Could not sign out session: ' + e.message, 'danger'); return; }
  refresh();
}
async function logout() {
  await api('POST', '/api/v1/admin/logout');
  location = '/admin/login';
}

/* ─── Drill-down ─────────────────────────────────────────────────── */
function openUser(uid)   { location = '/admin/user/'   + encodeURIComponent(uid); }
function openDevice(did) { location = '/admin/device/' + encodeURIComponent(did); }

/* ─── Audit filters / CSV export ─────────────────────────────────── */
function applyAuditFilters() { fetchAudit(); }
function clearAuditFilters() {
  $('auditFilterActor').value  = '';
  $('auditFilterAction').value = '';
  $('auditFilterTarget').value = '';
  $('auditFilterSince').value  = '24';
  fetchAudit();
}
function exportAuditCsv() {
  const q = new URLSearchParams();
  const a = $('auditFilterActor').value.trim();   if (a)  q.set('actor', a);
  const ac = $('auditFilterAction').value.trim(); if (ac) q.set('action', ac);
  const tg = $('auditFilterTarget').value.trim(); if (tg) q.set('target', tg);
  const sn = $('auditFilterSince').value;         if (sn) q.set('since_hours', sn);
  q.set('format', 'csv');
  location = '/api/v1/admin/stats/audit?' + q.toString();
}

/* ─── WebSocket live tail ────────────────────────────────────────── */
async function connectWS() {
  // Fetch a session token first — the HttpOnly cookie can't be read by JS,
  // but the server will hand us the session ID via HTTP (which sends the cookie).
  let token = '';
  try {
    const r = await fetch('/api/v1/admin/ws-token');
    if (r.ok) { const d = await r.json(); token = d.token; }
  } catch {}
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = proto + '//' + location.host + '/ws/admin' + (token ? '?token=' + encodeURIComponent(token) : '');
  const ws = new WebSocket(url);
  state.ws = ws;
  ws.onopen = () => {
    state.wsBackoff = 1000;
    $('wsStatus').classList.add('live');
    $('wsLabel').textContent = 'live';
  };
  ws.onclose = () => {
    state.ws = null;
    $('wsStatus').classList.remove('live');
    $('wsLabel').textContent = 'reconnecting';
    setTimeout(connectWS, state.wsBackoff);
    state.wsBackoff = Math.min(15000, state.wsBackoff * 2);
  };
  ws.onerror = () => { /* close handler will retry */ };
  ws.onmessage = ev => {
    try {
      const m = JSON.parse(ev.data);
      handleLiveEvent(m);
    } catch (e) {}
  };
}
function handleLiveEvent(m) {
  switch (m.type) {
    case 'audit':
      state.audit.unshift(m.row);
      state.audit = state.audit.slice(0, 100);
      if (state.tab === 'audit') renderAudit({
        audit_log: state.audit, failed_logins: state.failedLogins,
        recent_errors: state.recentErrors, sessions: m.sessions || [],
      });
      toast('Audit: ' + (m.row.action || '?'), 'ok');
      break;
    case 'error':
      state.recentErrors.unshift(m.row);
      state.recentErrors = state.recentErrors.slice(0, 100);
      if (state.tab === 'audit') $('errPill').textContent = state.recentErrors.length;
      if (m.row.status >= 500) toast('Server error: ' + m.row.path, 'danger');
      break;
    case 'failed_login':
      state.failedLogins.unshift(m.row);
      state.failedLogins = state.failedLogins.slice(0, 50);
      if (state.tab === 'audit') $('flPill').textContent = state.failedLogins.length;
      toast('Failed login from ' + (m.row.ip || '?'), 'warn');
      break;
    case 'pong':
      break;
  }
}
/* Keep the WS warm so reverse proxies don't idle-time it out. */
setInterval(() => {
  if (state.ws && state.ws.readyState === 1) {
    try { state.ws.send(JSON.stringify({ type: 'ping' })); } catch (e) {}
  }
}, 25000);

/* ─── Refresh loop ───────────────────────────────────────────────── */
function setRefreshInterval(ms) {
  state.refreshInterval = ms;
  if (state.refreshTimer) { clearInterval(state.refreshTimer); state.refreshTimer = null; }
  // Skip ticks while the browser tab is hidden; catch up when it returns.
  if (ms > 0) state.refreshTimer = setInterval(() => { if (!document.hidden) refresh(); }, ms);
  try { localStorage.setItem(LS_INTERVAL, String(ms)); } catch (e) {}
}
$('refreshInterval').addEventListener('change', e => {
  setRefreshInterval(parseInt(e.target.value, 10) || 0);
});

/* ─── Keyboard shortcuts ─────────────────────────────────────────── */
window.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    if ($('paletteBg').classList.contains('show')) closePalette(); else openPalette();
    return;
  }
  if ($('paletteBg').classList.contains('show')) return;   // the palette input handles its own keys
  // A dialog is open: Escape closes it even while typing in its fields.
  if ($('modalBg').classList.contains('show') ||
      $('cheatsheetBg').classList.contains('show')) {
    if (e.key === 'Escape') { e.preventDefault(); closeModal(false); closeCheatsheet(); }
    return;
  }
  if ((e.key === 'Enter' || e.key === ' ') && e.target.matches('.tab, .toggle')) {
    e.preventDefault(); e.target.click(); return;
  }
  if (e.target.matches('input, textarea, select')) {
    if (e.key === 'Escape') { e.target.blur(); }
    return;
  }
  if (e.key === '/') {
    e.preventDefault();
    const activeSection = document.querySelector('.section.active');
    const s = activeSection ? activeSection.querySelector('input.search') : null;
    if (s) { s.focus(); s.select(); }
    return;
  }
  if (e.key === 'r') { e.preventDefault(); refresh(); return; }
  if (e.key === '?') { e.preventDefault(); showCheatsheet(); return; }
  if (e.key === 't' && !state.pendingGoto) { e.preventDefault(); cycleTheme(); return; }

  /* `g` then a single letter to jump tabs */
  if (e.key === 'g') {
    state.pendingGoto = true;
    state.pendingGotoUntil = Date.now() + 1500;
    return;
  }
  if (state.pendingGoto && Date.now() < state.pendingGotoUntil) {
    state.pendingGoto = false;
    const map = { o:'overview', u:'users', d:'devices', c:'crypto', f:'files', a:'audit', y:'activity', n:'federation', b:'bans' };
    if (map[e.key]) { e.preventDefault(); goTab(map[e.key]); }
  }
});

/* ─── Boot ───────────────────────────────────────────────────────── */
(function init() {
  /* Honor URL hash on load */
  state.tab = currentTabFromHash();
  document.querySelectorAll('.tab').forEach(t => {
    t.classList.toggle('active', t.dataset.tab === state.tab);
  });
  document.querySelectorAll('.section').forEach(s => {
    s.classList.toggle('active', s.dataset.section === state.tab);
  });
  window.addEventListener('hashchange', () => {
    const t = currentTabFromHash();
    if (t !== state.tab) goTab(t);
  });

  /* Restore refresh interval */
  try {
    const saved = parseInt(localStorage.getItem(LS_INTERVAL) || '', 10);
    if (!isNaN(saved)) {
      $('refreshInterval').value = String(saved);
      setRefreshInterval(saved);
    } else {
      setRefreshInterval(8000);
    }
  } catch (e) { setRefreshInterval(8000); }

  Object.assign(ACTIONS, {
    openUser, openDevice, banUserPrompt, delUser, delDev, killSess,
    liftBan, liftUserCascade, awsAction, goTab, confirmToggle, ctrlConfirm,
    userMenu: userContextMenu,
  });
  hydrateIcons();
  // The top bar wraps on narrow screens; keep the sticky tab bar under it.
  const top = document.querySelector('.top');
  if (top && window.ResizeObserver) new ResizeObserver(() =>
    document.documentElement.style.setProperty('--topbar-h', top.offsetHeight + 'px')).observe(top);
  applyTheme(currentTheme());
  wireSearchInputs();
  wireTables();
  addExportButtons();
  setInterval(updateCountdowns, 50);
  setInterval(tickFreshness, 1000);
  setInterval(refreshRelTimes, 30000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden && state.refreshInterval > 0) refresh(); });
  loadBans();   // fills the Bans tab badge

  refresh();
  fetchTab(state.tab);
  fetchBadges();
  connectWS();
})();

/* Expose handlers used by inline onclick attributes */
window.goTab            = goTab;
window.refresh          = refresh;
window.toggleSetting    = toggleSetting;
window.ctrlConfirm      = ctrlConfirm;
window.copyFp           = copyFp;
window.delDev           = delDev;
window.delUser          = delUser;
window.killSess         = killSess;
window.logout           = logout;
window.openUser         = openUser;
window.openDevice       = openDevice;
window.applyAuditFilters = applyAuditFilters;
window.clearAuditFilters = clearAuditFilters;
window.exportAuditCsv   = exportAuditCsv;
window.showCheatsheet   = showCheatsheet;
window.closeCheatsheet  = closeCheatsheet;
window.closeModal       = closeModal;
window.cycleTheme       = cycleTheme;
window.confirmToggle    = confirmToggle;
window.openPalette      = openPalette;
window.closePalette     = closePalette;
window.addBanCustom     = addBanCustom;
window.banKindChanged   = banKindChanged;
window.loadBans         = loadBans;
window.loadFederation   = loadFederation;
window.forceFederationSync = forceFederationSync;
