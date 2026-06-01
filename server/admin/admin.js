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
  t.textContent = msg;
  $('toastStack').appendChild(t);
  setTimeout(() => {
    t.style.transition = 'opacity .3s';
    t.style.opacity = '0';
    setTimeout(() => t.remove(), 320);
  }, 3800);
}

/* ─── Modal ───────────────────────────────────────────────────────── */
let modalResolver = null;
function showModal({ title, body, impact, impactClass, confirmText, confirmClass }) {
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
  return new Promise(res => { modalResolver = res; });
}
function closeModal(result) {
  $('modalBg').classList.remove('show');
  if (modalResolver) { modalResolver(result === true); modalResolver = null; }
}
$('modalConfirm').addEventListener('click', () => closeModal(true));
$('modalBg').addEventListener('click', e => { if (e.target.id === 'modalBg') closeModal(false); });

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
  const valid = ['overview','users','devices','crypto','files','audit','activity'];
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
  const reason = window.prompt(
    `Ban "${username}" (cascades to every linked hardware ID)?\n\n` +
    `Optional reason — shown to the banned user on next login attempt. Leave empty for generic 'Account banned'.`,
    ''
  );
  if (reason === null) return;  // cancelled
  try {
    const r = await fetch('/api/v1/admin/bans', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCookie('shroud_csrf') || ''
      },
      body: JSON.stringify({ kind: 'username', value: username, reason })
    });
    if (!r.ok) {
      const t = await r.text();
      alert(`Ban failed: ${r.status} ${t}`);
      return;
    }
    const d = await r.json();
    const n = (d.hwids_banned || []).length;
    toast(`Banned ${username} + ${n} hardware ID${n === 1 ? '' : 's'}`);
    if (state.tab === 'bans') loadBans();
  } catch (e) {
    alert('Ban request failed: ' + e);
  }
}

function userContextMenu(ev, username, userId) {
  ev.preventDefault();
  const existing = document.getElementById('userCtxMenu');
  if (existing) existing.remove();
  const m = document.createElement('div');
  m.id = 'userCtxMenu';
  m.style.cssText = 'position:fixed;z-index:9999;background:#1a1a1a;border:1px solid #444;' +
    'padding:4px 0;min-width:200px;box-shadow:0 6px 18px rgba(0,0,0,.5)';
  m.style.left = ev.clientX + 'px';
  m.style.top  = ev.clientY + 'px';
  const item = (label, fn, danger) => {
    const i = document.createElement('div');
    i.textContent = label;
    i.style.cssText = 'padding:8px 14px;cursor:pointer;font-size:12px;' +
      (danger ? 'color:#ff7f7f' : 'color:#e0e0e0');
    i.onmouseover = () => { i.style.background = '#2a2a2a'; };
    i.onmouseout  = () => { i.style.background = 'transparent'; };
    i.onclick = () => { m.remove(); fn(); };
    m.appendChild(i);
  };
  item('Open user',          () => openUser(userId));
  item('Ban (cascades HWIDs)', () => banUserPrompt(username), true);
  item('Delete user',        () => delUser(userId, username, 0), true);
  document.body.appendChild(m);
  const dismiss = () => { m.remove(); document.removeEventListener('click', dismiss); };
  setTimeout(() => document.addEventListener('click', dismiss), 0);
}

async function loadBans() {
  try {
    const r = await fetch('/api/v1/admin/bans', { credentials: 'include' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    renderBans(d);
  } catch (e) {
    const t = document.getElementById('banTable');
    if (t) t.innerHTML = `<tr><td colspan="7" class="empty">load failed: ${esc(String(e))}</td></tr>`;
  }
}

function renderBans(d) {
  const arr = d.bans || [];
  const tbl = document.getElementById('banTable');
  if (!tbl) return;
  const pill = document.getElementById('banCountPill');
  if (pill) pill.textContent = arr.length;
  tbl.innerHTML = arr.map(b =>
    '<tr>' +
    '<td>' + b.id + '</td>' +
    '<td>' + esc(b.kind) + '</td>' +
    '<td>' + esc(b.value) + '</td>' +
    '<td>' + esc(b.reason || '') + '</td>' +
    '<td>' + esc(b.banned_by || '') + '</td>' +
    '<td>' + esc(b.banned_at || '') + '</td>' +
    '<td>' + esc(b.origin_user || '') + ' ' +
      '<button class="tinybtn" onclick="liftBan(' + b.id + ')">Lift</button>' +
      (b.origin_user ?
        ' <button class="tinybtn" onclick="liftUserCascade(\'' + esc(b.origin_user) +
          '\')">Lift cascade</button>' : '') +
    '</td>' +
    '</tr>'
  ).join('') || '<tr><td colspan="7" class="empty">no bans</td></tr>';
}

async function liftBan(id) {
  if (!confirm('Lift this single ban row?')) return;
  try {
    const r = await fetch('/api/v1/admin/bans/' + id, {
      method: 'DELETE', credentials: 'include',
      headers: { 'X-CSRF-Token': getCookie('shroud_csrf') || '' }
    });
    if (r.ok) { toast('Ban lifted'); loadBans(); }
    else      { alert('Lift failed: ' + r.status); }
  } catch (e) { alert('Lift failed: ' + e); }
}

async function liftUserCascade(username) {
  if (!confirm(`Remove EVERY ban row tied to user '${username}' (including all HWIDs)?`)) return;
  try {
    const r = await fetch('/api/v1/admin/bans/lift-user', {
      method: 'POST', credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCookie('shroud_csrf') || ''
      },
      body: JSON.stringify({ username })
    });
    if (r.ok) {
      const d = await r.json();
      toast(`Cascade lifted: ${d.deleted} row(s)`);
      loadBans();
    } else {
      alert('Lift failed: ' + r.status);
    }
  } catch (e) { alert('Lift failed: ' + e); }
}

async function addBanCustom() {
  const kind  = document.getElementById('banKindInput').value;
  const value = document.getElementById('banValueInput').value.trim();
  const reason = document.getElementById('banReasonInput').value.trim();
  if (!value) { alert('Value required'); return; }
  try {
    const r = await fetch('/api/v1/admin/bans', {
      method: 'POST', credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCookie('shroud_csrf') || ''
      },
      body: JSON.stringify({ kind, value, reason })
    });
    if (r.ok) {
      document.getElementById('banValueInput').value  = '';
      document.getElementById('banReasonInput').value = '';
      toast('Ban added');
      loadBans();
    } else {
      alert('Add failed: ' + r.status);
    }
  } catch (e) { alert('Add failed: ' + e); }
}

function getCookie(name) {
  return document.cookie.split(';').map(s => s.trim())
    .filter(s => s.startsWith(name + '='))
    .map(s => s.substring(name.length + 1))[0] || '';
}

function toast(msg) {
  // Minimal toast — if the page has a #toast element use that, else alert.
  const t = document.getElementById('toast');
  if (t) {
    t.textContent = msg;
    t.style.display = 'block';
    setTimeout(() => { t.style.display = 'none'; }, 2500);
  } else {
    console.log('[toast]', msg);
  }
}

/* ─── Federation ──────────────────────────────────────────────────── */
async function forceFederationSync() {
  try {
    const r = await fetch('/api/v1/admin/federation/sync-now', {
      method: 'POST', credentials: 'include',
      headers: { 'X-CSRF-Token': getCookie('shroud_csrf') || '' }
    });
    if (!r.ok) { alert('Sync failed: ' + r.status); return; }
    const d = await r.json();
    let total = 0;
    for (const p of (d.peers || [])) total += (p.applied || 0);
    toast(`Synced — applied ${total} new event(s).`);
    loadFederation();
  } catch (e) {
    alert('Sync failed: ' + e);
  }
}

async function loadFederation() {
  try {
    const r = await fetch('/api/v1/admin/federation', { credentials: 'include' });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const d = await r.json();
    renderFederation(d);
  } catch (e) {
    const grid = document.getElementById('fedGrid');
    if (grid) grid.innerHTML = `<div style="padding:10px;color:#ff8a8a">Federation poll failed: ${escapeHtml(String(e))}</div>`;
  }
}

function renderFederation(d) {
  const grid = document.getElementById('fedGrid');
  if (!grid) return;
  const relays = d.relays || [];
  document.getElementById('fedBadge').textContent = `${d.summary.reachable}/${d.summary.total}`;
  document.getElementById('fedSummary').textContent = `${d.summary.reachable} / ${d.summary.total} reachable`;

  let reqTotal = 0, anonPending = 0, diagPending = 0, torCount = 0;
  grid.innerHTML = '';
  for (const r of relays) {
    const s = r.stats || {};
    if (r.reachable) {
      reqTotal     += (s.traffic && s.traffic.requests_total) || 0;
      anonPending  += (s.traffic && s.traffic.anon_messages_pending) || 0;
      diagPending  += (s.traffic && s.traffic.diag_reports_pending)  || 0;
      if (s.tor && s.tor.enabled) torCount++;
    }
    const card = document.createElement('div');
    card.className = 'panel';
    card.style.margin = '0';
    const ok = r.reachable;
    const onionAddr = (s.tor && s.tor.onion_address) ? s.tor.onion_address : '';
    const fedPeers = (s.federation && s.federation.active_peers) || 0;
    card.innerHTML = `
      <div class="panel-hdr" style="padding:8px 10px;border-bottom:1px solid var(--bd)">
        <span style="font-size:11px">${escapeHtml(r.endpoint)}</span>
        <span class="pill" style="background:${ok ? 'var(--ok-bg)' : '#3a1010'};color:${ok ? 'var(--ok)' : '#ff8a8a'}">${ok ? 'OK' : 'DOWN'}</span>
      </div>
      <div style="padding:8px 10px;font-family:Consolas,monospace;font-size:11px;line-height:1.55">
        <div style="color:var(--dim)">${escapeHtml(r.operator || '—')}</div>
        ${ok ? `
        <div>v${escapeHtml(s.version || '?')}  <span style="color:var(--dim)">${escapeHtml(s.git_sha || '')}</span></div>
        <div>uptime: ${fmtUptime(s.uptime_seconds || 0)}</div>
        <div>federation peers: ${fedPeers}</div>
        <div>reqs: ${(s.traffic && s.traffic.requests_total || 0).toLocaleString()}  errs: ${(s.traffic && s.traffic.errors_total || 0).toLocaleString()}</div>
        <div>anon pending: ${(s.traffic && s.traffic.anon_messages_pending) ?? '—'}  diag: ${(s.traffic && s.traffic.diag_reports_pending) ?? '—'}</div>
        <div>disk: ${(s.capacity && s.capacity.disk_used_pct >= 0) ? s.capacity.disk_used_pct + '%' : '—'}  load: ${(s.capacity && s.capacity.load_avg || []).join(' ') || '—'}</div>
        <div style="color:${onionAddr ? 'var(--accent)' : 'var(--dim)'};word-break:break-all">tor: ${onionAddr ? escapeHtml(onionAddr) : 'disabled'}</div>
        ` : `<div style="color:#ff8a8a">${escapeHtml(r.error || 'unreachable')}</div>`}
      </div>
    `;
    grid.appendChild(card);
  }
  document.getElementById('fedReachable').textContent = d.summary.reachable;
  document.getElementById('fedTotal').textContent = `of ${d.summary.total} relays`;
  document.getElementById('fedTor').textContent = torCount;
  document.getElementById('fedReqTotal').textContent = reqTotal.toLocaleString();
  document.getElementById('fedAnonPending').textContent = anonPending.toLocaleString();
  document.getElementById('fedDiagPending').textContent = diagPending.toLocaleString();
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

async function refresh() {
  /* Always refresh the top-bar overview metrics (cheap), plus the active
   * tab if it isn't already overview. */
  try {
    await fetchOverview();
    if (state.tab !== 'overview') await fetchTab(state.tab);
    /* Badges on the inactive tabs — pull tiny counts. */
    fetchBadges();
  } catch (e) {
    console.error('refresh failed:', e);
  }
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
function renderOverview(d) {
  const cards = [
    ['accent', d.total_users,            'Users'],
    ['ok',     d.total_devices,          'Devices'],
    ['ok',     d.active_now,             'Active Now (60s)'],
    ['ok',     d.active_1min,            'Active (5 min)'],
    ['accent', d.active_today,           'Active Today'],
    ['warn',   d.os_windows + '/' + d.os_android + '/' + d.os_ios, 'Win/Android/iOS'],
    ['accent', (d.total_messages || 0).toLocaleString(), 'Total Messages'],
    ['ok',     (d.msgs_1h || 0).toLocaleString(),   'Msgs / 1h'],
    ['ok',     (d.msgs_24h || 0).toLocaleString(),  'Msgs / 24h'],
    ['warn',   d.undelivered,            'Undelivered'],
    ['purple', d.total_groups,           'Groups'],
    ['purple', d.total_friendships,      'Friendships'],
    ['warn',   d.avg_latency_ms + 'ms',  'Avg Msg Latency'],
    ['warn',   d.avg_req_ms + 'ms',      'Avg Req'],
    ['warn',   d.p95_req_ms + 'ms',      'p95 Req'],
    ['danger', d.file_count,             'Files'],
    ['danger', fmtSize(d.file_total_bytes), 'Encrypted Stored'],
    ['accent', fmtSize(d.files_dir_bytes),  'Files Folder'],
    ['accent', fmtSize(d.db_size_bytes),    'Database'],
    ['warn',   fmtSize(d.disk_free_bytes) + ' free', 'Disk'],
    ['danger', d.failed_logins_24h,      'Failed Logins 24h'],
    ['warn',   d.pending_friend_requests,'Pending Friend Req'],
    ['warn',   d.pending_group_invites,  'Pending Group Inv'],
    ['purple', (d.requests_total || 0).toLocaleString(), 'Reqs Since Boot'],
    ['danger', d.errors_total,           'Errors Since Boot'],
    ['accent', d.ecdh_cache_size,        'ECDH Cache'],
    ['ok',     fmtSize(d.bytes_24h),     'Msg Bytes / 24h'],
    ['ok',     fmtSize(d.avg_msg_size),  'Avg Msg Size'],
    ['purple', d.cover_count,            'Cover Messages'],
    ['purple', fmtSize(d.cover_bytes),   'Cover Bytes'],
    ['accent', d.onion_pct + '%',        'Reqs via Onion'],
  ];
  $('stats').innerHTML = cards.map(c =>
    '<div class="card ' + c[0] + '"><div class="val">' + esc(c[1]) +
    '</div><div class="lbl">' + esc(c[2]) + '</div></div>'
  ).join('');

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
  $('hourlyChart').innerHTML = buckets.map(b =>
    '<div class="bar" style="height:' + (b.count / hMax * 100) + '%">' +
    '<span class="tt">' + b.hour + ' — ' + b.count + '</span></div>'
  ).join('');

  /* Top endpoints */
  const ep = d.top_endpoints || [];
  const eMax = Math.max(1, ...ep.map(x => x.count));
  $('endpointList').innerHTML = ep.map(x =>
    '<div class="item"><span class="label">' + esc(x.path) +
    '</span><span class="track"><span class="fill" style="width:' +
    (x.count / eMax * 100) + '%"></span></span><span class="num">' + x.count +
    (x.errors ? ' <span style="color:var(--danger)">(' + x.errors + ')</span>' : '') +
    '</span></div>'
  ).join('') || '<div class="empty">no traffic yet</div>';
}

/* ─── Render: Users ──────────────────────────────────────────────── */
function renderUsers(d) {
  const users = d.users || [];
  $('userCountPill').textContent = users.length;
  $('userTable').innerHTML = users.map(u =>
    '<tr class="clickable" oncontextmenu="userContextMenu(event,\'' +
        esc(u.username) + '\',\'' + esc(u.user_id) + '\');return false"' +
    ' onclick="openUser(\'' + esc(u.user_id) + '\')">' +
    '<td>' + esc(u.username) + '</td>' +
    '<td>' + esc(u.user_id.substring(0, 16)) + '</td>' +
    '<td>' + u.devices + '</td>' +
    '<td>' + esc(u.created) + '</td>' +
    '<td>' +
      '<button class="tinybtn" onclick="event.stopPropagation();banUserPrompt(\'' +
          esc(u.username) + '\')">Ban</button> ' +
      '<button class="tinybtn" onclick="event.stopPropagation();delUser(\'' +
          esc(u.user_id) + '\',\'' + esc(u.username) + '\',' + u.devices + ')">X</button>' +
    '</td>' +
    '</tr>'
  ).join('') || '<tr><td colspan="5" class="empty">no users</td></tr>';

  const fr = d.friend_requests_pending || [];
  $('frPill').textContent = fr.length;
  $('frTable').innerHTML = fr.map(r =>
    '<tr><td>' + esc(r.from) + '</td><td>' + esc(r.to) + '</td>' +
    '<td>' + esc(r.reason) + '</td><td>' + esc(r.created) + '</td></tr>'
  ).join('') || '<tr><td colspan="4" class="empty">none</td></tr>';

  const gi = d.group_invites_pending || [];
  $('giPill').textContent = gi.length;
  $('giTable').innerHTML = gi.map(r =>
    '<tr><td>' + esc(r.group) + '</td><td>' + esc(r.from) + '</td>' +
    '<td>' + esc(r.to) + '</td><td>' + esc(r.reason) + '</td>' +
    '<td>' + esc(r.created) + '</td></tr>'
  ).join('') || '<tr><td colspan="5" class="empty">none</td></tr>';

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
function renderDevices(d) {
  const devices = d.devices || [];
  $('deviceCountPill').textContent = devices.length;
  $('devTable').innerHTML = devices.map(dv =>
    '<tr class="clickable" onclick="openDevice(\'' + esc(dv.id) + '\')">' +
    '<td>' + esc(dv.id.substring(0, 16)) + '</td>' +
    '<td>' + esc(dv.platform) + '</td>' +
    '<td>' + esc(dv.name) + '</td>' +
    '<td>' + esc(dv.registered) + '</td>' +
    '<td>' + esc(dv.last_seen) + '</td>' +
    '<td><button class="tinybtn" onclick="event.stopPropagation();delDev(\'' +
    esc(dv.id) + '\')">X</button></td>' +
    '</tr>'
  ).join('') || '<tr><td colspan="6" class="empty">no devices</td></tr>';

  const grp = d.groups || [];
  $('grpCountPill').textContent = grp.length;
  $('grpTable').innerHTML = grp.map(g =>
    '<tr><td>' + esc(g.id.substring(0, 12)) + '</td>' +
    '<td>' + esc(g.name) + '</td>' +
    '<td>' + g.members + '</td>' +
    '<td>' + esc(g.created) + '</td></tr>'
  ).join('') || '<tr><td colspan="4" class="empty">none</td></tr>';
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
    '<tr class="clickable" onclick="openDevice(\'' + esc(r.device_id) + '\')">' +
    '<td>' + esc(r.device_id.substring(0, 16)) + '</td>' +
    '<td>' + esc(r.username || '(detached)') + '</td>' +
    '<td><span class="tag ' + (r.prekeys === 0 ? 'danger' : 'warn') + '">' +
    r.prekeys + '</span></td>' +
    '<td>' + esc(r.last_seen || 'never') + '</td></tr>'
  ).join('') || '<tr><td colspan="4" class="empty">all devices well-stocked</td></tr>';
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
    '<tr><td>' + esc(r.ts) + '</td><td>' + esc(r.actor) +
    '</td><td><span class="tag ok">' + esc(r.action) + '</span></td>' +
    '<td>' + esc(r.target) + '</td><td>' + esc(r.detail) + '</td></tr>'
  ).join('') || '<tr><td colspan="5" class="empty">none</td></tr>';

  $('flPill').textContent = (d.failed_logins || []).length;
  $('flTable').innerHTML = (d.failed_logins || []).map(r =>
    '<tr><td>' + esc(r.ip) + '</td><td>' + esc(r.hwid) + '</td>' +
    '<td>' + esc(r.fp) + '</td><td>' + esc(r.ts) + '</td></tr>'
  ).join('') || '<tr><td colspan="4" class="empty">none</td></tr>';

  $('errPill').textContent = (d.recent_errors || []).length;
  $('errTable').innerHTML = (d.recent_errors || []).map(r =>
    '<tr><td>' + esc(r.ts) + '</td><td>' + esc(r.path) + '</td>' +
    '<td><span class="tag ' + (r.status >= 500 ? 'danger' : 'warn') + '">' +
    esc(r.status) + '</span></td><td>' + esc(r.detail) + '</td></tr>'
  ).join('') || '<tr><td colspan="4" class="empty">none</td></tr>';

  const sess = d.sessions || [];
  $('sessCountPill').textContent = sess.length;
  $('sessTable').innerHTML = sess.map(s =>
    '<tr><td>' + esc(s.id.substring(0, 12)) + '</td><td>' + esc(s.ip) +
    '</td><td>' + esc(s.login_at) + '</td><td>' + esc(s.last_activity) +
    '</td><td><span class="tag ' + (s.active ? 'ok' : 'warn') + '">' +
    (s.active ? 'Active' : 'Ended') + '</span></td>' +
    '<td>' + (s.active
      ? '<button class="tinybtn warn" onclick="killSess(\'' + esc(s.id) + '\')">Kill</button>'
      : '') + '</td></tr>'
  ).join('') || '<tr><td colspan="6" class="empty">none</td></tr>';
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
    '<tr><td>' + esc(m.ts) + '</td>' +
    '<td>' + esc(m.sender.substring(0, 12)) + '</td>' +
    '<td>' + esc(m.recipient.substring(0, 12)) + '</td>' +
    '<td>' + m.size + 'B</td>' +
    '<td><span class="tag ' + (m.delivered ? 'ok' : 'warn') + '">' +
    (m.delivered ? 'Delivered' : 'Pending') + '</span></td></tr>'
  ).join('') || '<tr><td colspan="5" class="empty">none</td></tr>';

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
  $('fileTable').innerHTML = h || '<tr><td colspan="8" class="empty">no files</td></tr>';
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
    toast(title + ': ' + (j.message || JSON.stringify(j)), 'ok');
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
    toast(which + ' = ' + (actual ? 'on' : 'off'), 'ok');
    await refresh();
  } catch (e) {
    toast(which + ' failed: ' + (e && e.message ? e.message : 'unknown'), 'danger');
  }
}
function copyFp() {
  const fp = $('idFp').textContent;
  if (navigator.clipboard) {
    navigator.clipboard.writeText(fp).then(() => toast('Fingerprint copied', 'ok'));
  } else {
    prompt('Fingerprint:', fp);
  }
}
async function delDev(id) {
  const ok = await showModal({
    title: 'Delete device',
    body: 'Delete device <code>' + esc(id.substring(0, 16)) + '…</code>?',
    impact: 'All messages to and from this device will be removed from the queue.',
    impactClass: 'warn',
    confirmText: 'Delete', confirmClass: 'danger',
  });
  if (!ok) return;
  await api('DELETE', '/api/v1/admin/devices/' + id);
  toast('Device deleted', 'ok');
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
  await api('DELETE', '/api/v1/admin/sessions/' + id);
  toast('Session killed', 'ok');
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
  if (ms > 0) state.refreshTimer = setInterval(refresh, ms);
  try { localStorage.setItem(LS_INTERVAL, String(ms)); } catch (e) {}
}
$('refreshInterval').addEventListener('change', e => {
  setRefreshInterval(parseInt(e.target.value, 10) || 0);
});

/* ─── Keyboard shortcuts ─────────────────────────────────────────── */
window.addEventListener('keydown', e => {
  if (e.target.matches('input, textarea, select')) {
    if (e.key === 'Escape') { e.target.blur(); }
    return;
  }
  if ($('modalBg').classList.contains('show') ||
      $('cheatsheetBg').classList.contains('show')) {
    if (e.key === 'Escape') { closeModal(false); closeCheatsheet(); }
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

  /* `g` then a single letter to jump tabs */
  if (e.key === 'g') {
    state.pendingGoto = true;
    state.pendingGotoUntil = Date.now() + 1500;
    return;
  }
  if (state.pendingGoto && Date.now() < state.pendingGotoUntil) {
    state.pendingGoto = false;
    const map = { o:'overview', u:'users', d:'devices', c:'crypto', f:'files', a:'audit', y:'activity' };
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

  wireSearchInputs();
  setInterval(updateCountdowns, 50);

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
