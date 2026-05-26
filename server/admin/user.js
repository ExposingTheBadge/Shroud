/* User drill-down page — one fetch, render everything, no live updates. */
'use strict';

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

const uid = decodeURIComponent(location.pathname.split('/').pop());

async function load() {
  const r = await fetch('/api/v1/admin/users/' + encodeURIComponent(uid) + '/details');
  if (r.status === 401) { location = '/admin/login'; return; }
  if (r.status === 404) { $('userTitle').textContent = 'user not found'; return; }
  const d = await r.json();

  $('userTitle').textContent = d.username;
  $('userSub').textContent   = 'id: ' + d.user_id + '  ·  registered ' + d.created_at;

  /* Summary cards */
  const cards = [
    ['accent', d.device_count,        'Devices'],
    ['ok',     (d.msgs_24h || 0).toLocaleString(),  'Msgs sent / 24h'],
    ['ok',     (d.msgs_7d  || 0).toLocaleString(),  'Msgs sent / 7d'],
    ['accent', (d.msgs_all || 0).toLocaleString(),  'Msgs sent / all'],
    ['purple', d.friend_count,        'Friends'],
    ['purple', d.group_count,         'Groups'],
    ['warn',   d.login_count_24h,     'Logins 24h'],
    ['danger', d.failed_login_count,  'Failed Logins'],
  ];
  $('userCards').innerHTML = cards.map(c =>
    '<div class="card ' + c[0] + '"><div class="val">' + esc(c[1]) +
    '</div><div class="lbl">' + esc(c[2]) + '</div></div>'
  ).join('');

  /* Devices */
  const devs = d.devices || [];
  $('devCountPill').textContent = devs.length;
  $('userDevices').innerHTML = devs.map(dv =>
    '<tr class="clickable" onclick="location=\'/admin/device/' + esc(dv.id) + '\'">' +
    '<td>' + esc(dv.id.substring(0, 16)) + '</td>' +
    '<td>' + esc(dv.platform) + '</td>' +
    '<td>' + esc(dv.name) + '</td>' +
    '<td>' + esc(dv.registered) + '</td>' +
    '<td>' + esc(dv.last_seen) + '</td>' +
    '<td><span class="tag ' + (dv.prekeys < 5 ? 'danger' : 'ok') + '">' +
    dv.prekeys + '</span></td></tr>'
  ).join('') || '<tr><td colspan="6" class="empty">no devices</td></tr>';

  /* Friendships */
  const friends = d.friendships || [];
  $('friendCountPill').textContent = friends.length;
  $('userFriends').innerHTML = friends.map(f =>
    '<tr class="clickable" onclick="location=\'/admin/user/' + esc(f.user_id) + '\'">' +
    '<td>' + esc(f.username) + '</td>' +
    '<td>' + esc(f.direction) + '</td>' +
    '<td>' + esc(f.established) + '</td></tr>'
  ).join('') || '<tr><td colspan="3" class="empty">none</td></tr>';

  /* Groups */
  const groups = d.groups || [];
  $('userGroupCountPill').textContent = groups.length;
  $('userGroups').innerHTML = groups.map(g =>
    '<tr><td>' + esc(g.id.substring(0, 12)) + '</td>' +
    '<td>' + esc(g.name) + '</td>' +
    '<td>' + esc((g.via_device || '').substring(0, 16)) + '</td></tr>'
  ).join('') || '<tr><td colspan="3" class="empty">none</td></tr>';

  /* Logins */
  const logins = d.logins || [];
  $('loginCountPill').textContent = logins.length;
  $('userLogins').innerHTML = logins.map(l =>
    '<tr><td>' + esc(l.ts) + '</td>' +
    '<td>' + esc(l.ip) + '</td>' +
    '<td>' + esc(l.hwid) + '</td>' +
    '<td><span class="tag ' + (l.success ? 'ok' : 'danger') + '">' +
    (l.success ? 'OK' : 'fail') + '</span></td></tr>'
  ).join('') || '<tr><td colspan="4" class="empty">none</td></tr>';

  /* Audit mentions */
  const audit = d.audit_mentions || [];
  $('auditMentionPill').textContent = audit.length;
  $('userAudit').innerHTML = audit.map(a =>
    '<tr><td>' + esc(a.ts) + '</td>' +
    '<td>' + esc(a.actor) + '</td>' +
    '<td><span class="tag ok">' + esc(a.action) + '</span></td>' +
    '<td>' + esc(a.target) + '</td>' +
    '<td>' + esc(a.detail) + '</td></tr>'
  ).join('') || '<tr><td colspan="5" class="empty">none</td></tr>';
}

load();
