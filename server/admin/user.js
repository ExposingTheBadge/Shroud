/* User drill-down page — one fetch, render everything, no live updates. */
'use strict';

function $(id) { return document.getElementById(id); }
/* esc(), api(), toast(), showModal() come from shared.js */
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

  /* Devices. Row click → device drill-down. The Delete button is its
     own column so clicking it doesn't navigate. */
  const devs = d.devices || [];
  $('devCountPill').textContent = devs.length;
  $('userDevices').innerHTML = devs.map(dv =>
    '<tr>' +
    '<td class="clickable" onclick="location=\'/admin/device/' + esc(dv.id) + '\'">' + esc(dv.id.substring(0, 16)) + '</td>' +
    '<td class="clickable" onclick="location=\'/admin/device/' + esc(dv.id) + '\'">' + esc(dv.platform) + '</td>' +
    '<td class="clickable" onclick="location=\'/admin/device/' + esc(dv.id) + '\'">' + esc(dv.name) + '</td>' +
    '<td class="clickable" onclick="location=\'/admin/device/' + esc(dv.id) + '\'">' + esc(dv.registered) + '</td>' +
    '<td class="clickable" onclick="location=\'/admin/device/' + esc(dv.id) + '\'">' + esc(dv.last_seen) + '</td>' +
    '<td class="clickable" onclick="location=\'/admin/device/' + esc(dv.id) + '\'"><span class="tag ' + (dv.prekeys < 5 ? 'danger' : 'ok') + '">' +
    dv.prekeys + '</span></td>' +
    '<td><button class="danger" onclick="deleteDevice(\'' + esc(dv.id) + '\', \'' + esc(dv.name) + '\')">Delete</button></td>' +
    '</tr>'
  ).join('') || '<tr><td colspan="7" class="empty">no devices</td></tr>';

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

async function deleteDevice(devId, devName) {
  const ok = await showModal({
    title: 'Delete device',
    body: 'Delete device <code>' + esc(devName || devId.substring(0, 16) + '…') + '</code>?',
    impact: 'All queued messages to and from this device will be removed. ' +
            'The user keeps their other devices.',
    impactClass: 'warn',
    confirmText: 'Yes, delete', confirmClass: 'danger',
  });
  if (!ok) return;
  try {
    await api('DELETE', '/api/v1/admin/devices/' + encodeURIComponent(devId));
    toast('Device deleted', 'ok');
    load();
  } catch (e) {
    toast('Delete failed: ' + (e && e.message ? e.message : 'unknown'), 'danger');
  }
}

load();
