/* Device drill-down page. */
'use strict';

function $(id) { return document.getElementById(id); }
/* esc(), api(), toast(), showModal() come from shared.js */
function fmtSize(b) {
  if (!b && b !== 0) return '—';
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
  return (b/1048576).toFixed(1) + ' MB';
}

const did = decodeURIComponent(location.pathname.split('/').pop());

async function load() {
  const r = await fetch('/api/v1/admin/devices/' + encodeURIComponent(did) + '/details');
  if (r.status === 401) { location = '/admin/login'; return; }
  if (r.status === 404) { $('devTitle').textContent = 'device not found'; return; }
  const d = await r.json();

  $('devTitle').textContent = d.id.substring(0, 16) + '…';
  $('devSub').textContent   = (d.username ? 'user: ' + d.username + '  ·  ' : '') +
                              'platform ' + (d.platform || '?') + '  ·  ' +
                              'registered ' + (d.registered_at || '?') +
                              '  ·  last seen ' + (d.last_seen || 'never');

  const cards = [
    [d.has_x25519 ? 'ok' : 'danger', d.has_x25519 ? 'YES' : 'NO',  'X25519 published'],
    [d.has_ed25519 ? 'ok' : 'danger', d.has_ed25519 ? 'YES' : 'NO', 'Ed25519 published'],
    [d.signed_prekey_age_days != null && d.signed_prekey_age_days > 30 ? 'warn' : 'ok',
     d.signed_prekey_age_days == null ? '—' : d.signed_prekey_age_days + 'd', 'Signed prekey age'],
    [d.one_time_prekeys < 5 ? 'danger' : 'ok',
     d.one_time_prekeys, 'One-time prekeys'],
    ['accent', (d.msgs_sent_24h || 0).toLocaleString(),    'Msgs sent 24h'],
    ['accent', (d.msgs_recv_24h || 0).toLocaleString(),    'Msgs recv 24h'],
    ['ok',     (d.msgs_sent_total || 0).toLocaleString(),  'Msgs sent total'],
    ['ok',     (d.msgs_recv_total || 0).toLocaleString(),  'Msgs recv total'],
    ['warn',   d.undelivered_to_me,        'Pending to me'],
    ['warn',   d.undelivered_from_me,      'Pending from me'],
    ['purple', d.group_count,              'In Groups'],
    ['danger', d.recent_error_count,       'Recent Errors'],
  ];
  $('devCards').innerHTML = cards.map(c =>
    '<div class="card ' + c[0] + '"><div class="val">' + esc(c[1]) +
    '</div><div class="lbl">' + esc(c[2]) + '</div></div>'
  ).join('');

  /* Ratchet info */
  const ri = d.ratchet || {};
  const rows = [
    ['Signed prekey id', ri.signed_prekey_id || '—'],
    ['Signed prekey published', ri.signed_prekey_at || '—'],
    ['Last X3DH bundle fetch', d.last_bundle_fetch || '—'],
    ['Ratchet messages received', ri.recv_count != null ? ri.recv_count : '—'],
    ['Ratchet messages sent',     ri.send_count != null ? ri.send_count : '—'],
  ];
  $('ratchetInfo').innerHTML = rows.map(r =>
    '<span style="color:var(--dim)">' + esc(r[0]) + '</span><span>' + esc(r[1]) + '</span>'
  ).join('');

  /* Siblings */
  const sib = d.siblings || [];
  $('siblingCountPill').textContent = sib.length;
  $('devSiblings').innerHTML = sib.map(s =>
    '<tr class="clickable" onclick="location=\'/admin/device/' + esc(s.id) + '\'">' +
    '<td>' + esc(s.id.substring(0, 16)) + '</td>' +
    '<td>' + esc(s.platform) + '</td>' +
    '<td>' + esc(s.name) + '</td>' +
    '<td>' + esc(s.last_seen) + '</td></tr>'
  ).join('') || '<tr><td colspan="4" class="empty">none</td></tr>';

  /* Recent messages */
  const msgs = d.recent_messages || [];
  $('msgCountPill').textContent = msgs.length;
  $('devMessages').innerHTML = msgs.map(m =>
    '<tr><td>' + esc(m.ts) + '</td>' +
    '<td><span class="tag ' + (m.direction === 'sent' ? 'ok' : 'warn') + '">' +
    esc(m.direction) + '</span></td>' +
    '<td>' + esc(m.peer.substring(0, 12)) + '</td>' +
    '<td>' + fmtSize(m.size) + '</td>' +
    '<td><span class="tag ' + (m.delivered ? 'ok' : 'warn') + '">' +
    (m.delivered ? 'Delivered' : 'Pending') + '</span></td></tr>'
  ).join('') || '<tr><td colspan="5" class="empty">none</td></tr>';

  /* Errors */
  const errs = d.recent_errors || [];
  $('errCountPill').textContent = errs.length;
  $('devErrors').innerHTML = errs.map(e =>
    '<tr><td>' + esc(e.ts) + '</td>' +
    '<td>' + esc(e.path) + '</td>' +
    '<td><span class="tag ' + (e.status >= 500 ? 'danger' : 'warn') + '">' +
    esc(e.status) + '</span></td>' +
    '<td>' + esc(e.detail) + '</td></tr>'
  ).join('') || '<tr><td colspan="4" class="empty">none</td></tr>';
}

async function deleteThisDevice() {
  const ok = await showModal({
    title: 'Delete device',
    body: 'Delete device <code>' + esc(did.substring(0, 16)) + '…</code>?',
    impact: 'All queued messages to and from this device will be removed. ' +
            'The owning user is not affected.',
    impactClass: 'warn',
    confirmText: 'Yes, delete', confirmClass: 'danger',
  });
  if (!ok) return;
  try {
    await api('DELETE', '/api/v1/admin/devices/' + encodeURIComponent(did));
    toast('Device deleted', 'ok');
    setTimeout(() => { location = '/admin#devices'; }, 600);
  } catch (e) {
    toast('Delete failed: ' + (e && e.message ? e.message : 'unknown'), 'danger');
  }
}

load();
