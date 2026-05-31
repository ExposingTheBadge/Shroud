/* Shared admin utilities for drill-down pages (user.html, device.html).
 *
 * Mirrors the helpers that admin.js owns on the main dashboard so
 * the drill-downs can show the same modal + toast UX without
 * pulling in the full dashboard runtime. Injects the required
 * overlay DOM lazily on first use.
 *
 * Globals exposed: esc, getCookie, api, toast, showModal, closeModal
 */
'use strict';

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  })[c]);
}

function getCookie(name) {
  const m = document.cookie.match('(^|;)\\s*' + name + '\\s*=\\s*([^;]+)');
  return m ? decodeURIComponent(m.pop()) : '';
}

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
  let host = document.getElementById('toastHost');
  if (!host) {
    host = document.createElement('div');
    host.id = 'toastHost';
    host.className = 'toast-stack';
    document.body.appendChild(host);
  }
  const t = document.createElement('div');
  t.className = 'toast ' + (level || '');
  t.textContent = msg;
  host.appendChild(t);
  setTimeout(() => {
    t.style.opacity = '0';
    setTimeout(() => t.remove(), 320);
  }, 3800);
}

/* ─── Modal ───────────────────────────────────────────────────────── */
let _modalResolver = null;

function _ensureModal() {
  if (document.getElementById('modalBg')) return;
  const wrap = document.createElement('div');
  wrap.id = 'modalBg';
  wrap.className = 'modal-bg';
  wrap.innerHTML =
    '<div class="modal">' +
      '<h2 id="modalTitle">Confirm</h2>' +
      '<div class="body" id="modalBody"></div>' +
      '<div class="impact" id="modalImpact" style="display:none"></div>' +
      '<div class="actions">' +
        '<button id="modalCancel">Cancel</button>' +
        '<button class="primary" id="modalConfirm">Confirm</button>' +
      '</div>' +
    '</div>';
  document.body.appendChild(wrap);
  document.getElementById('modalConfirm').addEventListener('click', () => closeModal(true));
  document.getElementById('modalCancel').addEventListener('click', () => closeModal(false));
  wrap.addEventListener('click', e => { if (e.target.id === 'modalBg') closeModal(false); });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && wrap.classList.contains('show')) closeModal(false);
  });
}

function showModal({ title, body, impact, impactClass, confirmText, confirmClass }) {
  _ensureModal();
  document.getElementById('modalTitle').textContent = title || 'Confirm';
  document.getElementById('modalBody').innerHTML    = body || '';
  const imp = document.getElementById('modalImpact');
  if (impact) {
    imp.textContent = impact;
    imp.className   = 'impact' + (impactClass ? ' ' + impactClass : '');
    imp.style.display = 'block';
  } else {
    imp.style.display = 'none';
  }
  const btn = document.getElementById('modalConfirm');
  btn.textContent = confirmText || 'Confirm';
  btn.className   = confirmClass || 'primary';
  document.getElementById('modalBg').classList.add('show');
  return new Promise(res => { _modalResolver = res; });
}

function closeModal(result) {
  const bg = document.getElementById('modalBg');
  if (bg) bg.classList.remove('show');
  if (_modalResolver) { _modalResolver(result === true); _modalResolver = null; }
}
