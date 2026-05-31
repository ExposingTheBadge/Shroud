/* SHROUD admin login — fingerprint grid + password.
 *
 * The fingerprint is a 256-hex-char value generated server-side on first
 * setup. Users paste it into the grid (anywhere — paste handler spreads
 * the value across consecutive cells from wherever the cursor is). Three
 * failed attempts within the ban window bans the IP permanently. */
(function () {
  'use strict';

  const FP_COLS = 32;
  const FP_LENGTH = 256;

  const fpGrid = document.getElementById('fpGrid');
  const inputs = [];

  for (let i = 0; i < FP_LENGTH; i++) {
    const inp = document.createElement('input');
    inp.type = 'text';
    inp.maxLength = 1;
    inp.dataset.idx = i;
    inp.setAttribute('autocomplete', 'off');
    inp.setAttribute('spellcheck', 'false');
    fpGrid.appendChild(inp);
    inputs.push(inp);
  }

  function onPaste(e) {
    e.preventDefault();
    let t = (e.clipboardData || window.clipboardData).getData('text') || '';
    t = t.replace(/[\s\n\r\t]/g, '');
    if (!t) return;
    const s = parseInt(this.dataset.idx, 10);
    const c = Math.min(t.length, FP_LENGTH - s);
    for (let i = 0; i < c; i++) {
      const idx = s + i;
      inputs[idx].value = t[i];
      inputs[idx].classList.add('filled');
    }
    const li = Math.min(s + c, FP_LENGTH - 1);
    inputs[li].focus();
    checkComplete();
  }

  inputs.forEach((inp, idx) => {
    inp.addEventListener('paste', onPaste);
    inp.addEventListener('input', function () {
      if (this.value.length === 1) {
        this.classList.add('filled');
        const n = inputs[idx + 1];
        if (n) { n.focus(); n.select(); }
      } else {
        this.classList.remove('filled');
      }
      checkComplete();
    });
    inp.addEventListener('keydown', function (e) {
      const p = inputs[idx - 1];
      const n = inputs[idx + 1];
      if (e.key === 'ArrowLeft' && p) { e.preventDefault(); p.focus(); p.select(); }
      if (e.key === 'ArrowRight' && n) { e.preventDefault(); n.focus(); n.select(); }
      if (e.key === 'Backspace') {
        if (this.value) {
          this.value = '';
          this.classList.remove('filled');
          checkComplete();
        } else if (p) {
          e.preventDefault();
          p.value = '';
          p.classList.remove('filled');
          p.focus();
          checkComplete();
        }
      }
    });
    inp.addEventListener('focus', function () { this.select(); });
  });

  function getHWID() {
    const p = [];
    try { p.push(screen.width + 'x' + screen.height); } catch (e) {}
    try { p.push(navigator.hardwareConcurrency || 0); } catch (e) {}
    try { p.push(navigator.deviceMemory || 0); } catch (e) {}
    try {
      const c = document.createElement('canvas');
      const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (gl) {
        const dbg = gl.getExtension('WEBGL_debug_renderer_info');
        if (dbg) p.push(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL));
      }
    } catch (e) {}
    try { p.push(Intl.DateTimeFormat().resolvedOptions().timeZone); } catch (e) {}
    return p.join('|');
  }

  function getFingerprintValue() {
    let v = '';
    for (let i = 0; i < FP_LENGTH; i++) v += inputs[i].value;
    return v;
  }

  const pwInput = document.getElementById('pw');
  pwInput.addEventListener('input', checkComplete);

  function checkComplete() {
    document.getElementById('fpBtn').disabled =
      getFingerprintValue().length !== FP_LENGTH || !pwInput.value;
  }

  (async function () {
    try {
      const r = await fetch('/api/v1/admin/login-status?hwid=' + encodeURIComponent(getHWID()));
      const d = await r.json();
      if (d.banned) {
        document.getElementById('banWarn').style.display = 'block';
        document.getElementById('fpBtn').style.display = 'none';
      }
      if (d.failCount > 0) {
        document.getElementById('fpStatus').textContent =
          d.failCount + ' of 3 attempts used — ' + (3 - d.failCount) + ' remaining';
        document.getElementById('fpStatus').style.color = 'var(--danger)';
      }
      if (d.needsSetup) {
        document.getElementById('fpLabel').textContent =
          'First run — set admin password to generate fingerprint';
        document.getElementById('fpGrid').style.display = 'none';
        document.getElementById('setupBtn').style.display = 'block';
        document.getElementById('fpBtn').style.display = 'none';
        pwInput.placeholder = 'Set admin password (12+ chars)';
        document.getElementById('setupBtn').disabled = false;
        pwInput.addEventListener('input', function () {
          document.getElementById('setupBtn').disabled = this.value.length < 12;
        });
      }
    } catch (e) {}
  })();

  document.getElementById('setupBtn').addEventListener('click', async function () {
    const pw = pwInput.value;
    if (pw.length < 12) return;
    this.disabled = true;
    document.getElementById('fpStatus').textContent = 'Generating fingerprint...';
    try {
      const r = await fetch('/api/v1/admin/setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: pw }),
      });
      const d = await r.json();
      if (d.ok) {
        document.getElementById('fpStatus').innerHTML =
          '<span style="color:var(--green)">Your fingerprint:</span><br>' +
          '<code style="word-break:break-all;font-size:11px">' + d.fingerprint_id + '</code><br>' +
          '<span style="color:var(--danger);font-weight:700">SAVE THIS — IT CANNOT BE RECOVERED</span><br>' +
          'Copy it, paste it into the grid, enter your password, and click Authenticate.';
        document.getElementById('fpGrid').style.display = 'grid';
        document.getElementById('setupBtn').style.display = 'none';
        document.getElementById('fpBtn').style.display = 'block';
        pwInput.placeholder = 'Admin password';
        pwInput.value = '';
      } else {
        document.getElementById('fpStatus').textContent = 'Setup failed';
      }
    } catch (e) {
      document.getElementById('fpStatus').textContent = 'Connection error';
    }
    this.disabled = false;
  });

  document.getElementById('fpBtn').addEventListener('click', async function () {
    const fp = getFingerprintValue();
    const pw = pwInput.value;
    if (fp.length !== FP_LENGTH || !pw) return;
    document.getElementById('err').style.display = 'none';
    this.disabled = true;
    document.getElementById('fpStatus').textContent = 'Verifying...';
    try {
      const r = await fetch('/api/v1/admin/fingerprint-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fingerprint_id: fp, password: pw, hwid: getHWID() }),
      });
      const d = await r.json();
      if (d.ok) {
        document.getElementById('fpStatus').textContent = 'Signed in. Redirecting...';
        location = '/admin';
      } else {
        document.getElementById('err').textContent = d.error || 'Authentication failed';
        document.getElementById('err').style.display = 'block';
        this.disabled = false;
        document.getElementById('fpStatus').textContent = '';
      }
    } catch (e) {
      document.getElementById('err').textContent = 'Connection error';
      document.getElementById('err').style.display = 'block';
      this.disabled = false;
      document.getElementById('fpStatus').textContent = '';
    }
  });
})();
