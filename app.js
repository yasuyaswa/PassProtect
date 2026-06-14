'use strict';

let mode = 'encrypt';

const textEl       = document.getElementById('text');
const passEl       = document.getElementById('password');
const pwdError     = document.getElementById('pwdError');
const resultEl     = document.getElementById('result');
const outputEl     = document.getElementById('output');
const statusSvg    = document.getElementById('statusSvg');
const statusText   = document.getElementById('statusText');
const copyBtn      = document.getElementById('copyBtn');
const downloadBtn  = document.getElementById('downloadBtn');
const processBtn   = document.getElementById('processBtn');
const processLabel = document.getElementById('processLabel');
const strengthFill = document.getElementById('strengthFill');
const strengthLabel= document.getElementById('strengthLabel');
const toastEl      = document.getElementById('toast');

let clearTimer, toastTimer;

/* ── Mode ─────────────────────────────────────────────── */
function setMode(newMode) {
  mode = newMode;
  const enc = mode === 'encrypt';

  document.getElementById('btn-encrypt').classList.toggle('active', enc);
  document.getElementById('btn-decrypt').classList.toggle('active', !enc);
  document.getElementById('btn-decrypt').classList.toggle('dec', !enc);
  document.getElementById('btn-encrypt').setAttribute('aria-pressed', enc);
  document.getElementById('btn-decrypt').setAttribute('aria-pressed', !enc);

  processLabel.textContent = enc ? 'Encrypt' : 'Decrypt';
  processBtn.classList.toggle('dec-mode', !enc);

  resultEl.hidden = true;
  restartAutoClear();
}

/* ── Password Visibility ──────────────────────────────── */
function togglePassword() {
  const show = passEl.type === 'password';
  passEl.type = show ? 'text' : 'password';
  document.getElementById('eyeIcon').innerHTML = show
    ? '<path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>'
    : '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
  restartAutoClear();
}

/* ── Character Counter ────────────────────────────────── */
function updateCharCount() {
  const n = textEl.value.length;
  document.getElementById('charCount').textContent =
    n === 0 ? '0 chars' : n.toLocaleString() + ' char' + (n !== 1 ? 's' : '');
  restartAutoClear();
}

/* ── Password Strength ────────────────────────────────── */
function updateStrength() {
  const p = passEl.value;
  let score = 0;
  if (p.length >= 8)           score++;
  if (p.length >= 14)          score++;
  if (/[A-Z]/.test(p))         score++;
  if (/[0-9]/.test(p))         score++;
  if (/[^A-Za-z0-9]/.test(p)) score++;

  const lvl = [
    { label: '',            color: '',        w: '0%'   },
    { label: 'Very Weak',   color: '#ef4444', w: '20%'  },
    { label: 'Weak',        color: '#f97316', w: '40%'  },
    { label: 'Fair',        color: '#f59e0b', w: '60%'  },
    { label: 'Strong',      color: '#22c55e', w: '80%'  },
    { label: 'Very Strong', color: '#10b981', w: '100%' },
  ][p.length === 0 ? 0 : Math.max(1, score)];

  strengthFill.style.width      = lvl.w;
  strengthFill.style.background = lvl.color;
  strengthLabel.textContent     = lvl.label;
  strengthLabel.style.color     = lvl.color;
  restartAutoClear();
}

/* ── Toast ────────────────────────────────────────────── */
function showToast(msg) {
  toastEl.textContent = msg;
  toastEl.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toastEl.classList.remove('show'), 2500);
}

/* ── Auto-clear ───────────────────────────────────────── */
function startAutoClear() {
  clearTimeout(clearTimer);
  clearTimer = setTimeout(resetAll, 120000);
  // Warn user 30 seconds before auto-clear
  clearTimeout(window._warnTimer);
  window._warnTimer = setTimeout(() => showToast('🕑 Auto-clearing in 30 seconds…'), 90000);
}
function restartAutoClear() { startAutoClear(); }

window.addEventListener('DOMContentLoaded', () => {
  startAutoClear();
  ['input', 'keydown', 'mousedown', 'touchstart', 'focus'].forEach(evt =>
    document.addEventListener(evt, restartAutoClear, { passive: true })
  );
});

/* ── Crypto (AES-256-GCM + PBKDF2) ───────────────────── */
const SALT = new TextEncoder().encode('FixedSalt123');

async function getKey(password) {
  const mat = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: SALT, iterations: 100000, hash: 'SHA-256' },
    mat,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encrypt(text, password) {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const key = await getKey(password);
  const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text));
  const out = new Uint8Array(iv.length + enc.byteLength);
  out.set(iv);
  out.set(new Uint8Array(enc), iv.length);
  return btoa(String.fromCharCode(...out));
}

async function decrypt(cipher, password) {
  const data = Uint8Array.from(atob(cipher), c => c.charCodeAt(0));
  const key  = await getKey(password);
  const dec  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12) }, key, data.slice(12));
  return new TextDecoder().decode(dec);
}

/* ── Status SVG helpers ───────────────────────────────── */
const SVG_OK   = '<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>';
const SVG_ERR  = '<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"/>';
const SVG_WARN = '<path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/>';

function setSuccess(msg) {
  statusSvg.innerHTML = SVG_OK;
  statusText.textContent = msg || 'Done';
  resultEl.classList.remove('invalid');
  resultEl.classList.add('success');
}

function setInvalid(type) {
  statusSvg.innerHTML   = type === 'warn' ? SVG_WARN : SVG_ERR;
  statusText.textContent = type === 'warn' ? 'Check the input format' : 'Invalid input or wrong password';
  resultEl.classList.remove('success');
  resultEl.classList.add('invalid');
}

/* ── Process ──────────────────────────────────────────── */
async function process() {
  pwdError.textContent = '';
  const pwd = passEl.value || '';

  if (pwd.length < 3 || pwd.length > 20) {
    pwdError.textContent = 'Password must be 3\u201320 characters';
    passEl.focus();
    return;
  }

  processBtn.disabled = true;
  processBtn.style.opacity = '0.65';

  try {
    const result = mode === 'encrypt'
      ? await encrypt(textEl.value, pwd)
      : await decrypt(textEl.value, pwd);

    setSuccess(mode === 'encrypt' ? 'Encrypted successfully' : 'Decrypted successfully');
    outputEl.textContent = result;
    copyBtn.disabled     = false;
    downloadBtn.disabled = false;
    resultEl.hidden      = false;
    restartAutoClear();
  } catch (err) {
    const fmt = /decode|atob|format|malformed/i.test(err?.message ?? '');
    setInvalid(fmt ? 'warn' : 'error');
    outputEl.textContent = '';
    copyBtn.disabled     = true;
    downloadBtn.disabled = true;
    resultEl.hidden      = false;
  } finally {
    processBtn.disabled = false;
    processBtn.style.opacity = '';
  }
}

/* ── Download ─────────────────────────────────────────── */
function downloadTxt() {
  const content =
    'PassProtect Export\n==================\n' +
    'Mode:  ' + mode.toUpperCase() + '\n' +
    'Date:  ' + new Date().toLocaleString() + '\n\n' +
    'Input:\n' + textEl.value + '\n\n' +
    'Output:\n' + outputEl.textContent;

  const blob = new Blob([content], { type: 'text/plain' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = 'passprotect-' + mode + '-' + Date.now() + '.txt';
  a.click();
  URL.revokeObjectURL(a.href);
  showToast('Downloaded \u2713');
  restartAutoClear();
}

/* ── Copy ─────────────────────────────────────────────── */
function copy() {
  if (!outputEl.textContent) return;
  navigator.clipboard.writeText(outputEl.textContent).then(() => {
    showToast('Copied to clipboard \u2713');
  });
  restartAutoClear();
}

/* ── Reset ────────────────────────────────────────────── */
function resetAll() {
  textEl.value         = '';
  passEl.value         = '';
  pwdError.textContent = '';
  outputEl.textContent = '';
  resultEl.hidden      = true;
  resultEl.classList.remove('success', 'invalid');
  copyBtn.disabled     = true;
  downloadBtn.disabled = true;
  updateCharCount();
  updateStrength();
}
