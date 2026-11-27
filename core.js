(() => {
'use strict';
/* ALEX SHADOW OS · shared core: icons, data, lock, shell (sidebar / top bar / footer), rain.
   Every page loads this first, then its own page script. */
const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const pad = n => String(n).padStart(2, '0');
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
/* ================= per-user private vault (stored on the ALEX server) =================
   Your wallet is encrypted in this browser (AES-GCM, key made from your WALLET PASSWORD, which only you know) and only the encrypted
   blob is sent to the server, so nobody else can read it, not even the admin or whoever runs the server.
   While the wallet is unlocked, a working copy lives in sessionStorage for this tab only; locking or signing out wipes it. */
if (!window.ALEX_BACKEND) { document.body.innerHTML = '<p style="padding:24px;color:#2bff3f;font-family:sans-serif">config.js is missing. Put config.js in the same folder as the pages.</p>'; return; }
const SESSION = (() => { try { return JSON.parse(sessionStorage.getItem('alex_session')) || {}; } catch { return {}; } })();
const CRYPTO_OK = !!(window.crypto && crypto.subtle);
if (!CRYPTO_OK || !SESSION.token) { location.replace('index.html'); return; }
const WALLET_OPEN = !!(sessionStorage.getItem('alex_ud') && sessionStorage.getItem('alex_key'));   // false until the Wallet Password has been entered
const SESSION_USER = String(SESSION.user || '');
const PBKDF2_ITER = 150000;                             // sign-in passkey stretching: must match the login page
const WALLET_ITER = 400000;                             // wallet password stretching (stored inside the wallet, so it can be raised later)
let UD = {}; if (WALLET_OPEN) { try { UD = JSON.parse(sessionStorage.getItem('alex_ud')) || {}; } catch {} }
let ver = 0, saved = 0, flushT = null, retryT = null, flushing = Promise.resolve(), flushLock = false;
const b64 = u8 => { let s = ''; for (let i = 0; i < u8.length; i += 8192) s += String.fromCharCode.apply(null, u8.subarray(i, i + 8192)); return btoa(s); };
const unb64 = s => Uint8Array.from(atob(s), ch => ch.charCodeAt(0));
const hexOf = u8 => [...u8].map(x => x.toString(16).padStart(2, '0')).join('');
const SESSION_KEYS = ['alex_session', 'alex_counted', 'alex_deadline', 'alex_ud', 'alex_key', 'alex_auth', 'alex_dirty', 'alex_wblob', 'alex_wsalt', 'alex_fresh'];
function sessionExpired() { SESSION_KEYS.forEach(k => sessionStorage.removeItem(k)); location.replace('index.html?expired=1'); }
async function api(method, path, body) {
  const r = await ALEX_BACKEND.request(method, path, body, SESSION.token);
  if (r.status === 401) { sessionExpired(); throw Object.assign(new Error('Session ended'), { status: 401 }); }
  if (!r.ok) throw Object.assign(new Error((r.data && r.data.error) || 'Request failed'), { status: r.status, data: r.data });
  return r.data;
}
async function deriveBits(pass, saltB64) {              // 64 bytes: first half = vault key, second half = what the server checks
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: unb64(saltB64), iterations: PBKDF2_ITER, hash: 'SHA-256' }, base, 512));
  return { enc: bits.slice(0, 32), auth: hexOf(bits.slice(32)) };
}
const aesKey = raw => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
async function encryptRaw(str, raw) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(raw), new TextEncoder().encode(str)));
  return JSON.stringify({ v: 1, iv: b64(iv), ct: b64(ct) });
}
async function deriveWallet(pass, saltB64, iter) {      // 32-byte wallet key from the Wallet Password
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: unb64(saltB64), iterations: iter, hash: 'SHA-256' }, base, 256));
}
async function encryptWallet(str, raw, iter) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(raw), new TextEncoder().encode(str)));
  return JSON.stringify({ v: 2, iter, iv: b64(iv), ct: b64(ct) });
}
async function decryptWallet(blobStr, raw) {
  const b = JSON.parse(blobStr);
  return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(b.iv) }, await aesKey(raw), unb64(b.ct)));
}
function flushNow() {                                   // sends the encrypted wallet to the server; safe to call any time
  clearTimeout(flushT);
  flushing = flushing.then(async () => {
    if (!WALLET_OPEN || flushLock) return;
    if (saved === ver && !sessionStorage.getItem('alex_dirty')) return;
    const v = ver, snap = JSON.stringify(UD);
    try {
      const keyRaw = sessionStorage.getItem('alex_key'), wsalt = sessionStorage.getItem('alex_wsalt');
      if (!keyRaw || !wsalt) throw new Error('no key');
      const blob = await encryptWallet(snap, unb64(keyRaw), WALLET_ITER);
      await api('PUT', '/api/vault', { salt: wsalt, blob });
      sessionStorage.setItem('alex_wblob', blob);
      saved = v; if (v === ver) sessionStorage.removeItem('alex_dirty');
    } catch (e) {
      console.error('Could not save your vault', e);
      if (e.status !== 401) { clearTimeout(retryT); retryT = setTimeout(flushNow, 5000); }      // offline? try again shortly
    }
  });
  return flushing;
}
function persist() {
  ver++; try { sessionStorage.setItem('alex_ud', JSON.stringify(UD)); sessionStorage.setItem('alex_dirty', '1'); } catch {}
  clearTimeout(flushT); flushT = setTimeout(flushNow, 120);
}
const store = {
  get(k, d) { return (k in UD) ? UD[k] : d; },
  set(k, v) {
    if (!WALLET_OPEN) return;                                                         // nothing is written while the wallet is locked
    if (k in UD && UD[k] === v && (v === null || typeof v !== 'object')) return;      // nothing changed
    UD[k] = v; persist();
  },
  del(k) { if (WALLET_OPEN && k in UD) { delete UD[k]; persist(); } }
};
if (sessionStorage.getItem('alex_dirty')) flushNow();   // a save was cut short by a page change: finish it
addEventListener('pagehide', () => { flushNow(); });
const DAY = 864e5;

/* ================= icons ================= */
const IC = {
  home:'<path d="M3 11l9-8 9 8v9a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z" fill="currentColor"/>',
  lock:'<rect x="4" y="10" width="16" height="11" rx="2.2" fill="currentColor"/><path d="M8 10V7a4 4 0 0 1 8 0v3" fill="none" stroke="currentColor" stroke-width="2.2"/><circle cx="12" cy="15.3" r="1.7" fill="#000"/>',
  unlock:'<rect x="4" y="10" width="16" height="11" rx="2.2" fill="currentColor"/><path d="M8 10V7a4 4 0 0 1 7.6-1.7" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/><circle cx="12" cy="15.3" r="1.7" fill="#000"/>',
  dice:'<rect x="3" y="3" width="18" height="18" rx="3.5" fill="currentColor"/><g fill="#000"><circle cx="8" cy="8" r="1.6"/><circle cx="16" cy="8" r="1.6"/><circle cx="12" cy="12" r="1.6"/><circle cx="8" cy="16" r="1.6"/><circle cx="16" cy="16" r="1.6"/></g>',
  shield:'<path d="M12 2l8 3v6c0 5-3.4 9-8 11-4.6-2-8-6-8-11V5z" fill="currentColor"/><path d="M8.5 12l2.5 2.5 4.5-5" fill="none" stroke="#000" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
  shieldchk:'<path d="M12 2.5l7.5 2.8v6c0 4.8-3.2 8.4-7.5 10.2-4.3-1.8-7.5-5.4-7.5-10.2v-6z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M8.6 12l2.4 2.4 4.4-4.8" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
  shieldlock:'<path d="M12 1.6l8.9 3.3v6.8c0 5.3-3.7 9.4-8.9 11-5.2-1.6-8.9-5.7-8.9-11V4.9z" fill="rgba(0,255,26,.18)" stroke="currentColor" stroke-width="2.2" stroke-linejoin="round"/><rect x="7.6" y="10.4" width="8.8" height="7.2" rx="1.4" fill="currentColor"/><path d="M9.4 10.4V8.9a2.6 2.6 0 0 1 5.2 0v1.5" fill="none" stroke="currentColor" stroke-width="1.9"/><circle cx="12" cy="13.5" r="1.1" fill="#031004"/><rect x="11.45" y="13.8" width="1.1" height="2.2" rx=".5" fill="#031004"/>',
  gear:'<circle cx="12" cy="12" r="7.2" fill="none" stroke="currentColor" stroke-width="3.6" stroke-dasharray="3.4 2.1"/><circle cx="12" cy="12" r="5.8" fill="currentColor"/><circle cx="12" cy="12" r="2.4" fill="#000"/>',
  doc:'<rect x="4" y="3" width="16" height="18" rx="2.5" fill="currentColor"/><path d="M8 8h8M8 12h8M8 16h5" stroke="#000" stroke-width="1.8" stroke-linecap="round"/>',
  trash:'<path d="M5 7h14l-1 13a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1z" fill="currentColor"/><rect x="4" y="4" width="16" height="2.6" rx="1" fill="currentColor"/><rect x="9" y="2" width="6" height="2.6" rx="1" fill="currentColor"/>',
  help:'<circle cx="12" cy="12" r="10" fill="currentColor"/><path d="M9.2 9.3a2.8 2.8 0 1 1 4 2.5c-.9.5-1.2 1-1.2 1.8" fill="none" stroke="#000" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="17" r="1.2" fill="#000"/>',
  key:'<circle cx="7.5" cy="16.5" r="4" fill="none" stroke="currentColor" stroke-width="2"/><path d="M10.5 13.5L20 4M16 8l3 3M13.5 10.5l2 2" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>',
  clock:'<circle cx="12" cy="12" r="9.5" fill="none" stroke="currentColor" stroke-width="2"/><path d="M12 6.5V12l3.5 2" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>',
  bell:'<path d="M6 17v-6a6 6 0 0 1 12 0v6l2 2H4zM10 21.5a2 2 0 0 0 4 0" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>',
  search:'<circle cx="11" cy="11" r="7" fill="none" stroke="currentColor" stroke-width="2.2"/><path d="M16.5 16.5L21 21" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/>',
  eye:'<path d="M1.5 12S5.5 5 12 5s10.5 7 10.5 7-4 7-10.5 7S1.5 12 1.5 12z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" stroke-width="1.8"/>',
  eyeoff:'<path d="M1.5 12S5.5 5 12 5s10.5 7 10.5 7-4 7-10.5 7S1.5 12 1.5 12z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M3 3l18 18" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
  copy:'<rect x="8.5" y="8.5" width="12" height="12" rx="2.2" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M15.5 8.5V5.7a2.2 2.2 0 0 0-2.2-2.2H5.7a2.2 2.2 0 0 0-2.2 2.2v7.6a2.2 2.2 0 0 0 2.2 2.2h2.8" fill="none" stroke="currentColor" stroke-width="1.8"/>',
  dots:'<circle cx="12" cy="5" r="1.9" fill="currentColor"/><circle cx="12" cy="12" r="1.9" fill="currentColor"/><circle cx="12" cy="19" r="1.9" fill="currentColor"/>',
  folder:'<path d="M2.5 6.5a2 2 0 0 1 2-2h4.8l2.2 2.5h8a2 2 0 0 1 2 2v9.5a2 2 0 0 1-2 2h-15a2 2 0 0 1-2-2z" fill="currentColor"/>',
  bolt:'<path d="M13.5 2L5 13.5h6L10 22l9-12h-6.2z" fill="currentColor"/>',
  plus:'<circle cx="12" cy="12" r="9.5" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M12 7.5v9M7.5 12h9" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
  cube:'<path d="M12 2.8l8 4.4v9.6l-8 4.4-8-4.4V7.2z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M4.4 7.4L12 12l7.6-4.6M12 12v9" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>',
  pulse:'<path d="M2 12h4l2.5-7 4 15 3-8H22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
  arrow:'<path d="M4 12h15M13 6l6 6-6 6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
  chevron:'<path d="M6 9l6 6 6-6" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>',
  sun:'<circle cx="12" cy="12" r="4" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M4.9 19.1L7 17M17 7l2.1-2.1" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
  moon:'<path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>',
  menu:'<path d="M3 6h18M3 12h18M3 18h18" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/>',
  x:'<path d="M5 5l14 14M19 5L5 19" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/>',
  user:'<circle cx="12" cy="8" r="3.4" fill="none" stroke="currentColor" stroke-width="2"/><path d="M5 20c.8-4 3.5-6 7-6s6.2 2 7 6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>',
  out:'<path d="M9 4H5a1.5 1.5 0 0 0-1.5 1.5v13A1.5 1.5 0 0 0 5 20h4M15 8l4 4-4 4M19 12H9" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
  check:'<circle cx="12" cy="12" r="9.5" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M8 12.3l2.8 2.8L16.2 9" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
  edit:'<path d="M12 4H5.5A1.5 1.5 0 0 0 4 5.5v13A1.5 1.5 0 0 0 5.5 20h13a1.5 1.5 0 0 0 1.5-1.5V12" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M9 15l.6-3.2 8.6-8.6a1.8 1.8 0 0 1 2.6 2.6l-8.6 8.6z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>',
  trashline:'<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
  upload:'<path d="M7 18a4.5 4.5 0 0 1-.6-8.96A6 6 0 0 1 18 8.5 4 4 0 0 1 17.5 18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M12 21v-9M8.5 15L12 11.5 15.5 15" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
  download:'<path d="M7 18a4.5 4.5 0 0 1-.6-8.96A6 6 0 0 1 18 8.5 4 4 0 0 1 17.5 18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M12 11v9M8.5 16.5L12 20l3.5-3.5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
  plus2:'<path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/>',
  chevl:'<path d="M15 6l-6 6 6 6" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>',
  chevr:'<path d="M9 6l6 6-6 6" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>',
  refresh:'<path d="M20 11a8 8 0 0 0-14.3-4.5L4 9M4 4v5h5M4 13a8 8 0 0 0 14.3 4.5L20 15M20 20v-5h-5" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/>',
  save:'<path d="M5 4h11l3 3v13H5zM8 4v5h7V4M8 20v-6h8v6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>',
  sliders:'<path d="M5 4v16M12 4v16M19 4v16M3 9h4M10 15h4M17 8h4" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"/>'
};
const ico = n => `<svg class="i" viewBox="0 0 24 24" aria-hidden="true">${IC[n] || ''}</svg>`;
const paintIcons = (root = document) => $$('[data-i]', root).forEach(e => { e.innerHTML = ico(e.dataset.i); });

/* ================= random / strength / hash ================= */
const rnd = n => { const a = new Uint32Array(1); crypto.getRandomValues(a); return a[0] % n; };
const SETS = { lower:'abcdefghijklmnopqrstuvwxyz', upper:'ABCDEFGHIJKLMNOPQRSTUVWXYZ', num:'0123456789', sym:'!@#$%^&*()-_=+[]{}?' };
function gen(len, o = { lower:1, upper:1, num:1, sym:1 }) {
  const bad = o.skip ? '0O1lI' : '';
  const sets = Object.keys(SETS).filter(k => o[k]).map(k => [...SETS[k]].filter(ch => !bad.includes(ch)).join(''));
  if (!sets.length) sets.push([...SETS.lower].filter(ch => !bad.includes(ch)).join(''));
  const all = sets.join('');
  const out = sets.map(s => s[rnd(s.length)]);
  while (out.length < len) out.push(all[rnd(all.length)]);
  for (let i = out.length - 1; i > 0; i--) { const j = rnd(i + 1); [out[i], out[j]] = [out[j], out[i]]; }
  return out.slice(0, len).join('');
}
function strength(p) {
  let c = 0;
  if (/[a-z]/.test(p)) c++; if (/[A-Z]/.test(p)) c++; if (/\d/.test(p)) c++; if (/[^A-Za-z0-9]/.test(p)) c++;
  return Math.min(p.length, 16) / 16 * 50 + c * 12.5;
}
function sha256js(s) {                       // pure-JS SHA-256 (used only where crypto.subtle is unavailable, e.g. http://192.168.x.x)
  const K = [], H = []; let n = 2;
  while (K.length < 64) { let p = true; for (let d = 2; d * d <= n; d++) if (n % d === 0) { p = false; break; } if (p) { if (H.length < 8) H.push((Math.pow(n, .5) % 1) * 4294967296 | 0); K.push((Math.pow(n, 1 / 3) % 1) * 4294967296 | 0); } n++; }
  const b = [...new TextEncoder().encode(s)], l = b.length * 8;
  b.push(0x80); while (b.length % 64 !== 56) b.push(0);
  for (let i = 7; i >= 0; i--) b.push(i > 3 ? 0 : (l >>> (i * 8)) & 255);
  const h = H.slice(), rr = (x, k) => (x >>> k) | (x << (32 - k));
  for (let o = 0; o < b.length; o += 64) {
    const w = []; for (let i = 0; i < 16; i++) w[i] = (b[o + i * 4] << 24) | (b[o + i * 4 + 1] << 16) | (b[o + i * 4 + 2] << 8) | b[o + i * 4 + 3];
    for (let i = 16; i < 64; i++) { const s0 = rr(w[i - 15], 7) ^ rr(w[i - 15], 18) ^ (w[i - 15] >>> 3), s1 = rr(w[i - 2], 17) ^ rr(w[i - 2], 19) ^ (w[i - 2] >>> 10); w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0; }
    let [a, bb, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const t1 = (hh + (rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) | 0, t2 = ((rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)) + ((a & bb) ^ (a & c) ^ (bb & c))) | 0;
      hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = bb; bb = a; a = (t1 + t2) | 0;
    }
    [a, bb, c, d, e, f, g, hh].forEach((v, i) => { h[i] = (h[i] + v) | 0; });
  }
  return h.map(x => (x >>> 0).toString(16).padStart(8, '0')).join('');
}
const sha256 = async s => (window.crypto && crypto.subtle)
  ? [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))].map(x => x.toString(16).padStart(2, '0')).join('')
  : sha256js(s);

/* ================= tiny event bus ================= */
const hooks = {};
const on = (ev, fn) => (hooks[ev] = hooks[ev] || []).push(fn);
const emit = (ev, ...a) => (hooks[ev] || []).forEach(f => { try { f(...a); } catch (e) { console.error(e); } });

/* ================= state (shared by every page) ================= */
const sess = (() => { try { return JSON.parse(sessionStorage.getItem('alex_session')) || {}; } catch { return {}; } })();
const DEFAULT_NAME = SESSION_USER.toLowerCase() === 'angel' ? 'Godsan' : (SESSION_USER ? SESSION_USER[0].toUpperCase() + SESSION_USER.slice(1) : 'User');
const NAME = store.get('alex_display_name', DEFAULT_NAME);
const DEMO_ACCOUNT = false;       // every vault starts empty
const CATS = ['Personal', 'Social', 'Work', 'Finance', 'Shopping', 'Entertainment', 'Other'];
const CATMAP = { Facebook:'Social', Instagram:'Social', Twitter:'Social', Discord:'Social', LinkedIn:'Social', GitHub:'Work', Dropbox:'Work', Amazon:'Shopping', Netflix:'Entertainment', Spotify:'Entertainment', Steam:'Entertainment', Google:'Personal' };

const S = { vault: store.get('alex_vault', null), trash: store.get('alex_trash', []), acts: store.get('alex_act', null), seen: store.get('alex_seen', 0) };
if (!S.vault && (store.get('alex_seeded', false) || !DEMO_ACCOUNT)) S.vault = [];
if (!S.vault) {
  const seed = ['Netflix','Spotify','Amazon','Instagram','Google','GitHub','Discord','Steam','Twitter','Dropbox','Facebook','LinkedIn'];
  const lens = [16,16,16,16,16,16,16,16,16,13,13,13];
  S.vault = seed.map((n, i) => ({ id: 'v' + i + '_' + Date.now(), name: n, user: 'godsan.' + n.toLowerCase() + '@mail.com', pass: gen(lens[i]), created: Date.now() - (i + 2) * 6 * DAY }));
  store.set('alex_vault', S.vault);
}
store.set('alex_seeded', true);
(() => { let ch = false; S.vault.forEach(v => { if (!v.cat) { v.cat = CATMAP[v.name] || 'Personal'; ch = true; } if (!v.updated) { v.updated = v.created || Date.now(); ch = true; } }); if (ch) store.set('alex_vault', S.vault); })();
if (!S.acts && !DEMO_ACCOUNT) { S.acts = []; store.set('alex_act', S.acts); }
if (!S.acts) {
  const n = Date.now();
  S.acts = [
    { t:'lock',   m:'Vault locked',             ts:n - 12 * 6e4 },
    { t:'copy',   m:'Password copied - Google', ts:n - 13 * 6e4 },
    { t:'unlock', m:'Vault unlocked',           ts:n - 13 * 6e4 - 5e3 }
  ];
  store.set('alex_act', S.acts);
}
const saveVault = () => { store.set('alex_vault', S.vault); emit('vault'); };
const saveTrash = () => store.set('alex_trash', S.trash);
const TRASH_DAYS = 30;                       // deleted passwords are removed for good after this long
function purgeTrash() {
  const keep = S.trash.filter(t => Date.now() - t.deleted < TRASH_DAYS * DAY), n = S.trash.length - keep.length;
  if (n) { S.trash = keep; saveTrash(); }
  return n;
}

let REVEAL = store.get('alex_reveal', 6);       // seconds a revealed password stays visible
let CLIP = store.get('alex_clip', false);       // wipe the clipboard 30 s after copying
let AGE = store.get('alex_age', 90);          // days before a password is flagged as old (0 = never)
function calcScore() {
  const v = S.vault; if (!v.length) return 100;
  const avg = v.reduce((a, x) => a + strength(x.pass), 0) / v.length;
  const cnt = {}; v.forEach(x => cnt[x.pass] = (cnt[x.pass] || 0) + 1);
  const reused = Object.values(cnt).filter(c => c > 1).reduce((a, c) => a + c, 0);
  const old = AGE ? v.filter(x => Date.now() - (x.updated || x.created) > AGE * DAY).length : 0;
  return Math.max(0, Math.min(100, Math.round(avg - reused * 4 - old * 2)));
}

/* ================= toast + activity ================= */
/* ================= preferences (Settings page) ================= */
const PREF_DEFAULTS = { matrix: true, speed: 'normal', glow: true, motion: true, badge: true, toasts: true, hour12: false, start: 'dashboard', perPage: 8, defCat: 'Personal', confirmDel: true };
const PREFS = Object.assign({}, PREF_DEFAULTS, store.get('alex_prefs', {}));
function fmtHM(d, secs) {
  let h = d.getHours(); const m = pad(d.getMinutes()), s = secs ? ':' + pad(d.getSeconds()) : '';
  if (PREFS.hour12) { const suf = h >= 12 ? ' PM' : ' AM'; h = h % 12 || 12; return h + ':' + m + s + suf; }
  return pad(h) + ':' + m + s;
}
function applyPrefs() {
  const h = document.documentElement;
  h.classList.toggle('no-glow', !PREFS.glow); h.classList.toggle('reduce-motion', !PREFS.motion);
  const cv = $('#rain'); if (cv) cv.style.display = (PREFS.matrix && PREFS.motion) ? '' : 'none';
  renderBadge(); tickClock(); emit('prefs');
}
function setPref(k, v) { PREFS[k] = v; store.set('alex_prefs', PREFS); applyPrefs(); }
function resetPrefs() { Object.keys(PREF_DEFAULTS).forEach(k => { PREFS[k] = PREF_DEFAULTS[k]; }); store.set('alex_prefs', PREFS); setTheme('dark'); applyPrefs(); }
function setName(n) {
  store.set('alex_display_name', n);
  const l = $('.u-av.letter'); if (l) l.textContent = n[0].toUpperCase();
  const u = $('#uName'); if (u) u.textContent = n;
}

let toastT;
function toast(msg) {
  if (!PREFS.toasts) return;
  const t = $('#toast'); if (!t) return; t.textContent = msg; t.classList.add('on');
  clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('on'), 2400);
}
const ACT_ICON = { out:'out', user:'user', lock:'check', unlock:'check', sec:'shieldchk', copy:'copy', add:'plus', edit:'edit', del:'trash', gen:'dice', login:'key', export:'download', import:'upload' };
const BROWSER = (() => { const u = navigator.userAgent; if (/Edg\//.test(u)) return 'Edge'; if (/OPR\//.test(u)) return 'Opera'; if (/Firefox\//.test(u)) return 'Firefox'; if (/Chrome\//.test(u)) return 'Chrome'; if (/Safari\//.test(u)) return 'Safari'; return 'Browser'; })();
const PAGE_LABEL = { dashboard: 'Dashboard', vault: 'Vault', generator: 'Generator', security: 'Security', settings: 'Settings', activity: 'Activity Log', recycle: 'Recycle Bin', help: 'Help & Support' };
function log(t, m) {
  const src = (t === 'login' || t === 'out') ? BROWSER : (PAGE_LABEL[document.body.dataset.page] || 'Vault');   // where the event happened
  S.acts.unshift({ t, m, ts: Date.now(), src }); S.acts = S.acts.slice(0, 200);
  store.set('alex_act', S.acts); renderBadge(); emit('acts');
}
const rel = ts => {
  const s = Math.max(0, (Date.now() - ts) / 1000);
  if (s < 45) return 'just now';
  if (s < 3600) return Math.round(s / 60) + ' min ago';
  if (s < 86400) return Math.round(s / 3600) + ' hr ago';
  return Math.round(s / 86400) + ' d ago';
};
function renderBadge() {
  const b = $('#badge'); if (!b) return;
  const n = S.acts.filter(a => a.ts > S.seen).length;
  b.hidden = !n || !PREFS.badge; b.textContent = n > 9 ? '9+' : n;
}

/* ================= modal + floating menu + clipboard ================= */
function ensureOverlays() {
  if (!$('#modal')) {
    const m = document.createElement('div'); m.className = 'modal'; m.id = 'modal'; m.hidden = true;
    m.innerHTML = '<div class="sheet" role="dialog" aria-modal="true" aria-labelledby="mTitle"><div class="sheet-h"><h3 id="mTitle"></h3><button class="ib" id="mClose" aria-label="Close" data-i="x"></button></div><div id="mBody"></div></div>';
    document.body.appendChild(m);
  }
  if (!$('#toast')) { const t = document.createElement('div'); t.className = 'toast'; t.id = 'toast'; t.setAttribute('role', 'status'); t.setAttribute('aria-live', 'polite'); document.body.appendChild(t); }
  if (!$('#rain')) { const c = document.createElement('canvas'); c.id = 'rain'; c.setAttribute('aria-hidden', 'true'); document.body.prepend(c); }
}
ensureOverlays();
const modal = $('#modal');
let modalLock = false;
function openModal(title, html, mount, opts) {
  modalLock = !!(opts && opts.locked); $('#mClose').style.display = modalLock ? 'none' : '';
  $('#mTitle').textContent = title; $('#mBody').innerHTML = html; paintIcons($('#mBody'));
  modal.hidden = false; mount && mount($('#mBody'));
}
function closeModal(force) { if (modalLock && force !== true) return; modalLock = false; $('#mClose').style.display = ''; modal.hidden = true; $('#mBody').innerHTML = ''; }
modal.addEventListener('mousedown', e => { if (e.target === modal) closeModal(); });
addEventListener('keydown', e => { if (e.key === 'Escape') { closeModal(); closeFloat(); closePanels(); } });

let fm = null;
function closeFloat() { if (fm) { fm.remove(); fm = null; } }
function openFloat(btn, items) {
  closeFloat();
  fm = document.createElement('div'); fm.className = 'fmenu';
  items.forEach(it => { const b = document.createElement('button'); b.textContent = it.l; if (it.cls) b.className = it.cls; b.onclick = () => { closeFloat(); it.f(); }; fm.appendChild(b); });
  document.body.appendChild(fm);
  const r = btn.getBoundingClientRect(), w = fm.offsetWidth, h = fm.offsetHeight;
  fm.style.left = Math.max(8, Math.min(innerWidth - w - 8, r.right - w)) + 'px';
  fm.style.top = (r.bottom + h + 8 > innerHeight ? r.top - h - 6 : r.bottom + 6) + 'px';
  setTimeout(() => addEventListener('click', closeFloat, { once: true }), 0);
}
let clipT;
async function copyText(t) {
  try { await navigator.clipboard.writeText(t); if (CLIP) { clearTimeout(clipT); clipT = setTimeout(() => { try { navigator.clipboard.writeText(' '); } catch {} }, 30000); } return true; } catch {}
  try { const a = document.createElement('textarea'); a.value = t; a.style.position = 'fixed'; a.style.opacity = '0'; document.body.appendChild(a); a.select(); const ok = document.execCommand('copy'); a.remove(); return ok; } catch { return false; }
}

/* ================= last access ================= */
let lastTs = store.get('alex_last_access', null) || sess.at || Date.now();
function touch() { lastTs = Date.now(); store.set('alex_last_access', lastTs); emit('touch'); }
function fmtLast(ts) {
  const d = new Date(ts), t = fmtHM(d);
  const diff = Math.round((new Date().setHours(0,0,0,0) - new Date(ts).setHours(0,0,0,0)) / DAY);
  if (diff <= 0) return 'Today, ' + t;
  if (diff === 1) return 'Yesterday, ' + t;
  return d.toLocaleDateString('en-US', { month:'short', day:'numeric' }) + ', ' + t;
}

/* ================= wallet lock ================= */
let AL = Object.assign({ mins: 5, hide: false }, store.get('alex_autolock', {}));
const limitSec = () => AL.mins * 60;
let deadline = +(sessionStorage.getItem('alex_deadline') || 0);
if (WALLET_OPEN && !deadline) { deadline = Date.now() + limitSec() * 1000; sessionStorage.setItem('alex_deadline', deadline); }
const isLocked = () => !WALLET_OPEN;                    // when it is locked the page only shows the "Unlock" window
const timeLeft = () => WALLET_OPEN ? Math.max(0, Math.ceil((deadline - Date.now()) / 1000)) : limitSec();
const requireUnlock = cb => cb();                       // pages only work while the wallet is open
let locking = false;
async function lockWallet(msg) {                        // saves, wipes the readable copy from this tab and asks for the Wallet Password again
  if (!WALLET_OPEN || locking) return;
  locking = true; log('lock', msg || 'Wallet locked'); await flushNow();
  if (sessionStorage.getItem('alex_dirty')) {           // could not save (offline?): keep the data and try again shortly
    locking = false; deadline = Date.now() + 10000; toast('Could not save your wallet yet. Check your connection.'); return;
  }
  ['alex_ud', 'alex_key', 'alex_deadline'].forEach(k => sessionStorage.removeItem(k));
  location.reload();
}
const setLock = v => { if (v) lockWallet(); };
const toggleLock = () => lockWallet();
function syncLock() { if (WALLET_OPEN && Date.now() >= deadline) lockWallet('Wallet auto-locked'); }
function setAL(p) {
  Object.assign(AL, p); store.set('alex_autolock', AL);
  if (WALLET_OPEN) { deadline = Date.now() + limitSec() * 1000; sessionStorage.setItem('alex_deadline', deadline); }
}

function setReveal(n) { REVEAL = n; store.set('alex_reveal', n); }
function setClip(b) { CLIP = !!b; store.set('alex_clip', CLIP); }
function setAge(d) { AGE = d; store.set('alex_age', d); emit('vault'); }
const newSalt = () => b64(crypto.getRandomValues(new Uint8Array(16)));

async function signOut() {
  if (WALLET_OPEN) { log('out', 'Signed out'); await flushNow(); }
  try { await api('POST', '/api/logout'); } catch {}
  SESSION_KEYS.forEach(k => sessionStorage.removeItem(k));
  location.replace('index.html');
}
/* change your own SIGN-IN passkey. The wallet is locked with the Wallet Password, so it is not touched. */
async function changePasskey(newPass, opts = {}) {
  const curAuth = (await deriveBits(opts.curPass || '', SESSION.salt)).auth;
  const salt = newSalt(), { auth } = await deriveBits(newPass, salt);
  if (auth === curAuth) throw Object.assign(new Error('Choose a passkey that is different from the current one'), { status: 400 });
  await api('POST', '/api/me/passkey', { cur: curAuth, salt, auth });
  SESSION.salt = salt; sessionStorage.setItem('alex_session', JSON.stringify(SESSION));
}

/* ----- Wallet Password: check it / change it ----- */
async function verifyWallet(pw) {
  const salt = sessionStorage.getItem('alex_wsalt'), key = sessionStorage.getItem('alex_key');
  if (!salt || !key || !pw) return false;
  let iter = WALLET_ITER; try { iter = JSON.parse(sessionStorage.getItem('alex_wblob')).iter || WALLET_ITER; } catch {}
  return b64(await deriveWallet(pw, salt, iter)) === key;
}
async function changeWallet(curPw, newPw) {
  if (!(await verifyWallet(curPw))) throw Object.assign(new Error('Current Wallet Password is wrong'), { status: 403 });
  flushLock = true;
  try {
    await flushing;
    const salt = newSalt(), key = await deriveWallet(newPw, salt, WALLET_ITER);
    const blob = await encryptWallet(JSON.stringify(UD), key, WALLET_ITER);
    await api('PUT', '/api/vault', { salt, blob });
    sessionStorage.setItem('alex_key', b64(key)); sessionStorage.setItem('alex_wsalt', salt); sessionStorage.setItem('alex_wblob', blob);
    saved = ver; sessionStorage.removeItem('alex_dirty');
  } finally { flushLock = false; }
}

function openAutoLock() {
  const opts = [1, 2, 5, 10, 15, 30];
  openModal('Auto-lock', `
    <p class="muted" style="margin-bottom:14px;font-size:13px">Your wallet locks itself this long after you unlock it, even while you are using the site.</p>
    <div class="chips">${opts.map(m => `<button type="button" class="chip ${m === AL.mins ? 'on' : ''}" data-m="${m}">${m} min</button>`).join('')}</div>
    <div class="chk" style="margin-top:16px"><label><input type="checkbox" id="alHide" ${AL.hide ? 'checked' : ''}>Also lock when I leave this tab or app</label></div>
    <div class="btn-row"><button class="btn" id="alDone" type="button">Done</button></div>`,
  root => {
    $$('.chip', root).forEach(c => c.onclick = () => { setAL({ mins: +c.dataset.m }); $$('.chip', root).forEach(x => x.classList.toggle('on', x === c)); toast('Auto-lock set to ' + AL.mins + ' min'); });
    $('#alHide', root).onchange = e => { setAL({ hide: e.target.checked }); toast(e.target.checked ? 'Will lock when you leave the app' : 'Leaving the app no longer locks'); };
    $('#alDone', root).onclick = closeModal;
  });
}
document.addEventListener('visibilitychange', () => { if (document.hidden && AL.hide && WALLET_OPEN) lockWallet('Wallet locked (app left)'); });

/* ================= add / edit / delete entry ================= */
function openEntry(entry, prefill) {
  const edit = !!entry, e = entry || { name:'', user:'', pass: prefill || '', cat: PREFS.defCat };
  openModal(edit ? 'Edit Password' : 'Add Password', `
    <label class="fld"><span>SITE / APP NAME</span><input type="text" id="fName" maxlength="40" autocomplete="off" value="${esc(e.name)}"></label>
    <label class="fld"><span>USERNAME OR EMAIL</span><input type="text" id="fUser" maxlength="80" autocomplete="off" autocapitalize="off" value="${esc(e.user === '—' ? '' : e.user)}"></label>
    <label class="fld"><span>PASSWORD</span><div class="inl"><input type="password" id="fPass" maxlength="64" autocomplete="new-password" value="${esc(e.pass)}"><button class="btn ghost" id="fGen" type="button">Generate</button></div></label>
    <div class="meter-s"><i id="fMeter"></i></div>
    <label class="fld"><span>CATEGORY</span><select id="eCat" class="sel">${CATS.map(c => `<option ${c === e.cat ? 'selected' : ''}>${c}</option>`).join('')}</select></label>
    <div class="btn-row"><button class="btn ghost" id="fCancel" type="button">Cancel</button><button class="btn" id="fSave" type="button">${edit ? 'Save changes' : 'Save password'}</button></div>`,
  root => {
    const pw = $('#fPass', root), m = $('#fMeter', root);
    const meter = () => { const s = strength(pw.value); m.style.width = s + '%'; m.style.background = s < 50 ? '#ff2a3d' : s < 75 ? '#ffb020' : '#2bff3f'; };
    if (prefill || edit) pw.type = 'text'; meter();
    pw.addEventListener('input', meter);
    $('#fGen', root).onclick = () => { pw.value = gen(16); pw.type = 'text'; meter(); };
    $('#fCancel', root).onclick = closeModal;
    $('#fSave', root).onclick = () => {
      const name = $('#fName', root).value.trim(), user = $('#fUser', root).value.trim(), pass = pw.value, cat = $('#eCat', root).value;
      if (!name || !pass) { toast('Enter a name and a password'); return; }
      if (edit) { Object.assign(entry, { name, user: user || '—', pass, cat, updated: Date.now() }); log('edit', 'Password updated - ' + name); }
      else { S.vault.unshift({ id: 'v' + Date.now(), name, user: user || '—', pass, cat, created: Date.now(), updated: Date.now() }); log('add', 'Password added - ' + name); }
      touch(); saveVault(); closeModal(); toast(name + (edit ? ' updated' : ' saved to vault'));
    };
    $('#fName', root).focus();
  });
}
function confirmDelete(v) {
  const doIt = () => {
    S.vault = S.vault.filter(x => x.id !== v.id); S.trash.unshift({ ...v, deleted: Date.now() });
    saveTrash(); touch(); log('del', 'Password deleted - ' + v.name); saveVault(); toast(v.name + ' moved to Recycle Bin');
  };
  if (!PREFS.confirmDel) { doIt(); return; }
  openModal('Move to Trash', `
    <p style="margin-bottom:16px;line-height:1.5">Move <b>${esc(v.name)}</b> to the Recycle Bin? You can restore it later.</p>
    <div class="btn-row"><button class="btn ghost" id="dNo" type="button">Cancel</button><button class="btn danger" id="dYes" type="button">Move to Trash</button></div>`,
  root => {
    $('#dNo', root).onclick = closeModal;
    $('#dYes', root).onclick = () => { closeModal(); doIt(); };
  });
}

/* ================= shell: sidebar, top bar, footer ================= */
const NAV = [['dashboard','Dashboard','home'], ['vault','Vault','lock'], ['generator','Generator','dice'], ['security','Security','shield'], ['settings','Settings','gear'], ['activity','Activity Logs','doc'], ['recycle','Recycle Bin','trash'], ['help','Help & Support','help']];
const BUILT = ['dashboard', 'vault', 'generator', 'security', 'settings', 'activity', 'recycle', 'help'];          // pages that exist so far
const PAGE = document.body.dataset.page || 'dashboard';
const TOP = document.body.dataset.top || 'terminal';
const TITLE = document.body.dataset.title || '';

function buildShell() {
  const side = `
  <aside class="side" id="side">
    <div class="logo"><span class="logo-ico" data-i="shieldlock"></span><b>ALEX</b><small>SHADOW OS</small></div>
    <nav>${NAV.map(([p, l, i]) => `<a class="nav ${p === PAGE ? 'active' : ''}" href="${BUILT.includes(p) ? p + '.html' : '#'}" data-page="${p}"><span data-i="${i}"></span>${l}</a>`).join('')}</nav>
    <div class="grow"></div>
    <div class="tag"><span class="tag-ico" data-i="shieldchk"></span><span>Stay Secure<br>Stay Anonymous</span></div>
    <div class="theme"><span data-i="sun"></span><button class="switch" id="themeBtn" aria-label="Toggle theme"></button><span data-i="moon"></span></div>
    <div class="ver">v1.0.0</div>
  </aside>
  <div class="scrim" id="scrim"></div>`;

  const left = TOP === 'search'
    ? '<label class="search"><span data-i="search"></span><input id="q" type="search" placeholder="Search passwords..." autocomplete="off"></label><div class="spacer"></div>'
    : `<div class="prompt"><span class="gt">&gt;</span><b id="typed"></b><i class="cursor"></i></div><div class="spacer"></div>
       <span class="live"><i class="dot"></i><b id="onl">Online</b><time id="clk">00:00:00</time></span>
       <button class="lockbtn" id="lockBtn" aria-label="Lock or unlock vault"></button>`;
  const user = TOP === 'search'
    ? `<button class="user" id="userBtn"><span class="u-av" data-i="user"></span><span class="u-txt"><b id="uName">${esc(NAME)}</b><small id="uStat"><i class="dot"></i>Online</small></span><span class="chev" data-i="chevron"></span></button>`
    : `<button class="user compact" id="userBtn"><span class="u-av letter">${esc(NAME[0].toUpperCase())}</span><span class="chev" data-i="chevron"></span></button>`;
  const top = `
  <header class="top ${TOP === 'search' ? '' : 'term'}">
    <button class="burger" id="burger" aria-label="Menu" data-i="menu"></button>
    ${left}
    <div class="pop-wrap"><button class="bell" id="bell" aria-label="Notifications"><span data-i="bell"></span><em class="badge" id="badge" hidden>0</em></button><div class="panel" id="bellPanel" hidden></div></div>
    <div class="pop-wrap">${user}
      <div class="panel menu-panel" id="userMenu" hidden>
        <button data-a="auto"><span data-i="clock"></span>Auto-lock</button>
        <button data-a="lock"><span data-i="lock"></span>Lock vault</button>
        <button data-a="out"><span data-i="out"></span>Sign out</button>
      </div>
    </div>
  </header>`;
  const foot = `
  <footer class="foot">
    <span class="f-l"><span data-i="lock"></span><b>ALEX SHADOW OS</b><i>•</i>Password Manager v1.0.0</span>
    <span class="net" id="net"><i class="dot"></i><span id="netTxt">Checking systems…</span><span class="bars" id="bars"><i></i><i></i><i></i><i></i></span></span>
  </footer>`;
  $('#sideSlot').outerHTML = side; $('#topSlot').outerHTML = top; $('#footSlot').outerHTML = foot;
  paintIcons();
}
buildShell();

/* ----- shell behaviour ----- */
const bellP = $('#bellPanel'), userM = $('#userMenu');
function closePanels() { bellP.hidden = true; userM.hidden = true; }
$('#bell').addEventListener('click', e => {
  e.stopPropagation(); const open = bellP.hidden; closePanels();
  if (open) {
    bellP.innerHTML = '<h4>NOTIFICATIONS</h4>' + (S.acts.slice(0, 6).map(a => `<div class="pn"><span>${esc(a.m)}</span><span>${rel(a.ts)}</span></div>`).join('') || '<div class="pn"><span>Nothing yet</span></div>');
    bellP.hidden = false; S.seen = Date.now(); store.set('alex_seen', S.seen); renderBadge(); emit('acts');
  }
});
$('#userBtn').addEventListener('click', e => { e.stopPropagation(); const open = userM.hidden; closePanels(); userM.hidden = !open; });
addEventListener('click', e => { if (!e.target.closest('.pop-wrap')) closePanels(); });
userM.addEventListener('click', e => {
  const b = e.target.closest('button'); if (!b) return; closePanels();
  if (b.dataset.a === 'auto') openAutoLock();
  if (b.dataset.a === 'lock') { if (isLocked()) toast('Your wallet is already locked'); else lockWallet(); }
  if (b.dataset.a === 'out') signOut();
});
$('#mClose').onclick = () => closeModal();
$('#burger').onclick = () => document.body.classList.toggle('nav-open');
$('#scrim').onclick = () => document.body.classList.remove('nav-open');
$$('[data-page]').forEach(a => {
  if (BUILT.includes(a.dataset.page)) { a.href = a.dataset.page + '.html'; return; }
  a.addEventListener('click', e => { e.preventDefault(); document.body.classList.remove('nav-open'); toast((a.textContent.trim() || 'This') + ' page is the next one to build'); });
});
const setTheme = t => { document.documentElement.dataset.theme = t; store.set('alex_theme', t); };
setTheme(store.get('alex_theme', 'dark'));
$('#themeBtn').onclick = () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
if ($('#lockBtn')) $('#lockBtn').onclick = toggleLock;

/* terminal-style page title */
if ($('#typed')) { const t = $('#typed'); let i = 0; t.textContent = ''; const iv = setInterval(() => { t.textContent = ' ' + TITLE.slice(0, ++i); if (i >= TITLE.length) clearInterval(iv); }, 70); }

/* ----- online + server status ----- */
const bars = $$('#bars i'), net = $('#net');
function setNet(ok, ms) {
  net.classList.toggle('bad', !ok);
  $('#netTxt').textContent = ok ? 'All Systems Operational' : 'Server Unreachable';
  net.title = ok ? ms + ' ms response' : 'No response from the server';
  const lvl = !ok ? 1 : ms < 80 ? 4 : ms < 200 ? 3 : ms < 500 ? 2 : 1;
  bars.forEach((b, i) => b.classList.toggle('on', i < lvl));
}
async function ping() {
  if (!navigator.onLine && location.protocol !== 'http:') return setNet(false);
  const t = performance.now();
  try {
    const r = await fetch('index.html?_=' + Date.now(), { method: 'HEAD', cache: 'no-store' });
    if (!r.ok) throw 0; setNet(true, Math.round(performance.now() - t));
  } catch { setNet(false); }
}
function renderOnline() {
  const on = navigator.onLine, s = $('#uStat'), o = $('#onl');
  if (s) { s.classList.toggle('off', !on); s.innerHTML = `<i class="dot"></i>${on ? 'Online' : 'Offline'}`; }
  if (o) { o.textContent = on ? 'Online' : 'Offline'; o.closest('.live').classList.toggle('off', !on); }
}
addEventListener('online', () => { renderOnline(); ping(); }); addEventListener('offline', () => { renderOnline(); ping(); });

function renderLockBtn() {
  const b = $('#lockBtn'); if (!b) return;
  const l = isLocked(), left = timeLeft();
  b.classList.toggle('open', !l);
  b.title = l ? 'Wallet locked' : 'Wallet unlocked — tap to lock it now';
  b.innerHTML = ico(l ? 'lock' : 'unlock') + (l ? '' : `<span>${Math.floor(left / 60)}:${pad(left % 60)}</span>`);
}
function tickClock() { const c = $('#clk'); if (c) c.textContent = fmtHM(new Date(), true); }
on('lock', renderLockBtn);

/* ================= matrix rain ================= */
(function rain() {
  const cv = $('#rain'); if (!cv || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  const cx = cv.getContext('2d'), size = 16;
  const chars = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEFXYZ'.split('');
  let drops = [], step = size * 1.5;
  function init() { cv.width = innerWidth; cv.height = innerHeight; drops = Array.from({ length: Math.ceil(cv.width / step) }, () => Math.random() * -40); }
  function frame() {
    if (document.hidden || !PREFS.matrix || !PREFS.motion) return;
    const light = document.documentElement.dataset.theme === 'light';
    cx.fillStyle = light ? 'rgba(232,243,234,.14)' : 'rgba(0,0,0,.12)'; cx.fillRect(0, 0, cv.width, cv.height);
    cx.font = size + 'px "Share Tech Mono", monospace';
    drops.forEach((y, i) => {
      cx.fillStyle = light ? 'rgba(0,140,20,.6)' : (Math.random() > .97 ? '#b8ffc0' : 'rgba(0,255,26,.6)');
      cx.fillText(chars[Math.random() * chars.length | 0], i * step, y * size);
      drops[i] = (y * size > cv.height && Math.random() > .975) ? 0 : y + .5;
    });
  }
  const MS = { slow: 110, normal: 60, fast: 32 };
  addEventListener('resize', init); init();
  (function loop() { frame(); setTimeout(loop, MS[PREFS.speed] || 60); })();
})();

/* ================= Wallet Password: create it (first time) or unlock ================= */
const walletRules = p => p.length >= 10 && strength(p) >= 55;
const WALLET_RULE_TEXT = 'Use at least 10 characters and mix letters, numbers or symbols.';
let wFails = 0, wLockUntil = 0;
function walletGate() { if (sessionStorage.getItem('alex_wblob')) showUnlock(); else showSetup(); }
function enterWallet(ud, keyRaw, wsalt, blob) {         // wallet is open: keep the readable copy for this tab, then reload the page
  sessionStorage.setItem('alex_ud', JSON.stringify(ud)); sessionStorage.setItem('alex_key', b64(keyRaw));
  sessionStorage.setItem('alex_wsalt', wsalt); sessionStorage.setItem('alex_wblob', blob);
  sessionStorage.removeItem('alex_deadline');
  const start = (ud.alex_prefs || {}).start, fresh = sessionStorage.getItem('alex_fresh'); sessionStorage.removeItem('alex_fresh');
  const cur = (location.pathname.split('/').pop() || 'index.html').replace('.html', '');
  if (fresh && ['dashboard', 'vault', 'generator', 'security', 'settings'].includes(start) && start !== cur) location.href = start + '.html'; else location.reload();
}
function showSetup() {
  openModal('Create your Wallet Password', `
    <p class="muted" style="margin-bottom:14px;font-size:13px;line-height:1.55">Your wallet is private and belongs only to you. Choose a <b>Wallet Password</b> now. You will enter it every time you open your wallet. Nobody else knows it, not even the admin, and nobody else can open your wallet.</p>
    <label class="fld"><span>NEW WALLET PASSWORD</span><input type="password" id="wsP1" autocomplete="new-password" autocapitalize="off" spellcheck="false"></label>
    <div class="meter-s"><i id="wsMeter"></i></div>
    <label class="fld"><span>CONFIRM WALLET PASSWORD</span><input type="password" id="wsP2" autocomplete="new-password" autocapitalize="off" spellcheck="false"></label>
    <p class="muted" style="font-size:12.5px;line-height:1.5;margin:-4px 0 8px">${WALLET_RULE_TEXT} <b>If you forget it, it cannot be recovered</b> — you could only erase the wallet and start again.</p>
    <p class="err" id="wsErr" role="alert"></p>
    <div class="btn-row"><button class="btn ghost" id="wsOut" type="button">Sign out</button><button class="btn" id="wsGo" type="button">Create wallet</button></div>`,
  root => {
    const p1 = $('#wsP1', root), p2 = $('#wsP2', root), err = $('#wsErr', root), go = $('#wsGo', root), m = $('#wsMeter', root);
    p1.addEventListener('input', () => { const s = strength(p1.value); m.style.width = s + '%'; m.style.background = s < 50 ? '#ff2a3d' : s < 75 ? '#ffb020' : '#2bff3f'; });
    $('#wsOut', root).onclick = () => signOut();
    const save = async () => {
      if (!walletRules(p1.value)) { err.textContent = WALLET_RULE_TEXT; return; }
      if (p1.value !== p2.value) { err.textContent = 'The Wallet Passwords do not match.'; return; }
      go.disabled = true; err.textContent = 'Creating your wallet…';
      try {
        const salt = newSalt(), key = await deriveWallet(p1.value, salt, WALLET_ITER);
        const ud = { alex_act: [{ t: 'sec', m: 'Wallet created', ts: Date.now(), src: 'Wallet' }] };
        const blob = await encryptWallet(JSON.stringify(ud), key, WALLET_ITER);
        await api('PUT', '/api/vault', { salt, blob });
        closeModal(true); enterWallet(ud, key, salt, blob);
      } catch (e) { err.textContent = e.message || 'Could not create the wallet.'; go.disabled = false; }
    };
    go.onclick = save; p2.addEventListener('keydown', e => { if (e.key === 'Enter') save(); }); p1.focus();
  }, { locked: true });
}
function showUnlock() {
  openModal('Unlock your wallet', `
    <p class="muted" style="margin-bottom:14px;font-size:13px">Enter your Wallet Password to open your wallet.</p>
    <label class="fld"><span>WALLET PASSWORD</span><div class="inl"><input type="password" id="wuPw" autocomplete="off" autocapitalize="off" spellcheck="false"><button class="btn ghost" id="wuEye" type="button">Show</button></div></label>
    <p class="err" id="wuErr" role="alert"></p>
    <div class="btn-row"><button class="btn ghost" id="wuOut" type="button">Sign out</button><button class="btn" id="wuGo" type="button">Unlock</button></div>
    <p style="margin-top:16px;text-align:center"><button class="clink" id="wuForgot" type="button" style="color:var(--g2);font-size:13.5px;text-decoration:underline">Forgot your Wallet Password?</button></p>`,
  root => {
    const pw = $('#wuPw', root), err = $('#wuErr', root), go = $('#wuGo', root);
    $('#wuEye', root).onclick = e => { const s = pw.type === 'password'; pw.type = s ? 'text' : 'password'; e.target.textContent = s ? 'Hide' : 'Show'; };
    $('#wuOut', root).onclick = () => signOut(); $('#wuForgot', root).onclick = showForgot;
    const unlock = async () => {
      if (Date.now() < wLockUntil) { err.textContent = `Too many wrong tries. Wait ${Math.ceil((wLockUntil - Date.now()) / 1000)} seconds.`; return; }
      if (!pw.value) { err.textContent = 'Enter your Wallet Password.'; return; }
      go.disabled = true; err.textContent = 'Opening…';
      try {
        const blob = sessionStorage.getItem('alex_wblob'), salt = sessionStorage.getItem('alex_wsalt'), iter = JSON.parse(blob).iter || WALLET_ITER;
        const key = await deriveWallet(pw.value, salt, iter);
        let ud; try { ud = JSON.parse(await decryptWallet(blob, key)); } catch { ud = null; }
        if (!ud) {
          wFails++; pw.value = ''; pw.focus(); go.disabled = false;
          if (wFails >= 5) { wFails = 0; wLockUntil = Date.now() + 30000; err.textContent = 'Too many wrong tries. Wait 30 seconds.'; }
          else err.textContent = `Wrong Wallet Password. ${5 - wFails} tries left.`;
          return;
        }
        ud.alex_act = [{ t: 'unlock', m: 'Wallet unlocked', ts: Date.now(), src: BROWSER }, ...(ud.alex_act || [])].slice(0, 200);
        sessionStorage.setItem('alex_dirty', '1');             // saves that log line on the next page
        closeModal(true); enterWallet(ud, key, salt, blob);
      } catch (e) { err.textContent = 'Could not open the wallet.'; go.disabled = false; }
    };
    go.onclick = unlock; pw.addEventListener('keydown', e => { if (e.key === 'Enter') unlock(); }); pw.focus();
  }, { locked: true });
}
function showForgot() {
  openModal('Forgot your Wallet Password?', `
    <p style="margin-bottom:12px;line-height:1.55;font-size:14px">A Wallet Password cannot be recovered, because it is the only key to your wallet. You can <b>erase your wallet and start again</b> with a new Wallet Password. Everything saved in it is deleted.</p>
    <label class="fld"><span>TYPE  ERASE  TO CONFIRM</span><input type="text" id="wfWord" autocomplete="off" autocapitalize="characters" spellcheck="false"></label>
    <p class="err" id="wfErr" role="alert"></p>
    <div class="btn-row"><button class="btn ghost" id="wfNo" type="button">Back</button><button class="btn danger" id="wfGo" type="button">Erase and start again</button></div>`,
  root => {
    const err = $('#wfErr', root), go = $('#wfGo', root);
    $('#wfNo', root).onclick = showUnlock;
    go.onclick = async () => {
      if ($('#wfWord', root).value.trim().toUpperCase() !== 'ERASE') { err.textContent = 'Type ERASE to confirm.'; return; }
      go.disabled = true;
      try { await api('DELETE', '/api/vault'); sessionStorage.removeItem('alex_wblob'); sessionStorage.removeItem('alex_wsalt'); showSetup(); }
      catch (e) { err.textContent = e.message || 'Could not erase the wallet.'; go.disabled = false; }
    };
  }, { locked: true });
}

/* ================= start-up ================= */
if (WALLET_OPEN) { const gone = purgeTrash(); if (gone) log('del', `${gone} item${gone === 1 ? '' : 's'} removed from the Recycle Bin after ${TRASH_DAYS} days`); }
if (WALLET_OPEN && !sessionStorage.getItem('alex_counted')) {
  sessionStorage.setItem('alex_counted', '1');
  touch(); log('login', 'Signed in as ' + (sess.user || 'user'));
}
applyPrefs(); renderOnline(); renderLockBtn(); ping();
if (!WALLET_OPEN) walletGate();
setInterval(() => { syncLock(); tickClock(); renderLockBtn(); emit('tick'); }, 1000);
setInterval(ping, 8000);

window.ALEX = { $, $$, pad, esc, store, DAY, ico, paintIcons, gen, SETS, strength, sha256, on, emit, S, NAME, CATS, calcScore, toast, log, rel, ACT_ICON,
  openModal, closeModal, openFloat, copyText, touch, fmtLast, getLast: () => lastTs, isLocked, timeLeft, setLock, requireUnlock, toggleLock, lockWallet, verifyWallet, changeWallet, walletRules, WALLET_RULE_TEXT, openAutoLock,
  openEntry, confirmDelete, saveVault, saveTrash, get AL() { return AL; },
  setAL, getAge: () => AGE, setAge, getReveal: () => REVEAL, setReveal, getClip: () => CLIP, setClip, sess, signOut, PREFS, setPref, resetPrefs, setName, setTheme, fmtHM, renderBadge, BROWSER, TRASH_DAYS, purgeTrash, CRYPTO_OK, DEFAULT_NAME, changePasskey, newSalt, flushNow, api, deriveBits };
emit('ready');
})();
