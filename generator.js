(() => {
'use strict';
/* Generate page — uses the shared core (core.js). Passwords are made in this browser with crypto.getRandomValues; nothing is sent anywhere. */
const A = window.ALEX;
const { $, $$, esc, ico, store, toast, log, copyText, openEntry, gen, SETS, touch } = A;

const KEYS = ['lower', 'upper', 'num', 'sym'];
const cfg = Object.assign({ len: 16, lower: true, upper: true, num: true, sym: true, skip: false }, store.get('alex_gen', {}));
cfg.len = Math.min(64, Math.max(6, +cfg.len || 16));
let cur = '', hist = [];       // history lives in memory only (this tab, this session)

/* ---------- strength ---------- */
const poolSize = () => {
  const bad = cfg.skip ? '0O1lI' : '';
  return KEYS.filter(k => cfg[k]).map(k => [...SETS[k]].filter(c => !bad.includes(c)).join('')).join('').length;
};
const bits = () => cfg.len * Math.log2(poolSize() || 1);
function level(b) {
  if (b < 28) return ['Very weak', 'bad']; if (b < 40) return ['Weak', 'bad']; if (b < 60) return ['Fair', 'warn'];
  if (b < 80) return ['Strong', '']; return ['Very strong', ''];
}
function crackTime(b) {
  const s = Math.pow(2, b) / 2 / 1e10;                   // 10 billion guesses per second, half the space on average
  if (s < 1) return 'instantly';
  if (s < 60) return Math.round(s) + ' seconds';
  if (s < 3600) return Math.round(s / 60) + ' minutes';
  if (s < 86400) return Math.round(s / 3600) + ' hours';
  if (s < 3.15e7) return Math.round(s / 86400) + ' days';
  const y = s / 3.15e7;
  if (y < 1e3) return Math.round(y) + ' years';
  if (y < 1e6) return Math.round(y / 1e3) + ' thousand years';
  if (y < 1e9) return Math.round(y / 1e6) + ' million years';
  if (y < 1e12) return Math.round(y / 1e9) + ' billion years';
  return 'longer than the age of the universe';
}

/* ---------- rendering ---------- */
function renderMeta() {
  const b = bits(), [name, cls] = level(b);
  const bar = $('#gBar'); bar.style.width = Math.min(100, b) + '%'; bar.className = cls;
  $('#gTxt').innerHTML = `<b class="${cls}">${name}</b> · about ${Math.round(b)} bits of randomness`;
  $('#gCrack').textContent = `Estimated time to crack by brute force: ${crackTime(b)}.`;
}
function renderOptions() {
  $$('.tg input').forEach(i => i.checked = !!cfg[i.dataset.k]);
  $('#gRange').value = cfg.len; $('#gLen').textContent = cfg.len;
  $('#gRange').style.setProperty('--p', ((cfg.len - 6) / 58 * 100) + '%');
  $$('#gChips .chip').forEach(c => c.classList.toggle('on', +c.dataset.m === cfg.len));
}
function renderHist() {
  $('#gHist').innerHTML = hist.length ? hist.map((h, i) =>
    `<div class="hrow"><code>${esc(h.p)}</code><small>${A.rel(h.t)}</small><button class="ib" data-a="copy" data-i="${i}" aria-label="Copy">${ico('copy')}</button><button class="ib" data-a="save" data-i="${i}" aria-label="Save to vault">${ico('save')}</button></div>`).join('')
    : '<p class="hempty">Passwords you generate will appear here. They are kept in memory only and disappear when you close the tab.</p>';
}

/* ---------- generating ---------- */
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
let scr;
function make(remember) {
  if (remember && cur) { hist.unshift({ p: cur, t: Date.now() }); hist = hist.slice(0, 6); renderHist(); }
  cur = gen(cfg.len, { lower: cfg.lower, upper: cfg.upper, num: cfg.num, sym: cfg.sym, skip: cfg.skip });
  const out = $('#gOut'); clearInterval(scr);
  if (reduce) { out.textContent = cur; }
  else {                                                   // quick "decode" animation
    let n = 0; const target = cur, all = Object.values(SETS).join('');
    scr = setInterval(() => {
      n++;
      out.textContent = target.split('').map((ch, i) => i < n * target.length / 8 ? ch : all[Math.random() * all.length | 0]).join('');
      if (n >= 8) { clearInterval(scr); out.textContent = target; }
    }, 35);
  }
  renderMeta();
}
const spin = b => { b.classList.remove('spin'); void b.offsetWidth; b.classList.add('spin'); };

async function copyCur() {
  const ok = await copyText(cur);
  if (ok) { log('gen', 'Password generated'); const o = $('#gOut'); o.classList.remove('flash'); void o.offsetWidth; o.classList.add('flash'); }
  toast(ok ? 'Password copied' : 'Copy failed');
}

/* ---------- events ---------- */
$('#gRef').onclick = e => { spin(e.currentTarget); make(true); };
$('#gNew').onclick = () => { spin($('#gRef')); make(true); };
$('#gCopy').onclick = copyCur;
$('#gOut').onclick = copyCur;
$('#gOut').addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); copyCur(); } });
$('#gSave').onclick = () => { log('gen', 'Password generated'); openEntry(null, cur); };

$('#gHist').addEventListener('click', async e => {
  const b = e.target.closest('.ib'); if (!b) return; const h = hist[+b.dataset.i]; if (!h) return;
  if (b.dataset.a === 'copy') { const ok = await copyText(h.p); toast(ok ? 'Password copied' : 'Copy failed'); }
  else openEntry(null, h.p);
});

function changed() { store.set('alex_gen', cfg); renderOptions(); make(false); }
$('#gRange').addEventListener('input', e => { cfg.len = +e.target.value; changed(); });
$('#gChips').innerHTML = [8, 12, 16, 24, 32, 48].map(m => `<button type="button" class="chip" data-m="${m}">${m}</button>`).join('');
$('#gChips').addEventListener('click', e => { const c = e.target.closest('.chip'); if (!c) return; cfg.len = +c.dataset.m; changed(); });
$$('.tg input').forEach(i => i.addEventListener('change', () => {
  const k = i.dataset.k; cfg[k] = i.checked;
  if (KEYS.includes(k) && !KEYS.some(x => cfg[x])) { cfg[k] = true; toast('Keep at least one character type on'); }
  changed();
}));

/* ---------- start ---------- */
renderOptions(); renderHist(); make(false);
setInterval(renderHist, 15000);
})();
