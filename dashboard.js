(() => {
'use strict';
/* Dashboard page — uses the shared core (core.js) for data, lock, modals and the shell. */
const A = window.ALEX;
const { $, $$, pad, esc, ico, store, S, on, rel, toast, log, copyText, openModal, closeModal, openFloat, strength, calcScore,
        isLocked, timeLeft, requireUnlock, toggleLock, touch, openEntry, confirmDelete, DAY, NAME, ACT_ICON } = A;

$('#wName').textContent = NAME;

/* ---------- day baseline + history (for the "+N" and the sparkline) ---------- */
const today = new Date().toDateString();
let day = store.get('alex_day', null);
if (!day || day.date !== today) day = { date: today, base: day ? S.vault.length : S.vault.length - 1, score: null };
let hist = store.get('alex_hist', null);
if (!hist) {
  const n = S.vault.length;
  hist = [...Array(13)].map((_, i) => Math.max(1, Math.round(n * (0.35 + 0.6 * i / 12))));
  hist.push(n);
}

/* ---------- charts ---------- */
function spark(svg, data) {
  const W = 240, H = 70, max = Math.max(...data), min = Math.min(...data) - 1;
  const pts = data.map((v, i) => [i / (data.length - 1) * W, H - 6 - (v - min) / (max - min || 1) * (H - 18)]);
  const line = pts.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ',' + p[1].toFixed(1)).join(' ');
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`); svg.setAttribute('preserveAspectRatio', 'none');
  svg.innerHTML = `<defs><linearGradient id="sg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#19e62e" stop-opacity=".55"/><stop offset="1" stop-color="#19e62e" stop-opacity="0"/></linearGradient></defs>
    <path d="${line} L${W},${H} L0,${H}Z" fill="url(#sg)"/>
    <path d="${line}" fill="none" stroke="#2bff3f" stroke-width="2" stroke-linejoin="round" vector-effect="non-scaling-stroke"/>`;
}
const wave = $('#wave'), wavePath = $('path', wave), waveDot = $('circle', wave);
let ph = 0;
const wy = (x, p) => 22 + 7 * Math.sin(x / 22 + p) + 4 * Math.sin(x / 9 - p * 1.6);
setInterval(() => {
  ph += .12; let d = '';
  for (let x = 0; x <= 300; x += 6) d += (x ? 'L' : 'M') + x + ',' + wy(x, ph).toFixed(1);
  wavePath.setAttribute('d', d); waveDot.setAttribute('cy', wy(75, ph).toFixed(1));
}, 70);

/* ---------- stat cards ---------- */
function renderStats() {
  const n = S.vault.length; $('#vTotal').textContent = n;
  const d = n - day.base;
  $('#vDelta').textContent = d > 0 ? `↑ +${d}` : d < 0 ? `↓ ${d}` : '→ 0';
  if (hist[hist.length - 1] !== n) { hist.push(n); hist = hist.slice(-14); store.set('alex_hist', hist); }
  spark($('#sparkPass'), hist);
  const s = calcScore(); if (day.score == null) day.score = s; store.set('alex_day', day);
  $('#vScore').textContent = s + '%';
  const ds = s - day.score;
  $('#sDelta').textContent = ds > 0 ? `↑ +${ds}%` : ds < 0 ? `↓ ${ds}%` : '→ 0%';
  const bar = $('#scoreBar'); bar.style.width = s + '%'; bar.className = s < 50 ? 'bad' : s < 75 ? 'warn' : '';
}
function renderLast() {
  $('#lastAccess').textContent = A.fmtLast(A.getLast());
  $('#uptime').textContent = 'Active ' + rel(A.getLast());
}
function renderStatus() {
  const locked = isLocked(), c = $('#cStatus'); c.classList.toggle('open', !locked);
  $('#stText').textContent = locked ? 'Locked' : 'Unlocked';
  const left = timeLeft();
  $('#stSub').textContent = locked ? 'Fully Protected' : `Locks in ${Math.floor(left / 60)}:${pad(left % 60)}`;
  const ic = ico(locked ? 'lock' : 'unlock');
  $('#stIco').innerHTML = ic; $('#stBig').innerHTML = ic;
}
$('#cStatus').addEventListener('click', toggleLock);
$('#cStatus').addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleLock(); } });

/* ---------- vault preview list ---------- */
const AVC = { Netflix:'#7a5a1e', Spotify:'#1f7a2e', Amazon:'#7a2a7a', Instagram:'#6a1f7a' };
const avColor = n => AVC[n] || `hsl(${[...n].reduce((a, c) => a + c.charCodeAt(0) * 7, 0) % 360},45%,32%)`;
let revealed = null, revealTimer = null;
function renderVault() {
  const q = $('#q').value.trim().toLowerCase();
  const list = S.vault.filter(v => !q || v.name.toLowerCase().includes(q) || v.user.toLowerCase().includes(q));
  const box = $('#vlist');
  if (!list.length) { box.innerHTML = `<p class="empty">${S.vault.length ? 'No matches for “' + esc(q) + '”.' : 'No passwords yet. Use Add Password to save your first one.'}</p>`; return; }
  box.innerHTML = list.map(v => {
    const show = revealed === v.id && !isLocked();
    return `<div class="row" data-id="${v.id}"><span class="av" style="background:${avColor(v.name)}">${esc(v.name[0].toUpperCase())}</span>
      <span class="nm" title="${esc(v.user)}">${esc(v.name)}</span>
      <span class="pw ${show ? 'show' : ''}">${show ? esc(v.pass) : '••••••••••'}</span>
      <button class="ib" data-a="eye" aria-label="${show ? 'Hide' : 'Show'} password">${ico(show ? 'eyeoff' : 'eye')}</button>
      <button class="ib" data-a="copy" aria-label="Copy password">${ico('copy')}</button>
      <button class="ib" data-a="more" aria-label="More options">${ico('dots')}</button></div>`;
  }).join('');
}
$('#vlist').addEventListener('click', e => {
  const b = e.target.closest('.ib'); if (!b) return;
  const id = b.closest('.row').dataset.id, v = S.vault.find(x => x.id === id); if (!v) return;
  const a = b.dataset.a;
  if (a === 'more') return openFloat(b, [
    { l:'Copy username', f: async () => { toast(await copyText(v.user) ? 'Username copied' : 'Copy failed'); } },
    { l:'Open in Vault', f: () => { location.href = 'vault.html'; } },
    { l:'Delete', cls:'danger', f: () => confirmDelete(v) }
  ]);
  requireUnlock(async () => {
    if (a === 'eye') {
      revealed = revealed === id ? null : id; clearTimeout(revealTimer); touch();
      if (revealed) revealTimer = setTimeout(() => { revealed = null; renderVault(); }, A.getReveal() * 1000);
      renderVault();
    } else if (a === 'copy') {
      const ok = await copyText(v.pass); if (ok) { touch(); log('copy', 'Password copied - ' + v.name); }
      toast(ok ? 'Password copied' : 'Copy failed');
    }
  });
});
$('#q').addEventListener('input', renderVault);

/* ---------- activity ---------- */
function renderActs() {
  $('#acts').innerHTML = S.acts.slice(0, 4).map(a =>
    `<li class="${a.ts > S.seen ? 'new' : ''}"><i class="dot"></i><span class="a-ic">${ico(ACT_ICON[a.t] || 'check')}</span><span class="a-m">${esc(a.m)}</span><span class="a-t">${rel(a.ts)}</span></li>`).join('');
}

/* ---------- quick actions ---------- */
$$('.q').forEach(b => b.addEventListener('click', () => ({ add: () => openEntry(), gen: () => { location.href = 'generator.html'; }, sec: () => { location.href = 'security.html'; } })[b.dataset.q]()));

/* ---------- render + live updates ---------- */
function renderAll() { renderVault(); renderStats(); renderActs(); renderStatus(); renderLast(); }
renderAll();
on('vault', renderAll);
on('acts', renderActs);
on('touch', renderLast);
on('lock', () => { revealed = null; clearTimeout(revealTimer); renderVault(); renderStatus(); });
on('tick', () => { renderStatus(); renderLast(); });
setInterval(() => { renderActs(); renderStats(); }, 15000);
})();
