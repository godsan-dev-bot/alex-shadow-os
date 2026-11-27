(() => {
'use strict';
/* Activity Log page — uses the shared core (core.js). Every action in the app is recorded here and stays on this device. */
const A = window.ALEX;
const { $, $$, esc, ico, S, on, toast, log, openModal, closeModal, store } = A;

/* ---------- classify entries ---------- */
const CAT = { add: 'vault', edit: 'vault', del: 'vault', copy: 'vault', lock: 'vault', unlock: 'vault', export: 'backup', import: 'backup', login: 'session', out: 'session', gen: 'generator', sec: 'security', user: 'security' };
const catOf = a => /failed/i.test(a.m) ? 'security' : (CAT[a.t] || 'vault');
const ICON = { login: 'user', out: 'out', gen: 'dice', copy: 'copy', add: 'plus', edit: 'edit', del: 'trashline', lock: 'lock', unlock: 'unlock', export: 'download', import: 'upload', sec: 'shield', user: 'user' };
const SRC = { gen: 'Generator', sec: 'Security', user: 'Security', export: 'Vault', import: 'Vault' };       // for older entries that have no source saved
const srcOf = a => a.src || (a.t === 'login' || a.t === 'out' ? A.BROWSER : SRC[a.t] || 'Vault');
const FILTERS = [['all', 'All'], ['vault', 'Vault'], ['backup', 'Backup'], ['session', 'Session'], ['security', 'Security'], ['generator', 'Generator']];

const st = { cat: 'all', q: '', shown: 30 };

/* ---------- time helpers ---------- */
const plural = (n, w) => n + ' ' + w + (n === 1 ? '' : 's');
function ago(ts) {
  const s = Math.max(0, (Date.now() - ts) / 1000);
  if (s < 45) return 'just now';
  if (s < 3600) return plural(Math.max(1, Math.round(s / 60)), 'min') + ' ago';
  if (s < 86400) return plural(Math.round(s / 3600), 'hour') + ' ago';
  return plural(Math.round(s / 86400), 'day') + ' ago';
}
const dayStart = ts => new Date(ts).setHours(0, 0, 0, 0);
function groupName(ts) {
  const diff = Math.round((dayStart(Date.now()) - dayStart(ts)) / 864e5);
  if (diff <= 0) return 'TODAY';
  if (diff === 1) return 'YESTERDAY';
  return new Date(ts).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }).toUpperCase();
}

/* ---------- render ---------- */
function renderChips() {
  const counts = {}; S.acts.forEach(a => { const c = catOf(a); counts[c] = (counts[c] || 0) + 1; });
  $('#aChips').innerHTML = FILTERS.map(([k, l]) => `<button class="achip ${st.cat === k ? 'on' : ''}" role="tab" aria-selected="${st.cat === k}" data-c="${k}">${l}${k !== 'all' && counts[k] ? `<em>${counts[k]}</em>` : ''}</button>`).join('');
}
function render() {
  const q = st.q.toLowerCase();
  const all = S.acts, list = all.filter(a => (st.cat === 'all' || catOf(a) === st.cat) && (!q || a.m.toLowerCase().includes(q) || srcOf(a).toLowerCase().includes(q)));
  $('#aCount').textContent = `${all.length} event${all.length === 1 ? '' : 's'} recorded on this device`;
  renderChips();

  const slice = list.slice(0, st.shown); let last = '', html = '';
  slice.forEach(a => {
    const g = groupName(a.ts);
    if (g !== last) { html += `<div class="agroup">${esc(g)}</div>`; last = g; }
    const bad = /failed/i.test(a.m);
    html += `<div class="arow ${bad ? 'bad' : ''}"><span class="aic">${ico(bad ? 'shield' : ICON[a.t] || 'check')}</span>
      <div class="abody"><div class="am">${esc(a.m)}</div><div class="as">${esc(srcOf(a))}</div></div>
      <span class="at">${A.fmtHM(new Date(a.ts))} · ${ago(a.ts)}</span></div>`;
  });
  $('#aList').innerHTML = html || `<p class="aempty">${all.length ? 'No events match your filters.' : 'Nothing has been recorded yet.'}</p>`;
  const more = $('#aMore'); more.hidden = list.length <= st.shown; more.textContent = `Show more (${list.length - st.shown} left)`;
  $('#aClear').disabled = !all.length; $('#aClear').style.opacity = all.length ? '' : '.5';
}

/* ---------- events ---------- */
$('#aChips').addEventListener('click', e => { const b = e.target.closest('.achip'); if (!b) return; st.cat = b.dataset.c; st.shown = 30; render(); });
$('#aq').addEventListener('input', e => { st.q = e.target.value.trim(); st.shown = 30; render(); });
$('#aMore').onclick = () => { st.shown += 30; render(); };
$('#aClear').onclick = () => {
  if (!S.acts.length) return;
  openModal('Clear activity log', `<p style="margin-bottom:16px;line-height:1.5">Remove all <b>${S.acts.length}</b> events from the Activity Log? This cannot be undone.</p>
    <div class="btn-row"><button class="btn ghost" id="clNo" type="button">Cancel</button><button class="btn danger" id="clYes" type="button">Clear log</button></div>`,
  root => {
    $('#clNo', root).onclick = closeModal;
    $('#clYes', root).onclick = () => { S.acts.length = 0; store.set('alex_act', S.acts); log('sec', 'Activity log cleared'); closeModal(); toast('Activity log cleared'); };
  });
};

/* opening the log counts as reading the notifications */
S.seen = Date.now(); store.set('alex_seen', S.seen); A.renderBadge();

render();
on('acts', () => { S.seen = Date.now(); store.set('alex_seen', S.seen); A.renderBadge(); render(); });
on('prefs', render);                      // clock format may have changed
setInterval(render, 30000);               // keeps "x min ago" fresh
})();
