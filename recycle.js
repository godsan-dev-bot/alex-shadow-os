(() => {
'use strict';
/* Recycle Bin page — uses the shared core (core.js). Deleted passwords wait here and are removed for good after 30 days. */
const A = window.ALEX;
const { $, esc, ico, S, on, toast, log, openModal, closeModal, touch, DAY } = A;
const DAYS = A.TRASH_DAYS;

const plural = (n, w) => n + ' ' + w + (n === 1 ? '' : 's');
function ago(ts) {
  const s = Math.max(0, (Date.now() - ts) / 1000);
  if (s < 45) return 'just now';
  if (s < 3600) return plural(Math.max(1, Math.round(s / 60)), 'min') + ' ago';
  if (s < 86400) return plural(Math.round(s / 3600), 'hour') + ' ago';
  return plural(Math.round(s / 86400), 'day') + ' ago';
}
function timeLeft(t) {
  const left = t.deleted + DAYS * DAY - Date.now();
  const days = Math.floor(left / DAY);
  return { txt: days >= 1 ? plural(days, 'day') : plural(Math.max(1, Math.ceil(left / 36e5)), 'hour'), soon: left < 3 * DAY };
}

function render() {
  A.purgeTrash();
  const list = [...S.trash].sort((a, b) => b.deleted - a.deleted), n = list.length;
  $('#rCount').textContent = `${n} deleted password${n === 1 ? '' : 's'}. Items are removed for good after ${DAYS} days.`;
  $('#rEmpty').disabled = !n; $('#rRestoreAll').disabled = !n;
  $('#rBox').innerHTML = n ? list.map(t => {
    const l = timeLeft(t);
    return `<div class="rrow" data-id="${esc(t.id)}">
      <span class="rav">${esc(t.name[0].toUpperCase())}</span>
      <div class="rinfo"><b>${esc(t.name)}</b><small>${esc(t.user)} · deleted ${ago(t.deleted)} · <span class="${l.soon ? 'soon' : ''}">Deleted automatically in ${l.txt}</span></small></div>
      <button class="rrest" data-a="restore"><span data-i="refresh"></span>Restore</button>
      <button class="rx ib" data-a="forever" aria-label="Delete forever">${ico('x')}</button>
    </div>`;
  }).join('') : `<div class="rempty"><span data-i="trash"></span><b>The Recycle Bin is empty</b><span>Passwords you delete wait here for ${DAYS} days before they are removed for good.</span></div>`;
  A.paintIcons($('#rBox'));
}

function restore(t) {
  S.trash = S.trash.filter(x => x.id !== t.id);
  const e = { ...t }; delete e.deleted; e.updated = e.updated || Date.now();
  S.vault.unshift(e);
  A.saveTrash(); touch(); log('add', 'Password restored - ' + e.name); A.saveVault();
}
$('#rBox').addEventListener('click', ev => {
  const b = ev.target.closest('[data-a]'); if (!b) return;
  const t = S.trash.find(x => x.id === b.closest('.rrow').dataset.id); if (!t) return;
  if (b.dataset.a === 'restore') { restore(t); render(); toast(t.name + ' restored to your vault'); }
  else openModal('Delete forever', `<p style="margin-bottom:16px;line-height:1.5">Permanently delete <b>${esc(t.name)}</b>? This cannot be undone.</p>
    <div class="btn-row"><button class="btn ghost" id="dfNo" type="button">Cancel</button><button class="btn danger" id="dfYes" type="button">Delete forever</button></div>`,
  root => {
    $('#dfNo', root).onclick = closeModal;
    $('#dfYes', root).onclick = () => { S.trash = S.trash.filter(x => x.id !== t.id); A.saveTrash(); log('del', 'Password permanently deleted - ' + t.name); closeModal(); render(); toast(t.name + ' deleted forever'); };
  });
});
$('#rRestoreAll').onclick = () => {
  const items = [...S.trash]; if (!items.length) return;
  items.forEach(t => { const e = { ...t }; delete e.deleted; e.updated = e.updated || Date.now(); S.vault.unshift(e); });
  S.trash = []; A.saveTrash(); touch(); log('add', `Restored ${plural(items.length, 'password')} from the Recycle Bin`); A.saveVault(); render();
  toast(plural(items.length, 'password') + ' restored');
};
$('#rEmpty').onclick = () => {
  const n = S.trash.length; if (!n) return;
  openModal('Empty Trash', `<p style="margin-bottom:16px;line-height:1.5">Permanently delete all <b>${plural(n, 'password')}</b> in the Recycle Bin? This cannot be undone.</p>
    <div class="btn-row"><button class="btn ghost" id="etNo" type="button">Cancel</button><button class="btn danger" id="etYes" type="button">Empty Trash</button></div>`,
  root => {
    $('#etNo', root).onclick = closeModal;
    $('#etYes', root).onclick = () => { S.trash = []; A.saveTrash(); log('del', `Recycle Bin emptied (${plural(n, 'password')})`); closeModal(); render(); toast('Recycle Bin emptied'); };
  });
};

render();
on('vault', render);
setInterval(render, 60000);              // keeps "deleted x ago" and the countdown fresh
})();
