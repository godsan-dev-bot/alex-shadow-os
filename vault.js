(() => {
'use strict';
/* My Vault page — uses the shared core (core.js). */
const A = window.ALEX;
const { $, $$, esc, ico, S, CATS, on, toast, log, copyText, openModal, closeModal, strength, requireUnlock, touch, openEntry, confirmDelete, saveVault } = A;

const PER_PAGE = A.PREFS.perPage || 8;
const st = { q: '', type: 'all', cat: 'all', sort: 'new', page: 1 };
let revealed = null, revealTimer = null;

/* filters */
$('#fCat').innerHTML = '<option value="all">All categories</option>' + CATS.map(c => `<option>${c}</option>`).join('');

function reusedSet() {
  const cnt = {}; S.vault.forEach(v => cnt[v.pass] = (cnt[v.pass] || 0) + 1);
  return new Set(S.vault.filter(v => cnt[v.pass] > 1).map(v => v.id));
}
function view() {
  const reused = reusedSet(), q = st.q.toLowerCase();
  let list = S.vault.filter(v => {
    if (q && !(v.name.toLowerCase().includes(q) || v.user.toLowerCase().includes(q) || v.cat.toLowerCase().includes(q))) return false;
    if (st.cat !== 'all' && v.cat !== st.cat) return false;
    const weak = strength(v.pass) < 60;
    if (st.type === 'weak' && !weak) return false;
    if (st.type === 'strong' && weak) return false;
    if (st.type === 'reused' && !reused.has(v.id)) return false;
    return true;
  });
  const by = {
    new: (a, b) => b.created - a.created, old: (a, b) => a.created - b.created,
    az: (a, b) => a.name.localeCompare(b.name), za: (a, b) => b.name.localeCompare(a.name),
    weak: (a, b) => strength(a.pass) - strength(b.pass)
  }[st.sort];
  return { list: list.sort(by), reused };
}

function render() {
  const { list, reused } = view();
  const total = list.length, pages = Math.max(1, Math.ceil(total / PER_PAGE));
  st.page = Math.min(st.page, pages);
  const start = (st.page - 1) * PER_PAGE, slice = list.slice(start, start + PER_PAGE);
  const locked = A.isLocked();

  $('#vCount').textContent = `${S.vault.length} password${S.vault.length === 1 ? '' : 's'} stored`;
  $('#vrows').innerHTML = slice.length ? slice.map(v => {
    const show = revealed === v.id && !locked;
    return `<div class="vrow" data-id="${v.id}">
      <span class="vav">${esc(v.name[0].toUpperCase())}</span>
      <div class="vinfo"><b><span>${esc(v.name)}</span>${strength(v.pass) < 60 ? '<em class="tagw">Weak</em>' : ''}${reused.has(v.id) ? '<em class="tagr">Reused</em>' : ''}</b><small>${esc(v.user)}<span class="cm"> · ${esc(v.cat)}</span></small></div>
      <span class="vpw ${show ? 'show' : ''}">${show ? esc(v.pass) : '• • • • • • • • •'}</span>
      <div class="vact"><button class="ib" data-a="eye" aria-label="${show ? 'Hide' : 'Show'} password">${ico(show ? 'eyeoff' : 'eye')}</button><button class="ib" data-a="copy" aria-label="Copy password">${ico('copy')}</button></div>
      <span class="vcat"><span class="pill">${esc(v.cat)}</span></span>
      <div class="vact"><button class="ib" data-a="edit" aria-label="Edit">${ico('edit')}</button><button class="ib del" data-a="del" aria-label="Delete">${ico('trashline')}</button></div>
    </div>`;
  }).join('') : `<p class="vempty">${S.vault.length ? 'No passwords match your filters.' : 'Your vault is empty. Tap “Add Password” to save your first one.'}</p>`;

  $('#vShow').textContent = total ? `Showing ${start + 1}-${start + slice.length} of ${total} entr${total === 1 ? 'y' : 'ies'}` : 'No entries';
  let pg = `<button data-p="${st.page - 1}" ${st.page === 1 ? 'disabled' : ''} aria-label="Previous page">${ico('chevl')}</button>`;
  for (let i = 1; i <= pages; i++) pg += `<button data-p="${i}" class="${i === st.page ? 'on' : ''}">${i}</button>`;
  pg += `<button data-p="${st.page + 1}" ${st.page === pages ? 'disabled' : ''} aria-label="Next page">${ico('chevr')}</button>`;
  $('#pager').innerHTML = pg;
}

/* row actions */
$('#vrows').addEventListener('click', e => {
  const b = e.target.closest('.ib'); if (!b) return;
  const id = b.closest('.vrow').dataset.id, v = S.vault.find(x => x.id === id); if (!v) return;
  const a = b.dataset.a;
  if (a === 'del') return confirmDelete(v);
  requireUnlock(async () => {
    if (a === 'eye') {
      revealed = revealed === id ? null : id; clearTimeout(revealTimer); touch();
      if (revealed) revealTimer = setTimeout(() => { revealed = null; render(); }, A.getReveal() * 1000);
      render();
    } else if (a === 'copy') {
      const ok = await copyText(v.pass); if (ok) { touch(); log('copy', 'Password copied - ' + v.name); }
      toast(ok ? 'Password copied' : 'Copy failed');
    } else if (a === 'edit') openEntry(v);
  });
});
$('#pager').addEventListener('click', e => { const b = e.target.closest('button'); if (!b || b.disabled) return; st.page = +b.dataset.p; render(); });
$('#vq').addEventListener('input', e => { st.q = e.target.value.trim(); st.page = 1; render(); });
[['fType', 'type'], ['fCat', 'cat'], ['fSort', 'sort']].forEach(([id, k]) => $('#' + id).addEventListener('change', e => { st[k] = e.target.value; st.page = 1; render(); }));
$('#bAdd').onclick = () => openEntry();

/* ---------- export ---------- */
function download(name, text, mime) {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
const stamp = () => new Date().toISOString().slice(0, 10);
function doExport(kind) {
  const rows = S.vault.map(v => ({ name: v.name, username: v.user, password: v.pass, category: v.cat, created: new Date(v.created).toISOString() }));
  if (kind === 'json') download(`alex-vault-${stamp()}.json`, JSON.stringify({ app: 'ALEX SHADOW OS', exported: new Date().toISOString(), entries: rows }, null, 2), 'application/json');
  else {
    const q = s => '"' + String(s).replace(/"/g, '""') + '"', head = ['name', 'username', 'password', 'category', 'created'];
    download(`alex-vault-${stamp()}.csv`, [head.join(','), ...rows.map(r => head.map(h => q(r[h])).join(','))].join('\n'), 'text/csv');
  }
  touch(); log('export', `Vault exported (${kind.toUpperCase()}, ${rows.length})`); toast('Vault exported');
}
$('#bExp').onclick = () => requireUnlock(() => {
  if (!S.vault.length) { toast('Nothing to export yet'); return; }
  openModal('Export Vault', `
    <p style="margin-bottom:16px;line-height:1.5;font-size:14px">The file will contain all <b>${S.vault.length}</b> passwords in <b>plain text</b>. Keep it somewhere safe and delete it when you are done.</p>
    <div class="btn-row"><button class="btn" id="xJson" type="button">Download JSON</button><button class="btn ghost" id="xCsv" type="button">Download CSV</button></div>`,
  root => { $('#xJson', root).onclick = () => { closeModal(); doExport('json'); }; $('#xCsv', root).onclick = () => { closeModal(); doExport('csv'); }; });
});

/* ---------- import ---------- */
function parseCSV(t) {
  const rows = []; let row = [], cur = '', q = false;
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (q) { if (c === '"') { if (t[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
    else if (c === '"') q = true;
    else if (c === ',') { row.push(cur); cur = ''; }
    else if (c === '\n' || c === '\r') { if (c === '\r' && t[i + 1] === '\n') i++; row.push(cur); cur = ''; if (row.some(x => x !== '')) rows.push(row); row = []; }
    else cur += c;
  }
  row.push(cur); if (row.some(x => x !== '')) rows.push(row);
  const head = (rows.shift() || []).map(h => h.trim().toLowerCase());
  return rows.map(r => Object.fromEntries(head.map((h, i) => [h, r[i] || ''])));
}
function parseImport(text) {
  let arr;
  try { const j = JSON.parse(text); arr = Array.isArray(j) ? j : (j.entries || []); } catch { arr = parseCSV(text); }
  return arr.slice(0, 500).map(o => {
    const cat = o.category || o.cat;
    return { name: String(o.name || o.title || '').trim().slice(0, 40), user: String(o.username || o.user || o.email || '').trim().slice(0, 80), pass: String(o.password || o.pass || '').slice(0, 64), cat: CATS.includes(cat) ? cat : 'Personal' };
  }).filter(o => o.name && o.pass);
}
$('#bImp').onclick = () => $('#fileIn').click();
$('#fileIn').addEventListener('change', async e => {
  const f = e.target.files[0]; e.target.value = ''; if (!f) return;
  if (f.size > 1e6) { toast('File is too large (max 1 MB)'); return; }
  let items; try { items = parseImport(await f.text()); } catch { items = []; }
  if (!items.length) { toast('No passwords found in that file'); return; }
  const key = o => (o.name + '|' + o.user).toLowerCase(), have = new Set(S.vault.map(key));
  let added = 0;
  items.forEach(o => { if (have.has(key(o))) return; have.add(key(o)); S.vault.push({ id: 'v' + Date.now() + '_' + added, ...o, created: Date.now() - added, updated: Date.now() }); added++; });
  if (!added) { toast('Everything in that file is already in your vault'); return; }
  touch(); log('import', `Imported ${added} password${added === 1 ? '' : 's'}`); saveVault();
  toast(`Imported ${added}${items.length - added ? `, skipped ${items.length - added} duplicate${items.length - added === 1 ? '' : 's'}` : ''}`);
});

/* live updates */
on('vault', render);
on('lock', () => { revealed = null; clearTimeout(revealTimer); render(); });
render();
})();
