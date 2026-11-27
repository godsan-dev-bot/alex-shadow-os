(() => {
'use strict';
/* Settings page — every change is saved the moment you make it. Uses the shared core (core.js). */
const A = window.ALEX;
const { $, $$, store, toast, openModal, closeModal, CATS, PREFS } = A;
const me = A.sess || {};
const saved = () => toast('Saved');

/* ---------- fill the controls ---------- */
$('#pCat').innerHTML = CATS.map(c => `<option>${c}</option>`).join('');
$('#pName').value = A.NAME;
(() => { $('#pUser').textContent = (me.user || '—') + (me.role === 'admin' ? ' · Admin' : ''); })();      // username + role
function load() {
  $$('[data-pref]').forEach(el => {
    const v = PREFS[el.dataset.pref];
    if (el.type === 'checkbox') el.checked = !!v; else el.value = String(v);
  });
  $('#aTheme').value = document.documentElement.dataset.theme || 'dark';
  $('#pLen').value = String((store.get('alex_gen', {}) || {}).len || 16);
}
load();

/* ---------- generic preferences ---------- */
$$('[data-pref]').forEach(el => el.addEventListener('change', () => {
  const k = el.dataset.pref, t = el.dataset.type;
  let v = el.type === 'checkbox' ? el.checked : el.value;
  if (t === 'num') v = +v; if (t === 'bool-str') v = v === 'true';
  A.setPref(k, v); saved();
}));

/* ---------- special ones ---------- */
$('#aTheme').addEventListener('change', e => { A.setTheme(e.target.value); saved(); });
$('#pLen').addEventListener('change', e => {
  const g = Object.assign({}, store.get('alex_gen', {}) || {}); g.len = +e.target.value; store.set('alex_gen', g); saved();
});
let nameT;
$('#pName').addEventListener('input', e => {
  clearTimeout(nameT);
  nameT = setTimeout(() => {
    const n = e.target.value.trim();
    if (!n) return;                                          // keep the old name until something is typed
    A.setName(n); saved();
  }, 500);
});
$('#pName').addEventListener('blur', e => { if (!e.target.value.trim()) e.target.value = store.get('alex_display_name', A.NAME); });

/* ---------- reset ---------- */
$('#rReset').onclick = () => openModal('Reset settings', `
  <p style="margin-bottom:16px;line-height:1.5">Put every setting on this page back to its default? Your passwords, users and security settings are not changed.</p>
  <div class="btn-row"><button class="btn ghost" id="rsNo" type="button">Cancel</button><button class="btn danger" id="rsYes" type="button">Reset</button></div>`,
root => {
  $('#rsNo', root).onclick = closeModal;
  $('#rsYes', root).onclick = () => {
    A.resetPrefs();
    const g = Object.assign({}, store.get('alex_gen', {}) || {}); g.len = 16; store.set('alex_gen', g);
    A.setName(A.DEFAULT_NAME); $('#pName').value = A.DEFAULT_NAME;
    closeModal(); load(); toast('Settings reset to defaults');
  };
});
})();
