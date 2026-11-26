(() => {
'use strict';
/* Security page — uses the shared core (core.js). */
const A = window.ALEX;
const { $, $$, esc, ico, S, on, toast, log, rel, openModal, closeModal, requireUnlock, openEntry, strength, sha256, calcScore, DAY } = A;
const me = A.sess || {};

/* =============== users (stored on the server; only the admin 'angel' manages them) =============== */
const isAdmin = () => me.role === 'admin';
const isMe = u => u.name === String(me.user || '').toLowerCase();
let USERS = [];
const fmtDate = ts => new Date(ts).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });

/* =============== password audit =============== */
function audit() {
  const cnt = {}; S.vault.forEach(v => cnt[v.pass] = (cnt[v.pass] || 0) + 1);
  const age = A.getAge();
  return S.vault.map(v => {
    const issues = [], days = Math.floor((Date.now() - (v.updated || v.created)) / DAY);
    if (strength(v.pass) < 60) issues.push(['tg-w', 'Weak']);
    if (cnt[v.pass] > 1) issues.push(['tg-r', 'Reused']);
    if (age && days > age) issues.push(['tg-o', days + ' days old']);
    return { v, issues };
  });
}
const CIRC = 2 * Math.PI * 58;
function renderOverview() {
  const rows = audit(), score = calcScore(), age = A.getAge();
  const weak = rows.filter(r => r.issues.some(i => i[1] === 'Weak')).length;
  const reused = rows.filter(r => r.issues.some(i => i[1] === 'Reused')).length;
  const old = rows.filter(r => r.issues.some(i => i[0] === 'tg-o')).length;
  const strong = rows.length - weak;

  const cls = score < 50 ? 'bad' : score < 75 ? 'warn' : '';
  $('#gScore').textContent = score;
  $('#gArc').style.strokeDashoffset = (CIRC * (1 - score / 100)).toFixed(1); $('#gArc').setAttribute('class', 'gv ' + cls);
  $('#gLabel').textContent = score >= 90 ? 'Excellent' : score >= 75 ? 'Good' : score >= 50 ? 'Needs attention' : 'At risk'; $('#gLabel').className = 'glabel ' + cls;
  const issues = rows.filter(r => r.issues.length).length;
  $('#gNote').textContent = !rows.length ? 'Your vault is empty. Add a password to get a score.' : issues ? `${issues} of ${rows.length} passwords need attention.` : `All ${rows.length} passwords look healthy.`;

  const tile = (id, n, lvl) => { $('#' + id).textContent = n; $('#' + id).closest('.tile').className = 'card tile ' + (n ? lvl : ''); };
  tile('tWeak', weak, 'bad'); tile('tReused', reused, 'warn'); tile('tOld', old, 'warn');
  $('#tStrong').textContent = strong;
  $('#tOldL').textContent = age ? `Older than ${age} days` : 'Old passwords (check is off)';

}
/* =============== settings =============== */
function loadSettings() {
  $('#sAuto').value = A.AL.mins; $('#sHide').checked = !!A.AL.hide;
  $('#sAge').value = A.getAge(); $('#sReveal').value = A.getReveal(); $('#sClip').checked = A.getClip();
}
$('#sAuto').onchange = e => { A.setAL({ mins: +e.target.value }); toast('Auto-lock set to ' + e.target.value + ' min'); };
$('#sHide').onchange = e => { A.setAL({ hide: e.target.checked }); toast(e.target.checked ? 'Will lock when you leave the app' : 'Leaving the app no longer locks'); };
$('#sAge').onchange = e => { A.setAge(+e.target.value); toast(+e.target.value ? 'Old-password warning: ' + e.target.value + ' days' : 'Old-password warning turned off'); };
$('#sReveal').onchange = e => { A.setReveal(+e.target.value); toast('Passwords hide after ' + e.target.value + ' s'); };
$('#sClip').onchange = e => { A.setClip(e.target.checked); toast(e.target.checked ? 'Clipboard will be cleared after 30 s' : 'Clipboard clearing off'); };

/* meter helper for passkey forms */
const meterBind = (pw, m) => { const f = () => { const s = strength(pw.value); m.style.width = s + '%'; m.style.background = s < 50 ? '#ff2a3d' : s < 75 ? '#ffb020' : '#2bff3f'; }; pw.addEventListener('input', f); f(); };

$('#sPass').onclick = () => openModal('Change Wallet Password', `
  <p class="muted" style="margin-bottom:14px;font-size:13px;line-height:1.5">Your Wallet Password is the only key to your wallet. Nobody can recover it for you, so choose one you will remember.</p>
  <label class="fld"><span>CURRENT WALLET PASSWORD</span><input type="password" id="pkCur" autocomplete="current-password"></label>
  <label class="fld"><span>NEW WALLET PASSWORD</span><input type="password" id="pkNew" autocomplete="new-password"></label>
  <div class="meter-s"><i id="pkMeter"></i></div>
  <label class="fld"><span>CONFIRM NEW WALLET PASSWORD</span><input type="password" id="pkNew2" autocomplete="new-password"></label>
  <p class="muted" style="font-size:12.5px;margin:-4px 0 8px">${esc(A.WALLET_RULE_TEXT)}</p>
  <p class="err" id="pkErr" role="alert"></p>
  <div class="btn-row"><button class="btn ghost" id="pkNo" type="button">Cancel</button><button class="btn" id="pkGo" type="button">Change password</button></div>`,
root => {
  const cur = $('#pkCur', root), n1 = $('#pkNew', root), n2 = $('#pkNew2', root), err = $('#pkErr', root), go = $('#pkGo', root);
  meterBind(n1, $('#pkMeter', root)); $('#pkNo', root).onclick = closeModal; cur.focus();
  go.onclick = async () => {
    if (!cur.value) { err.textContent = 'Enter your current Wallet Password.'; return; }
    if (!A.walletRules(n1.value)) { err.textContent = A.WALLET_RULE_TEXT; return; }
    if (n1.value === cur.value) { err.textContent = 'Choose a password that is different from the current one.'; return; }
    if (n1.value !== n2.value) { err.textContent = 'The new passwords do not match.'; return; }
    go.disabled = true; err.textContent = 'Saving…';
    try { await A.changeWallet(cur.value, n1.value); log('sec', 'Wallet Password changed'); closeModal(); toast('Wallet Password changed'); }
    catch (e) { err.textContent = e.message || 'Could not change the password.'; go.disabled = false; }
  };
});

/* =============== manage users =============== */
async function loadUsers() {
  try { USERS = (await A.api('GET', '/api/users')).users; } catch (e) { if (e.status !== 401) toast('Could not load the user list'); }
  renderUsers();
}
function renderUsers() {
  const admin = isAdmin();
  $('#xAddUser').hidden = !admin;
  $('#users').innerHTML = USERS.map(u => `<div class="urow" data-n="${esc(u.name)}">
    <div><b>${esc(u.name)}${isMe(u) ? ' (you)' : ''}</b><small>${u.role === 'admin' ? 'Admin · ' : ''}Created ${fmtDate(u.created)}${!u.wallet_set && !isMe(u) ? ' · No wallet created yet' : ''}</small></div>
    <div class="uact">${admin || isMe(u) ? `<button class="sb" data-a="reset"><span data-i="key"></span>Reset passkey</button>` : ''}${admin && !isMe(u) ? `<button class="sb danger" data-a="rm"><span data-i="trashline"></span>Remove</button>` : ''}</div></div>`).join('')
    + (admin ? '' : '<p class="unote">Only the admin (angel) can add or remove users. You can reset your own passkey.</p>');
  A.paintIcons($('#users'));
}
const nextId = () => { for (let i = 1; i < 100; i++) { const n = 'user' + String(i).padStart(2, '0'); if (!USERS.some(u => u.name === n)) return n; } return ''; };
const tempPass = () => A.gen(12, { lower: 1, upper: 1, num: 1, skip: true });
function shareModal(title, name, pass) {
  const text = `ALEX SHADOW OS\nSign-in page: ${location.origin}/\nUser ID: ${name}\nSign-in passkey: ${pass}\nAfter you sign in you will be asked to create your own Wallet Password. Only you will know it.`;
  openModal(title, `<p class="muted" style="margin-bottom:12px;font-size:13px;line-height:1.5">Send this to your friend. The sign-in passkey is shown only now. After signing in they create their own Wallet Password, which only they will know, so you can never open their wallet.</p>
    <pre class="share">${esc(text)}</pre>
    <div class="btn-row"><button class="btn ghost" id="shCopy" type="button">Copy</button><button class="btn" id="shDone" type="button">Done</button></div>`,
  root => {
    $('#shCopy', root).onclick = async () => toast(await A.copyText(text) ? 'Copied — send it to your friend' : 'Copy failed');
    $('#shDone', root).onclick = closeModal;
  });
}
$('#xAddUser').onclick = () => openModal('Add user', `
  <p class="muted" style="margin-bottom:14px;font-size:13px;line-height:1.5">You give each friend a <b>User ID and a sign-in passkey</b>. After signing in, they create their own <b>Wallet Password</b>, so their wallet stays private: nobody else can open it, not even you.</p>
  <label class="fld"><span>USER ID (3–20 LETTERS, NUMBERS, . _ -)</span><input type="text" id="auName" maxlength="20" autocomplete="off" autocapitalize="off" spellcheck="false" value="${nextId()}"></label>
  <label class="fld"><span>SIGN-IN PASSKEY</span><div class="inl"><input type="text" id="auPass" autocomplete="off" autocapitalize="off" spellcheck="false" value="${tempPass()}"><button class="btn ghost" id="auGen" type="button">New</button></div></label>
  <p class="err" id="auErr" role="alert"></p>
  <div class="btn-row"><button class="btn ghost" id="auNo" type="button">Cancel</button><button class="btn" id="auGo" type="button">Create user</button></div>`,
root => {
  const name = $('#auName', root), pw = $('#auPass', root), err = $('#auErr', root), go = $('#auGo', root);
  $('#auGen', root).onclick = () => { pw.value = tempPass(); }; $('#auNo', root).onclick = closeModal;
  go.onclick = async () => {
    const n = name.value.trim().toLowerCase();
    if (!/^[a-z0-9_.-]{3,20}$/.test(n)) { err.textContent = 'User ID must be 3–20 letters, numbers, dots, dashes or underscores.'; return; }
    if (n === 'angel' || USERS.some(u => u.name === n)) { err.textContent = 'That User ID is already taken.'; return; }
    if (pw.value.length < 8) { err.textContent = 'The sign-in passkey needs at least 8 characters.'; return; }
    go.disabled = true; err.textContent = 'Creating…';
    try {
      const salt = A.newSalt(), { auth } = await A.deriveBits(pw.value, salt);
      await A.api('POST', '/api/users', { name: n, salt, auth });
      log('user', 'User added - ' + n); await loadUsers(); shareModal('User created', n, pw.value);
    } catch (e) { err.textContent = e.message || 'Could not create the user.'; go.disabled = false; }
  };
});
$('#users').addEventListener('click', e => {
  const b = e.target.closest('[data-a]'); if (!b) return;
  const user = USERS.find(u => u.name === b.closest('.urow').dataset.n); if (!user) return;
  if (b.dataset.a === 'reset') (isMe(user) ? resetOwn() : resetOther(user)); else removeUser(user);
});
function resetOwn() {
  openModal('Reset your sign-in passkey', `
    <p class="muted" style="margin-bottom:14px;font-size:13px;line-height:1.5">This is the passkey you sign in with. Your wallet keeps its own Wallet Password.</p>
    <label class="fld"><span>CURRENT PASSKEY</span><input type="password" id="rpCur" autocomplete="current-password"></label>
    <label class="fld"><span>NEW PASSKEY (8+ CHARACTERS)</span><input type="password" id="rpP1" autocomplete="new-password"></label>
    <div class="meter-s"><i id="rpMeter"></i></div>
    <label class="fld"><span>CONFIRM NEW PASSKEY</span><input type="password" id="rpP2" autocomplete="new-password"></label>
    <p class="err" id="rpErr" role="alert"></p>
    <div class="btn-row"><button class="btn ghost" id="rpNo" type="button">Cancel</button><button class="btn" id="rpGo" type="button">Reset passkey</button></div>`,
  root => {
    const cur = $('#rpCur', root), p1 = $('#rpP1', root), p2 = $('#rpP2', root), err = $('#rpErr', root), go = $('#rpGo', root);
    meterBind(p1, $('#rpMeter', root)); $('#rpNo', root).onclick = closeModal; cur.focus();
    go.onclick = async () => {
      if (!cur.value) { err.textContent = 'Enter your current passkey.'; return; }
      if (p1.value.length < 8) { err.textContent = 'The new passkey needs at least 8 characters.'; return; }
      if (p1.value !== p2.value) { err.textContent = 'The new passkeys do not match.'; return; }
      go.disabled = true; err.textContent = 'Saving…';
      try { await A.changePasskey(p1.value, { curPass: cur.value }); log('user', 'Sign-in passkey changed'); closeModal(); toast('Your sign-in passkey was changed'); }
      catch (e) { err.textContent = e.message || 'Could not change the passkey.'; go.disabled = false; }
    };
  });
}
function resetOther(user) {
  openModal('Reset passkey · ' + user.name, `
    <p class="muted" style="margin-bottom:14px;font-size:13px;line-height:1.5">This changes how ${esc(user.name)} signs in. Their wallet is <b>not</b> affected, and you still cannot read it.</p>
    <label class="fld"><span>NEW SIGN-IN PASSKEY</span><div class="inl"><input type="text" id="rpTmp" autocomplete="off" autocapitalize="off" spellcheck="false" value="${tempPass()}"><button class="btn ghost" id="rpGen" type="button">New</button></div></label>
    <p class="err" id="rpErr" role="alert"></p>
    <div class="btn-row"><button class="btn ghost" id="rpNo" type="button">Cancel</button><button class="btn" id="rpGo" type="button">Reset sign-in passkey</button></div>`,
  root => {
    const pw = $('#rpTmp', root), err = $('#rpErr', root), go = $('#rpGo', root);
    $('#rpGen', root).onclick = () => { pw.value = tempPass(); }; $('#rpNo', root).onclick = closeModal;
    go.onclick = async () => {
      if (pw.value.length < 8) { err.textContent = 'The sign-in passkey needs at least 8 characters.'; return; }
      go.disabled = true; err.textContent = 'Saving…';
      try {
        const salt = A.newSalt(), { auth } = await A.deriveBits(pw.value, salt);
        await A.api('POST', '/api/users/' + encodeURIComponent(user.name) + '/reset', { salt, auth });
        log('user', 'Sign-in passkey reset - ' + user.name); await loadUsers(); shareModal('Sign-in passkey reset', user.name, pw.value);
      } catch (e) { err.textContent = e.message || 'Could not reset the passkey.'; go.disabled = false; }
    };
  });
}
function removeUser(user) {
  openModal('Remove user', `<p style="margin-bottom:16px;line-height:1.5">Remove <b>${esc(user.name)}</b>? They will no longer be able to sign in, and their wallet is deleted.</p>
    <div class="btn-row"><button class="btn ghost" id="ruNo" type="button">Cancel</button><button class="btn danger" id="ruYes" type="button">Remove</button></div>`,
  root => {
    $('#ruNo', root).onclick = closeModal;
    $('#ruYes', root).onclick = async () => {
      try { await A.api('DELETE', '/api/users/' + encodeURIComponent(user.name)); log('user', 'User removed - ' + user.name); closeModal(); await loadUsers(); toast(user.name + ' removed'); }
      catch (e) { toast(e.message || 'Could not remove the user'); }
    };
  });
}

/* =============== data =============== */
function download(name, text, mime) {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
$('#dExport').onclick = () => requireUnlock(() => {
  if (!S.vault.length) { toast('Nothing to export yet'); return; }
  openModal('Export vault', `<p style="margin-bottom:16px;line-height:1.5;font-size:14px">The backup contains all <b>${S.vault.length}</b> passwords in <b>plain text</b>. Keep it somewhere safe and delete it when you are done.</p>
    <div class="btn-row"><button class="btn ghost" id="exNo" type="button">Cancel</button><button class="btn" id="exGo" type="button">Download JSON</button></div>`,
  root => {
    $('#exNo', root).onclick = closeModal;
    $('#exGo', root).onclick = () => {
      const rows = S.vault.map(v => ({ name: v.name, username: v.user, password: v.pass, category: v.cat, created: new Date(v.created).toISOString() }));
      download(`alex-vault-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify({ app: 'ALEX SHADOW OS', exported: new Date().toISOString(), entries: rows }, null, 2), 'application/json');
      A.touch(); log('export', `Vault exported (JSON, ${rows.length})`); closeModal(); toast('Vault exported');
    };
  });
});
$('#dClear').onclick = () => openModal('Clear activity log', `<p style="margin-bottom:16px;line-height:1.5">Remove every entry from the Activity Log? This cannot be undone.</p>
  <div class="btn-row"><button class="btn ghost" id="clNo" type="button">Cancel</button><button class="btn danger" id="clYes" type="button">Clear log</button></div>`,
root => {
  $('#clNo', root).onclick = closeModal;
  $('#clYes', root).onclick = () => { S.acts.length = 0; A.store.set('alex_act', S.acts); log('sec', 'Activity log cleared'); closeModal(); toast('Activity log cleared'); };
});
$('#dErase').onclick = () => openModal('Erase vault', `
  <p style="margin-bottom:14px;line-height:1.5;font-size:14px">This permanently deletes <b>all passwords, the Recycle Bin and the activity log</b> from your vault. It cannot be undone — export a backup first if you might need it.</p>
  <label class="fld"><span>TYPE  ERASE  TO CONFIRM</span><input type="text" id="erWord" autocomplete="off" autocapitalize="characters" spellcheck="false"></label>
  <label class="fld"><span>WALLET PASSWORD</span><input type="password" id="erPass" autocomplete="current-password"></label>
  <p class="err" id="erErr" role="alert"></p>
  <div class="btn-row"><button class="btn ghost" id="erNo" type="button">Cancel</button><button class="btn danger" id="erGo" type="button">Erase everything</button></div>`,
root => {
  const err = $('#erErr', root); $('#erNo', root).onclick = closeModal; $('#erWord', root).focus();
  $('#erGo', root).onclick = async () => {
    if ($('#erWord', root).value.trim().toUpperCase() !== 'ERASE') { err.textContent = 'Type ERASE to confirm.'; return; }
    if (!(await A.verifyWallet($('#erPass', root).value))) { err.textContent = 'Wrong Wallet Password.'; return; }
    const st = A.store;
    st.set('alex_vault', []); st.set('alex_trash', []); st.set('alex_act', []);
    ['alex_hist', 'alex_seen', 'alex_last_access'].forEach(k => st.del(k));
    st.set('alex_day', { date: new Date().toDateString(), base: 0, score: null });
    sessionStorage.removeItem('alex_deadline');
    toast('Vault erased'); setTimeout(() => { location.href = 'dashboard.html'; }, 700);
  };
});

/* =============== private vault status =============== */
$('#pvState').textContent = 'Encrypted';

/* =============== start =============== */
function renderAll() { renderOverview(); loadUsers(); loadSettings(); }
renderAll();
on('vault', renderOverview);
})();
