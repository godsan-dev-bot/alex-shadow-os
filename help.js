(() => {
'use strict';
/* Help & Support page — uses the shared core (core.js). */
const A = window.ALEX;
const EMAIL = 'godawmsensation@gmail.com';

/* some phones have no mail app, so offer a plain copy button too */
document.getElementById('cCopy').addEventListener('click', async () => {
  const ok = await A.copyText(EMAIL);
  A.toast(ok ? 'Email address copied' : 'Copy failed — ' + EMAIL);
});
})();
