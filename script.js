(() => {
  'use strict';

  /* ===== sign in =====
     You sign in with the User ID and sign-in passkey the admin gave you. The passkey never leaves this browser: it is stretched
     (PBKDF2) and only the result is sent to prove who you are. Your wallet is a separate thing, locked with your own
     Wallet Password, which you enter on the dashboard after signing in. */
  const CRYPTO_OK = !!(window.crypto && crypto.subtle), PBKDF2_ITER = 150000;
  const OFFLINE_MSG = ALEX_BACKEND.mode === 'supabase' ? 'DATABASE NOT REACHABLE · CHECK config.js' : 'SERVER NOT REACHABLE · RUN server.py';
  const nextPage = () => 'dashboard.html';        // your start-page preference is inside your wallet and is applied once it is unlocked
  const MAX_TRIES = 5, LOCK_SECONDS = 30;
  const b64 = u8 => { let t = ''; for (let i = 0; i < u8.length; i += 8192) t += String.fromCharCode.apply(null, u8.subarray(i, i + 8192)); return btoa(t); };
  const unb64 = t => Uint8Array.from(atob(t), ch => ch.charCodeAt(0));
  const hex = u8 => [...u8].map(x => x.toString(16).padStart(2, '0')).join('');
  const sha256 = async t => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t))));
  async function deriveBits(pass, saltB64) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: unb64(saltB64), iterations: PBKDF2_ITER, hash: 'SHA-256' }, base, 512));
    return { enc: bits.slice(0, 32), auth: hex(bits.slice(32)) };
  }
  const call = (method, path, body) => ALEX_BACKEND.request(method, path, body);
  function openSession(res) {                     // keep only what the next page needs: who you are + your (still locked) wallet
    ['alex_ud', 'alex_key', 'alex_dirty', 'alex_deadline', 'alex_counted', 'alex_auth'].forEach(k => sessionStorage.removeItem(k));
    sessionStorage.setItem('alex_wblob', res.blob || '');          // '' = no wallet yet: the dashboard will ask for a new Wallet Password
    sessionStorage.setItem('alex_wsalt', res.wallet_salt || '');
    sessionStorage.setItem('alex_fresh', '1');
    sessionStorage.setItem('alex_session', JSON.stringify({ user: res.name, role: res.role, at: Date.now(), token: res.token, salt: res.salt }));
  }

  const $ = id => document.getElementById(id);
  const card = $('card'), stage = $('stage');

  /* ===== fit exact-size card to any screen ===== */
  function fit() {
    const s = Math.min(1, (innerWidth - 24) / 700, (innerHeight - 24) / 870);
    stage.style.setProperty('--s', s.toFixed(4));
  }
  addEventListener('resize', fit); addEventListener('orientationchange', fit); fit();

  /* ===== matrix rain ===== */
  const cv = $('rain'), cx = cv.getContext('2d');
  const chars = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEFXYZ'.split('');
  let cols, drops, size = 18;
  function initRain() {
    cv.width = innerWidth; cv.height = innerHeight;
    cols = Math.ceil(cv.width / (size * 1.6));
    drops = Array.from({ length: cols }, () => Math.random() * -50);
  }
  function rain() {
    cx.fillStyle = 'rgba(0,0,0,.1)'; cx.fillRect(0, 0, cv.width, cv.height);
    cx.font = size + 'px "Share Tech Mono", monospace';
    drops.forEach((y, i) => {
      const x = i * size * 1.6;
      cx.fillStyle = Math.random() > .96 ? '#b8ffc0' : 'rgba(0,255,26,.5)';
      cx.fillText(chars[Math.random() * chars.length | 0], x, y * size);
      drops[i] = (y * size > cv.height && Math.random() > .975) ? 0 : y + .5;
    });
  }
  addEventListener('resize', initRain); initRain(); setInterval(rain, 60);

  /* ===== biometric sync (live) + clock (live) ===== */
  const arc = $('ringArc'), bar = $('bioBar'), pctEl = $('bioPct');
  const CIRC = 270;
  let pct = 0, target = 94;

  function paint(v) {
    pctEl.textContent = Math.round(v) + '%';
    bar.style.width = v + '%';
    arc.style.strokeDashoffset = (CIRC * (1 - v / 100)).toFixed(1);
  }
  // first sync-up from 0 to ~94
  let boot = setInterval(() => {
    pct += (target - pct) * 0.12 + 0.4;
    if (pct >= target - 0.4) { pct = target; clearInterval(boot); startLive(); }
    paint(pct);
  }, 40);

  // then it keeps drifting like a real signal (88-99%)
  function startLive() {
    setInterval(() => {
      target = Math.min(99, Math.max(88, target + (Math.random() * 6 - 3)));
      pct = Math.round(target);
      paint(pct);
    }, 1400);
  }

  const pad = n => String(n).padStart(2, '0');
  function tick() {
    const d = new Date();
    $('clock').textContent = pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }
  tick();
  setTimeout(function loop() { tick(); setTimeout(loop, 1000 - (Date.now() % 1000)); }, 1000 - (Date.now() % 1000));

  /* title glitch every few seconds */
  const h1 = $('glitch');
  setInterval(() => { h1.classList.remove('glitch'); void h1.offsetWidth; h1.classList.add('glitch'); }, 6000);

  /* ===== show / hide passkey ===== */
  const pass = $('pass'), eye = $('eye'), slash = $('eyeSlash');
  eye.addEventListener('click', () => {
    const show = pass.type === 'password';
    pass.type = show ? 'text' : 'password';
    slash.style.display = show ? 'block' : 'none';
    eye.classList.toggle('on', show);
    eye.setAttribute('aria-label', show ? 'Hide passkey' : 'Show passkey');
  });

  /* ===== status line ===== */
  const status = $('status'), statusText = $('statusText');
  const setStatus = (txt, cls = '') => { status.className = 'status ' + cls; statusText.textContent = txt; };
  if (!CRYPTO_OK) setStatus('OPEN VIA HTTPS OR LOCALHOST TO SIGN IN', 'err');
  else if (/expired=1/.test(location.search)) setStatus('SESSION ENDED · SIGN IN AGAIN', 'err');
  if (CRYPTO_OK) call('GET', '/api/setup_status').then(r => { if (r.ok && r.data.needs_setup) setStatus('NO ADMIN YET · OPEN setup.html FIRST', 'err'); else if (r.status === 503) setStatus('SET UP config.js FIRST', 'err'); }).catch(() => {});

  /* ===== login ===== */
  let tries = 0, locked = false;
  const btn = $('auth');

  function lock(seconds) {
    locked = true; btn.disabled = true;
    let s = seconds || LOCK_SECONDS;
    const t = setInterval(() => {
      setStatus(`LOCKED · RETRY IN ${s}s`, 'err');
      if (--s < 0) { clearInterval(t); locked = false; tries = 0; btn.disabled = false; setStatus('ENCRYPTED'); card.classList.remove('denied'); }
    }, 1000);
  }

  function denied() {
    tries++;
    card.classList.remove('shake'); void card.offsetWidth; card.classList.add('shake', 'denied');
    pass.value = ''; btn.disabled = false;
    if (tries >= MAX_TRIES) lock();
    else { setStatus(`ACCESS DENIED · ${MAX_TRIES - tries} TRIES LEFT`, 'err'); setTimeout(() => !locked && card.classList.remove('denied'), 1200); }
  }

  $('loginForm').addEventListener('submit', async e => {
    e.preventDefault();
    if (locked) return;
    const id = $('uid').value.trim().toLowerCase(), pw = pass.value;

    if (!id || !pw) { setStatus('ENTER ID AND PASSKEY', 'err'); return; }
    if (!CRYPTO_OK) { setStatus('OPEN VIA HTTPS OR LOCALHOST TO SIGN IN', 'err'); return; }

    btn.disabled = true; setStatus('CHECKING…');
    let r;
    try {
      const s = await call('GET', '/api/salt?u=' + encodeURIComponent(id));
      if (s.status === 503) { btn.disabled = false; setStatus('SET UP config.js FIRST', 'err'); return; }
      if (!s.ok) throw new Error('salt');
      var { enc, auth } = await deriveBits(pw, s.data.salt);
      r = await call('POST', '/api/login', { u: id, auth });
    } catch (err) {
      console.error(err); btn.disabled = false; setStatus(OFFLINE_MSG, 'err'); return;
    }
    if (r.status === 429) { lock(r.data.retry || 60); return; }
    if (r.status !== 200) { denied(); return; }

    openSession(r.data);
    setStatus('ACCESS GRANTED', 'ok');
    setTimeout(() => card.classList.add('granted'), 500);
    setTimeout(() => { location.href = nextPage(); }, 1300);
  });
})();
