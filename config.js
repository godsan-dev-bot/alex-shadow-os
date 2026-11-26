/* =====================================================================
   ALEX SHADOW OS · backend settings   (the only file you need to edit)
   backend: 'supabase'  -> a free Supabase database. Use this when the site is hosted on GitHub Pages.
            'local'     -> the Python server on your own device (python server.py).
   The Supabase "anon / publishable" key is meant to be public, it is safe to upload this file to GitHub.
   NEVER put the "service_role" / "secret" key anywhere in this project.
   ===================================================================== */
window.ALEX_CONFIG = {
  backend: 'supabase',
  supabaseUrl: 'https://feqyynrifjbxybsqtima.supabase.co/rest/v1/',      // Supabase > Project Settings > API > Project URL
  supabaseKey: 'sb_publishable_xffI93p_F_s1EMGbDJP9qQ_fFWLvjJW'          // Supabase > Project Settings > API > anon / publishable key
};

/* ---------------------------------------------------------------------
   Everything below turns the app's requests into calls to the chosen backend. No need to edit.
   --------------------------------------------------------------------- */
window.ALEX_BACKEND = (() => {
  const C = window.ALEX_CONFIG;
  const parse = async r => { try { return await r.json(); } catch { return {}; } };

  async function local(method, path, body, token) {
    const h = { 'Content-Type': 'application/json' }; if (token) h.Authorization = 'Bearer ' + token;
    const r = await fetch(path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, ok: r.ok, data: await parse(r) };
  }

  async function supa(method, path, body, token) {
    if (!C.supabaseUrl || !C.supabaseKey || /PASTE-YOUR/.test(C.supabaseUrl + C.supabaseKey)) return { status: 503, ok: false, data: { error: 'config.js is not set up yet' } };
    const u = new URL(path, 'http://x'), p = u.pathname, b = body || {};
    let m, fn, args;
    if (method === 'GET' && p === '/api/salt') { fn = 'alex_salt'; args = { p_u: u.searchParams.get('u') || '' }; }
    else if (method === 'GET' && p === '/api/setup_status') { fn = 'alex_setup_status'; args = {}; }
    else if (method === 'POST' && p === '/api/setup') { fn = 'alex_setup'; args = { p_code: b.code, p_salt: b.salt, p_auth: b.auth }; }
    else if (method === 'POST' && p === '/api/login') { fn = 'alex_login'; args = { p_u: b.u, p_auth: b.auth }; }
    else if (method === 'POST' && p === '/api/logout') { fn = 'alex_logout'; args = { p_t: token }; }
    else if (method === 'GET' && p === '/api/vault') { fn = 'alex_vault_get'; args = { p_t: token }; }
    else if (method === 'PUT' && p === '/api/vault') { fn = 'alex_vault_put'; args = { p_t: token, p_salt: b.salt, p_blob: b.blob }; }
    else if (method === 'DELETE' && p === '/api/vault') { fn = 'alex_vault_delete'; args = { p_t: token }; }
    else if (method === 'POST' && p === '/api/me/passkey') { fn = 'alex_me_passkey'; args = { p_t: token, p_cur: b.cur, p_salt: b.salt, p_auth: b.auth }; }
    else if (method === 'GET' && p === '/api/users') { fn = 'alex_users_list'; args = { p_t: token }; }
    else if (method === 'POST' && p === '/api/users') { fn = 'alex_users_create'; args = { p_t: token, p_name: b.name, p_salt: b.salt, p_auth: b.auth }; }
    else if (method === 'POST' && (m = p.match(/^\/api\/users\/([^/]+)\/reset$/))) { fn = 'alex_users_reset'; args = { p_t: token, p_name: decodeURIComponent(m[1]), p_salt: b.salt, p_auth: b.auth }; }
    else if (method === 'DELETE' && (m = p.match(/^\/api\/users\/([^/]+)$/))) { fn = 'alex_users_delete'; args = { p_t: token, p_name: decodeURIComponent(m[1]) }; }
    else return { status: 404, ok: false, data: { error: 'Not found' } };

    const h = { 'Content-Type': 'application/json', apikey: C.supabaseKey };
    if (/^eyJ/.test(C.supabaseKey)) h.Authorization = 'Bearer ' + C.supabaseKey;          // classic JWT-style keys; newer "publishable" keys go in apikey only
    const r = await fetch(C.supabaseUrl.replace(/\/+$/, '') + '/rest/v1/rpc/' + fn, { method: 'POST', headers: h, body: JSON.stringify(args) });
    const d = await parse(r);
    if (!r.ok) return { status: r.status === 404 ? 503 : r.status, ok: false, data: { error: d.message || 'Database error' } };
    const status = d.status || 200; delete d.status;                                       // the database functions report their own status
    return { status, ok: status < 400, data: d };
  }

  return { mode: C.backend, request: (m, p, b, t) => (C.backend === 'supabase' ? supa(m, p, b, t) : local(m, p, b, t)) };
})();
