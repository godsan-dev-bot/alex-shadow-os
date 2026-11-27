#!/usr/bin/env python3
"""
ALEX SHADOW OS · server
-----------------------
Serves the website and a small JSON API backed by SQLite. Standard library only (works in Termux).

Accounts and privacy
  * Only the admin 'angel' creates User IDs (with a sign-in passkey). Nobody can register on their own.
  * After signing in, each user creates their own WALLET PASSWORD. The wallet is encrypted IN THE BROWSER (AES-GCM) with a
    key made from that password, so the server only ever stores unreadable data. Neither the server owner nor the admin
    (even though the admin knows the sign-in passkey) can read anyone's wallet.
  * The server also stores a hash of a value derived from the sign-in passkey (never the passkey itself).

Run:   python server.py                      (this device only:  http://localhost:8000)
       python server.py --host 0.0.0.0       (share on your Wi-Fi / network)
       python server.py --cert cert.pem --key key.pem     (HTTPS, needed so other devices can encrypt)
"""
import argparse, base64, functools, hashlib, hmac, json, os, re, secrets, sqlite3, ssl, threading, time
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

ROOT = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get('ALEX_DB', os.path.join(ROOT, 'alex.db'))
ADMIN = 'angel'                       # the one and only admin
PBKDF2_ITER = 150000                  # must match the browser code
SESSION_TTL = 12 * 3600
MAX_BLOB = 6 * 1024 * 1024
MAX_USERS = 100
NAME_RE = re.compile(r'^[a-z0-9_.-]{3,20}$')
HEX64 = re.compile(r'^[0-9a-f]{64}$')
STATIC_OK = {'.html', '.css', '.js', '.svg', '.png', '.jpg', '.jpeg', '.webp', '.ico', '.txt'}

# ---------------------------------------------------------------- database
class DB:
    def __enter__(self):
        self.c = sqlite3.connect(DB_PATH, timeout=10)
        self.c.row_factory = sqlite3.Row
        self.c.execute('PRAGMA journal_mode=WAL')
        return self.c
    def __exit__(self, et, ev, tb):
        if et is None: self.c.commit()
        else: self.c.rollback()
        self.c.close()

SECRET = b''
def init_db():
    global SECRET
    with DB() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            name TEXT PRIMARY KEY, salt TEXT NOT NULL, auth_salt TEXT NOT NULL, auth_hash TEXT NOT NULL,
            must_change INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, blob TEXT, blob_updated INTEGER)''')
        if 'wallet_salt' not in [r['name'] for r in c.execute('PRAGMA table_info(users)')]:
            c.execute('ALTER TABLE users ADD COLUMN wallet_salt TEXT')       # salt of the user's Wallet Password
        c.execute('CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)')
        r = c.execute("SELECT v FROM meta WHERE k='secret'").fetchone()
        if not r:
            c.execute("INSERT INTO meta VALUES ('secret', ?)", (secrets.token_hex(32),))
            r = c.execute("SELECT v FROM meta WHERE k='secret'").fetchone()
        SECRET = bytes.fromhex(r['v'])
        if not c.execute('SELECT 1 FROM users WHERE name=?', (ADMIN,)).fetchone():
            code = c.execute("SELECT v FROM meta WHERE k='setup_code'").fetchone()
            if not code:
                c.execute("INSERT INTO meta VALUES ('setup_code', ?)", (secrets.token_urlsafe(9),))
                code = c.execute("SELECT v FROM meta WHERE k='setup_code'").fetchone()
            print(f"\n  FIRST RUN: open  /setup.html  and create the admin account '{ADMIN}'.\n  Your setup code is:  {code['v']}\n")

def store_hash(auth_hex, asalt_bytes):
    return hashlib.pbkdf2_hmac('sha256', auth_hex.encode(), asalt_bytes, 100000).hex()

def role_of(name): return 'admin' if name == ADMIN else 'member'

# ---------------------------------------------------------------- sessions + rate limiting
SESSIONS, FAILS, LOCK = {}, {}, threading.Lock()

def new_session(name):
    tok = secrets.token_hex(32)
    with LOCK:
        now = time.time()
        for t in [t for t, s in SESSIONS.items() if s[1] < now]: del SESSIONS[t]
        SESSIONS[tok] = (name, now + SESSION_TTL)
    return tok

def drop_sessions(name, keep=None):
    with LOCK:
        for t in [t for t, s in SESSIONS.items() if s[0] == name and t != keep]: del SESSIONS[t]

def lock_left(keys):
    now = time.time()
    with LOCK:
        return max([0] + [FAILS[k][1] - now for k in keys if k in FAILS])

def register_fail(ip, name):
    now = time.time()
    with LOCK:
        for key, limit, wait in (((ip, name), 5, 60), (('*', name), 15, 300)):
            n, until = FAILS.get(key, (0, 0))
            n += 1
            if n >= limit: n, until = 0, now + wait
            FAILS[key] = (n, until)

def clear_fails(ip, name):
    with LOCK: FAILS.pop((ip, name), None)

# ---------------------------------------------------------------- HTTP handler
class Handler(SimpleHTTPRequestHandler):
    server_version = 'ALEX'
    behind_proxy = False

    def log_message(self, *a): pass

    def end_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Frame-Options', 'DENY')
        if not self.path.startswith('/api/'): self.send_header('Cache-Control', 'no-cache')
        super().end_headers()

    # ---- static files (only web assets; never the database or this script)
    def _static_ok(self):
        p = urlparse(self.path).path
        if p.endswith('/'): self.path = p + 'index.html'; return True
        return os.path.splitext(p)[1].lower() in STATIC_OK

    def do_GET(self):
        if self.path.startswith('/api/'): return self.api('GET')
        if not self._static_ok(): return self.send_error(404)
        super().do_GET()

    def do_HEAD(self):
        if self.path.startswith('/api/'): return self.send_error(405)
        if not self._static_ok(): return self.send_error(404)
        super().do_HEAD()

    def do_POST(self): self.api('POST')
    def do_PUT(self): self.api('PUT')
    def do_DELETE(self): self.api('DELETE')

    # ---- helpers
    def ip(self):
        if self.behind_proxy:
            f = self.headers.get('CF-Connecting-IP') or (self.headers.get('X-Forwarded-For') or '').split(',')[0].strip()
            if f: return f
        return self.client_address[0]

    def reply(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        n = int(self.headers.get('Content-Length') or 0)
        if n > MAX_BLOB + 4096: raise ValueError('too large')
        if n == 0: return {}
        d = json.loads(self.rfile.read(n).decode())
        if not isinstance(d, dict): raise ValueError('bad json')
        return d

    def me(self):
        h = self.headers.get('Authorization', '')
        tok = h[7:] if h.startswith('Bearer ') else ''
        with LOCK:
            s = SESSIONS.get(tok)
            if s and s[1] > time.time(): return s[0], tok
        return None, None

    # ---- API router
    def api(self, method):
        u = urlparse(self.path); path = u.path.rstrip('/'); q = parse_qs(u.query)
        try:
            data = self.body() if method in ('POST', 'PUT') else {}
        except Exception:
            return self.reply(400, {'error': 'Bad request'})
        try:
            if method == 'GET' and path == '/api/salt': return self.salt(q)
            if method == 'POST' and path == '/api/login': return self.login(data)
            if method == 'GET' and path == '/api/setup_status': return self.setup_status()
            if method == 'POST' and path == '/api/setup': return self.claim_admin(data)

            name, tok = self.me()
            if not name: return self.reply(401, {'error': 'Not signed in'})

            if method == 'POST' and path == '/api/logout':
                with LOCK: SESSIONS.pop(tok, None)
                return self.reply(200, {'ok': True})
            if path == '/api/vault':
                if method == 'GET': return self.vault_get(name)
                if method == 'PUT': return self.vault_put(name, data)
                if method == 'DELETE': return self.vault_delete(name)
            if method == 'POST' and path == '/api/me/passkey': return self.me_passkey(name, tok, data)
            if path == '/api/users':
                if method == 'GET': return self.users_list(name)
                if method == 'POST': return self.users_create(name, data)
            m = re.match(r'^/api/users/([a-z0-9_.-]{3,20})(/reset)?$', path)
            if m:
                target = m.group(1)
                if method == 'POST' and m.group(2): return self.users_reset(name, target, data)
                if method == 'DELETE' and not m.group(2): return self.users_delete(name, target)
            return self.reply(404, {'error': 'Not found'})
        except (BrokenPipeError, ConnectionResetError):
            return                                                  # the browser went away: nothing to answer
        except Exception as e:
            print('error:', repr(e))
            try: return self.reply(500, {'error': 'Server error'})
            except Exception: return

    # ---- endpoints
    def salt(self, q):
        name = (q.get('u', [''])[0] or '').strip().lower()
        if NAME_RE.match(name):
            with DB() as c:
                r = c.execute('SELECT salt FROM users WHERE name=?', (name,)).fetchone()
            if r: return self.reply(200, {'salt': r['salt']})
        fake = hmac.new(SECRET, b'salt:' + name.encode(), hashlib.sha256).digest()[:16]     # unknown names look the same as known ones
        self.reply(200, {'salt': base64.b64encode(fake).decode()})

    def setup_status(self):
        with DB() as c: n = c.execute('SELECT COUNT(*) n FROM users').fetchone()['n']
        self.reply(200, {'needs_setup': n == 0})

    def claim_admin(self, d):                       # one-time: claim the admin account with the code printed in the console
        with DB() as c:
            if c.execute('SELECT 1 FROM users').fetchone(): return self.reply(403, {'error': 'Setup is already done'})
            left = lock_left([('setup', 'setup')])
            if left > 0: return self.reply(429, {'error': 'Too many attempts', 'retry': int(left) + 1})
            want = (c.execute("SELECT v FROM meta WHERE k='setup_code'").fetchone() or {'v': ''})['v']
            if not want or not hmac.compare_digest(str(d.get('code', '')), want):
                register_fail('setup', 'setup'); return self.reply(401, {'error': 'Wrong setup code'})
            creds = self._valid_creds(d)
            if not creds: return self.reply(400, {'error': 'Invalid passkey data'})
            asalt = os.urandom(16)
            c.execute('INSERT INTO users (name, salt, auth_salt, auth_hash, must_change, created) VALUES (?,?,?,?,0,?)',
                      (ADMIN, creds[0], asalt.hex(), store_hash(creds[1], asalt), int(time.time() * 1000)))
            c.execute("DELETE FROM meta WHERE k='setup_code'")
        self.reply(200, {'ok': True})

    def login(self, d):
        name = str(d.get('u', '')).strip().lower(); auth = str(d.get('auth', '')).lower(); ip = self.ip()
        left = lock_left([(ip, name), ('*', name)])
        if left > 0: return self.reply(429, {'error': 'Too many attempts', 'retry': int(left) + 1})
        row = None
        if NAME_RE.match(name) and HEX64.match(auth):
            with DB() as c:
                row = c.execute('SELECT * FROM users WHERE name=?', (name,)).fetchone()
        ok = False
        if row:
            ok = hmac.compare_digest(store_hash(auth, bytes.fromhex(row['auth_salt'])), row['auth_hash'])
        else:
            store_hash(auth or '0' * 64, b'\0' * 16)                                       # same work for unknown users
        if not ok:
            register_fail(ip, name)
            return self.reply(401, {'error': 'Wrong user ID or passkey'})
        clear_fails(ip, name)
        self.reply(200, {'token': new_session(name), 'name': name, 'role': role_of(name), 'salt': row['salt'],
                         'wallet_salt': row['wallet_salt'], 'blob': row['blob']})             # blob = the encrypted wallet (null until the user creates one)

    def vault_get(self, name):
        with DB() as c: r = c.execute('SELECT wallet_salt, blob FROM users WHERE name=?', (name,)).fetchone()
        self.reply(200, {'blob': r['blob'] if r else None, 'salt': r['wallet_salt'] if r else None})

    def vault_put(self, name, d):             # create or update the user's own encrypted wallet
        blob, salt = d.get('blob'), d.get('salt')
        try: salt_ok = isinstance(salt, str) and len(base64.b64decode(salt, validate=True)) == 16
        except Exception: salt_ok = False
        if not isinstance(blob, str) or len(blob) > MAX_BLOB or not salt_ok: return self.reply(400, {'error': 'Bad wallet data'})
        with DB() as c: c.execute('UPDATE users SET wallet_salt=?, blob=?, blob_updated=? WHERE name=?', (salt, blob, int(time.time() * 1000), name))
        self.reply(200, {'ok': True})

    def vault_delete(self, name):             # "forgot my Wallet Password": erase the wallet so a new one can be created
        with DB() as c: c.execute('UPDATE users SET wallet_salt=NULL, blob=NULL, blob_updated=NULL WHERE name=?', (name,))
        self.reply(200, {'ok': True})

    def _valid_creds(self, d):
        salt, auth = d.get('salt'), str(d.get('auth', '')).lower()
        try:
            if len(base64.b64decode(salt, validate=True)) != 16: return None
        except Exception: return None
        return (salt, auth) if HEX64.match(auth) else None

    def me_passkey(self, name, tok, d):       # change your own SIGN-IN passkey (the wallet is not touched)
        cur = str(d.get('cur', '')).lower(); creds = self._valid_creds(d)
        if not creds or not HEX64.match(cur): return self.reply(400, {'error': 'Bad request'})
        with DB() as c:
            r = c.execute('SELECT * FROM users WHERE name=?', (name,)).fetchone()
            if not r or not hmac.compare_digest(store_hash(cur, bytes.fromhex(r['auth_salt'])), r['auth_hash']):
                return self.reply(403, {'error': 'Current passkey is wrong'})
            asalt = os.urandom(16)
            c.execute('UPDATE users SET salt=?, auth_salt=?, auth_hash=? WHERE name=?', (creds[0], asalt.hex(), store_hash(creds[1], asalt), name))
        drop_sessions(name, keep=tok)
        self.reply(200, {'ok': True})

    def users_list(self, name):
        with DB() as c:
            rows = c.execute('SELECT name, created, blob IS NOT NULL AS wallet FROM users ' + ('' if name == ADMIN else 'WHERE name=? ') + 'ORDER BY created',
                             () if name == ADMIN else (name,)).fetchall()
        self.reply(200, {'users': [{'name': r['name'], 'role': role_of(r['name']), 'created': r['created'], 'wallet_set': bool(r['wallet'])} for r in rows]})

    def users_create(self, who, d):
        if who != ADMIN: return self.reply(403, {'error': 'Only the admin can create users'})
        name = str(d.get('name', '')).strip().lower(); creds = self._valid_creds(d)
        if not NAME_RE.match(name) or name == ADMIN or not creds: return self.reply(400, {'error': 'Invalid user ID'})
        with DB() as c:
            if c.execute('SELECT COUNT(*) n FROM users').fetchone()['n'] >= MAX_USERS: return self.reply(400, {'error': 'User limit reached'})
            if c.execute('SELECT 1 FROM users WHERE name=?', (name,)).fetchone(): return self.reply(409, {'error': 'That user ID already exists'})
            asalt = os.urandom(16)
            c.execute('INSERT INTO users (name, salt, auth_salt, auth_hash, must_change, created) VALUES (?,?,?,?,0,?)',
                      (name, creds[0], asalt.hex(), store_hash(creds[1], asalt), int(time.time() * 1000)))
        self.reply(200, {'ok': True, 'name': name})

    def users_reset(self, who, target, d):    # admin gives someone a new SIGN-IN passkey; their wallet is untouched (and unreadable to the admin)
        if who != ADMIN: return self.reply(403, {'error': 'Only the admin can reset a passkey'})
        creds = self._valid_creds(d)
        if target == ADMIN or not creds: return self.reply(400, {'error': 'Invalid request'})
        with DB() as c:
            if not c.execute('SELECT 1 FROM users WHERE name=?', (target,)).fetchone(): return self.reply(404, {'error': 'No such user'})
            asalt = os.urandom(16)
            c.execute('UPDATE users SET salt=?, auth_salt=?, auth_hash=? WHERE name=?', (creds[0], asalt.hex(), store_hash(creds[1], asalt), target))
        drop_sessions(target)
        self.reply(200, {'ok': True})

    def users_delete(self, who, target):
        if who != ADMIN: return self.reply(403, {'error': 'Only the admin can remove users'})
        if target == ADMIN: return self.reply(400, {'error': 'The admin account cannot be removed'})
        with DB() as c: c.execute('DELETE FROM users WHERE name=?', (target,))
        drop_sessions(target)
        self.reply(200, {'ok': True})

class Server(ThreadingHTTPServer):
    daemon_threads = True
    def handle_error(self, request, client_address):          # a browser closing a connection early is normal: stay quiet
        import sys
        if isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError, ssl.SSLError)): return
        super().handle_error(request, client_address)

# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description='ALEX SHADOW OS server')
    ap.add_argument('--host', default='127.0.0.1', help='127.0.0.1 = this device only, 0.0.0.0 = whole network')
    ap.add_argument('--port', type=int, default=8000)
    ap.add_argument('--cert'); ap.add_argument('--key')
    ap.add_argument('--behind-proxy', action='store_true', help='trust X-Forwarded-For (use with a tunnel / reverse proxy)')
    a = ap.parse_args()
    init_db()
    Handler.behind_proxy = a.behind_proxy
    srv = Server((a.host, a.port), functools.partial(Handler, directory=ROOT))
    scheme = 'http'
    if a.cert and a.key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(a.cert, a.key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True); scheme = 'https'
    print(f'\n  ALEX SHADOW OS is running  ->  {scheme}://{"localhost" if a.host in ("127.0.0.1", "0.0.0.0") else a.host}:{a.port}/')
    if a.host == '0.0.0.0' and scheme == 'http':
        print('  Note: other devices need HTTPS (or localhost) so the browser can encrypt vaults. See SETUP.md.')
    print('  Database:', DB_PATH, '\n  Press Ctrl+C to stop.\n')
    try: srv.serve_forever()
    except KeyboardInterrupt: print('\n  Stopped.')

if __name__ == '__main__':
    main()
