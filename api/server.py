"""Same-origin admin API. Run behind the supplied TLS reverse proxy."""
import base64
import hashlib
import json
import mimetypes
import os
import secrets
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, urlopen

from .store import Store, digest, connection_uri


class App:
    def __init__(self):
        self.store = Store(os.environ.get('DATABASE_PATH', 'data/vpn.sqlite3'))
        self.origin = os.environ.get('PUBLIC_URL', 'http://localhost:8092').rstrip('/')
        parsed = urlsplit(self.origin)
        if parsed.scheme != 'https' and parsed.hostname not in ('localhost', '127.0.0.1'):
            raise ValueError('PUBLIC_URL must use HTTPS outside localhost.')
        self.secure = parsed.scheme == 'https'
        self.client_id = os.environ.get('GOOGLE_CLIENT_ID', '')
        self.client_secret = os.environ.get('GOOGLE_CLIENT_SECRET', '')
        self.admin = os.environ.get('ADMIN_EMAIL', '').lower().strip()
        self.host = os.environ.get('VPN_HOST', '')
        self.port = int(os.environ.get('VPN_PORT', '443'))
        self.ws_path = os.environ.get('VPN_WS_PATH', '')
        self.dist = Path(__file__).resolve().parents[1] / 'ui' / 'dist'

    def configured(self):
        return bool(self.client_id and self.client_secret and self.admin)

    def cookie(self, name, value, age):
        return '{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{}'.format(name,value,age,'; Secure' if self.secure else '')

    def session(self, token):
        with self.store.connect() as db:
            db.execute('DELETE FROM sessions WHERE expires < ?', (int(time.time()),))
            r = db.execute('SELECT email FROM sessions WHERE token=?', (digest(token),)).fetchone()
        return r['email'] if r and r['email'] == self.admin else None


def handler_for(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = 'VPNConsole'

        def setup(self):
            super().setup()
            self.connection.settimeout(20)

        def log_message(self, fmt, *args):
            # Paths can contain bearer subscription tokens or OAuth codes.
            pass

        def send(self, status, body=b'', content_type='application/json', headers=None):
            if isinstance(body, (dict,list)):
                body = json.dumps(body).encode()
            elif isinstance(body,str):
                body = body.encode()
            self.send_response(status)
            self.send_header('Content-Type',content_type)
            self.send_header('Content-Length',str(len(body)))
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Referrer-Policy','no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
            for key,value in (headers or {}).items():
                self.send_header(key,value)
            self.end_headers()
            self.wfile.write(body)

        def cookies(self):
            c = SimpleCookie()
            try:
                c.load(self.headers.get('Cookie',''))
            except Exception:
                return {}
            return {k:v.value for k,v in c.items()}

        def do_GET(self):
            try:
                self.get()
            except Exception:
                self.send(502, {'error':'The request could not be completed. Check server configuration.'})

        def get(self):
            parsed = urlsplit(self.path)
            path = parsed.path
            if path == '/api/health':
                return self.send(200, {'ok':True})
            if path == '/api/session':
                email = app.session(self.cookies().get('session',''))
                return self.send(200, {'email':email,'loginConfigured':app.configured()})
            if path == '/api/auth/google':
                if not app.configured():
                    return self.send(503, {'error':'Admin Google sign-in has not been configured.'})
                state,verifier = secrets.token_urlsafe(32),secrets.token_urlsafe(48)
                with app.store.connect() as db:
                    db.execute('DELETE FROM oauth WHERE expires < ?', (int(time.time()),))
                    db.execute('INSERT INTO oauth VALUES (?,?,?)',(digest(state),verifier,int(time.time())+600))
                query = urlencode({'client_id':app.client_id,'redirect_uri':app.origin+'/api/auth/callback',
                    'response_type':'code','scope':'openid email','state':state,'prompt':'select_account',
                    'code_challenge':base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('='),
                    'code_challenge_method':'S256'})
                return self.send(302,headers={'Location':'https://accounts.google.com/o/oauth2/v2/auth?'+query,
                    'Set-Cookie':app.cookie('oauth_state',state,600)})
            if path == '/api/auth/callback':
                q = parse_qs(parsed.query)
                state = q.get('state',[''])[0]
                if not state or not secrets.compare_digest(state,self.cookies().get('oauth_state','')):
                    return self.send(400,{'error':'Invalid login state. Start sign-in again.'})
                with app.store.connect() as db:
                    db.execute('BEGIN IMMEDIATE')
                    row = db.execute('SELECT * FROM oauth WHERE state=? AND expires>?',(digest(state),int(time.time()))).fetchone()
                    db.execute('DELETE FROM oauth WHERE state=?',(digest(state),))
                if not row or not q.get('code'):
                    return self.send(400,{'error':'Login expired or cancelled. Start sign-in again.'})
                data = urlencode({'code':q['code'][0],'client_id':app.client_id,'client_secret':app.client_secret,
                    'redirect_uri':app.origin+'/api/auth/callback','grant_type':'authorization_code','code_verifier':row['verifier']}).encode()
                with urlopen(Request('https://oauth2.googleapis.com/token',data=data),timeout=15) as response:
                    token = json.load(response)['access_token']
                # Retrieve identity directly over verified TLS; never trust a decoded, unverified JWT.
                with urlopen(Request('https://openidconnect.googleapis.com/v1/userinfo',headers={'Authorization':'Bearer '+token}),timeout=15) as response:
                    identity = json.load(response)
                email = identity.get('email','').lower()
                if identity.get('email_verified') is not True or email != app.admin:
                    return self.send(403,{'error':'This Google account is not the administrator.'})
                session = secrets.token_urlsafe(32)
                with app.store.connect() as db:
                    db.execute('INSERT INTO sessions VALUES (?,?,?)',(digest(session),email,int(time.time())+43200))
                return self.send(302,headers={'Location':'/','Set-Cookie':app.cookie('session',session,43200)})
            if path.startswith('/sub/'):
                token = path.removeprefix('/sub/') if hasattr(path,'removeprefix') else path[5:]
                with app.store.connect() as db:
                    row = db.execute('SELECT * FROM users WHERE token=? AND enabled=1',(token,)).fetchone()
                if not row:
                    return self.send(404,{'error':'Subscription not found.'})
                meta = app.store.meta()
                if meta['revision'] != meta['applied'] or not app.host or not app.ws_path:
                    return self.send(503,{'error':'VPN configuration is pending. Try again after the controller syncs.'})
                uri = connection_uri(dict(row),app.host,app.port,app.ws_path)
                return self.send(200,base64.b64encode(uri.encode()),'text/plain; charset=utf-8',{
                    'Subscription-Userinfo':'upload={}; download={}'.format(row['upload'],row['download']),
                    'Profile-Update-Interval':'6'})
            if path.startswith('/api/'):
                if not app.session(self.cookies().get('session','')):
                    return self.send(401,{'error':'Sign in to continue.'})
                if path == '/api/dashboard':
                    users = app.store.users()
                    for u in users:
                        del u['credential']
                        u['subscription'] = app.origin+'/sub/'+u.pop('token')
                        u['tags'] = json.loads(u['tags'])
                    with app.store.connect() as db:
                        history = [dict(r) for r in db.execute("SELECT day,SUM(upload) AS upload,SUM(download) AS download FROM daily WHERE day>=date('now','-13 days') GROUP BY day ORDER BY day")]
                        audit = [dict(r) for r in db.execute('SELECT audit.*,users.name FROM audit LEFT JOIN users ON users.id=audit.user_id ORDER BY audit.id DESC LIMIT 12')]
                    return self.send(200,{'users':users,'meta':app.store.meta(),'history':history,'audit':audit,'vpnConfigured':bool(app.host and app.ws_path)})
                return self.send(404,{'error':'Endpoint not found.'})
            target = (app.dist / path.lstrip('/')).resolve()
            if not target.is_relative_to(app.dist.resolve()):
                return self.send(404,{'error':'Not found.'})
            if not target.is_file():
                target = app.dist/'index.html'
            if not target.is_file():
                return self.send(503,{'error':'React UI is not built. Run npm ci && npm run build in /ui (npm install on first setup). '})
            return self.send(200,target.read_bytes(),mimetypes.guess_type(str(target))[0] or 'application/octet-stream')

        def do_POST(self):
            if self.headers.get('Origin') != app.origin:
                return self.send(403,{'error':'Request origin rejected.'})
            if not app.session(self.cookies().get('session','')):
                return self.send(401,{'error':'Sign in to continue.'})
            try:
                length = int(self.headers.get('Content-Length','0'))
                if not 0 <= length <= 16384:
                    return self.send(413,{'error':'Request too large.'})
                payload = json.loads(self.rfile.read(length) or b'{}')
                if not isinstance(payload,dict):
                    raise ValueError('Expected a JSON object.')
                path = urlsplit(self.path).path
                if path == '/api/logout':
                    with app.store.connect() as db:
                        db.execute('DELETE FROM sessions WHERE token=?',(digest(self.cookies().get('session','')),))
                    return self.send(200,{'ok':True},headers={'Set-Cookie':app.cookie('session','',0)})
                if path == '/api/users':
                    uid = app.store.mutate('create',payload=payload)
                    return self.send(201,{'id':uid})
                parts = path.strip('/').split('/')
                if len(parts)==4 and parts[:2]==['api','users'] and parts[3] in ('edit','toggle','rotate'):
                    app.store.mutate(parts[3],parts[2],payload)
                    return self.send(200,{'ok':True})
                return self.send(404,{'error':'Endpoint not found.'})
            except (ValueError,TypeError):
                return self.send(400,{'error':'Invalid request. Check the name and tags.'})
            except LookupError:
                return self.send(404,{'error':'User not found.'})
            except Exception:
                return self.send(500,{'error':'Unable to save the change.'})
    return Handler


if __name__ == '__main__':
    os.umask(0o077)
    app = App()
    server = ThreadingHTTPServer((os.environ.get('BIND_HOST','127.0.0.1'),int(os.environ.get('PORT','8092'))),handler_for(app))
    print('VPN Console API listening on port',server.server_port,flush=True)
    server.serve_forever()
