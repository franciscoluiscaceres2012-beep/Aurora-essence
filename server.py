from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse
import json, os, hashlib, secrets, base64, mimetypes, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PUBLIC = ROOT / 'public'
DATA = ROOT / 'data'
IMAGES = PUBLIC / 'uploads'
DATA.mkdir(exist_ok=True)
IMAGES.mkdir(exist_ok=True)
PRODUCTS_FILE = DATA / 'products.json'
ADMIN_FILE = DATA / 'admin.json'
SESSIONS = {}
SESSION_TTL = 60 * 60 * 12

if not PRODUCTS_FILE.exists():
    PRODUCTS_FILE.write_text('[]', encoding='utf-8')

def read_json(path, default):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return default

def write_json(path, obj):
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding='utf-8')
    tmp.replace(path)

def hash_password(password, salt=None):
    salt_b = os.urandom(16) if salt is None else bytes.fromhex(salt)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_b, 210000)
    return salt_b.hex(), digest.hex()

def verify_password(password, salt, digest):
    _, d = hash_password(password, salt)
    return secrets.compare_digest(d, digest)

def parse_cookies(header):
    out = {}
    if not header: return out
    for part in header.split(';'):
        if '=' in part:
            k, v = part.strip().split('=', 1)
            out[k] = v
    return out

def clean_sessions():
    now = time.time()
    for k in list(SESSIONS):
        if SESSIONS[k] < now:
            del SESSIONS[k]

class Handler(SimpleHTTPRequestHandler):
    def translate_path(self, path):
        path = urlparse(path).path
        rel = path.lstrip('/') or 'index.html'
        return str(PUBLIC / rel)

    def log_message(self, format, *args):
        print('[Aurora Essence]', format % args)

    def send_json(self, obj, status=200, cookie=None):
        raw = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(raw)

    def read_body_json(self):
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if length > 8_000_000:
                raise ValueError('payload too large')
            return json.loads(self.rfile.read(length).decode('utf-8') or '{}')
        except Exception:
            return None

    def is_admin(self):
        clean_sessions()
        cookies = parse_cookies(self.headers.get('Cookie'))
        token = cookies.get('ae_session')
        return bool(token and token in SESSIONS and SESSIONS[token] > time.time())

    def do_GET(self):
        path = urlparse(self.path).path
        if path == '/api/products':
            products = read_json(PRODUCTS_FILE, [])
            public = [p for p in products if int(p.get('stock',0)) > 0]
            return self.send_json(public)
        if path == '/api/admin/status':
            return self.send_json({'configured': ADMIN_FILE.exists(), 'authenticated': self.is_admin()})
        if path == '/api/admin/products':
            if not self.is_admin(): return self.send_json({'error':'No autorizado'}, 401)
            return self.send_json(read_json(PRODUCTS_FILE, []))
        return super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        body = self.read_body_json()
        if body is None: return self.send_json({'error':'Solicitud inválida'}, 400)

        if path == '/api/admin/setup':
            if ADMIN_FILE.exists(): return self.send_json({'error':'El administrador ya fue configurado'}, 409)
            password = str(body.get('password',''))
            if len(password) < 8: return self.send_json({'error':'La contraseña debe tener al menos 8 caracteres'}, 400)
            salt, digest = hash_password(password)
            write_json(ADMIN_FILE, {'username':'admin','salt':salt,'digest':digest})
            return self.send_json({'ok':True})

        if path == '/api/admin/login':
            if not ADMIN_FILE.exists(): return self.send_json({'error':'Primero configurá el administrador'}, 400)
            admin = read_json(ADMIN_FILE,{})
            if body.get('username') != admin.get('username') or not verify_password(str(body.get('password','')), admin.get('salt',''), admin.get('digest','')):
                return self.send_json({'error':'Usuario o contraseña incorrectos'}, 401)
            token = secrets.token_urlsafe(32)
            SESSIONS[token] = time.time() + SESSION_TTL
            cookie = f'ae_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}'
            return self.send_json({'ok':True}, cookie=cookie)

        if path == '/api/admin/logout':
            cookies = parse_cookies(self.headers.get('Cookie'))
            token = cookies.get('ae_session')
            if token: SESSIONS.pop(token, None)
            return self.send_json({'ok':True}, cookie='ae_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')

        if not self.is_admin(): return self.send_json({'error':'No autorizado'}, 401)

        if path == '/api/admin/products':
            products = read_json(PRODUCTS_FILE, [])
            name = str(body.get('name','')).strip()
            brand = str(body.get('brand','')).strip()
            if not name or not brand: return self.send_json({'error':'Nombre y marca son obligatorios'},400)
            try:
                price = float(body.get('price',0))
                stock = max(0, int(body.get('stock',0)))
            except Exception:
                return self.send_json({'error':'Precio o stock inválidos'},400)
            pid = secrets.token_hex(6)
            image_path = self.save_image(body.get('imageData'), pid)
            product = {
                'id':pid, 'name':name, 'brand':brand, 'price':price, 'stock':stock,
                'size':str(body.get('size','')).strip(), 'gender':str(body.get('gender','Unisex')).strip(),
                'description':str(body.get('description','')).strip(), 'notes':str(body.get('notes','')).strip(),
                'image':image_path or '', 'featured':bool(body.get('featured',False))
            }
            products.insert(0, product)
            write_json(PRODUCTS_FILE, products)
            return self.send_json(product, 201)

        return self.send_json({'error':'Ruta no encontrada'},404)

    def do_PUT(self):
        path = urlparse(self.path).path
        if not path.startswith('/api/admin/products/') or not self.is_admin():
            return self.send_json({'error':'No autorizado'},401)
        body = self.read_body_json()
        if body is None: return self.send_json({'error':'Solicitud inválida'},400)
        pid = path.rsplit('/',1)[-1]
        products = read_json(PRODUCTS_FILE, [])
        idx = next((i for i,p in enumerate(products) if p.get('id') == pid), None)
        if idx is None: return self.send_json({'error':'Producto no encontrado'},404)
        p = products[idx]
        for key in ['name','brand','size','gender','description','notes']:
            if key in body: p[key] = str(body.get(key,'')).strip()
        if 'price' in body: p['price'] = float(body['price'])
        if 'stock' in body: p['stock'] = max(0, int(body['stock']))
        if 'featured' in body: p['featured'] = bool(body['featured'])
        if body.get('imageData'):
            old = p.get('image','')
            new_path = self.save_image(body['imageData'], pid)
            if new_path:
                p['image'] = new_path
                if old.startswith('/uploads/'):
                    try: (PUBLIC / old.lstrip('/')).unlink(missing_ok=True)
                    except Exception: pass
        products[idx] = p
        write_json(PRODUCTS_FILE, products)
        return self.send_json(p)

    def do_DELETE(self):
        path = urlparse(self.path).path
        if not path.startswith('/api/admin/products/') or not self.is_admin():
            return self.send_json({'error':'No autorizado'},401)
        pid = path.rsplit('/',1)[-1]
        products = read_json(PRODUCTS_FILE, [])
        target = next((p for p in products if p.get('id') == pid), None)
        if not target: return self.send_json({'error':'Producto no encontrado'},404)
        products = [p for p in products if p.get('id') != pid]
        write_json(PRODUCTS_FILE, products)
        old = target.get('image','')
        if old.startswith('/uploads/'):
            try: (PUBLIC / old.lstrip('/')).unlink(missing_ok=True)
            except Exception: pass
        return self.send_json({'ok':True})

    def save_image(self, data_url, pid):
        if not data_url or not isinstance(data_url, str) or not data_url.startswith('data:image/'):
            return ''
        try:
            header, payload = data_url.split(',',1)
            mime = header.split(';')[0].split(':')[1]
            ext = mimetypes.guess_extension(mime) or '.jpg'
            if ext == '.jpe': ext = '.jpg'
            raw = base64.b64decode(payload)
            if len(raw) > 5_000_000: return ''
            filename = f'{pid}{ext}'
            (IMAGES / filename).write_bytes(raw)
            return f'/uploads/{filename}'
        except Exception:
            return ''

if __name__ == '__main__':
    port = int(os.environ.get('PORT','8000'))
    print(f'Aurora Essence disponible en http://localhost:{port}')
    ThreadingHTTPServer(('0.0.0.0', port), Handler).serve_forever()
