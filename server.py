from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import json
import os
import hashlib
import secrets
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PUBLIC = ROOT / "public"

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")

SESSIONS = {}
SESSION_TTL = 60 * 60 * 12


def hash_password(password, salt=None):
    salt_bytes = os.urandom(16) if salt is None else bytes.fromhex(salt)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_bytes,
        210000
    )

    return salt_bytes.hex(), digest.hex()


def verify_password(password, salt, digest):
    _, calculated = hash_password(password, salt)
    return secrets.compare_digest(calculated, digest)


def parse_cookies(header):
    cookies = {}

    if not header:
        return cookies

    for part in header.split(";"):
        if "=" in part:
            key, value = part.strip().split("=", 1)
            cookies[key] = value

    return cookies


def clean_sessions():
    now = time.time()

    for token in list(SESSIONS):
        if SESSIONS[token] < now:
            del SESSIONS[token]


def supabase_request(path, method="GET", body=None, prefer=None):

    if not SUPABASE_URL or not SUPABASE_KEY:
        raise RuntimeError("Supabase no está configurado")

    url = f"{SUPABASE_URL}/rest/v1/{path}"

    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json"
    }

    if prefer:
        headers["Prefer"] = prefer

    data = None

    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")

    request = Request(
        url,
        data=data,
        headers=headers,
        method=method
    )

    try:

        with urlopen(request, timeout=20) as response:

            text = response.read().decode("utf-8")

            if not text:
                return None

            return json.loads(text)

    except HTTPError as error:

        detail = error.read().decode("utf-8", errors="replace")

        print("SUPABASE ERROR:", error.code, detail)

        raise


def get_products():

    result = supabase_request(
        "products?select=*&order=created_at.desc"
    )

    return result or []


def create_product(product):

    result = supabase_request(
        "products",
        method="POST",
        body=product,
        prefer="return=representation"
    )

    if result:
        return result[0]

    return product


def update_product(product_id, updates):

    result = supabase_request(
        f"products?id=eq.{quote(product_id, safe='')}",
        method="PATCH",
        body=updates,
        prefer="return=representation"
    )

    if result:
        return result[0]

    return None


def delete_product(product_id):

    result = supabase_request(
        f"products?id=eq.{quote(product_id, safe='')}",
        method="DELETE",
        prefer="return=representation"
    )

    return bool(result)


def get_admin():

    result = supabase_request(
        "app_config?key=eq.admin&select=value"
    )

    if not result:
        return None

    return result[0]["value"]


def save_admin(admin):

    supabase_request(
        "app_config?on_conflict=key",
        method="POST",
        body={
            "key": "admin",
            "value": admin
        },
        prefer="resolution=merge-duplicates"
    )


class Handler(SimpleHTTPRequestHandler):

    def translate_path(self, path):

        path = urlparse(path).path

        relative = path.lstrip("/") or "index.html"

        return str(PUBLIC / relative)


    def log_message(self, format, *args):

        print("[Aurora Essence]", format % args)


    def send_json(self, obj, status=200, cookie=None):

        raw = json.dumps(
            obj,
            ensure_ascii=False
        ).encode("utf-8")

        self.send_response(status)

        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8"
        )

        self.send_header(
            "Content-Length",
            str(len(raw))
        )

        self.send_header(
            "Cache-Control",
            "no-store"
        )

        self.send_header(
            "X-Content-Type-Options",
            "nosniff"
        )

        self.send_header(
            "X-Frame-Options",
            "DENY"
        )

        if cookie:
            self.send_header(
                "Set-Cookie",
                cookie
            )

        self.end_headers()

        self.wfile.write(raw)


    def read_body_json(self):

        try:

            length = int(
                self.headers.get(
                    "Content-Length",
                    "0"
                )
            )

            if length > 8_000_000:
                raise ValueError()

            content = self.rfile.read(length)

            return json.loads(
                content.decode("utf-8") or "{}"
            )

        except Exception:

            return None


    def is_admin(self):

        clean_sessions()

        cookies = parse_cookies(
            self.headers.get("Cookie")
        )

        token = cookies.get("ae_session")

        return bool(
            token
            and token in SESSIONS
            and SESSIONS[token] > time.time()
        )


    def do_GET(self):

        path = urlparse(self.path).path

        try:

            if path == "/api/products":

                products = get_products()

                public_products = [
                    product
                    for product in products
                    if int(product.get("stock", 0)) > 0
                ]

                return self.send_json(
                    public_products
                )


            if path == "/api/admin/status":

                return self.send_json({
                    "configured": get_admin() is not None,
                    "authenticated": self.is_admin(),
                    "persistent": True
                })


            if path == "/api/admin/products":

                if not self.is_admin():
                    return self.send_json(
                        {"error": "No autorizado"},
                        401
                    )

                return self.send_json(
                    get_products()
                )


            if path == "/api/health":

                return self.send_json({
                    "ok": True,
                    "database": "Supabase"
                })


        except Exception as error:

            print(
                "ERROR DATABASE:",
                error
            )

            return self.send_json(
                {
                    "error":
                    "No se pudo acceder a la base de datos"
                },
                500
            )


        return super().do_GET()


    def do_POST(self):

        path = urlparse(self.path).path

        body = self.read_body_json()

        if body is None:

            return self.send_json(
                {"error": "Solicitud inválida"},
                400
            )


        try:

            if path == "/api/admin/setup":

                if get_admin() is not None:

                    return self.send_json(
                        {
                            "error":
                            "El administrador ya fue configurado"
                        },
                        409
                    )

                password = str(
                    body.get(
                        "password",
                        ""
                    )
                )

                if len(password) < 8:

                    return self.send_json(
                        {
                            "error":
                            "La contraseña debe tener al menos 8 caracteres"
                        },
                        400
                    )

                salt, digest = hash_password(
                    password
                )

                save_admin({
                    "username": "admin",
                    "salt": salt,
                    "digest": digest
                })

                return self.send_json({
                    "ok": True
                })


            if path == "/api/admin/login":

                admin = get_admin()

                if not admin:

                    return self.send_json(
                        {
                            "error":
                            "Primero configurá el administrador"
                        },
                        400
                    )

                username = body.get(
                    "username"
                )

                password = str(
                    body.get(
                        "password",
                        ""
                    )
                )

                correct = (
                    username
                    == admin.get("username")
                    and verify_password(
                        password,
                        admin.get("salt", ""),
                        admin.get("digest", "")
                    )
                )

                if not correct:

                    return self.send_json(
                        {
                            "error":
                            "Usuario o contraseña incorrectos"
                        },
                        401
                    )

                token = secrets.token_urlsafe(
                    32
                )

                SESSIONS[token] = (
                    time.time()
                    + SESSION_TTL
                )

                cookie = (
                    f"ae_session={token}; "
                    "HttpOnly; "
                    "SameSite=Strict; "
                    "Secure; "
                    "Path=/; "
                    f"Max-Age={SESSION_TTL}"
                )

                return self.send_json(
                    {"ok": True},
                    cookie=cookie
                )


            if path == "/api/admin/logout":

                cookies = parse_cookies(
                    self.headers.get(
                        "Cookie"
                    )
                )

                token = cookies.get(
                    "ae_session"
                )

                if token:

                    SESSIONS.pop(
                        token,
                        None
                    )

                return self.send_json(
                    {"ok": True},
                    cookie=(
                        "ae_session=; "
                        "HttpOnly; "
                        "SameSite=Strict; "
                        "Secure; "
                        "Path=/; "
                        "Max-Age=0"
                    )
                )


            if not self.is_admin():

                return self.send_json(
                    {"error": "No autorizado"},
                    401
                )


            if path == "/api/admin/products":

                name = str(
                    body.get(
                        "name",
                        ""
                    )
                ).strip()

                brand = str(
                    body.get(
                        "brand",
                        ""
                    )
                ).strip()


                if not name or not brand:

                    return self.send_json(
                        {
                            "error":
                            "Nombre y marca son obligatorios"
                        },
                        400
                    )


                try:

                    price = float(
                        body.get(
                            "price",
                            0
                        )
                    )

                    stock = max(
                        0,
                        int(
                            body.get(
                                "stock",
                                0
                            )
                        )
                    )

                except Exception:

                    return self.send_json(
                        {
                            "error":
                            "Precio o stock inválidos"
                        },
                        400
                    )


                product = {

                    "id":
                    secrets.token_hex(6),

                    "name":
                    name,

                    "brand":
                    brand,

                    "price":
                    price,

                    "stock":
                    stock,

                    "size":
                    str(
                        body.get(
                            "size",
                            ""
                        )
                    ).strip(),

                    "gender":
                    str(
                        body.get(
                            "gender",
                            "Unisex"
                        )
                    ).strip(),

                    "description":
                    str(
                        body.get(
                            "description",
                            ""
                        )
                    ).strip(),

                    "notes":
                    str(
                        body.get(
                            "notes",
                            ""
                        )
                    ).strip(),

                    "image":
                    body.get(
                        "imageData",
                        ""
                    ),

                    "featured":
                    bool(
                        body.get(
                            "featured",
                            False
                        )
                    )
                }


                created = create_product(
                    product
                )

                return self.send_json(
                    created,
                    201
                )


        except Exception as error:

            print(
                "ERROR DATABASE:",
                error
            )

            return self.send_json(
                {
                    "error":
                    "Error de base de datos"
                },
                500
            )


        return self.send_json(
            {
                "error":
                "Ruta no encontrada"
            },
            404
        )


    def do_PUT(self):

        path = urlparse(
            self.path
        ).path


        if (
            not path.startswith(
                "/api/admin/products/"
            )
            or not self.is_admin()
        ):

            return self.send_json(
                {"error": "No autorizado"},
                401
            )


        body = self.read_body_json()

        if body is None:

            return self.send_json(
                {"error": "Solicitud inválida"},
                400
            )


        product_id = path.rsplit(
            "/",
            1
        )[-1]


        try:

            updates = {}


            for key in [
                "name",
                "brand",
                "size",
                "gender",
                "description",
                "notes"
            ]:

                if key in body:

                    updates[key] = str(
                        body.get(
                            key,
                            ""
                        )
                    ).strip()


            if "price" in body:

                updates["price"] = float(
                    body["price"]
                )


            if "stock" in body:

                updates["stock"] = max(
                    0,
                    int(
                        body["stock"]
                    )
                )


            if "featured" in body:

                updates["featured"] = bool(
                    body["featured"]
                )


            if body.get("imageData"):

                updates["image"] = (
                    body["imageData"]
                )


            product = update_product(
                product_id,
                updates
            )


            if not product:

                return self.send_json(
                    {
                        "error":
                        "Producto no encontrado"
                    },
                    404
                )


            return self.send_json(
                product
            )


        except Exception as error:

            print(
                "ERROR DATABASE:",
                error
            )

            return self.send_json(
                {
                    "error":
                    "Error de base de datos"
                },
                500
            )


    def do_DELETE(self):

        path = urlparse(
            self.path
        ).path


        if (
            not path.startswith(
                "/api/admin/products/"
            )
            or not self.is_admin()
        ):

            return self.send_json(
                {"error": "No autorizado"},
                401
            )


        product_id = path.rsplit(
            "/",
            1
        )[-1]


        try:

            deleted = delete_product(
                product_id
            )


            if not deleted:

                return self.send_json(
                    {
                        "error":
                        "Producto no encontrado"
                    },
                    404
                )


            return self.send_json(
                {"ok": True}
            )


        except Exception as error:

            print(
                "ERROR DATABASE:",
                error
            )

            return self.send_json(
                {
                    "error":
                    "Error de base de datos"
                },
                500
            )


if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            "8000"
        )
    )

    print(
        f"Aurora Essence disponible en puerto {port}"
    )

    print(
        "Base de datos: Supabase persistente"
    )

    ThreadingHTTPServer(
        ("0.0.0.0", port),
        Handler
    ).serve_forever()
