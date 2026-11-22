#!/usr/bin/env python3
"""Rusdi Site - catalogo leve de sites de episodios.

Apenas biblioteca padrao do Python (sem pip). Pensado para rodar no Termux:
    python server.py            -> http://IP-DO-CELULAR:8089
Variaveis opcionais:
    RUSDI_PORT=8089   porta
    RUSDI_PIN=1234    exige PIN para ver/alterar a lista (recomendado fora de casa)
    RUSDI_DATA=...    caminho do arquivo de dados (padrao: sites.json ao lado do script)
"""
import hashlib
import hmac
import html
import json
import os
import re
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PORT = int(os.environ.get("RUSDI_PORT", "8089"))
PIN = os.environ.get("RUSDI_PIN", "")
DATA = os.environ.get("RUSDI_DATA", os.path.join(os.path.dirname(os.path.abspath(__file__)), "sites.json"))
MAX_ITEMS = 500
MAX_BODY = 16 * 1024
LOCK = threading.Lock()
TOKEN = hashlib.sha256(("rusdi:" + PIN).encode()).hexdigest()

CSS = """
html{background:#14110f;color:#f0ece8;font:20px/1.4 sans-serif}
@media(min-width:1200px){html{font-size:30px}}
body{margin:0}.w{max-width:1100px;margin:0 auto;padding:16px}
h1{color:#f74c00;margin:.3em 0}a{color:#f74c00}
.i{background:#26211e;border-radius:10px;margin:12px 0;padding:12px 16px}
a.o{display:block;font-weight:bold;color:#f0ece8;text-decoration:none;padding:6px 0;word-break:break-word}
.n{color:#968e88;display:block;word-break:break-word}.u{color:#6f6862;font-size:.7em;word-break:break-all}
input,button{font:inherit;box-sizing:border-box;width:100%;padding:12px;margin:6px 0;border-radius:8px;border:2px solid #4a423d;background:#1c1816;color:#fff}
button,.b{background:#f74c00;border:0;color:#fff;font-weight:bold;cursor:pointer}
.d{background:#8a2a14}.b{display:inline-block;width:auto;padding:12px 24px;text-decoration:none;margin:6px 10px 6px 0}
a:focus,button:focus,input:focus{outline:4px solid #fff}.e{background:#5a1f12;padding:10px;border-radius:8px}
"""


def load():
    try:
        with open(DATA, encoding="utf-8") as f:
            d = json.load(f)
        return [x for x in d if isinstance(x, dict)] if isinstance(d, list) else []
    except (OSError, ValueError):
        return []


def save(items):
    tmp = DATA + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False, indent=1)
    os.replace(tmp, DATA)  # troca atomica: nunca deixa o arquivo pela metade


def norm_url(u):
    u = (u or "").strip()
    if not u or len(u) > 500:
        return None
    u = u.replace(" ", "%20")
    if "://" not in u:
        u = "http://" + u
    try:
        p = urlparse(u)
        host = p.hostname
        p.port  # levanta ValueError se a porta nao for numerica
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not host:
        return None
    if not re.fullmatch(r"[A-Za-z0-9._-]+|[0-9A-Fa-f:]+", host):
        return None
    return u


def esc(s):
    return html.escape(str(s), quote=True)


def page(body):
    doc = ("<!doctype html><html lang=pt-BR><head><meta charset=utf-8>"
           "<meta name=viewport content='width=device-width,initial-scale=1'>"
           "<title>Rusdi Site</title><style>%s</style></head><body><div class=w>%s</div></body></html>" % (CSS, body))
    return doc.encode("utf-8")


def form_fields(it):
    return ("<input name=title placeholder='Titulo (ex.: Naruto)' maxlength=120 required value='%s'>"
            "<input name=url placeholder='Endereco do site (ex.: exemplo.com/naruto)' maxlength=500 required value='%s'>"
            "<input name=note placeholder='Nota (ex.: parei no ep 12)' maxlength=300 value='%s'>"
            % (esc(it.get("title", "")), esc(it.get("url", "")), esc(it.get("note", ""))))


def index_page(error="", form=None):
    items = load()
    out = ["<h1>Rusdi Site</h1>"]
    if error:
        out.append("<p class=e>%s</p>" % esc(error))
    out.append("<form method=post action=/add>%s<button>Adicionar</button></form>" % form_fields(form or {}))
    if not items:
        out.append("<p class=n>Nenhum site salvo ainda.</p>")
    for it in items:
        note = "<span class=n>%s</span>" % esc(it["note"]) if it.get("note") else ""
        out.append("<div class=i><a class=o href='%s'>%s</a>%s<span class=u>%s</span>"
                   "<a class=b href='/edit?id=%s'>Editar</a></div>"
                   % (esc(it.get("url", "")), esc(it.get("title", "")), note, esc(it.get("url", "")), esc(it.get("id", ""))))
    return page("".join(out))


def edit_page(it):
    i = esc(it["id"])
    return page("<h1>Editar</h1><form method=post action=/save><input type=hidden name=id value='%s'>%s"
                "<button>Salvar</button></form><a class=b href='/'>Cancelar</a>"
                "<form method=post action=/del><input type=hidden name=id value='%s'><button class=d>Excluir</button></form>"
                % (i, form_fields(it), i))


def login_page(error=""):
    e = "<p class=e>PIN incorreto.</p>" if error else ""
    return page("<h1>Rusdi Site</h1>%s<form method=post action=/login>"
                "<input name=pin type=password placeholder=PIN autofocus><button>Entrar</button></form>" % e)


class Handler(BaseHTTPRequestHandler):
    server_version = "RusdiSite"

    def log_message(self, *a):
        pass

    def send(self, code, body=b"", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, to, extra=None):
        self.send(303, b"", dict({"Location": to}, **(extra or {})))

    def authed(self):
        if not PIN:
            return True
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "rp" and hmac.compare_digest(v, TOKEN):
                return True
        return False

    def form(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        if n < 0 or n > MAX_BODY:
            return None
        raw = self.rfile.read(n).decode("utf-8", "replace")
        return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/login":
            return self.send(200, login_page())
        if not self.authed():
            return self.redirect("/login")
        if u.path == "/":
            return self.send(200, index_page())
        if u.path == "/edit":
            wanted = parse_qs(u.query).get("id", [""])[0]
            for it in load():
                if it.get("id") == wanted:
                    return self.send(200, edit_page(it))
            return self.redirect("/")
        self.send(404, page("<h1>404</h1><a class=b href='/'>Voltar</a>"))

    def do_POST(self):
        f = self.form()
        if f is None:
            return self.send(413, page("<p class=e>Pedido grande demais.</p>"))
        path = urlparse(self.path).path
        if path == "/login":
            if PIN and hmac.compare_digest(f.get("pin", ""), PIN):
                return self.redirect("/", {"Set-Cookie": "rp=%s; Max-Age=31536000; Path=/; HttpOnly" % TOKEN})
            return self.send(401, login_page(error=True))
        if not self.authed():
            return self.redirect("/login")

        title = f.get("title", "").strip()[:120]
        note = f.get("note", "").strip()[:300]
        url = norm_url(f.get("url"))
        if path in ("/add", "/save"):
            if not title or not url:
                msg = "Informe um titulo e um endereco http(s) valido."
                return self.send(400, index_page(msg, {"title": title, "url": f.get("url", ""), "note": note}))
        with LOCK:
            items = load()
            if path == "/add":
                if len(items) >= MAX_ITEMS:
                    return self.send(400, index_page("Limite de %d sites atingido." % MAX_ITEMS))
                items.insert(0, {"id": uuid.uuid4().hex[:8], "title": title, "url": url, "note": note, "ts": int(time.time())})
            elif path == "/save":
                for it in items:
                    if it.get("id") == f.get("id"):
                        it.update(title=title, url=url, note=note)
            elif path == "/del":
                items = [it for it in items if it.get("id") != f.get("id")]
            else:
                return self.send(404, page("<h1>404</h1>"))
            try:
                save(items)
            except OSError as e:
                return self.send(500, page("<p class=e>Nao foi possivel salvar: %s</p>" % esc(e)))
        self.redirect("/")


def lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))  # nao envia nada; so descobre a interface
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "IP-DO-CELULAR"


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("Rusdi Site rodando. Abra na TV/celular: http://%s:%d" % (lan_ip(), PORT))
    print("PIN:", "ativado" if PIN else "desativado (defina RUSDI_PIN para proteger)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrado.")
