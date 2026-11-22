#!/usr/bin/env python3
"""Rusdi Site - catalogo leve de sites de episodios.

Apenas biblioteca padrao do Python (sem pip). Pensado para rodar no Termux:
    python server.py            -> http://IP-DO-CELULAR:8089
Variaveis opcionais:
    RUSDI_PORT=8089   porta
    RUSDI_PIN=1234    exige PIN para ver/alterar a lista (recomendado fora de casa)
    RUSDI_DATA=...    caminho do arquivo de dados (padrao: sites.json ao lado do script)
    RUSDI_ALLOW_LAN=1 permite o "Abrir limpo" acessar enderecos da rede local (padrao: bloqueado)

"Abrir limpo": o celular abre o site no lugar da TV, remove scripts, iframes, pop-ups,
redirecionamentos e dominios de anuncios (lista abaixo + blocklist.txt opcional) e entrega
a pagina limpa. Sites que dependem de JavaScript para o player nao funcionam nesse modo.
"""
import hashlib
import gzip
import hmac
import html
import ipaddress
import json
import os
import re
import socket
import threading
import time
import uuid
import urllib.error
import urllib.request
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urljoin, urlparse

PORT = int(os.environ.get("RUSDI_PORT", "8089"))
PIN = os.environ.get("RUSDI_PIN", "")
DATA = os.environ.get("RUSDI_DATA", os.path.join(os.path.dirname(os.path.abspath(__file__)), "sites.json"))
MAX_ITEMS = 500
MAX_BODY = 16 * 1024
MAX_HTML = 4 * 1024 * 1024
ALLOW_LAN = os.environ.get("RUSDI_ALLOW_LAN") == "1"
UA = "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110 Safari/537.36"
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


# ---------------------------------------------------------------- Modo "Abrir limpo"
AD_DOMAINS = {
    "doubleclick.net", "googlesyndication.com", "googleadservices.com", "adservice.google.com",
    "google-analytics.com", "googletagmanager.com", "googletagservices.com", "adnxs.com", "adsrvr.org",
    "taboola.com", "outbrain.com", "criteo.com", "criteo.net", "popads.net", "popcash.net",
    "propellerads.com", "propellerclick.com", "exoclick.com", "exosrv.com", "juicyads.com",
    "trafficjunky.com", "adsterra.com", "hilltopads.net", "clickadu.com", "adcash.com",
    "onclickads.net", "a-ads.com", "mgid.com", "revcontent.com", "bidvertiser.com", "admaven.com",
    "ad-maven.com", "richads.com", "pubmatic.com", "rubiconproject.com", "openx.net", "amazon-adsystem.com",
    "facebook.net", "hotjar.com", "scorecardresearch.com", "yandex.ru", "adform.net", "smartadserver.com",
}
_extra = os.path.join(os.path.dirname(DATA), "blocklist.txt")
try:
    with open(_extra, encoding="utf-8") as _f:
        AD_DOMAINS |= {l.strip().lower() for l in _f if l.strip() and not l.startswith("#")}
except OSError:
    pass

DROP_TAGS = {"script", "iframe", "frame", "frameset", "object", "embed", "noscript", "applet"}
VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
LAZY_ATTRS = ("data-src", "data-original", "data-lazy-src", "data-lazy")
CSS_URL = re.compile(r"url\(\s*(['\"]?)([^)'\"]*)\1\s*\)", re.I)
CSS_IMPORT = re.compile(r"@import\s+(['\"])(.*?)\1", re.I)


class Blocked(Exception):
    pass


def is_ad_host(host):
    host = (host or "").lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in AD_DOMAINS)


def host_ok(host):
    """Evita que o proxy seja usado para alcancar a rede local (SSRF)."""
    if ALLOW_LAN:
        return True
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0].split("%")[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return False
    except (OSError, ValueError):
        return True  # falha de DNS: deixa o urllib relatar o erro real
    return True


def proxy_url(absolute):
    return "/p?u=" + quote(absolute, safe="")


def css_rewrite(text, base):
    def r(m):
        u = m.group(2).strip()
        if not u or u.startswith("data:"):
            return m.group(0)
        a = urljoin(base, u)
        return "url('%s')" % (proxy_url(a) if not is_ad_host(urlparse(a).hostname) else "")
    text = CSS_URL.sub(r, text)
    return CSS_IMPORT.sub(lambda m: "@import '%s'" % proxy_url(urljoin(base, m.group(2))), text)


class Cleaner(HTMLParser):
    """Reescreve o HTML: sem scripts/anuncios/redirecionamentos, links e recursos via /p."""

    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.out = []
        self.drop_tag = None
        self.drop_depth = 0
        self.in_style = False

    def abs(self, u):
        a = urljoin(self.base, u.strip())
        p = urlparse(a)
        if p.scheme not in ("http", "https") or is_ad_host(p.hostname):
            return None
        return a

    def start(self, tag, attrs):
        if self.drop_tag:
            if tag == self.drop_tag:
                self.drop_depth += 1
            return
        if tag in DROP_TAGS:
            if tag not in VOID_TAGS:
                self.drop_tag, self.drop_depth = tag, 1
            return
        d = {k.lower(): v for k, v in attrs}
        if tag == "base":
            if d.get("href"):
                self.base = urljoin(self.base, d["href"])
            return
        if tag == "meta" and (d.get("http-equiv") or "").lower() == "refresh":
            return  # redirecionamento automatico
        if tag == "link":
            rel = (d.get("rel") or "").lower()
            if any(x in rel for x in ("preload", "prefetch", "preconnect", "dns-prefetch", "modulepreload")):
                return
        if tag == "img":
            lazy = next((d[k] for k in LAZY_ATTRS if d.get(k)), None)
            if lazy:
                d["src"] = lazy
        keep = []
        for k, v in d.items():
            if k.startswith("on") or k in ("srcset", "sizes", "integrity", "crossorigin", "target", "nonce", "ping", "rel") and not (k == "rel" and tag == "link"):
                continue
            if v is None:
                keep.append((k, None))
                continue
            if k in ("href", "src", "action", "poster"):
                if v.startswith("#"):
                    keep.append((k, v))
                    continue
                if v.lower().startswith("data:") and k in ("src", "poster"):
                    keep.append((k, v))
                    continue
                a = self.abs(v)
                if a is None:
                    if tag in ("img", "source", "video", "audio", "track") or (tag == "link" and k == "href"):
                        return  # recurso de anuncio / invalido: descarta o elemento inteiro
                    continue
                keep.append((k, proxy_url(a)))
            elif k == "style":
                keep.append((k, css_rewrite(v, self.base)))
            elif k.startswith("data-") and k in LAZY_ATTRS:
                continue
            else:
                keep.append((k, v))
        attrs_s = "".join(" %s" % k if v is None else ' %s="%s"' % (k, html.escape(v, quote=True)) for k, v in keep)
        self.out.append("<%s%s>" % (tag, attrs_s))
        if tag == "style":
            self.in_style = True
        if tag == "body":
            self.out.append("<div style='background:#14110f;padding:8px'><a href='/' style='color:#f74c00;font:bold 22px sans-serif'>"
                            "&#9664; Rusdi Site &middot; modo limpo (sem scripts e anuncios)</a></div>")

    def handle_starttag(self, tag, attrs):
        self.start(tag, attrs)

    def handle_startendtag(self, tag, attrs):
        if tag in DROP_TAGS:
            return
        self.start(tag, attrs)

    def handle_endtag(self, tag):
        if self.drop_tag:
            if tag == self.drop_tag:
                self.drop_depth -= 1
                if self.drop_depth <= 0:
                    self.drop_tag = None
            return
        if tag == "style":
            self.in_style = False
        if tag not in VOID_TAGS and tag not in DROP_TAGS:
            self.out.append("</%s>" % tag)

    def handle_data(self, data):
        if self.drop_tag:
            return
        if self.in_style:
            self.out.append(css_rewrite(data, self.base))
        else:
            self.out.append(html.escape(data, quote=False))

    def handle_decl(self, decl):
        self.out.append("<!%s>" % decl)


class _Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        p = urlparse(urljoin(req.full_url, newurl))
        if p.scheme not in ("http", "https"):
            raise Blocked("redirecionamento invalido")
        if is_ad_host(p.hostname):
            raise Blocked("redirecionamento para anuncio bloqueado (%s)" % p.hostname)
        if not host_ok(p.hostname):
            raise Blocked("endereco da rede local nao permitido")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = urllib.request.build_opener(_Redirects)


def sniff_charset(raw, header_cs):
    cs = header_cs
    if not cs:
        m = re.search(rb"charset=[\"']?([\w-]+)", raw[:2048], re.I)
        cs = m.group(1).decode("ascii", "ignore") if m else "utf-8"
    try:
        return raw.decode(cs, "replace")
    except LookupError:
        return raw.decode("utf-8", "replace")


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
                   "<a class=b href='/p?u=%s'>Abrir limpo</a><a class=b href='/edit?id=%s'>Editar</a>"
                   "<form method=post action=/del style='display:inline' onsubmit=\"return confirm('Apagar este site da lista?')\">"
                   "<input type=hidden name=id value='%s'><button class='b d'>Apagar</button></form></div>"
                   % (esc(it.get("url", "")), esc(it.get("title", "")), note, esc(it.get("url", "")),
                      esc(quote(it.get("url", ""), safe="")), esc(it.get("id", "")), esc(it.get("id", ""))))
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


    def proxy(self, query):
        target = norm_url(parse_qs(query).get("u", [""])[0])
        back = "<a class=b href='/'>Voltar</a>"
        if not target:
            return self.send(400, page("<p class=e>Endereco invalido.</p>" + back))
        host = urlparse(target).hostname
        if is_ad_host(host):
            return self.send(403, page("<p class=e>Dominio de anuncio bloqueado: %s</p>%s" % (esc(host), back)))
        if not host_ok(host):
            return self.send(403, page("<p class=e>Enderecos da rede local nao sao permitidos.</p>" + back))
        req = urllib.request.Request(target, headers={"User-Agent": UA, "Accept": "*/*",
                                                      "Accept-Encoding": "gzip, identity", "Accept-Language": "pt-BR,pt;q=0.9"})
        if self.headers.get("Range"):
            req.add_header("Range", self.headers["Range"])
        try:
            resp = OPENER.open(req, timeout=15)
        except Blocked as e:
            return self.send(403, page("<p class=e>Bloqueado: %s</p>%s" % (esc(e), back)))
        except urllib.error.HTTPError as e:
            resp = e  # 404/403 etc. tambem sao respostas validas para repassar
        except (urllib.error.URLError, OSError, ValueError) as e:
            reason = getattr(e, "reason", e)
            return self.send(502, page("<p class=e>O celular nao conseguiu abrir o site: %s</p>%s" % (esc(reason), back)))
        status = getattr(resp, "status", None) or resp.code
        ctype = resp.headers.get("Content-Type", "application/octet-stream")
        final = resp.geturl()
        low = ctype.lower()
        if "text/html" in low or "application/xhtml" in low or "text/css" in low:
            raw = resp.read(MAX_HTML + 1)
            if len(raw) > MAX_HTML:
                return self.send(502, page("<p class=e>Pagina grande demais.</p>" + back))
            if resp.headers.get("Content-Encoding", "").lower() == "gzip":
                try:
                    raw = gzip.decompress(raw)
                except (OSError, EOFError):
                    return self.send(502, page("<p class=e>Resposta comprimida invalida.</p>" + back))
            text = sniff_charset(raw, resp.headers.get_content_charset())
            if "text/css" in low:
                body, out_type = css_rewrite(text, final).encode("utf-8"), "text/css; charset=utf-8"
            else:
                c = Cleaner(final)
                c.feed(text)
                c.close()
                body, out_type = "".join(c.out).encode("utf-8"), "text/html; charset=utf-8"
            return self.send(status, body, {"Content-Type": out_type})
        # demais tipos (imagens, video, fontes...): repassa em blocos, com suporte a Range
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        for h in ("Content-Length", "Content-Range", "Accept-Ranges", "Content-Encoding"):
            if resp.headers.get(h):
                self.send_header(h, resp.headers[h])
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        try:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass  # a TV fechou/pulou o trecho: normal em videos
        finally:
            resp.close()

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/login":
            return self.send(200, login_page())
        if not self.authed():
            return self.redirect("/login")
        if u.path == "/":
            return self.send(200, index_page())
        if u.path == "/p":
            return self.proxy(u.query)
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
