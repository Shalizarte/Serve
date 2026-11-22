#!/usr/bin/env python3
"""Rusdi Site - biblioteca leve de animes com episodios puxados dos sites que voce cadastra.

Apenas biblioteca padrao do Python (sem pip). Feito para rodar no Termux:
    python server.py            -> http://IP-DO-CELULAR:8089

Abas:
  Assistir   -> pesquisa e lista de animes; expanda o anime, depois a temporada, e toque no episodio.
  Adicionar  -> cole os links dos animes (um por linha); o servidor puxa temporadas e episodios.

Variaveis opcionais:
  RUSDI_PORT=8089    porta
  RUSDI_PIN=1234     exige PIN para abrir o site (recomendado fora de casa)
  RUSDI_DATA=...     arquivo de dados (padrao: animes.json ao lado do script)
  RUSDI_ALLOW_LAN=1  permite cadastrar enderecos da rede local (padrao: bloqueado)
"""
import gzip
import hashlib
import hmac
import html
import io
import ipaddress
import json
import os
import re
import socket
import threading
import time
import unicodedata
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urljoin, urlparse

PORT = int(os.environ.get("RUSDI_PORT", "8089"))
PIN = os.environ.get("RUSDI_PIN", "")
ALLOW_LAN = os.environ.get("RUSDI_ALLOW_LAN") == "1"
DATA = os.environ.get("RUSDI_DATA", os.path.join(os.path.dirname(os.path.abspath(__file__)), "animes.json"))
POSTERS = os.path.join(os.path.dirname(DATA), "posters")
MAX_ANIMES = 300
MAX_EPISODES = 3000
MAX_BATCH = 5
MAX_BODY = 16 * 1024
MAX_PAGE = 4 * 1024 * 1024
MAX_POSTER = 2 * 1024 * 1024
LOCK = threading.Lock()
TOKEN = hashlib.sha256(("rusdi:" + PIN).encode()).hexdigest()
UA = "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110 Mobile Safari/537.36"


# ------------------------------------------------------------------ dados
def load():
    try:
        with open(DATA, encoding="utf-8") as f:
            d = json.load(f)
        return [x for x in d if isinstance(x, dict) and x.get("id")] if isinstance(d, list) else []
    except (OSError, ValueError):
        return []


def save(items):
    tmp = DATA + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False)
    os.replace(tmp, DATA)  # troca atomica: nunca deixa o arquivo pela metade


def norm_url(u):
    u = (u or "").strip().replace(" ", "%20")
    if not u or len(u) > 500:
        return None
    if "://" not in u:
        u = "http://" + u
    try:
        p = urlparse(u)
        host = p.hostname
        p.port  # levanta ValueError se a porta nao for numerica
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not host or not re.fullmatch(r"[A-Za-z0-9._-]+|[0-9A-Fa-f:]+", host):
        return None
    return u


def fold(s):
    s = unicodedata.normalize("NFD", str(s).casefold())
    return "".join(c for c in s if unicodedata.category(c) != "Mn")


def total_eps(a):
    return sum(len(s.get("eps", [])) for s in a.get("seasons", []))


def ordered_eps(a):
    return [(s["n"], e) for s in a.get("seasons", []) for e in s.get("eps", [])]


# ------------------------------------------------------------------ rede / scraper
class FetchError(Exception):
    pass


def host_ok(host):
    """Impede usar o servidor para alcancar a rede local (SSRF)."""
    if ALLOW_LAN:
        return True
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0].split("%")[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return False
    except (OSError, ValueError):
        return True  # falha de DNS: o urllib relata o erro real
    return True


class _Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        p = urlparse(urljoin(req.full_url, newurl))
        if p.scheme not in ("http", "https") or not host_ok(p.hostname):
            raise FetchError("redirecionamento nao permitido")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = urllib.request.build_opener(_Redirects)


def fetch(url, max_bytes, accept="text/html,*/*"):
    p = urlparse(url)
    if not host_ok(p.hostname):
        raise FetchError("enderecos da rede local nao sao permitidos")
    req = urllib.request.Request(url, headers={
        "User-Agent": UA, "Accept": accept, "Accept-Language": "pt-BR,pt;q=0.9",
        "Accept-Encoding": "gzip, identity", "Referer": "%s://%s/" % (p.scheme, p.netloc)})
    try:
        with OPENER.open(req, timeout=20) as resp:
            raw = resp.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise FetchError("resposta grande demais")
            if resp.headers.get("Content-Encoding", "").lower() == "gzip":
                raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read(max_bytes * 4)
            return resp.geturl(), resp.headers.get("Content-Type", ""), raw, resp.headers.get_content_charset()
    except urllib.error.HTTPError as e:
        raise FetchError("o site respondeu HTTP %d" % e.code)
    except FetchError:
        raise
    except (urllib.error.URLError, OSError, ValueError, EOFError) as e:
        raise FetchError("nao consegui abrir o site (%s)" % getattr(e, "reason", e))


ANCHOR = re.compile(r"<a\b([^>]*)>(.*?)</a>", re.I | re.S)
HREF = re.compile(r"""href\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.I)
ATTR = re.compile(r"""([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')""")
EP_STRICT = re.compile(r"-(\d+)-(?:episodio|episode|ep)-(\d+)(?:-[a-z0-9-]*)?$", re.I)
EP_LOOSE = re.compile(r"(?<![a-z])(?:episodio|episode|ep)-(\d+)", re.I)
TAIL = re.compile(r"\s+(?:todos\s+(?:os\s+)?epis[oó]dios|online|assistir)\s*$", re.I)


def text_of(fragment):
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", fragment))).strip()


def meta(page, key):
    for m in re.finditer(r"<meta\b[^>]*>", page, re.I):
        a = {k.lower(): (v1 or v2) for k, v1, v2 in ATTR.findall(m.group(0))}
        if a.get("property", a.get("name", "")).lower() == key and a.get("content"):
            return html.unescape(a["content"]).strip()
    return ""


def clean_title(t):
    t = re.sub(r"\s*[-|–]\s*meus animes.*$", "", t, flags=re.I)
    prev = None
    while prev != t:
        prev, t = t, TAIL.sub("", t)
    return t.strip()


def parse_page(url, page):
    slug = urlparse(url).path.rstrip("/").rsplit("/", 1)[-1].lower()
    cands = []
    seen = set()
    for m in ANCHOR.finditer(page):
        h = HREF.search(m.group(1))
        if not h:
            continue
        href = html.unescape(h.group(1) or h.group(2) or "").strip()
        if not href or href.startswith(("#", "javascript:", "mailto:")):
            continue
        ep_url = urljoin(url, href).split("#")[0]
        p = urlparse(ep_url)
        if p.scheme not in ("http", "https") or ep_url in seen:
            continue
        seg = p.path.rstrip("/").rsplit("/", 1)[-1].lower()
        s = EP_STRICT.search(seg)
        if s:
            cands.append((0 if slug and seg.startswith(slug + "-") else 1, int(s.group(1)), int(s.group(2)), ep_url, text_of(m.group(2))))
            seen.add(ep_url)
            continue
        l = EP_LOOSE.search(seg)
        if l:
            cands.append((2, 1, int(l.group(1)), ep_url, text_of(m.group(2))))
            seen.add(ep_url)
    if not cands:
        raise FetchError("nenhum episodio encontrado nessa pagina")
    best = min(c[0] for c in cands)  # prefere os que combinam com o nome do anime
    chosen = {}
    for _, season, num, ep_url, label in sorted((c for c in cands if c[0] == best), key=lambda c: (c[1], c[2])):
        chosen.setdefault((season, num), {"n": num, "t": label if 0 < len(label) <= 60 and not label.isdigit() else "Episódio %d" % num, "u": ep_url})
    seasons = {}
    for (season, _), ep in chosen.items():
        seasons.setdefault(season, []).append(ep)
    out = [{"n": n, "eps": eps[:MAX_EPISODES]} for n, eps in sorted(seasons.items())]
    title = clean_title(meta(page, "og:title"))
    if not title:
        h1 = re.search(r"<h1[^>]*>(.*?)</h1>", page, re.I | re.S)
        title = clean_title(text_of(h1.group(1))) if h1 else ""
    if not title:
        title = slug.replace("-", " ").title() or url
    poster = meta(page, "og:image")
    return {"title": title[:150], "desc": meta(page, "og:description")[:400],
            "poster": urljoin(url, poster) if poster else "", "seasons": out}


def scrape(url):
    final, ctype, raw, cs = fetch(url, MAX_PAGE)
    m = re.search(rb"charset=[\"']?([\w-]+)", raw[:2048], re.I)
    enc = cs or (m.group(1).decode("ascii", "ignore") if m else "utf-8")
    try:
        text = raw.decode(enc, "replace")
    except LookupError:
        text = raw.decode("utf-8", "replace")
    return parse_page(final, text)


def save_poster(aid, purl):
    try:
        _, ctype, raw, _ = fetch(purl, MAX_POSTER, "image/*")
    except FetchError:
        return None
    ctype = ctype.split(";")[0].strip().lower()
    if not ctype.startswith("image/") or not raw:
        return None
    try:
        os.makedirs(POSTERS, exist_ok=True)
        path = os.path.join(POSTERS, aid)
        with open(path + ".tmp", "wb") as f:
            f.write(raw)
        os.replace(path + ".tmp", path)
    except OSError:
        return None
    return ctype


def add_one(raw_url):
    url = norm_url(raw_url)
    if not url:
        return False, "endereco invalido (%s)" % raw_url[:60]
    items = load()
    if any(a.get("url") == url for a in items):
        return False, "ja esta na lista (%s)" % url[:60]
    if len(items) >= MAX_ANIMES:
        return False, "limite de %d animes atingido" % MAX_ANIMES
    try:
        info = scrape(url)
    except FetchError as e:
        return False, "%s: %s" % (url[:60], e)
    aid = uuid.uuid4().hex[:8]
    ptype = save_poster(aid, info["poster"]) if info["poster"] else None
    rec = {"id": aid, "url": url, "title": info["title"], "desc": info["desc"], "seasons": info["seasons"],
           "poster_type": ptype, "watched": [], "last": 0, "added": int(time.time()), "updated": int(time.time())}
    with LOCK:
        items = load()
        if any(a.get("url") == url for a in items):
            return False, "ja esta na lista"
        items.append(rec)
        save(items)
    return True, "%s (%d episodios)" % (rec["title"], total_eps(rec))


def refresh_one(aid):
    a = next((x for x in load() if x["id"] == aid), None)
    if not a:
        return False, "anime nao encontrado"
    try:
        info = scrape(a["url"])
    except FetchError as e:
        return False, "%s: %s" % (a.get("title", "?"), e)
    ptype = a.get("poster_type")
    if info["poster"] and not (ptype and os.path.exists(os.path.join(POSTERS, aid))):
        ptype = save_poster(aid, info["poster"]) or ptype
    with LOCK:
        items = load()
        cur = next((x for x in items if x["id"] == aid), None)
        if not cur:
            return False, "anime removido"
        before = total_eps(cur)
        urls = {e["u"] for s in info["seasons"] for e in s["eps"]}
        cur.update(title=info["title"], desc=info["desc"], seasons=info["seasons"], poster_type=ptype,
                   watched=[u for u in cur.get("watched", []) if u in urls], updated=int(time.time()),
                   current=cur.get("current", "") if cur.get("current", "") in urls else "")
        save(items)
    now = total_eps(cur)
    return True, "%s: %d episodios%s" % (cur["title"], now, " (+%d novos)" % (now - before) if now > before else "")


# ------------------------------------------------------------------ paginas
CSS = """
:root{--bg:#0f0d0c;--c1:#1d1917;--c2:#2a2421;--ac:#f74c00;--ac2:#ff8a3d;--tx:#f3efeb;--mu:#9a918b}
*{box-sizing:border-box}
html{background:var(--bg);color:var(--tx);font:18px/1.45 -apple-system,"Segoe UI",Roboto,sans-serif}
@media(min-width:1200px){html{font-size:28px}}
body{margin:0}a{color:var(--ac2)}
.top{position:sticky;top:0;z-index:5;display:flex;gap:8px;align-items:center;padding:10px 14px;background:rgba(15,13,12,.97);border-bottom:1px solid #2a2523}
.lg{font-weight:800;color:var(--ac);margin-right:auto;font-size:1.1em;letter-spacing:.5px}
.tab{padding:9px 18px;border-radius:999px;color:var(--mu);text-decoration:none;font-weight:700}
.tab.on{background:linear-gradient(135deg,var(--ac),var(--ac2));color:#fff}
.w{max-width:1000px;margin:0 auto;padding:14px}
h2{margin:.2em 0 .4em;font-size:1.1em}.mu{color:var(--mu)}.sm{font-size:.8em}
input,textarea,button{font:inherit;color:var(--tx);border-radius:12px;border:2px solid #3a322f;background:var(--c1);padding:12px 14px;width:100%}
textarea{min-height:5em;resize:vertical}
button,.btn{background:linear-gradient(135deg,var(--ac),var(--ac2));border:0;color:#fff;font-weight:700;cursor:pointer;text-decoration:none;display:inline-block;width:auto;padding:11px 20px}
button.s,.btn.s{background:var(--c2);color:var(--tx)}button.d{background:#7d2a14}
.sr{display:flex;gap:8px;margin:6px 0 12px}.sr button{flex:none}
.msg{padding:12px 14px;border-radius:12px;margin:8px 0;background:#1f3a22;color:#b8f0b0}.msg.err{background:#4a1d14;color:#ffc2b0}
details.an{background:var(--c1);border-radius:18px;margin:12px 0;overflow:hidden;border:1px solid #2a2523}
summary{cursor:pointer;list-style:none;outline:none}summary::-webkit-details-marker{display:none}
.an>summary{display:flex;gap:14px;padding:12px;align-items:center}
.po{width:76px;height:112px;border-radius:10px;object-fit:cover;background:linear-gradient(135deg,#3a2a24,#241d1a);flex:none}
.nm{flex:1;min-width:0}.nm b{display:block;font-size:1.05em;word-break:break-word}.nm .mu{display:block}
.bt{display:inline-block;margin-top:6px;padding:5px 14px;border-radius:999px;background:var(--c2);font-size:.8em;font-weight:700}
.an:not([open])>summary .bt::before{content:"Expandir \\25BE"}.an[open]>summary .bt::before{content:"Recolher \\25B4"}
.se:not([open])>summary .bt::before{content:"Abrir \\25BE"}.se[open]>summary .bt::before{content:"Fechar \\25B4"}
.an>summary:focus,.se>summary:focus,.ep:focus,a:focus,button:focus,input:focus,textarea:focus{outline:4px solid #fff}
.bd{padding:2px 12px 14px}.cb{margin:4px 0 10px}
details.se{background:var(--c2);border-radius:14px;margin:8px 0}
.se>summary{display:flex;justify-content:space-between;align-items:center;padding:12px 14px;font-weight:700}
.se>summary .bt{margin:0;background:#3a312d}
.eps{display:grid;grid-template-columns:repeat(auto-fill,minmax(64px,1fr));gap:8px;padding:4px 12px 14px}
.ep{display:block;text-align:center;padding:12px 0;border-radius:10px;background:#3a312d;color:var(--tx);text-decoration:none;font-weight:700}
.ep.v{background:#26402a;color:#a6e89c}.ep.c{background:#7a4a08;color:#ffd58a;box-shadow:0 0 0 2px #ffb347 inset}
.row{background:var(--c1);border-radius:14px;padding:12px 14px;margin:10px 0;border:1px solid #2a2523}
.row b{display:block;word-break:break-word}.row form{display:inline}.row .btn,.row button{margin:8px 8px 0 0;padding:9px 16px}
.empty{text-align:center;padding:40px 10px;color:var(--mu)}
"""

JS = """(function(){var K="rusdi.open",s={};try{s=JSON.parse(localStorage.getItem(K)||"{}")}catch(e){}
var d=document.querySelectorAll("details[data-k]");
for(var i=0;i<d.length;i++){(function(el){var k=el.getAttribute("data-k");if(s[k])el.open=true;
el.addEventListener("toggle",function(){if(el.open)s[k]=1;else delete s[k];try{localStorage.setItem(K,JSON.stringify(s))}catch(e){}})})(d[i])}})();"""


def esc(s):
    return html.escape(str(s), quote=True)


def layout(body, tab, flash=""):
    nav = "".join("<a class='tab%s' href='%s'>%s</a>" % (" on" if tab == k else "", h, t)
                  for k, h, t in (("w", "/", "Assistir"), ("a", "/add", "Adicionar")))
    doc = ("<!doctype html><html lang=pt-BR><head><meta charset=utf-8>"
           "<meta name=viewport content='width=device-width,initial-scale=1'><title>Rusdi Site</title>"
           "<style>%s</style></head><body><div class=top><span class=lg>RUSDI</span>%s</div>"
           "<div class=w>%s%s</div><script>%s</script></body></html>" % (CSS, nav, flash, body, JS))
    return doc.encode("utf-8")


def flash_html(kind, msg):
    if not msg:
        return ""
    return "<div class='msg%s'>%s</div>" % (" err" if kind == "err" else "", esc(msg))


def ep_label(a, url):
    for sn, e in ordered_eps(a):
        if e["u"] == url:
            return "T%d Ep %d" % (sn, e["n"])
    return ""


def next_up(a):
    watched = set(a.get("watched", []))
    eps = ordered_eps(a)
    cur = a.get("current", "")
    aid = esc(a["id"])
    if cur and ep_label(a, cur):
        return ("<div class=cb><a class=btn href='/ver?a=%s&amp;u=%s'>&#9654; Continuar &middot; %s</a> "
                "<form method=post action=/done style='display:inline'><input type=hidden name=id value='%s'>"
                "<button class=s>&#10003; Terminei</button></form></div>" % (aid, esc(quote(cur, safe="")), ep_label(a, cur), aid))
    last = next((i for i, (_, e) in enumerate(eps) if e["u"] == a.get("last_u")), -1)
    nxt = (next(((sn, e) for sn, e in eps[last + 1:] if e["u"] not in watched), None)
           or next(((sn, e) for sn, e in eps if e["u"] not in watched), None))
    if not nxt:
        return "<div class='cb mu'>&#10003; Tudo visto</div>"
    verb = "Próximo" if watched else "Começar"
    return "<a class='btn cb' href='/ver?a=%s&amp;u=%s'>&#9654; %s &middot; T%d Ep %d</a>" % (
        aid, esc(quote(nxt[1]["u"], safe="")), verb, nxt[0], nxt[1]["n"])


def anime_card(a):
    aid = esc(a["id"])
    watched = set(a.get("watched", []))
    seasons = a.get("seasons", [])
    seen = sum(1 for _, e in ordered_eps(a) if e["u"] in watched)
    poster = "<img class=po src='/img/%s' alt='' loading=lazy>" % aid if a.get("poster_type") else "<div class=po></div>"
    meta_s = "%d temporada%s &middot; %d episódios%s" % (
        len(seasons), "" if len(seasons) == 1 else "s", total_eps(a), (" &middot; assistindo %s" % ep_label(a, a.get("current", "")) if ep_label(a, a.get("current", "")) else "")
        + (" &middot; %d vistos" % seen if seen else ""))
    out = ["<details class=an data-k='a%s'><summary>%s<div class=nm><b>%s</b><span class='mu sm'>%s</span>"
           "<span class=bt></span></div></summary><div class=bd>%s" % (aid, poster, esc(a["title"]), meta_s, next_up(a))]
    for s in seasons:
        links = "".join("<a class='ep%s' href='/ver?a=%s&amp;u=%s' title='%s'>%d</a>" % (
            " c" if e["u"] == a.get("current") else (" v" if e["u"] in watched else ""),
            aid, esc(quote(e["u"], safe="")), esc(e["t"]), e["n"]) for e in s["eps"])
        out.append("<details class=se data-k='a%ss%d'><summary><span>Temporada %d <span class='mu sm'>&middot; %d eps</span></span>"
                   "<span class=bt></span></summary><div class=eps>%s</div></details>" % (aid, s["n"], s["n"], len(s["eps"]), links))
    out.append("</div></details>")
    return "".join(out)


def watch_page(q=""):
    items = load()
    if q:
        fq = fold(q)
        items = [a for a in items if fq in fold(a.get("title", ""))]
    items.sort(key=lambda a: (0 if a.get("last") else 1, -a.get("last", 0), fold(a.get("title", ""))))
    form = ("<form class=sr method=get action=/><input name=q placeholder='Pesquisar anime...' value='%s' maxlength=80>"
            "<button>Buscar</button></form>" % esc(q))
    if items:
        body = "".join(anime_card(a) for a in items)
    elif q:
        body = "<div class=empty>Nenhum anime encontrado para &ldquo;%s&rdquo;.</div>" % esc(q)
    else:
        body = "<div class=empty>Nenhum anime ainda.<br>Vá na aba <b>Adicionar</b> e cole o link de um anime.</div>"
    return layout(form + body, "w")


def add_page(kind="", msg=""):
    items = sorted(load(), key=lambda a: fold(a.get("title", "")))
    form = ("<h2>Adicionar animes</h2><form method=post action=/add>"
            "<textarea name=urls placeholder='Cole aqui o link da página do anime (um por linha, até %d)&#10;"
            "ex.: https://meusanimes.blog/a/fullmetal-alchemist-brotherhood-dublado/' required></textarea><br>"
            "<button>Adicionar e puxar episódios</button></form>" % MAX_BATCH)
    rows = []
    for a in items:
        i = esc(a["id"])
        when = time.strftime("%d/%m/%Y %H:%M", time.localtime(a.get("updated", 0))) if a.get("updated") else "-"
        rows.append("<div class=row><b>%s</b><span class='mu sm'>%d episódios &middot; atualizado %s</span><br>"
                    "<form method=post action=/refresh><input type=hidden name=id value='%s'><button class=s>Atualizar</button></form>"
                    "<form method=post action=/unwatch><input type=hidden name=id value='%s'><button class=s>Limpar vistos</button></form>"
                    "<form method=post action=/del onsubmit=\"return confirm('Remover este anime da lista?')\">"
                    "<input type=hidden name=id value='%s'><button class=d>Remover</button></form></div>" % (esc(a["title"]), total_eps(a), when, i, i, i))
    lst = "<h2 style='margin-top:1.2em'>Na lista (%d)</h2>" % len(items)
    if items:
        lst += ("<form method=post action=/refresh><input type=hidden name=id value=all><button class=s>Atualizar todos</button></form>" + "".join(rows))
    else:
        lst += "<div class=empty>Lista vazia.</div>"
    return layout(form + lst, "a", flash_html(kind, msg))


def login_page(bad=False):
    e = "<div class='msg err'>PIN incorreto.</div>" if bad else ""
    return layout("<h2>Entrar</h2>%s<form method=post action=/login><input name=pin type=password placeholder=PIN autofocus>"
                  "<br><button>Entrar</button></form>" % e, "")


# ------------------------------------------------------------------ servidor
class Handler(BaseHTTPRequestHandler):
    server_version = "RusdiSite"

    def log_message(self, *a):
        pass

    def send(self, code, body=b"", extra=None):
        headers = {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"}
        headers.update(extra or {})
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers.items():
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

    def flash_redirect(self, kind, msg):
        self.redirect("/add?k=%s&m=%s" % (kind, quote(msg[:600])))

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/login":
            return self.send(200, login_page())
        if not self.authed():
            return self.redirect("/login")
        if u.path == "/":
            return self.send(200, watch_page(q.get("q", "").strip()[:80]))
        if u.path == "/add":
            return self.send(200, add_page(q.get("k", ""), q.get("m", "")[:600]))
        if u.path.startswith("/img/"):
            return self.poster(u.path[5:])
        if u.path == "/ver":
            return self.watch(q.get("a", ""), q.get("u", ""))
        self.send(404, layout("<div class=empty>Página não encontrada.</div>", ""))

    def poster(self, aid):
        a = next((x for x in load() if x["id"] == aid), None)
        if not a or not a.get("poster_type") or not re.fullmatch(r"[0-9a-f]{8}", aid):
            return self.send(404, b"")
        try:
            with open(os.path.join(POSTERS, aid), "rb") as f:
                data = f.read()
        except OSError:
            return self.send(404, b"")
        self.send(200, data, {"Content-Type": a["poster_type"], "Cache-Control": "public, max-age=86400"})

    def watch(self, aid, url):
        with LOCK:
            items = load()
            a = next((x for x in items if x["id"] == aid), None)
            if not a or not any(e["u"] == url for _, e in ordered_eps(a)):
                return self.redirect("/")  # so abre episodios que pertencem a um anime da lista
            order = [e["u"] for _, e in ordered_eps(a)]
            prev = a.get("current", "")
            watched = a.setdefault("watched", [])
            # avancou para um episodio posterior: considera o anterior concluido
            if prev and prev != url and prev in order and order.index(url) > order.index(prev) and prev not in watched:
                watched.append(prev)
            if url in watched and url != prev:
                watched.remove(url)  # reassistindo: volta a "assistindo"
            a["current"] = url
            a["last"] = int(time.time())
            a["last_u"] = url
            save(items)
        self.redirect(url)

    def do_POST(self):
        f = self.form()
        if f is None:
            return self.send(413, layout("<div class='msg err'>Pedido grande demais.</div>", ""))
        path = urlparse(self.path).path
        if path == "/login":
            if PIN and hmac.compare_digest(f.get("pin", ""), PIN):
                return self.redirect("/", {"Set-Cookie": "rp=%s; Max-Age=31536000; Path=/; HttpOnly" % TOKEN})
            return self.send(401, login_page(True))
        if not self.authed():
            return self.redirect("/login")
        if path == "/add":
            urls = [x for x in re.split(r"[\s,]+", f.get("urls", "")) if x][:MAX_BATCH]
            if not urls:
                return self.flash_redirect("err", "Cole pelo menos um link.")
            res = [add_one(x) for x in urls]
            ok = [m for good, m in res if good]
            bad = [m for good, m in res if not good]
            msg = ("Adicionado: " + "; ".join(ok) if ok else "") + (" | " if ok and bad else "") + ("Falhou: " + "; ".join(bad) if bad else "")
            return self.flash_redirect("ok" if ok and not bad else "err", msg)
        if path == "/refresh":
            ids = [a["id"] for a in load()] if f.get("id") == "all" else [f.get("id", "")]
            res = [refresh_one(i) for i in ids]
            bad = [m for good, m in res if not good]
            msg = "Atualizado: %d de %d." % (len(res) - len(bad), len(res)) + (" Falhou: " + "; ".join(bad) if bad else "")
            if len(res) == 1:
                msg = res[0][1]
            return self.flash_redirect("err" if bad else "ok", msg)
        if path == "/done":
            with LOCK:
                items = load()
                a = next((x for x in items if x["id"] == f.get("id")), None)
                if a and a.get("current"):
                    if a["current"] not in a.setdefault("watched", []):
                        a["watched"].append(a["current"])
                    a["current"] = ""
                    save(items)
            return self.redirect("/")
        if path in ("/del", "/unwatch"):
            with LOCK:
                items = load()
                if path == "/del":
                    items = [a for a in items if a["id"] != f.get("id")]
                    try:
                        os.remove(os.path.join(POSTERS, f.get("id", "x")))
                    except OSError:
                        pass
                else:
                    for a in items:
                        if a["id"] == f.get("id"):
                            a["watched"], a["last"], a["last_u"], a["current"] = [], 0, "", ""
                try:
                    save(items)
                except OSError as e:
                    return self.flash_redirect("err", "Nao foi possivel salvar: %s" % e)
            return self.flash_redirect("ok", "Removido." if path == "/del" else "Vistos limpos.")
        self.send(404, layout("<div class=empty>Não encontrado.</div>", ""))


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
