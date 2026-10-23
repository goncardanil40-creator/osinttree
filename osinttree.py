#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
#  ██████╗ ███████╗██╗███╗   ██╗████████╗████████╗██████╗ ███████╗███████╗
#  ██╔══██╗██╔════╝██║████╗  ██║╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝
#  ██████╔╝███████╗██║██╔██╗ ██║   ██║      ██║   ██████╔╝█████╗  █████╗
#  ██╔══██╗╚════██║██║██║╚██╗██║   ██║      ██║   ██╔══██╗██╔══╝  ██╔══╝
#  ██████╔╝███████║██║██║ ╚████║   ██║      ██║   ██║  ██║███████╗███████╗
#  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝
# ----------------------------------------------------------------------------
#  OSINT TREE — многофункциональный CLI-комбайн для разведки по ОТКРЫТЫМ данным.
#
#  СОЗДАТЕЛЬ: @loomaxer
#  TELEGRAM : https://t.me/loomaxer
#
#  Модули: поиск никнеймов по 40+ площадкам, разбор email, DNS/WHOIS/CT-логи,
#  IP-геолокация, разбор телефонов, извлечение метаданных (EXIF/PDF/DOCX),
#  разведка веб-ресурса, экспорт отчётов в JSON / CSV / HTML.
#
#  Только стандартная библиотека Python 3.8+. Никаких pip install.
#  Инструмент работает исключительно с публичными данными и не выполняет
#  атак, брутфорса или обхода аутентификации. Соблюдайте ToS площадок и
#  законодательство своей страны. Ответственность за использование — на вас.
#
#  © 2026 @loomaxer · t.me/loomaxer
# ============================================================================

"""
OSINT Tree — главный модуль CLI.

Примеры:
    python3 osinttree.py user loomaxer
    python3 osinttree.py email test@example.com --html report.html
    python3 osinttree.py domain example.com --json out.json
    python3 osinttree.py ip 8.8.8.8
    python3 osinttree.py phone +77051234567
    python3 osinttree.py meta photo.jpg
    python3 osinttree.py url https://example.com
"""

import argparse
import csv
import hashlib
import html as html_mod
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

# ============================================================================
#  МЕТАДАННЫЕ И ВОДЯНОЙ ЗНАК СОЗДАТЕЛЯ — @loomaxer (https://t.me/loomaxer)
# ============================================================================
__title__ = "OSINT Tree"
__version__ = "1.0.0"
__author__ = "@loomaxer"
__telegram__ = "https://t.me/loomaxer"
WATERMARK = "OSINT Tree · создатель: @loomaxer · t.me/loomaxer"
WATERMARK_LINE = "─" * 64 + "\n  ▲ " + WATERMARK + "\n" + "─" * 64

USER_AGENT = "Mozilla/5.0 (compatible; OSINTTree/1.0; +https://t.me/loomaxer)"
DEFAULT_TIMEOUT = 12


# ============================================================================
#  ЦВЕТНОЙ ВЫВОД
# ============================================================================
class C:
    """ANSI-цвета (автоотключение для не-TTY и NO_COLOR)."""

    ON = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    R = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"

    @classmethod
    def p(cls, color, text):
        if not cls.ON:
            return str(text)
        return f"{color}{text}{cls.R}"


BANNER = r"""
   ╔═╗╔═╗╦╔╗╔╔╦╗╔╦╗╦═╗╔═╗╔═╗
   ║ ║╚═╗║║║║ ║  ║ ╠╦╝║╣ ║╣
   ╚═╝╚═╝╩╝╚╝ ╩  ╩ ╩╚═╚═╝╚═╝  """ + C.p(C.CYAN, "v" + __version__) + """
   """ + C.p(C.BOLD, "открытые источники · дерево разведки") + """
   """ + C.p(C.MAGENTA, "создатель: @loomaxer · t.me/loomaxer")


def print_banner():
    print(C.p(C.CYAN, BANNER))
    print()


def kv(key, value, color=C.BLUE):
    print(f"  {C.p(color, key + ':'):<22} {value}")


def stamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def result_skeleton(module, target):
    """Каркас любого отчёта — водяной знак @loomaxer внутри каждого файла."""
    return {
        "tool": __title__,
        "version": __version__,
        "module": module,
        "target": target,
        "generated_at_utc": stamp(),
        "creator": __author__,
        "creator_telegram": __telegram__,
        "watermark": WATERMARK,
        "rows": [],
        "data": {},
    }


# ============================================================================
#  HTTP-КЛИЕНТ
# ============================================================================
def http_get(url, timeout=DEFAULT_TIMEOUT, max_bytes=300_000):
    """GET без зависимостей. Возвращает (status, headers, body_text)."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(max_bytes)
            return resp.status, dict(resp.headers), body.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(max_bytes)
        except Exception:
            pass
        return e.code, dict(e.headers or {}), body.decode("utf-8", "replace")
    except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as e:
        return None, {}, f"__error__:{e}"


# ============================================================================
#  МИНИ DNS-РЕЗОЛЬВЕР НА СЫРЫХ UDP-ПАКЕТАХ (без сторонних библиотек)
#  создано @loomaxer — https://t.me/loomaxer
# ============================================================================
RTYPE_IDS = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}
RTYPE_NAMES = {v: k for k, v in RTYPE_IDS.items()}


def _dns_servers():
    servers = []
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            if line.startswith("nameserver"):
                servers.append(line.split()[1])
    except Exception:
        pass
    servers.extend(["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    return servers


def _encode_name(name):
    out = b""
    for label in name.strip(".").split("."):
        if not label:
            continue
        b = label.encode("ascii", "replace")
        out += bytes([min(len(b), 63)]) + b[:63]
    return out + b"\x00"


def _read_name(data, offset):
    labels, jumped, end = [], False, offset
    guard = 0
    while guard < 128:
        guard += 1
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # компрессия, указатель
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            offset, jumped = pointer, True
            continue
        labels.append(data[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    return ".".join(labels), (end if jumped else offset)


def dns_query(name, rtype="A", timeout=5):
    """DNS-запись по UDP. Возвращает список dict(type, value, ttl)."""
    qtype = RTYPE_IDS[rtype]
    tid = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    packet = header + _encode_name(name) + struct.pack(">HH", qtype, 1)

    for server in _dns_servers():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(packet, (server, 53))
                data, _ = s.recvfrom(4096)
            if len(data) < 12 or struct.unpack(">H", data[:2])[0] != tid:
                continue
            flags, qd, an = struct.unpack(">HHH", data[2:8])
            if flags & 0x000F != 0:  # RCODE != 0
                return []
            off = 12
            for _ in range(qd):  # пропускаем Question section
                _, off = _read_name(data, off)
                off += 4
            answers = []
            for _ in range(an):
                _, off = _read_name(data, off)
                rtype_id, _rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
                off += 10
                rdata = data[off:off + rdlen]
                kind = RTYPE_NAMES.get(rtype_id, str(rtype_id))
                if rtype_id == 1 and rdlen == 4:
                    answers.append({"type": "A", "value": socket.inet_ntoa(rdata), "ttl": ttl})
                elif rtype_id == 28 and rdlen == 16:
                    answers.append({"type": "AAAA",
                                    "value": socket.inet_ntop(socket.AF_INET6, rdata), "ttl": ttl})
                elif rtype_id in (2, 5):
                    target, _ = _read_name(data, off)
                    answers.append({"type": kind, "value": target, "ttl": ttl})
                elif rtype_id == 15:
                    pref = struct.unpack(">H", rdata[:2])[0]
                    target, _ = _read_name(data, off + 2)
                    answers.append({"type": "MX", "value": f"{pref} {target}", "ttl": ttl})
                elif rtype_id == 16:
                    txt, pos = [], 0
                    while pos < len(rdata):
                        slen = rdata[pos]
                        txt.append(rdata[pos + 1:pos + 1 + slen].decode("utf-8", "replace"))
                        pos += slen + 1
                    answers.append({"type": "TXT", "value": " ".join(txt), "ttl": ttl})
                elif rtype_id == 6:
                    mname, p1 = _read_name(data, off)
                    rname, p2 = _read_name(data, p1)
                    serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", data[p2:p2 + 20])
                    answers.append({"type": "SOA",
                                    "value": f"{mname} {rname} serial={serial} refresh={refresh} "
                                             f"retry={retry} expire={expire} min={minimum}",
                                    "ttl": ttl})
                off += rdlen
            return answers
        except (socket.timeout, OSError, IndexError, struct.error):
            continue
    return []


def dns_first(name, rtype="A"):
    records = dns_query(name, rtype)
    return records[0]["value"] if records else None


# ============================================================================
#  МОДУЛЬ 1. ПОИСК НИКНЕЙМА НА 40+ ПЛОЩАДКАХ
#  создано @loomaxer — https://t.me/loomaxer
# ============================================================================
# mode:
#   status  -> 200 = найден, 404 = свободен
#   contains-> маркер есть в теле = найден
#   absent  -> маркер есть в теле = свободен
SITES = [
    ("GitHub", "https://github.com/{}", "status"),
    ("GitLab", "https://gitlab.com/{}", "status"),
    ("Bitbucket", "https://bitbucket.org/{}/", "status"),
    ("Codeberg", "https://codeberg.org/{}", "status"),
    ("Launchpad", "https://launchpad.net/~{}", "status"),
    ("PyPI", "https://pypi.org/user/{}/", "status"),
    ("npm", "https://www.npmjs.com/~{}", "status"),
    ("Docker Hub", "https://hub.docker.com/u/{}", "status"),
    ("Keybase", "https://keybase.io/{}", "status"),
    ("HackerOne", "https://hackerone.com/{}", "status"),
    ("Bugcrowd", "https://bugcrowd.com/{}", "status"),
    ("Reddit", "https://www.reddit.com/user/{}/about.json", "status"),
    ("Telegram", "https://t.me/{}", "contains", "tgme_page_title"),
    ("TikTok", "https://www.tiktok.com/@{}", "status"),
    ("Instagram", "https://www.instagram.com/{}/", "status"),
    ("Twitch", "https://www.twitch.tv/{}", "status"),
    ("Pinterest", "https://www.pinterest.com/{}/", "status"),
    ("Tumblr", "https://{}.tumblr.com/", "status"),
    ("Vimeo", "https://vimeo.com/{}", "status"),
    ("Flickr", "https://www.flickr.com/people/{}/", "status"),
    ("SoundCloud", "https://soundcloud.com/{}", "status"),
    ("Spotify", "https://open.spotify.com/user/{}", "status"),
    ("YouTube", "https://www.youtube.com/@{}", "status"),
    ("Dev.to", "https://dev.to/{}", "status"),
    ("Medium", "https://medium.com/@{}", "status"),
    ("Hashnode", "https://hashnode.com/@{}", "status"),
    ("Replit", "https://replit.com/@{}", "status"),
    ("CodePen", "https://codepen.io/{}", "status"),
    ("Steam", "https://steamcommunity.com/id/{}", "absent",
     "The specified profile could not be found"),
    ("VK", "https://vk.com/{}", "status"),
    ("Habr", "https://habr.com/ru/users/{}/", "status"),
    ("Pikabu", "https://pikabu.ru/@{}", "status"),
    ("OK.ru", "https://ok.ru/{}", "status"),
    ("Patreon", "https://www.patreon.com/{}", "status"),
    ("Behance", "https://www.behance.net/{}", "status"),
    ("Dribbble", "https://dribbble.com/{}", "status"),
    ("About.me", "https://about.me/{}", "status"),
    ("Ask.fm", "https://ask.fm/{}", "status"),
    ("Pastebin", "https://pastebin.com/u/{}", "status"),
    ("Gravatar", "https://gravatar.com/{}", "status"),
    ("Wikimedia", "https://meta.wikimedia.org/wiki/Special:CentralAuth/{}", "absent",
     "does not exist"),
    ("OpenStreetMap", "https://www.openstreetmap.org/user/{}", "status"),
    ("Last.fm", "https://www.last.fm/user/{}", "status"),
    ("Bandcamp", "https://{}.bandcamp.com/", "status"),
    ("Kaggle", "https://www.kaggle.com/{}", "status"),
    ("Hugging Face", "https://huggingface.co/{}", "status"),
]


CHALLENGE_MARKERS = (
    "Client Challenge", "Just a moment", "Attention Required",
    "Please enable JavaScript to continue", "cf-challenge", "captcha-bypass",
)


def _check_site(site, username, timeout):
    entry = site
    name, template, mode = entry[0], entry[1], entry[2]
    marker = entry[3] if len(entry) > 3 else None
    url = template.format(urllib.parse.quote(username))
    status, _headers, body = http_get(url, timeout=timeout)
    if status is None:
        state = "error"
    elif any(ch in body for ch in CHALLENGE_MARKERS):
        # анти-бот страница (Cloudflare/Fastly/…) — достоверный вывод невозможен
        state = "unknown"
    elif mode == "status":
        state = "found" if status == 200 else ("free" if status == 404 else "unknown")
    elif mode == "contains":
        state = "found" if (status == 200 and marker and marker in body) else (
            "free" if status == 404 else "unknown")
    else:  # absent
        state = "free" if (marker and marker in body) else (
            "found" if status == 200 else "unknown")
    return {"site": name, "state": state, "status": status, "url": url}


def cmd_user(username, timeout, workers=12):
    res = result_skeleton("username", username)
    print(C.p(C.BOLD, f"\n[*] Поиск ника {C.p(C.YELLOW, username)} по {len(SITES)} площадкам"))
    print(C.p(C.DIM, "    движок: @loomaxer · t.me/loomaxer\n"))
    rows = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_check_site, s, username, timeout) for s in SITES]
        for fut in as_completed(futures):
            rows.append(fut.result())
    order = {"found": 0, "free": 1, "unknown": 2, "error": 3}
    rows.sort(key=lambda r: (order.get(r["state"], 9), r["site"].lower()))
    icons = {"found": C.p(C.GREEN, "● ЕСТЬ   "), "free": C.p(C.DIM, "○ свободен"),
             "unknown": C.p(C.YELLOW, "? н/д    "), "error": C.p(C.RED, "✕ ошибка ")}
    for r in rows:
        print(f"  {icons.get(r['state'], r['state'])}  {r['site']:<16} {C.p(C.DIM, r['url'])}")
    found = [r for r in rows if r["state"] == "found"]
    print(f"\n  {C.p(C.BOLD, 'Найдено профилей:')} {C.p(C.GREEN, str(len(found)))} / {len(rows)}")
    res["rows"] = rows
    res["data"]["found_count"] = len(found)
    print("\n" + WATERMARK_LINE)
    return res


# ============================================================================
#  МОДУЛЬ 2. РАЗБОР EMAIL
#  создано @loomaxer — https://t.me/loomaxer
# ============================================================================
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def cmd_email(address, timeout):
    res = result_skeleton("email", address)
    address = address.strip().lower()
    print(C.p(C.BOLD, f"\n[*] Разбор адреса {C.p(C.YELLOW, address)}"))
    valid = bool(EMAIL_RE.match(address))
    kv("Синтаксис", C.p(C.GREEN, "корректный") if valid else C.p(C.RED, "некорректный"))
    res["data"]["syntax_valid"] = valid
    if not valid:
        print("\n" + WATERMARK_LINE)
        return res

    local, domain = address.split("@", 1)
    kv("Локальная часть", local)
    kv("Домен", domain)
    kv("Длина local-part", f"{len(local)} симв.")
    kv("Gmail-алиас?", "да (точки/+) игнорируются" if domain in ("gmail.com", "googlemail.com")
       and ("." in local or "+" in local) else "нет")

    print(C.p(C.DIM, "\n  -- DNS домена --"))
    mx = dns_query(domain, "MX")
    mxs = [r["value"] for r in mx]
    a = dns_first(domain, "A")
    kv("MX", ", ".join(mxs) if mxs else C.p(C.RED, "нет (почта не принимается?)"))
    kv("A", a or "нет")
    res["data"]["mx"] = mxs
    res["data"]["a"] = a

    print(C.p(C.DIM, "\n  -- Gravatar --"))
    h = hashlib.md5(address.encode()).hexdigest()
    g_url = f"https://gravatar.com/{h}"
    status, _, body = http_get(g_url + ".json", timeout=timeout)
    if status == 200:
        try:
            profile = json.loads(body)["entry"][0]
            kv("Gravatar", C.p(C.GREEN, "профиль найден"))
            kv("Имя", profile.get("displayName", "—"))
            kv("Аватар", g_url)
            res["data"]["gravatar"] = profile
        except (json.JSONDecodeError, KeyError, IndexError):
            kv("Gravatar", "профиль отсутствует")
    else:
        kv("Gravatar", "профиль отсутствует")
    kv("Hash (MD5)", h)

    print(C.p(C.DIM, "\n  -- Сервисы для ручной проверки --"))
    links = [
        ("Have I Been Pwned", f"https://haveibeenpwned.com/account/{urllib.parse.quote(address)}"),
        ("EmailRep", f"https://emailrep.io/{urllib.parse.quote(address)}"),
        ("Hunter.io", f"https://hunter.io/verify/{urllib.parse.quote(address)}"),
        ("Поиск Google", "https://www.google.com/search?q=" + urllib.parse.quote(f'"{address}"')),
    ]
    for label, link in links:
        print(f"  • {label:<20} {C.p(C.DIM, link)}")
    res["data"]["lookup_links"] = [{"name": n, "url": u} for n, u in links]
    print("\n" + WATERMARK_LINE)
    return res


# ============================================================================
#  МОДУЛЬ 3. РАЗВЕДКА ДОМЕНА: DNS + ПОДДОМЕНЫ + CT-ЛОГИ + WHOIS
#  создано @loomaxer — https://t.me/loomaxer
# ============================================================================
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2", "ns3", "dns",
    "webmail", "cpanel", "whm", "autodiscover", "autoconfig", "m", "mobile",
    "test", "dev", "staging", "stage", "beta", "demo", "old", "new", "vpn",
    "portal", "admin", "api", "app", "blog", "shop", "store", "cdn", "static",
    "img", "images", "media", "files", "download", "docs", "help", "support",
    "login", "sso", "auth", "account", "dashboard", "git", "gitlab", "jenkins",
    "jira", "confluence", "wiki", "status", "monitor", "grafana", "kibana",
    "internal", "intranet", "proxy", "gateway", "remote", "secure", "payment",
    "pay", "cloud", "drive", "backup", "b2b", "partner", "lk", "cabinet",
    "office", "my", "mx", "relay", "wap", "web", "panel", "console",
]

WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
    "org": "whois.publicinterestregistry.org", "io": "whois.nic.io",
    "co": "whois.nic.co", "me": "whois.nic.me", "tv": "whois.nic.tv",
    "info": "whois.afilias.net", "biz": "whois.nic.biz", "ru": "whois.tcinet.ru",
    "su": "whois.tcinet.ru", "рф": "whois.tcinet.ru", "kz": "whois.nic.kz",
    "ua": "whois.ua", "uk": "whois.nominet.org.uk", "de": "whois.denic.de",
    "nl": "whois.domain-registry.nl", "eu": "whois.eu", "fr": "whois.afnic.fr",
    "it": "whois.nic.it", "es": "whois.nic.es", "pl": "whois.dns.pl",
    "cn": "whois.cnnic.cn", "jp": "whois.jprs.jp", "br": "whois.registro.br",
    "au": "whois.auda.org.au", "ca": "whois.cira.ca", "info": "whois.afilias.net",
}


def whois_query(server, query, timeout=10):
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            buf = s.recv(4096)
            if not buf:
                break
            chunks.append(buf)
    return b"".join(chunks).decode("utf-8", "replace")


def parse_whois(text):
    fields = {}
    patterns = {
        "registrar": r"(?:Registrar|регистратор|registrar-name)\s*:?\s*(.+)",
        "created": r"(?:Creation Date|created|Создан|paid-till|registered|Registered Date)\s*:?\s*(.+)",
        "expires": r"(?:Registry Expiry Date|expires|Expiry|Expiration|paid-till|free-date)\s*:?\s*(.+)",
        "status": r"(?:Domain Status|state)\s*:?\s*(.+)",
    }
    for key, pat in patterns.items():
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            fields[key] = m.group(1).strip().splitlines()[0][:120]
    nss = sorted(set(re.findall(r"(?im)^\s*(?:nserver|name server)\s*:?\s*([\w.\-]+)", text)))
    if nss:
        fields["name_servers"] = ", ".join(n.lower() for n in nss[:8])
    return fields


def cmd_domain(domain, timeout):
    res = result_skeleton("domain", domain)
    domain = domain.lower().strip("/")
    if "://" in domain:
        domain = urllib.parse.urlparse(domain).hostname or domain
    print(C.p(C.BOLD, f"\n[*] Разведка домена {C.p(C.YELLOW, domain)}"))

    print(C.p(C.DIM, "\n  -- DNS-записи (собственный DNS-клиент @loomaxer) --"))
    all_records = []
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"):
        records = dns_query(domain, rtype)
        for r in records:
            all_records.append(r)
            print(f"  {C.p(C.CYAN, f'{rtype:<6}')} {r['value']}  {C.p(C.DIM, 'ttl=' + str(r['ttl']))}")
    if not all_records:
        print(C.p(C.RED, "  записей не получено (нет сети или домен не существует)"))
    res["rows"] = all_records

    print(C.p(C.DIM, "\n  -- Перебор поддоменов по словарю --"))
    found_subs = []

    def _probe(sub):
        host = f"{sub}.{domain}"
        rec = dns_query(host, "A")
        return {"subdomain": host, "a": ", ".join(x["value"] for x in rec)} if rec else None

    with ThreadPoolExecutor(max_workers=16) as pool:
        for fut in as_completed([pool.submit(_probe, s) for s in SUBDOMAIN_WORDLIST]):
            item = fut.result()
            if item:
                found_subs.append(item)
    found_subs.sort(key=lambda x: x["subdomain"])
    for item in found_subs:
        print(f"  {C.p(C.GREEN, '●')} {item['subdomain']:<32} {C.p(C.DIM, item['a'])}")
    if not found_subs:
        print(C.p(C.DIM, "  из словаря ничего не разрешилось"))
    res["data"]["subdomains_wordlist"] = found_subs

    print(C.p(C.DIM, "\n  -- Certificate Transparency (crt.sh) --"))
    status, _h, body = http_get(
        f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json", timeout=timeout)
    ct_names = []
    if status == 200 and body and not body.startswith("__error__"):
        try:
            for entry in json.loads(body):
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lstrip("*.").lower()
                    if name and name not in ct_names:
                        ct_names.append(name)
            for name in ct_names[:60]:
                print(f"  {C.p(C.GREEN, '●')} {name}")
        except json.JSONDecodeError:
            print(C.p(C.YELLOW, "  crt.sh вернул не-JSON, пропуск"))
    else:
        print(C.p(C.YELLOW, "  crt.sh недоступен, пропуск"))
    res["data"]["crtsh_names"] = ct_names

    print(C.p(C.DIM, "\n  -- WHOIS --"))
    tld = domain.rsplit(".", 1)[-1]
    whois_data = {}
    try:
        server = WHOIS_SERVERS.get(tld)
        if not server:
            iana = whois_query("whois.iana.org", domain, timeout)
            m = re.search(r"(?im)^refer:\s*(\S+)", iana)
            server = m.group(1) if m else "whois.iana.org"
        whois_data = parse_whois(whois_query(server, domain, timeout))
        for k, v in whois_data.items():
            kv(k, v)
    except (OSError, socket.timeout) as e:
        print(C.p(C.YELLOW, f"  WHOIS недоступен: {e}"))
    res["data"]["whois"] = whois_data
    print("\n" + WATERMARK_LINE)
    return res


# ============================================================================
#  МОДУЛЬ 4. IP-АДРЕС
#  создано @loomaxer — https://t.me/loomaxer
# ============================================================================
def cmd_ip(ip, timeout):
    res = result_skeleton("ip", ip)
    print(C.p(C.BOLD, f"\n[*] Разбор IP {C.p(C.YELLOW, ip)}"))
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        print(C.p(C.RED, "  некорректный IP-адрес"))
        return res
    kv("Версия", f"IPv{addr.version}")
    kv("Диапазон", "приватный/служебный" if addr.is_private else "публичный")
    kv("Loopback", "да" if addr.is_loopback else "нет")
    kv("Multicast", "да" if addr.is_multicast else "нет")
    res["data"]["classification"] = {
        "version": addr.version, "private": addr.is_private,
        "loopback": addr.is_loopback, "multicast": addr.is_multicast}

    if not addr.is_private and not addr.is_loopback:
        print(C.p(C.DIM, "\n  -- Геолокация (ip-api.com) --"))
        status, _h, body = http_get(f"http://ip-api.com/json/{urllib.parse.quote(ip)}"
                                    f"?fields=status,country,regionName,city,zip,lat,lon,"
                                    f"timezone,isp,org,as,query", timeout=timeout)
        if status == 200:
            try:
                geo = json.loads(body)
                if geo.get("status") == "success":
                    for label, key in (("Страна", "country"), ("Регион", "regionName"),
                                       ("Город", "city"), ("Индекс", "zip"),
                                       ("Часовой пояс", "timezone"), ("ISP", "isp"),
                                       ("Организация", "org"), ("AS", "as")):
                        kv(label, geo.get(key, "—"))
                    kv("Координаты", f"{geo.get('lat')}, {geo.get('lon')}")
                    maps = ("https://www.google.com/maps?q="
                            f"{geo.get('lat')},{geo.get('lon')}")
                    kv("Карта", maps)
                    res["data"]["geo"] = geo
            except json.JSONDecodeError:
                pass
        if not res["data"].get("geo"):
            print(C.p(C.YELLOW, "  geo-API недоступен"))

    print(C.p(C.DIM, "\n  -- Обратный DNS --"))
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        kv("PTR", hostname)
        if aliases:
            kv("Алиасы", ", ".join(aliases))
        res["data"]["ptr"] = hostname
    except OSError:
        kv("PTR", C.p(C.DIM, "нет"))
    print("\n" + WATERMARK_LINE)
    return res


# ============================================================================
#  МОДУЛЬ 5. ТЕЛЕФОННЫЕ НОМЕРА (без внешних API)
#  создано @loomaxer — https://t.me/loomaxer
# ============================================================================
COUNTRY_CODES = {
    "1": ("США/Канада", 10), "7": ("Россия/Казахстан", 10), "20": ("Египет",), "27": ("ЮАР",),
    "30": ("Греция",), "31": ("Нидерланды",), "32": ("Бельгия",), "33": ("Франция",),
    "34": ("Испания",), "36": ("Венгрия",), "39": ("Италия",), "40": ("Румыния",),
    "41": ("Швейцария",), "43": ("Австрия",), "44": ("Великобритания",), "45": ("Дания",),
    "46": ("Швеция",), "47": ("Норвегия",), "48": ("Польша",), "49": ("Германия",),
    "51": ("Перу",), "52": ("Мексика",), "53": ("Куба",), "54": ("Аргентина",),
    "55": ("Бразилия",), "56": ("Чили",), "57": ("Колумбия",), "58": ("Венесуэла",),
    "60": ("Малайзия",), "61": ("Австралия",), "62": ("Индонезия",), "63": ("Филиппины",),
    "64": ("Новая Зеландия",), "65": ("Сингапур",), "66": ("Таиланд",), "81": ("Япония",),
    "82": ("Южная Корея",), "84": ("Вьетнам",), "86": ("Китай",), "90": ("Турция",),
    "91": ("Индия",), "92": ("Пакистан",), "93": ("Афганистан",), "94": ("Шри-Ланка",),
    "95": ("Мьянма",), "98": ("Иран",), "212": ("Марокко",), "213": ("Алжир",),
    "216": ("Тунис",), "218": ("Ливия",), "234": ("Нигерия",), "254": ("Кения",),
    "351": ("Португалия",), "352": ("Люксембург",), "353": ("Ирландия",),
    "358": ("Финляндия",), "359": ("Болгария",), "370": ("Литва",), "371": ("Латвия",),
    "372": ("Эстония",), "373": ("Молдова",), "374": ("Армения",), "375": ("Беларусь",),
    "380": ("Украина",), "420": ("Чехия",), "421": ("Словакия",), "852": ("Гонконг",),
    "966": ("Саудовская Аравия",), "971": ("ОАЭ",), "972": ("Израиль",), "974": ("Катар",),
    "992": ("Таджикистан",), "993": ("Туркменистан",), "994": ("Азербайджан",),
    "995": ("Грузия",), "996": ("Киргизия",), "998": ("Узбекистан",),
}

# Примерное распределение DEF-кодов РФ (без учёта переноса номеров MNP)
RU_OPERATORS = [
    (range(900, 904), "Tele2"), (range(905, 907), "Билайн"), (range(908, 910), "Tele2/МТС"),
    (range(910, 920), "МТС"), (range(920, 930), "МегаФон"), (range(930, 940), "МТС/МегаФон"),
    (range(950, 954), "Tele2"), (range(960, 969), "Билайн/МегаФон"),
    (range(977, 981), "МТС/Йота"), (range(980, 990), "МТС"), (range(991, 1000), "МТС/Ростелеком"),
]
KZ_OPERATORS = {
    "700": "Altel/Tele2 (KZ)", "701": "Kcell/activ (KZ)", "702": "Kcell/activ (KZ)",
    "704": "Altel/Tele2 (KZ)", "705": "Beeline (KZ)", "747": "Altel/Tele2 (KZ)",
    "771": "Beeline (KZ)", "775": "Kcell/activ (KZ)", "776": "Beeline (KZ)",
    "777": "Beeline (KZ)", "778": "Kcell/activ (KZ)",
}


def cmd_phone(raw, _timeout):
    res = result_skeleton("phone", raw)
    print(C.p(C.BOLD, f"\n[*] Разбор номера {C.p(C.YELLOW, raw)}"))
    digits = re.sub(r"\D", "", raw)
    if raw.strip().startswith("+"):
        cc_digits = digits
    elif digits.startswith("8") and len(digits) == 11:  # внутр. набор РФ/KZ
        cc_digits = "7" + digits[1:]
    elif digits.startswith("00"):
        cc_digits = digits[2:]
    else:
        cc_digits = digits
    kv("Цифр", len(cc_digits))

    code, country = None, "неизвестно"
    for length in (3, 2, 1):
        candidate = cc_digits[:length]
        if candidate in COUNTRY_CODES:
            code, country = candidate, COUNTRY_CODES[candidate][0]
            break
    kv("Код страны", f"+{code}" if code else "не распознан")
    kv("Страна", country)
    national = cc_digits[len(code):] if code else cc_digits
    kv("Нац. номер", national)
    e164 = f"+{code}{national}" if code else cc_digits
    kv("E.164", C.p(C.GREEN, e164))

    line_type, operator = "—", "—"
    if code == "7" and len(national) == 10:
        abc = national[:3]
        if abc in KZ_OPERATORS or abc[0] in ("6", "7"):
            country = "Казахстан"
            operator = KZ_OPERATORS.get(abc, "мобильный (KZ)")
            line_type = "мобильный"
        elif abc[0] == "9":
            country = "Россия"
            line_type = "мобильный"
            for rng, name in RU_OPERATORS:
                if int(abc) in rng:
                    operator = name + " [оценка без MNP]"
                    break
        elif abc.startswith("80"):
            country = "Россия"
            line_type = "бесплатная/сервисная линия 8-800"
        elif abc[0] in ("3", "4", "5", "8"):
            country = "Россия"
            line_type = "городской/фиксированный"
        kv("Страна", country)
        kv("Тип линии", line_type)
        kv("Оператор", operator)
    elif code:
        line_type = "мобильный/городской (по стране)"
        kv("Тип линии", line_type)

    links = [
        ("Поиск Google", "https://www.google.com/search?q=" + urllib.parse.quote(e164)),
        ("Truecaller (web)", "https://www.truecaller.com/search/ww/" + urllib.parse.quote(e164.lstrip("+"))),
        ("WhatsApp", f"https://wa.me/{code}{national}" if code else "#"),
        ("Telegram", f"https://t.me/+{code}{national}" if code else "#"),
    ]
    print(C.p(C.DIM, "\n  -- Проверка в открытых сервисах --"))
    for label, link in links:
        print(f"  • {label:<18} {C.p(C.DIM, link)}")
    res["data"].update({"e164": e164, "country": country, "line_type": line_type,
                        "operator": operator,
                        "lookup_links": [{"name": n, "url": u} for n, u in links]})
    print(C.p(C.DIM, "\n  Оператор определяется приблизительно; перенос номеров (MNP) не учитывается."))
    print("\n" + WATERMARK_LINE)
    return res


# ============================================================================
#  МОДУЛЬ 6. МЕТАДАННЫЕ ФАЙЛОВ (EXIF / PNG / PDF / DOCX / XLSX)
#  создано @loomaxer — https://t.me/loomaxer
# ============================================================================
MAGIC = [
    (b"\xff\xd8\xff", "JPEG-изображение"), (b"\x89PNG\r\n\x1a\n", "PNG-изображение"),
    (b"GIF8", "GIF-изображение"), (b"%PDF-", "PDF-документ"),
    (b"PK\x03\x04", "ZIP/Office-документ (docx/xlsx/zip)"),
    (b"\x1f\x8b", "GZIP-архив"), (b"Rar!", "RAR-архив"),
    (b"7z\xbc\xaf\x27\x1c", "7z-архив"), (b"ID3", "MP3-аудио"),
    (b"\x00\x00\x01\x00", "ICO/курсор"), (b"BM", "BMP-изображение"),
]

EXIF_TAGS = {
    0x010F: "Make", 0x0110: "Model", 0x011B: "Software", 0x0131: "Software",
    0x013B: "Artist", 0x8298: "Copyright", 0x0132: "DateTime",
    0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized", 0x8769: "ExifIFD",
    0x8825: "GPSIFD", 0x927C: "MakerNote", 0xA002: "PixelXDimension",
    0xA003: "PixelYDimension", 0x829A: "ExposureTime", 0x829D: "FNumber",
    0x8827: "ISO", 0x920A: "FocalLength", 0x010E: "ImageDescription",
    0x011A: "XResolution", 0x011D: "YResolution",
}
GPS_TAGS = {1: "GPSLatitudeRef", 2: "GPSLatitude", 3: "GPSLongitudeRef",
            4: "GPSLongitude", 5: "GPSAltitudeRef", 6: "GPSAltitude",
            7: "GPSTimeStamp", 29: "GPSDateStamp"}
TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}


def _tiff_value(buf, endian, tag_type, count, raw):
    fmt_char = {1: "B", 2: "c", 3: "H", 4: "I", 5: "II", 9: "i", 10: "ii"}.get(tag_type)
    if fmt_char is None:
        return raw
    if tag_type == 2:  # ASCII
        size = count
        block = raw[:size] if size <= 4 else \
            buf[struct.unpack(endian + "I", raw[:4])[0]:][:size]
        return block.rstrip(b"\x00").decode("utf-8", "replace")
    if tag_type in (5, 10):  # рациональные числа: SRATIONAL/RATIONAL
        size = 8 * count
        base = raw if size <= 4 else \
            buf[struct.unpack(endian + "I", raw[:4])[0]:]
        vals = []
        for i in range(count):
            a, b = struct.unpack(endian + "II", base[i * 8:i * 8 + 8])
            vals.append(a / b if b else 0)
        return vals[0] if count == 1 else vals
    size = TYPE_SIZE[tag_type] * count
    if size <= 4:
        block = raw[:size]
    else:
        offset = struct.unpack(endian + "I", raw[:4])[0]
        block = buf[offset:offset + size]
    if count == 1:
        return struct.unpack(endian + fmt_char, block)[0]
    return list(struct.unpack(endian + fmt_char * count, block))


def parse_exif(blob):
    """Ручной парсер JPEG/TIFF EXIF — без Pillow. @loomaxer"""
    if blob[:2] != b"\xff\xd8":
        return {}, None
    off, tags = 2, {}
    while off < len(blob) - 4:
        if blob[off] != 0xFF:
            break
        marker = blob[off + 1]
        seglen = struct.unpack(">H", blob[off + 2:off + 4])[0]
        if marker == 0xE1 and blob[off + 4:off + 10] == b"Exif\x00\x00":
            tiff = blob[off + 10:off + 2 + seglen]
            return _parse_tiff(tiff), tiff
        off += 2 + seglen
    return {}, None


def _parse_tiff(buf):
    endian = ">" if buf[:2] == b"MM" else "<"
    ifd0 = struct.unpack(endian + "I", buf[4:8])[0]
    out, gps = {}, {}

    def walk(ifd, tag_map, sink):
        count = struct.unpack(endian + "H", buf[ifd:ifd + 2])[0]
        p = ifd + 2
        linked = {}
        for _ in range(count):
            tag, ttype, cnt = struct.unpack(endian + "HHI", buf[p:p + 8])
            raw = buf[p + 8:p + 12]
            if tag in (0x8769, 0x8825):  # внутренние указатели IFD — не выводим
                linked[tag] = struct.unpack(endian + "I", raw[:4])[0]
            else:
                name = tag_map.get(tag, hex(tag))
                try:
                    sink[name] = _tiff_value(buf, endian, ttype, cnt, raw)
                except (struct.error, IndexError):
                    sink[name] = "<unparsed>"
            p += 12
        nxt = struct.unpack(endian + "I", buf[p:p + 4])[0]
        return linked, nxt

    linked, _ = walk(ifd0, EXIF_TAGS, out)
    if 0x8769 in linked:
        walk(linked[0x8769], EXIF_TAGS, out)
    if 0x8825 in linked:
        walk(linked[0x8825], GPS_TAGS, gps)
        out["GPS"] = gps
    return out


def gps_to_decimal(dms, ref):
    if not isinstance(dms, list) or len(dms) != 3:
        return None
    dec = dms[0] + dms[1] / 60 + dms[2] / 3600
    return -dec if ref in ("S", "W") else dec


def parse_png(blob):
    if blob[:8] != b"\x89PNG\r\n\x1a\n":
        return {}
    info, off = {}, 8
    while off + 8 <= len(blob):
        length, ctype = struct.unpack(">I4s", blob[off:off + 8])
        chunk = blob[off + 8:off + 8 + length]
        name = ctype.decode("ascii", "replace")
        if name == "IHDR":
            w, h = struct.unpack(">II", chunk[:8])
            info["width"], info["height"] = w, h
        elif name == "tEXt":
            if b"\x00" in chunk:
                k, v = chunk.split(b"\x00", 1)
                info[k.decode("latin1")] = v.decode("latin1")
        elif name == "zTXt":
            if b"\x00" in chunk:
                k, rest = chunk.split(b"\x00", 1)
                try:
                    info[k.decode("latin1")] = zlib.decompress(rest[1:]).decode("latin1")
                except zlib.error:
                    pass
        elif name == "iTXt":
            parts = chunk.split(b"\x00", 4)
            if len(parts) >= 5:
                info[parts[0].decode("latin1")] = parts[4].decode("utf-8", "replace")
        off += 12 + length
    return info


def _pdf_decode(rm):
    raw = rm.group(1)
    # На случай нестандартной обёртки "(<hex>)" — вырезаем внутренний hex
    if raw.startswith(b"(<") and raw.rstrip().endswith(b">)"):
        raw = raw[1:-1]
    if raw.startswith(b"<"):
        hx = re.sub(rb"\s", b"", raw[1:-1])
        try:
            b = bytes.fromhex(hx.decode())
        except ValueError:
            return raw.decode("latin1")
    else:
        s = raw[1:-1]
        s = s.replace(b"\\n", b"\n").replace(b"\\r", b"\r").replace(b"\\t", b"\t")
        s = s.replace(b"\\(", b"(").replace(b"\\)", b")").replace(b"\\\\", b"\\")
        b = s
    if b.startswith(b"\xfe\xff"):
        return b[2:].decode("utf-16-be", "replace")
    return b.decode("utf-8", "replace")


def parse_pdf(blob):
    out = {}

    class _Piece:
        def __init__(self, piece):
            self._piece = piece

        def group(self, i):
            return self._piece

    for key in (b"Title", b"Author", b"Subject", b"Keywords", b"Creator",
                b"Producer", b"CreationDate", b"ModDate"):
        m = re.search(rb"/" + key + rb"\s*(<[0-9A-Fa-f\s]+>|\((?:[^)\\]|\\.)*\))", blob)
        if m:
            out[key.decode()] = _pdf_decode(_Piece(m.group(1)))
    return out


def parse_ooxml(blob):
    import tempfile
    out = {}
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
        tf.write(blob)
        tmp = tf.name
    try:
        with zipfile.ZipFile(tmp) as z:
            names = z.namelist()
            if "docProps/core.xml" in names:
                root = ET.fromstring(z.read("docProps/core.xml"))
                for child in root:
                    tag = child.tag.split("}")[-1]
                    out[tag] = (child.text or "").strip()
            media = [n for n in names if n.startswith("word/media/") or n.startswith("xl/media/")]
            if media:
                out["embedded_media"] = ", ".join(media[:10]) + (
                    f" …(+{len(media) - 10})" if len(media) > 10 else "")
            out["archive_entries"] = len(names)
    finally:
        os.unlink(tmp)
    return out


def cmd_meta(path, _timeout):
    res = result_skeleton("metadata", str(path))
    p = Path(path)
    print(C.p(C.BOLD, f"\n[*] Метаданные файла {C.p(C.YELLOW, p)}"))
    if not p.is_file():
        print(C.p(C.RED, "  файл не найден"))
        return res
    blob = p.read_bytes()
    size = len(blob)
    kv("Размер", f"{size:,} байт".replace(",", " "))
    kv("MD5", hashlib.md5(blob).hexdigest())
    kv("SHA-1", hashlib.sha1(blob).hexdigest())
    kv("SHA-256", hashlib.sha256(blob).hexdigest())
    kind = next((name for sig, name in MAGIC if blob.startswith(sig)), "неизвестный формат")
    kv("Тип", kind)
    meta = {}
    try:
        if kind.startswith("JPEG"):
            meta, _ = parse_exif(blob)
        elif kind.startswith("PNG"):
            meta = parse_png(blob)
        elif kind.startswith("PDF"):
            meta = parse_pdf(blob)
        elif kind.startswith("ZIP"):
            meta = parse_ooxml(blob)
    except Exception as e:  # парсеры не должны ронять CLI
        meta["parse_error"] = str(e)

    gps = meta.pop("GPS", None)
    if meta:
        print(C.p(C.DIM, "\n  -- Найденные поля --"))
        for k, v in meta.items():
            kv(k, str(v)[:200])
    else:
        print(C.p(C.DIM, "\n  метаданные не обнаружены (или формат не поддерживается)"))
    if gps:
        print(C.p(C.DIM, "\n  -- GPS --"))
        for k, v in gps.items():
            kv(k, str(v)[:120])
        lat = gps_to_decimal(gps.get("GPSLatitude"), gps.get("GPSLatitudeRef"))
        lon = gps_to_decimal(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef"))
        if lat is not None and lon is not None:
            link = f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}"
            kv("Карта Google", link)
            res["data"]["gps"] = {"lat": lat, "lon": lon, "map": link}
    res["data"]["file"] = {"name": p.name, "size": size, "type": kind,
                           "md5": hashlib.md5(blob).hexdigest(),
                           "sha1": hashlib.sha1(blob).hexdigest(),
                           "sha256": hashlib.sha256(blob).hexdigest()}
    res["data"]["metadata"] = meta
    print(C.p(C.DIM, "\n  Совет: фото из соцсетей обычно «зачищены» — ищите оригиналы."))
    print("\n" + WATERMARK_LINE)
    return res


# ============================================================================
#  МОДУЛЬ 7. РАЗВЕДКА ВЕБ-РЕСУРСА
#  создано @loomaxer — https://t.me/loomaxer
# ============================================================================
SECURITY_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy",
                    "X-Frame-Options", "X-Content-Type-Options",
                    "Referrer-Policy", "Permissions-Policy"]
TECH_SIGNATURES = [
    ("nginx", "Nginx"), ("apache", "Apache"), ("cloudflare", "Cloudflare"),
    ("microsoft-iis", "Microsoft IIS"), ("litespeed", "LiteSpeed"),
    ("x-powered-by: php", "PHP"), ("phpsessid", "PHP (сессия)"),
    ("asp.net", "ASP.NET"), ("wp-content", "WordPress"), ("wp-json", "WordPress REST"),
    ("drupal", "Drupal"), ("laravel", "Laravel"), ("bitrix", "1C-Битрикс"),
    ("react", "React"), ("__next_data__", "Next.js"), ("vue", "Vue.js"),
    ("angular", "Angular"), ("django", "Django"), ("rails", "Ruby on Rails"),
    ("cf-ray", "Cloudflare"), ("google-analytics", "Google Analytics"),
    ("metrika", "Яндекс.Метрика"), ("jumla|joomla", "Joomla"),
]


class _RedirectTrace(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append({"code": code, "from": req.full_url,
                           "to": urllib.parse.urljoin(req.full_url, newurl)})
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def cmd_url(url, timeout):
    res = result_skeleton("url", url)
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    print(C.p(C.BOLD, f"\n[*] Разведка URL {C.p(C.YELLOW, url)}"))
    tracer = _RedirectTrace()
    opener = urllib.request.build_opener(tracer)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        resp = opener.open(req, timeout=timeout)
        body = resp.read(400_000).decode("utf-8", "replace")
        status, headers, final_url = resp.status, dict(resp.headers), resp.url
    except urllib.error.HTTPError as e:
        status, headers, final_url = e.code, dict(e.headers or {}), e.url
        body = ""
    except (urllib.error.URLError, OSError) as e:
        print(C.p(C.RED, f"  недоступно: {e}"))
        print("\n" + WATERMARK_LINE)
        return res

    kv("Финальный статус", status)
    kv("Финальный URL", final_url)
    if tracer.chain:
        print(C.p(C.DIM, "\n  -- Цепочка редиректов --"))
        for hop in tracer.chain:
            print(f"  {C.p(C.YELLOW, hop['code'])} {hop['from']}")
            print(f"      → {hop['to']}")
    print(C.p(C.DIM, "\n  -- Заголовки --"))
    interesting = ["Server", "X-Powered-By", "Set-Cookie", "Content-Type",
                   "Date", "Cache-Control"]
    for h in interesting:
        for real_h in headers:
            if real_h.lower() == h.lower():
                kv(h, str(headers[real_h])[:160])
    print(C.p(C.DIM, "\n  -- Security-заголовки --"))
    present = {h.lower() for h in headers}
    missing = []
    for sh in SECURITY_HEADERS:
        ok = sh.lower() in present
        print(f"  {C.p(C.GREEN, '●') if ok else C.p(C.RED, '○')} {sh}")
        if not ok:
            missing.append(sh)
    grade = "A" if not missing else ("B" if len(missing) <= 2 else ("C" if len(missing) <= 4 else "D"))
    kv("Оценка безопасности", C.p(C.BOLD, grade))

    print(C.p(C.DIM, "\n  -- Технологии (эвристика) --"))
    haystack = (str(headers) + "\n" + body[:200_000]).lower()
    tech = sorted({name for pat, name in TECH_SIGNATURES if re.search(pat, haystack)})
    for t in tech:
        print(f"  {C.p(C.GREEN, '●')} {t}")
    if not tech:
        print(C.p(C.DIM, "  явных маркеров не найдено"))

    if final_url.startswith("https://"):
        print(C.p(C.DIM, "\n  -- TLS-сертификат --"))
        host = urllib.parse.urlparse(final_url).hostname
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    cert = tls.getpeercert()
            issuer = dict(x[0] for x in cert.get("issuer", []))
            kv("Издатель", issuer.get("organizationName", "—"))
            kv("Действует до", cert.get("notAfter", "—"))
            kv("SAN-записей", len(cert.get("subjectAltName", [])))
            res["data"]["tls"] = {"issuer": issuer, "notAfter": cert.get("notAfter")}
        except (OSError, ssl.SSLError) as e:
            print(C.p(C.YELLOW, f"  TLS: {e}"))
    res["data"].update({"status": status, "final_url": final_url,
                        "redirects": tracer.chain, "missing_headers": missing,
                        "technologies": tech})
    print("\n" + WATERMARK_LINE)
    return res


# ============================================================================
#  ЭКСПОРТЁРЫ ОТЧЁТОВ — водяной знак @loomaxer в каждом файле
#  создано @loomaxer — https://t.me/loomaxer
# ============================================================================
def export_json(res, path):
    Path(path).write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    print(C.p(C.GREEN, f"[+] JSON-отчёт сохранён: {path}"))


def export_csv(res, path):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow([WATERMARK])
        writer.writerow([f"module={res['module']}", f"target={res['target']}",
                         f"generated_at_utc={res['generated_at_utc']}",
                         f"creator={__author__}", f"telegram={__telegram__}"])
        writer.writerow([])
        if res["rows"]:
            keys = sorted({k for row in res["rows"] for k in row})
            writer.writerow(keys)
            for row in res["rows"]:
                writer.writerow([row.get(k, "") for k in keys])
        else:
            writer.writerow(["key", "value"])
            for k, v in res["data"].items():
                writer.writerow([k, json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v])
        writer.writerow([])
        writer.writerow(["© 2026 @loomaxer · https://t.me/loomaxer"])
    print(C.p(C.GREEN, f"[+] CSV-отчёт сохранён: {path}"))


def export_html(res, path):
    def esc(v):
        return html_mod.escape(str(v))

    rows_html = ""
    if res["rows"]:
        keys = sorted({k for row in res["rows"] for k in row})
        rows_html = "<table><thead><tr>" + "".join(f"<th>{esc(k)}</th>" for k in keys) + \
                    "</tr></thead><tbody>"
        for row in res["rows"]:
            rows_html += "<tr>" + "".join(
                f"<td>{esc('<не задано>') if row.get(k) is None else esc(row.get(k))}</td>"
                for k in keys) + "</tr>"
        rows_html += "</tbody></table>"
    data_html = "".join(
        f"<div class='kv'><b>{esc(k)}</b><span>{esc(json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v)}</span></div>"
        for k, v in res["data"].items())
    doc = f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="author" content="@loomaxer (https://t.me/loomaxer)">
<meta name="generator" content="OSINT Tree by @loomaxer">
<title>OSINT Tree · отчёт · {esc(res['target'])} · @loomaxer</title>
<style>
  :root {{ --bg:#0b0f17; --card:#131a26; --line:#22304a; --txt:#dbe6f5; --dim:#7d8da6; --acc:#4fd1c5; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font-family:'Segoe UI',Arial,sans-serif; background:var(--bg); color:var(--txt); padding:32px; }}
  body::after {{ content:"@loomaxer"; position:fixed; inset:0; display:grid; place-items:center;
    font-size:120px; font-weight:800; color:rgba(79,209,197,.055); transform:rotate(-28deg);
    pointer-events:none; z-index:0; letter-spacing:6px; }}
  .wrap {{ max-width:1080px; margin:0 auto; position:relative; z-index:1; }}
  header {{ border-bottom:2px solid var(--acc); padding-bottom:16px; margin-bottom:24px; }}
  h1 {{ margin:0 0 6px; font-size:28px; }} h1 span {{ color:var(--acc); }}
  .meta {{ color:var(--dim); font-size:13px; }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:12px; padding:18px 20px; margin-bottom:18px; }}
  h2 {{ font-size:16px; color:var(--acc); margin:0 0 12px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th,td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }}
  th {{ color:var(--acc); font-weight:600; }}
  .kv {{ display:flex; gap:14px; padding:7px 0; border-bottom:1px dashed var(--line); font-size:14px; }}
  .kv b {{ min-width:200px; color:var(--dim); font-weight:600; }}
  .kv span {{ word-break:break-all; }}
  footer {{ margin-top:26px; padding:18px; text-align:center; border:1px solid var(--line);
    border-radius:12px; background:var(--card); font-weight:700; }}
  footer a {{ color:var(--acc); text-decoration:none; }}
</style></head><body><div class="wrap">
<header>
  <h1>◈ OSINT <span>Tree</span> — отчёт разведки</h1>
  <div class="meta">модуль: <b>{esc(res['module'])}</b> · цель: <b>{esc(res['target'])}</b>
  · время (UTC): {esc(res['generated_at_utc'])}</div>
</header>
<section class="card"><h2>Табличные данные</h2>{rows_html or '<p class="meta">нет табличных строк</p>'}</section>
<section class="card"><h2>Сводка</h2>{data_html or '<p class="meta">нет данных</p>'}</section>
<footer>Создатель: <a href="https://t.me/loomaxer" target="_blank" rel="noopener">@loomaxer</a>
 · t.me/loomaxer · {esc(WATERMARK)}</footer>
</div></body></html>"""
    Path(path).write_text(doc, encoding="utf-8")
    print(C.p(C.GREEN, f"[+] HTML-отчёт сохранён: {path} (водяной знак @loomaxer внутри)"))


# ============================================================================
#  SELF-TEST (работает офлайн) — @loomaxer
# ============================================================================
def cmd_selftest():
    print(C.p(C.BOLD, "\n[*] Встроенные офлайн-тесты OSINT Tree (@loomaxer)\n"))
    checks = []

    def check(name, cond):
        checks.append(cond)
        print(f"  {C.p(C.GREEN, 'PASS') if cond else C.p(C.RED, 'FAIL')}  {name}")

    check("DNS-кодирование имени", _encode_name("example.com") == b"\x07example\x03com\x00")
    decoded, _ = _read_name(b"\x07example\x03com\x00rest", 0)
    check("DNS-декодирование имени", decoded == "example.com")
    check("Email-валидатор (валидный)", bool(EMAIL_RE.match("a.b+tag@sub.example.co")))
    check("Email-валидатор (плохой)", not EMAIL_RE.match("no@dot"))
    check("MD5 пустой строки", hashlib.md5(b"").hexdigest() == "d41d8cd98f00b204e9800998ecf8427e")
    check("ipaddress: 10.0.0.1 приватный", ipaddress.ip_address("10.0.0.1").is_private)

    import tempfile
    pdf = b"%PDF-1.4\n/Author (Ivan Petrov) /Producer <FEFF004C0069006200720065>\n%%EOF"
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tf:
        tf.write(pdf)
        pdf_path = tf.name
    pdf_meta = parse_pdf(Path(pdf_path).read_bytes())
    check("PDF: Author", pdf_meta.get("Author") == "Ivan Petrov")
    check("PDF: UTF-16 Producer", pdf_meta.get("Producer") == "Libre")
    os.unlink(pdf_path)

    with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as tf:
        with zipfile.ZipFile(tf.name, "w") as z:
            z.writestr("docProps/core.xml",
                       '<?xml version="1.0"?><cp:coreProperties '
                       'xmlns:cp="urn:cp" xmlns:dc="urn:dc">'
                       '<dc:creator>loomaxer</dc:creator>'
                       '<cp:lastModifiedBy>agent</cp:lastModifiedBy></cp:coreProperties>')
            z.writestr("word/media/image1.png", "x")
        docx_path = tf.name
    ooxml = parse_ooxml(Path(docx_path).read_bytes())
    check("DOCX: creator", ooxml.get("creator") == "loomaxer")
    check("DOCX: вложенный медиа-файл", "image1.png" in ooxml.get("embedded_media", ""))
    os.unlink(docx_path)

    # телефонные кейсы
    r1 = _phone_offline("+79112345678")
    check("Телефон РФ: МТС 911", r1["country"] == "Россия" and "МТС" in r1["operator"])
    r2 = _phone_offline("+77051234567")
    check("Телефон KZ: Beeline 705", r2["country"] == "Казахстан" and "Beeline" in r2["operator"])
    r3 = _phone_offline("+14155552671")
    check("Телефон США", r3["country"] == "США/Канада")
    r4 = _phone_offline("89112345678")
    check("Телефон: выход через 8 → +7", r4["e164"] == "+79112345678")

    # анти-бот челлендж не должен давать ложное «найдено»
    global http_get
    orig_http_get = http_get
    http_get = lambda u, timeout=DEFAULT_TIMEOUT: (200, {}, "Just a moment... Cloudflare")
    chall = _check_site(("Challenged", "https://example.com/{}", "status"), "x", 5)
    check("Анти-бот челлендж → unknown", chall["state"] == "unknown")
    http_get = orig_http_get

    print(f"\n  {C.p(C.BOLD, 'Итог:')} {sum(checks)}/{len(checks)} проверок пройдено")
    print("\n" + WATERMARK_LINE)
    return {"selftest_passed": sum(checks), "selftest_total": len(checks),
            "creator": __author__, "watermark": WATERMARK}


def _phone_offline(raw):
    digits = re.sub(r"\D", "", raw)
    cc_digits = ("7" + digits[1:]) if (digits.startswith("8") and len(digits) == 11) else digits
    code = next((c for c in ("380", "375", "998", "996", "994", "995", "374", "371",
                             "370", "372", "373", "420", "359", "971", "966", "972",
                             "992", "993", "212", "213", "216", "234", "254", "351",
                             "352", "353", "358", "421", "852", "1", "7", "20", "27",
                             "30", "31", "32", "33", "34", "36", "39", "40", "41",
                             "43", "44", "45", "46", "47", "48", "49", "51", "52",
                             "53", "54", "55", "56", "57", "58", "60", "61", "62",
                             "63", "64", "65", "66", "81", "82", "84", "86", "90",
                             "91", "92", "93", "94", "95", "98") if cc_digits.startswith(c)), None)
    country = COUNTRY_CODES.get(code, ("?",))[0]
    national = cc_digits[len(code):] if code else cc_digits
    operator = "—"
    if code == "7" and len(national) == 10:
        abc = national[:3]
        if abc in KZ_OPERATORS or abc[0] in ("6", "7"):
            country = "Казахстан"
            operator = KZ_OPERATORS.get(abc, "мобильный (KZ)")
        elif abc[0] == "9":
            country = "Россия"
            for rng, name in RU_OPERATORS:
                if int(abc) in rng:
                    operator = name
                    break
    return {"e164": f"+{code}{national}", "country": country, "operator": operator}


# ============================================================================
#  CLI
# ============================================================================
def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    # SUPPRESS: не заданные в подпарсере опции не затирают опции родителя
    common.add_argument("--json", metavar="FILE", default=argparse.SUPPRESS,
                        help="экспорт результата в JSON (водяной знак внутри)")
    common.add_argument("--csv", metavar="FILE", default=argparse.SUPPRESS,
                        help="экспорт табличных данных в CSV")
    common.add_argument("--html", metavar="FILE", default=argparse.SUPPRESS,
                        help="экспорт HTML-отчёта с водяным знаком @loomaxer")
    common.add_argument("--timeout", type=int, default=argparse.SUPPRESS,
                        help="таймаут запросов, сек")
    common.add_argument("--no-banner", action="store_true", default=argparse.SUPPRESS,
                        help="не печатать баннер")

    p = argparse.ArgumentParser(
        prog="osinttree.py",
        parents=[common],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{__title__} v{__version__} — мощный OSINT-комбайн по открытым данным.\n"
                    f"Создатель: {__author__} · {__telegram__}",
        epilog="Только публичные данные. Никаких атак и брутфорса.\n"
               "Создатель: @loomaxer · https://t.me/loomaxer")
    p.add_argument("--version", action="version",
                   version=f"OSINT Tree {__version__} · by @loomaxer · t.me/loomaxer")

    sub = p.add_subparsers(dest="module", required=True)

    s = sub.add_parser("user", parents=[common], help="поиск никнейма по 40+ площадкам")
    s.add_argument("username")

    s = sub.add_parser("email", parents=[common],
                       help="разбор email: DNS, Gravatar, ссылки на проверки")
    s.add_argument("address")

    s = sub.add_parser("domain", parents=[common], help="DNS, поддомены, CT-логи, WHOIS")
    s.add_argument("domain")

    s = sub.add_parser("ip", parents=[common], help="геолокация и классификация IP")
    s.add_argument("ip")

    s = sub.add_parser("phone", parents=[common],
                       help="разбор телефонного номера (страна/оператор)")
    s.add_argument("number")

    s = sub.add_parser("meta", parents=[common],
                       help="метаданные файла (EXIF/PNG/PDF/DOCX/XLSX)")
    s.add_argument("file")

    s = sub.add_parser("url", parents=[common],
                       help="разведка веб-ресурса: заголовки, редиректы, TLS, технологии")
    s.add_argument("url")

    sub.add_parser("selftest", parents=[common], help="офлайн самодиагностика")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    timeout = getattr(args, "timeout", DEFAULT_TIMEOUT)
    no_banner = getattr(args, "no_banner", False)
    if not no_banner and args.module != "selftest":
        print_banner()

    if args.module == "user":
        res = cmd_user(args.username, timeout)
    elif args.module == "email":
        res = cmd_email(args.address, timeout)
    elif args.module == "domain":
        res = cmd_domain(args.domain, timeout)
    elif args.module == "ip":
        res = cmd_ip(args.ip, timeout)
    elif args.module == "phone":
        res = cmd_phone(args.number, timeout)
    elif args.module == "meta":
        res = cmd_meta(args.file, timeout)
    elif args.module == "url":
        res = cmd_url(args.url, timeout)
    elif args.module == "selftest":
        res = cmd_selftest()
    else:  # pragma: no cover
        build_parser().print_help()
        return 2

    if getattr(args, "json", None):
        export_json(res, args.json)
    if getattr(args, "csv", None):
        export_csv(res, args.csv)
    if getattr(args, "html", None):
        export_html(res, args.html)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Прервано пользователем. " + WATERMARK)
        sys.exit(130)
