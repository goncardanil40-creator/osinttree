#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
#  ████████╗ ██████╗     ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
#  ╚══██╔══╝██╔════╝     ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
#     ██║   ██║  ███╗    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
#     ██║   ██║   ██║    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
#     ██║   ╚██████╔╝    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
#     ╚═╝    ╚═════╝     ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
# ----------------------------------------------------------------------------
#  TG SENTINEL — инструмент подачи жалоб на Telegram-ботов, каналы и аккаунты,
#  которые распространяют ЧУЖИЕ персональные данные (доксинг, сливы баз, деанон).
#
#  Работает через официальный MTProto (библиотека Telethon) от имени
#  ПОЛЬЗОВАТЕЛЬСКОГО аккаунта — Bot API методов жалобы не содержит вообще.
#
#  СОЗДАТЕЛЬ: @loomaxer
#  TELEGRAM : https://t.me/loomaxer
#
#  Методы API (официальная документация core.telegram.org):
#    account.reportPeer  — жалоба на бота/аккаунт/канал целиком (Bool)
#    messages.report     — жалоба на конкретные сообщения-доказательства
#    account.reportProfilePhoto — жалоба на аватар с чужими данными
#    contacts.block      — блокировка нарушителя
#
#  ⚠  ТОЛЬКО ДЛЯ ПРАВДИВЫХ, ДОКАЗАТЕЛЬНЫХ ЖАЛОБ НА РЕАЛЬНЫЕ НАРУШЕНИЯ.
#  Ложные и массовые жалобы = злоупотребление, бан вашего аккаунта и нарушение
#  Telegram ToS. Ответственность за использование — полностью на пользователе.
#
#  © 2026 @loomaxer · t.me/loomaxer
# ============================================================================

"""
TG Sentinel — главная точка входа CLI.

Примеры:
    python3 tg_sentinel.py login
    python3 tg_sentinel.py check @doxx_bot
    python3 tg_sentinel.py evidence @doxx_bot
    python3 tg_sentinel.py report @doxx_bot --reason personal --live
    python3 tg_sentinel.py report targets.json --dry-run
    python3 tg_sentinel.py draft @doxx_bot
    python3 tg_sentinel.py ledger
    python3 tg_sentinel.py selftest
"""

import argparse
import asyncio
import html as html_mod
import inspect
import json
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# ============================================================================
#  МЕТАДАННЫЕ И ВОДЯНОЙ ЗНАК СОЗДАТЕЛЯ — @loomaxer (https://t.me/loomaxer)
# ============================================================================
__title__ = "TG Sentinel"
__version__ = "1.0.0"
__author__ = "@loomaxer"
__telegram__ = "https://t.me/loomaxer"
WATERMARK = "TG Sentinel · создатель: @loomaxer · t.me/loomaxer"
WATERMARK_LINE = "─" * 66 + "\n  ▲ " + WATERMARK + "\n" + "─" * 66

ROOT = Path(__file__).resolve().parent
SESS_DIR = ROOT / "sessions"
EVID_DIR = ROOT / "evidence"
DRAFT_DIR = ROOT / "drafts"
LEDGER_PATH = ROOT / "ledger.json"
DEFAULT_CONFIG = ROOT / "config.json"

# Причина по умолчанию — разглашение персональных данных (наш профильный кейс)
DEFAULT_REASON = "personal"
MAX_FLOOD_WAIT_DEFAULT = 90          # сек: дольше — не ждём, помечаем flood
DAILY_LIMIT_DEFAULT = 5              # суточный лимит живых жалоб с аккаунта
EVIDENCE_LIMIT_DEFAULT = 50          # сколько последних сообщений сканировать


# ============================================================================
#  ЦВЕТА И АНИМАЦИЯ (только stdlib, красивый вывод в терминале)
#  создано @loomaxer — https://t.me/loomaxer
# ============================================================================
class C:
    """ANSI-цвета с автоотключением для не-TTY и NO_COLOR."""

    ON = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    R = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    @classmethod
    def p(cls, color, text):
        return f"{color}{text}{cls.R}" if cls.ON else str(text)


ANIM_ON = sys.stdout.isatty() and os.environ.get("NO_ANIM") is None

BANNER = r"""
  ████████╗ ██████╗      ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
  ╚══██╔══╝██╔════╝      ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
     ██║   ██║  ███╗     ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
     ██║   ██║   ██║     ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
     ██║   ╚██████╔╝     ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
     ╚═╝    ╚═════╝      ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝"""


def clear_screen():
    if ANIM_ON:
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()


def typewrite(text, delay=0.012):
    """Эффект печатной машинки (мгновенно при отключённой анимации)."""
    if not ANIM_ON:
        print(text)
        return
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay if ch != "\n" else delay * 2)
    print()


class Spinner:
    """Бесшумный спиннер в отдельном потоке: брайль-кадры + таймер."""

    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, text, color=C.CYAN):
        self.text = text
        self.color = color
        self._event = threading.Event()
        self._thread = None
        self._start = 0.0

    def _loop(self):
        i = 0
        while not self._event.is_set():
            frame = self.FRAMES[i % len(self.FRAMES)]
            elapsed = time.time() - self._start
            line = f"\r  {C.p(self.color, frame)} {self.text} {C.p(C.DIM, f'{elapsed:5.1f}s')}"
            sys.stdout.write(line)
            sys.stdout.flush()
            i += 1
            time.sleep(0.09)

    def __enter__(self):
        self._start = time.time()
        if ANIM_ON:
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
        else:
            print(f"  {C.p(C.CYAN, '•')} {self.text} …")
        return self

    def _erase(self):
        if ANIM_ON:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()

    def stop(self, mark="●", color=C.GREEN, note="готово"):
        self._event.set()
        if self._thread:
            self._thread.join(timeout=1)
        self._erase()
        print(f"  {C.p(color, mark)} {self.text} — {C.p(C.DIM, note)}")

    def ok(self, note="успешно"):
        self.stop("✔", C.GREEN, note)

    def fail(self, note="ошибка"):
        self.stop("✖", C.RED, note)

    def warn(self, note="пропущено"):
        self.stop("!", C.YELLOW, note)

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            self.fail(str(exc)[:60])
        elif self._thread is not None or not ANIM_ON:
            if not self._event.is_set():
                self.ok()
        return False


def progress(iterable, label, total=None):
    """Прогресс-бар по итерируемому объекту."""
    items = list(iterable)
    total = total or len(items) or 1
    width = 32
    for idx, item in enumerate(items, 1):
        ratio = idx / total
        filled = int(width * ratio)
        if ANIM_ON:
            bar = C.p(C.GREEN, "█" * filled) + C.p(C.DIM, "░" * (width - filled))
            sys.stdout.write(f"\r  {label} {bar} {idx}/{total}")
            sys.stdout.flush()
        if idx == total and ANIM_ON:
            sys.stdout.write("\n")
        yield item
    if not ANIM_ON:
        print(f"  {label}: {total} шт.")


def boot_sequence():
    """Короткая кинематографичная заставка при старте."""
    if not ANIM_ON:
        print(C.p(C.CYAN, BANNER))
        print("  " + C.p(C.BOLD, "v" + __version__) + " · "
              + C.p(C.MAGENTA, "создатель: @loomaxer · t.me/loomaxer") + "\n")
        return
    clear_screen()
    lines = [
        ("инициализация ядра TG Sentinel", 0.18),
        ("загрузка протокола MTProto", 0.18),
        ("проверка этических ограничений", 0.18),
        ("подключение водяного знака @loomaxer", 0.22),
    ]
    for text, pause in lines:
        with Spinner(text):
            time.sleep(pause)
    time.sleep(0.25)
    clear_screen()
    for line in BANNER.split("\n"):
        print(C.p(C.CYAN, line))
        time.sleep(0.045)
    print()
    typewrite("  версия " + C.p(C.BOLD, __version__) + " · защита персональных данных · "
              + C.p(C.MAGENTA, "by @loomaxer"), 0.014)
    print()


def kv(key, value, color=C.BLUE):
    print(f"  {C.p(color, key + ':'):<26} {value}")


def stamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def watermark_footer():
    print("\n" + WATERMARK_LINE)


# ============================================================================
#  КОНФИГУРАЦИЯ И ЖУРНАЛ ЖАЛОБ (ЛЕДЖЕР)
#  создано @loomaxer — https://t.me/loomaxer
# ============================================================================
def load_config(path):
    p = Path(path)
    if not p.exists():
        die(f"Конфиг {p} не найден. Скопируйте config.example.json → config.json "
            f"и впишите api_id/api_hash с https://my.telegram.org")
    cfg = json.loads(p.read_text(encoding="utf-8"))
    for required in ("api_id", "api_hash"):
        if not cfg.get(required):
            die(f"В конфиге отсутствует обязательное поле: {required}")
    cfg.setdefault("daily_limit", DAILY_LIMIT_DEFAULT)
    cfg.setdefault("max_flood_wait", MAX_FLOOD_WAIT_DEFAULT)
    cfg.setdefault("evidence_limit", EVIDENCE_LIMIT_DEFAULT)
    return cfg


class Ledger:
    """Журнал отправленных жалоб: защита от дублей и суточного лимита."""

    def __init__(self, path=LEDGER_PATH):
        self.path = Path(path)
        self.data = {"tool": __title__, "version": __version__,
                     "creator": __author__, "creator_telegram": __telegram__,
                     "watermark": WATERMARK, "entries": []}
        if self.path.exists():
            try:
                self.data.update(json.loads(self.path.read_text(encoding="utf-8")))
            except json.JSONDecodeError:
                pass

    def save(self):
        self.path.write_text(json.dumps(self.data, ensure_ascii=False, indent=2),
                             encoding="utf-8")

    @staticmethod
    def _key(target):
        return str(target).lower().lstrip("@")

    def already_sent(self, target, account, reason):
        key = self._key(target)
        return any(e["target_key"] == key and e["account"] == account
                   and e["reason"] == reason and e["status"] == "accepted"
                   for e in self.data["entries"])

    def today_count(self, account):
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return sum(1 for e in self.data["entries"]
                   if e["account"] == account and e.get("at_utc", "").startswith(today)
                   and e["status"] == "accepted")

    def add(self, entry):
        entry["at_utc"] = stamp()
        entry["creator"] = __author__
        self.data["entries"].append(entry)
        self.save()

    def print_table(self):
        entries = self.data["entries"]
        if not entries:
            print(C.p(C.DIM, "  Журнал пуст — ещё не отправлено ни одной жалобы."))
            return
        print(C.p(C.BOLD, f"\n  Журнал жалоб ({len(entries)} записей):\n"))
        for e in entries[-20:]:
            color = C.GREEN if e["status"] == "accepted" else (
                C.YELLOW if e["status"] == "flood" else C.RED)
            print(f"  {C.p(color, '●')} {e['at_utc']}  {e['target']:<24} "
                  f"{e['reason']:<10} {e['account']:<18} {e['status']}")
        print(C.p(C.DIM, f"\n  Всего принято жалоб: "
                         f"{sum(1 for e in entries if e['status'] == 'accepted')}"))


# ============================================================================
#  LAZY-IMPORT TELETHON (чтобы selftest/help работали без установленной либы)
# ============================================================================
def load_telethon():
    try:
        from telethon import TelegramClient, functions, types, errors
        return TelegramClient, functions, types, errors
    except ImportError:
        die("Не установлена библиотека Telethon.\n"
            "  Установка:  pip install -r requirements.txt\n"
            "           или pip install telethon")


# ============================================================================
#  ПРИЧИНЫ ЖАЛОБ — официальный список ReportReason (core.telegram.org/type/ReportReason)
# ============================================================================
REASONS = {
    "personal": ("InputReportReasonPersonalDetails",
                 "Разглашение персональных данных (доксинг, сливы, деанон)"),
    "spam": ("InputReportReasonSpam", "Спам, навязчивая реклама, массовые рассылки"),
    "fake": ("InputReportReasonFake", "Самозванец, поддельный аккаунт/бренд"),
    "violence": ("InputReportReasonViolence", "Угрозы насилия, призывы к агрессии"),
    "pornography": ("InputReportReasonPornography", "Порнографические материалы"),
    "child_abuse": ("InputReportReasonChildAbuse", "Жестокость/эксплуатация несовершеннолетних"),
    "copyright": ("InputReportReasonCopyright", "Нарушение авторских прав"),
    "illegal_drugs": ("InputReportReasonIllegalDrugs", "Незаконные наркотики"),
    "geo": ("InputReportReasonGeoIrrelevant", "Нерелевантная геопривязка"),
    "other": ("InputReportReasonOther", "Иное нарушение Telegram ToS"),
}

# Ключевые слова для выбора динамической категории messages.report (RU+EN)
OPTION_KEYWORDS = ("personal", "личн", "персональн", "приватн", "private",
                   "data", "данны", "details", "dox", "деанон")


def build_reason(types, key):
    constructor = REASONS.get(key, REASONS[DEFAULT_REASON])[0]
    return getattr(types, constructor)()


def type_name(obj):
    return type(obj).__name__


def pick_report_option(options):
    """Выбор категории из серверного списка MessageReportOption по ключевым словам."""
    if not options:
        return None
    for opt in options:
        text = getattr(opt, "text", "").lower()
        if any(k in text for k in OPTION_KEYWORDS):
            return opt
    return options[0]


# ============================================================================
#  РАЗБОР ЦЕЛЕЙ: @username, t.me-ссылки, числовые ID
#  создано @loomaxer — https://t.me/loomaxer
# ============================================================================
def parse_target(raw):
    """Нормализует цель в {'kind': 'username'|'id', 'value': ...}."""
    s = str(raw).strip()
    if not s:
        raise ValueError("пустая цель")
    if s.lstrip("-").isdigit():
        return {"kind": "id", "value": int(s), "raw": s}
    m = re.match(r"(?:https?://)?t\.me/(?:joinchat/|\+)?([A-Za-z0-9_]{4,32})", s, re.I)
    if m:
        return {"kind": "username", "value": m.group(1), "raw": s}
    username = s.lstrip("@").split("/")[0].split("?")[0]
    if re.fullmatch(r"[A-Za-z0-9_]{4,32}", username):
        return {"kind": "username", "value": username, "raw": s}
    raise ValueError(f"не распознал цель: {raw!r} (ожидаю @username, t.me/ссылку или ID)")


def load_targets_file(path):
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = payload.get("targets", [])
    for row in rows:
        row["_parsed"] = parse_target(row["target"])
        row.setdefault("reason", DEFAULT_REASON)
    return rows


# ============================================================================
#  СКАНЕР ПЕРСОНАЛЬНЫХ ДАННЫХ В ТЕКСТЕ (эвристика, работает офлайн)
# ============================================================================
PII_PATTERNS = [
    ("email", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), 3),
    ("телефон", re.compile(r"(?:\+?\d[\d\-\s()]{8,}\d)"), 2),
    ("паспорт РФ", re.compile(r"\b\d{4}\s?\d{6}\b"), 4),
    ("СНИЛС", re.compile(r"\b\d{3}-\d{3}-\d{3}[- ]?\d{2}\b"), 4),
    ("ИИН/ИНН", re.compile(r"\b\d{12}\b"), 3),
    ("банковская карта", re.compile(r"\b(?:\d[ -]?){13,19}\b"), 3),
    ("Telegram для связи", re.compile(r"@[A-Za-z0-9_]{4,32}"), 1),
    ("ссылка на слив", re.compile(r"https?://[^\s]+(?:dump|base|sliv| leak|archive)[^\s]*", re.I), 3),
]
PII_KEYWORDS = [
    ("паспорт", 3), ("прописка", 3), ("адрес", 2), ("снилс", 4), ("инн", 3),
    ("удостоверение", 3), ("персональные данные", 4), ("деанон", 4), ("докс", 4),
    ("слив базы", 4), ("номер телефона", 2), ("почта", 1), ("фамилия", 1),
    ("дата рождения", 2), ("место работы", 1),
]


def scan_pii(text):
    """Возвращает список находок {'label','snippet','weight'} и суммарный score."""
    hits, score = [], 0
    if not text:
        return hits, 0
    for label, pattern, weight in PII_PATTERNS:
        m = pattern.search(text)
        if m:
            snippet = m.group(0)[:80]
            hits.append({"label": label, "snippet": snippet, "weight": weight})
            score += weight
    low = text.lower()
    for keyword, weight in PII_KEYWORDS:
        if keyword in low:
            hits.append({"label": f"ключевое слово: {keyword}", "snippet": keyword,
                         "weight": weight})
            score += weight
    return hits, score


# ============================================================================
#  СЕССИИ И ПОДКЛЮЧЕНИЕ К TELEGRAM
#  создано @loomaxer — https://t.me/loomaxer
# ============================================================================
def list_sessions():
    SESS_DIR.mkdir(exist_ok=True)
    return sorted(p.stem for p in SESS_DIR.glob("*.session"))


async def make_client(cfg, session_name):
    TelegramClient, _, _, errors = load_telethon()
    SESS_DIR.mkdir(exist_ok=True)
    client = TelegramClient(
        str(SESS_DIR / session_name), cfg["api_id"], cfg["api_hash"],
        device_model="TG Sentinel @loomaxer",
        system_version="OSINT/1.0", app_version=__version__,
        lang_code="ru", receive_updates=False,
    )
    await client.connect()
    if not await client.is_user_authorized():
        print(C.p(C.YELLOW, f"\n  Сессия {session_name!r} не авторизована. Вход в аккаунт:"))
        phone = input("  Номер телефона (в формате +7...): ").strip()
        await client.send_code_request(phone)
        code = input("  Код из Telegram: ").strip()
        try:
            me = await client.sign_in(phone=phone, code=code)
        except errors.SessionPasswordNeededError:
            import getpass
            password = getpass.getpass("  Облачный пароль 2FA: ")
            me = await client.sign_in(password=password)
        print(C.p(C.GREEN, f"  Добро пожаловать, id={me.id} (@{getattr(me, 'username', None)})"))
    return client


async def resolve_entity(client, target):
    parsed = parse_target(target)
    entity = await client.get_entity(
        parsed["value"] if parsed["kind"] == "username" else parsed["value"])
    return parsed, entity


def entity_brief(entity):
    """Краткое досье на цель для вывода и доказательств."""
    return {
        "id": getattr(entity, "id", None),
        "username": getattr(entity, "username", None),
        "name": getattr(entity, "first_name", None) or getattr(entity, "title", None),
        "last_name": getattr(entity, "last_name", None),
        "is_bot": getattr(entity, "bot", False),
        "verified": getattr(entity, "verified", False),
        "type": type_name(entity),
    }


# ============================================================================
#  СБОР ДОКАЗАТЕЛЬСТВ (профиль + сообщения с PII)
# ============================================================================
async def collect_evidence(client, functions, entity, limit):
    brief = entity_brief(entity)
    profile = {}
    try:
        full = await client(functions.users.GetFullUserRequest(entity))
        profile["about"] = getattr(full.full_user, "about", None)
        profile["common_chats"] = getattr(full.full_user, "common_chats_count", None)
    except Exception:
        try:
            full = await client(functions.channels.GetFullChannelRequest(entity))
            profile["about"] = getattr(full.full_chat, "about", None)
            profile["subscribers"] = getattr(full.full_chat, "participants_count", None)
        except Exception as e:
            profile["error"] = str(e)[:120]

    messages, pii_messages = [], []
    async for msg in client.iter_messages(entity, limit=limit):
        text = msg.message or ""
        hits, score = scan_pii(text)
        row = {"id": msg.id, "date": str(msg.date), "text": text[:2000],
               "pii_score": score, "pii_hits": hits}
        messages.append(row)
        if hits:
            pii_messages.append(row)
    return {"brief": brief, "profile": profile,
            "messages_scanned": len(messages),
            "pii_messages": pii_messages, "messages": messages}


def save_evidence(target_value, evidence):
    EVID_DIR.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base = EVID_DIR / f"{str(target_value).lstrip('@')}_{ts}"
    (base.with_suffix(".json")).write_text(
        json.dumps({"watermark": WATERMARK, "creator": __author__, **evidence},
                   ensure_ascii=False, indent=2), encoding="utf-8")
    lines = [WATERMARK, f"Цель: {target_value}", f"Время (UTC): {stamp()}", "=" * 60]
    for row in evidence["pii_messages"] or evidence["messages"][:20]:
        lines.append(f"[{row['id']}] {row['date']}  PII-score={row['pii_score']}")
        lines.append(row["text"][:500] or "<нет текста>")
        for hit in row["pii_hits"]:
            lines.append(f"   ⚠ {hit['label']}: {hit['snippet']}")
        lines.append("-" * 60)
    base.with_suffix(".txt").write_text("\n".join(lines), encoding="utf-8")
    return base.with_suffix(".json"), base.with_suffix(".txt")


# ============================================================================
#  ЯДРО ЖАЛОБ — официальные методы MTProto
#  создано @loomaxer — https://t.me/loomaxer
# ============================================================================
async def guarded(call_factory, errors, max_wait, spinner_note):
    """Обёртка с обработкой FloodWait: короткий флуд ждём с обратным отсчётом."""
    try:
        return await call_factory()
    except errors.FloodWaitError as e:
        if e.seconds > max_wait:
            raise
        for left in range(e.seconds, 0, -1):
            sys.stdout.write(f"\r  {C.p(C.YELLOW, '⏳ FloodWait')}: пауза {left:>3}s "
                             f"({spinner_note})")
            sys.stdout.flush()
            await asyncio.sleep(1)
        sys.stdout.write("\r\033[K")
        return await call_factory()


async def report_peer(client, functions, types, errors, entity, reason_key,
                      comment, max_wait, dry_run):
    reason = build_reason(types, reason_key)
    if dry_run:
        return {"step": "reportPeer", "status": "simulated",
                "reason": reason_key, "comment": comment[:200]}
    request = functions.account.ReportPeerRequest(
        peer=entity, reason=reason, message=comment[:500])
    ok = await guarded(lambda: client(request), errors, max_wait, "reportPeer")
    return {"step": "reportPeer", "status": "accepted" if ok else "rejected",
            "reason": reason_key, "comment": comment[:200]}


async def report_messages_flow(client, functions, types, errors, entity, msg_ids,
                               reason_key, comment, max_wait, dry_run):
    """Жалоба на сообщения: новый динамический флоу (option) + легаси (reason)."""
    ids = list(msg_ids)
    if dry_run:
        return {"step": "messages.report", "status": "simulated",
                "message_ids": ids, "reason": reason_key}
    sig = inspect.signature(functions.messages.ReportRequest.__init__).parameters
    if "option" in sig:
        first = await guarded(
            lambda: client(functions.messages.ReportRequest(
                peer=entity, id=ids, option=b"", message="")),
            errors, max_wait, "messages.report/categories")
        if type_name(first) == "ReportResultChooseOption":
            chosen = pick_report_option(first.options)
            second = await guarded(
                lambda: client(functions.messages.ReportRequest(
                    peer=entity, id=ids, option=chosen.option, message=comment[:500])),
                errors, max_wait, "messages.report/option")
            if type_name(second) == "ReportResultAddComment":
                third = await guarded(
                    lambda: client(functions.messages.ReportRequest(
                        peer=entity, id=ids, option=second.option,
                        message=comment[:500])),
                    errors, max_wait, "messages.report/comment")
                return {"step": "messages.report", "status": "accepted",
                        "category": getattr(chosen, "text", "?"),
                        "server_result": type_name(third), "message_ids": ids}
            return {"step": "messages.report", "status": "accepted",
                    "category": getattr(chosen, "text", "?"),
                    "server_result": type_name(second), "message_ids": ids}
        if type_name(first) == "ReportResultAddComment":
            second = await guarded(
                lambda: client(functions.messages.ReportRequest(
                    peer=entity, id=ids, option=first.option, message=comment[:500])),
                errors, max_wait, "messages.report/comment")
            return {"step": "messages.report", "status": "accepted",
                    "server_result": type_name(second), "message_ids": ids}
        return {"step": "messages.report", "status": "accepted",
                "server_result": type_name(first), "message_ids": ids}
    # Старые версии Telethon: параметр reason вместо option
    reason = build_reason(types, reason_key)
    ok = await guarded(
        lambda: client(functions.messages.ReportRequest(
            peer=entity, id=ids, reason=reason, message=comment[:500])),
        errors, max_wait, "messages.report/legacy")
    return {"step": "messages.report", "status": "accepted" if ok else "rejected",
            "message_ids": ids, "reason": reason_key}


async def report_profile_photo(client, functions, types, errors, entity,
                               reason_key, comment, max_wait, dry_run):
    photo = getattr(entity, "photo", None)
    if not photo:
        return {"step": "reportProfilePhoto", "status": "skipped", "note": "нет аватара"}
    if dry_run:
        return {"step": "reportProfilePhoto", "status": "simulated", "photo_id": photo.photo_id}
    input_photo = types.InputPhoto(
        id=photo.photo_id, access_hash=photo.access_hash,
        file_reference=getattr(photo, "file_reference", b""))
    ok = await guarded(
        lambda: client(functions.account.ReportProfilePhotoRequest(
            peer=entity, photo_id=input_photo,
            reason=build_reason(types, reason_key), message=comment[:500])),
        errors, max_wait, "reportProfilePhoto")
    return {"step": "reportProfilePhoto", "status": "accepted" if ok else "rejected"}


async def block_peer(client, functions, entity, dry_run):
    if dry_run:
        return {"step": "block", "status": "simulated"}
    ok = await client(functions.contacts.BlockRequest(id=entity))
    return {"step": "block", "status": "accepted" if ok else "rejected"}


# ============================================================================
#  ГОТОВЫЕ ТЕКСТЫ ЖАЛОБ: письмо в Telegram и форма GitHub
# ============================================================================
def build_comment(reason_key, target, evidence=None, custom=None):
    if custom:
        return custom.strip()
    reason_desc = REASONS.get(reason_key, REASONS[DEFAULT_REASON])[1]
    pii_count = len(evidence["pii_messages"]) if evidence else 0
    scanned = evidence["messages_scanned"] if evidence else 0
    return (f"Жалоба: {reason_desc}. Бот/аккаунт {target} публикует чужие персональные "
            f"данные без согласия людей (доксинг). Найдено сообщений с персональными "
            f"данными: {pii_count} из {scanned} проверенных. Прошу проверить и принять меры "
            f"согласно Telegram Terms of Service.")


def build_drafts(target, evidence, reason_key=DEFAULT_REASON):
    brief = evidence.get("brief", {}) if evidence else {}
    pii_n = len(evidence["pii_messages"]) if evidence else 0
    tg_mail = f"""Кому: abuse@telegram.org
Тема: Report: disclosure of personal data / doxxing — {target}

Здравствуйте!

Направляю жалобу на Telegram-объект {target} (id: {brief.get('id', '—')},
тип: {brief.get('type', '—')}, бот: {brief.get('is_bot', '—')}).

Суть нарушения: {REASONS[reason_key][1]}. Объект публикует персональные данные
третьих лиц без их согласия — имена, адреса, телефоны, документы и иную личную
информацию (доксинг), что нарушает Telegram Terms of Service.

Фактов с признаками персональных данных собрано: {pii_n}.
Доказательства сохранены локально (снимки сообщений с ID и датами), готов
предоставить по запросу.

Прошу рассмотреть жалобу и принять меры вплоть до блокировки.

С уважением,
пользователь Telegram.

—
{WATERMARK}
{__telegram__}"""

    github_form = f"""Категория формы: «I want to report a copyright, trademark violation,
or private information» → private information / personal data.

Описание:
I report the publication of private personal information (doxxing).
Telegram object: {target} (id {brief.get('id', '—')}).
The linked content discloses third parties' personal data (names, addresses,
phone numbers, identity documents) without consent. Please remove the private
information and review the account per GitHub/Telegram policies.
Evidence (message IDs, timestamps) collected and available on request.

—
{WATERMARK} · {__telegram__}"""
    return {"telegram_email": tg_mail, "github_form": github_form}


def save_drafts(target, drafts):
    DRAFT_DIR.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base = DRAFT_DIR / f"{str(target).lstrip('@')}_{ts}"
    paths = {}
    for name, content in drafts.items():
        p = base.with_name(base.name + f"_{name}.txt")
        p.write_text(content, encoding="utf-8")
        paths[name] = str(p)
    return paths


# ============================================================================
#  HTML-ОТЧЁТ С ВОДЯНЫМ ЗНАКОМ @loomaxer
# ============================================================================
def export_html(entries, path):
    rows = "".join(
        "<tr>" + "".join(f"<td>{html_mod.escape(str(e.get(k, '—')))}</td>"
                         for k in ("at_utc", "target", "reason", "account", "status"))
        + "</tr>" for e in entries)
    doc = f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="author" content="@loomaxer (https://t.me/loomaxer)">
<meta name="generator" content="TG Sentinel by @loomaxer">
<title>TG Sentinel · отчёт о жалобах · @loomaxer</title>
<style>
  :root {{ --bg:#0a0e16; --card:#131c2e; --line:#223352; --txt:#dce7f7;
           --dim:#7e90ad; --acc:#4fd1c5; --acc2:#7c8cff; }}
  body {{ margin:0; font-family:'Segoe UI',Arial,sans-serif; background:var(--bg);
          color:var(--txt); padding:34px; }}
  body::after {{ content:"@loomaxer"; position:fixed; inset:0; display:grid;
    place-items:center; font-size:110px; font-weight:800;
    color:rgba(79,209,197,.06); transform:rotate(-26deg); pointer-events:none; }}
  .wrap {{ max-width:1050px; margin:0 auto; position:relative; z-index:1; }}
  h1 {{ color:var(--acc); border-bottom:2px solid var(--acc); padding-bottom:12px; }}
  table {{ width:100%; border-collapse:collapse; background:var(--card);
    border:1px solid var(--line); border-radius:12px; overflow:hidden; }}
  th,td {{ text-align:left; padding:10px 12px; font-size:13px;
    border-bottom:1px solid var(--line); }}
  th {{ color:var(--acc2); }}
  footer {{ margin-top:26px; text-align:center; font-weight:700;
    background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px; }}
  footer a {{ color:var(--acc); text-decoration:none; }}
</style></head><body><div class="wrap">
<h1>🛡 TG Sentinel — отчёт о поданных жалобах</h1>
<p style="color:var(--dim)">Сформировано (UTC): {stamp()} · записей: {len(entries)}</p>
<table><thead><tr><th>Время (UTC)</th><th>Цель</th><th>Причина</th>
<th>Аккаунт</th><th>Статус</th></tr></thead><tbody>{rows}</tbody></table>
<footer>Создатель: <a href="https://t.me/loomaxer">@loomaxer</a> · t.me/loomaxer
 · {html_mod.escape(WATERMARK)}</footer>
</div></body></html>"""
    Path(path).write_text(doc, encoding="utf-8")
    return str(path)


# ============================================================================
#  КОМАНДЫ CLI
#  создано @loomaxer — https://t.me/loomaxer
# ============================================================================
def die(msg, code=1):
    print(C.p(C.RED, f"\n[!] {msg}"))
    print(C.p(C.DIM, WATERMARK))
    sys.exit(code)


async def cmd_login(cfg, name):
    client = await make_client(cfg, name)
    me = await client.get_me()
    print(C.p(C.GREEN, f"\n[+] Сессия сохранена: {name}.session · "
                       f"id={me.id} · @{me.username}"))
    await client.disconnect()
    watermark_footer()


async def cmd_check(cfg, target, limit):
    TelegramClient, functions, _, _ = load_telethon()
    sessions = list_sessions()
    if not sessions:
        die("Нет сессий. Сначала: python3 tg_sentinel.py login")
    async with TelegramClient(str(SESS_DIR / sessions[0]),
                              cfg["api_id"], cfg["api_hash"]) as client:
        parsed, entity = await resolve_entity(client, target)
        brief = entity_brief(entity)
        print(C.p(C.BOLD, f"\n[*] Досье на цель {target}"))
        for k, v in brief.items():
            kv(k, v)
        with Spinner("Сканирую сообщения на персональные данные"):
            evidence = await collect_evidence(client, functions, entity, limit)
        kv("Проверено сообщений", evidence["messages_scanned"])
        kv("Сообщений с PII", C.p(C.RED, str(len(evidence["pii_messages"]))))
        for row in evidence["pii_messages"][:5]:
            print(C.p(C.YELLOW, f"   ⚠ id={row['id']} score={row['pii_score']}: "
                                f"{row['text'][:70]!r}"))
    watermark_footer()
    return evidence


async def cmd_evidence(cfg, target, limit):
    TelegramClient, functions, _, _ = load_telethon()
    sessions = list_sessions()
    if not sessions:
        die("Нет сессий. Сначала: python3 tg_sentinel.py login")
    async with TelegramClient(str(SESS_DIR / sessions[0]),
                              cfg["api_id"], cfg["api_hash"]) as client:
        _, entity = await resolve_entity(client, target)
        with Spinner(f"Собираю доказательства по {target}"):
            evidence = await collect_evidence(client, functions, entity, limit)
        json_path, txt_path = save_evidence(target, evidence)
    print(C.p(C.GREEN, f"\n[+] Доказательства сохранены:\n  {json_path}\n  {txt_path}"))
    watermark_footer()


async def run_report(cfg, row, account, dry_run, do_block, do_photo, comment_text, ledger):
    TelegramClient, functions, types, errors = load_telethon()
    target = row["target"]
    reason_key = row.get("reason", DEFAULT_REASON)
    if reason_key not in REASONS:
        die(f"Неизвестная причина {reason_key!r}. Доступно: {', '.join(REASONS)}")
    if ledger.already_sent(target, account, reason_key):
        print(C.p(C.YELLOW, f"  ↷ Жалоба уже подавалась — пропускаю {target}"))
        return None
    if not dry_run and ledger.today_count(account) >= cfg["daily_limit"]:
        die(f"Достигнут суточный лимит {cfg['daily_limit']} жалоб с аккаунта {account}. "
            f"Лимит защищает от бана. Завтра лимит обновится.")

    client = await make_client(cfg, account)
    result = {"target": target, "target_key": ledger._key(target), "account": account,
              "reason": reason_key, "dry_run": dry_run, "steps": []}
    try:
        _, entity = await resolve_entity(client, target)
        with Spinner(f"Сбор доказательств: {target}"):
            evidence = await collect_evidence(
                client, functions, entity, cfg["evidence_limit"])
        ev_json, _ = save_evidence(target, evidence)
        result["evidence_file"] = str(ev_json)
        comment = build_comment(reason_key, target, evidence, comment_text or row.get("comment"))

        steps = [await report_peer(client, functions, types, errors, entity,
                                   reason_key, comment, cfg["max_flood_wait"], dry_run)]
        msg_ids = row.get("message_ids") or [m["id"] for m in evidence["pii_messages"][:5]]
        if msg_ids:
            steps.append(await report_messages_flow(
                client, functions, types, errors, entity, msg_ids, reason_key,
                comment, cfg["max_flood_wait"], dry_run))
        if do_photo:
            steps.append(await report_profile_photo(
                client, functions, types, errors, entity, reason_key, comment,
                cfg["max_flood_wait"], dry_run))
        if do_block:
            steps.append(await block_peer(client, functions, entity, dry_run))
        for step in progress(steps, f"Жалоба {target}"):
            result["steps"].append(step)
        result["status"] = "accepted" if any(
            s["status"] == "accepted" for s in steps) else (
            "simulated" if dry_run else "rejected")
    except errors.FloodWaitError as e:
        result["status"] = "flood"
        result["error"] = f"FloodWait {e.seconds}s"
        print(C.p(C.YELLOW, f"\n  ⏳ Telegram просит подождать {e.seconds}s — цель {target}"))
    except errors.PeerIdInvalidError:
        result["status"] = "invalid_target"
        result["error"] = "PeerIdInvalid"
        print(C.p(C.RED, f"\n  ✖ Неверная цель: {target}"))
    except Exception as e:  # сеть, ограничения и пр. — не роняем весь прогон
        result["status"] = "error"
        result["error"] = str(e)[:200]
        print(C.p(C.RED, f"\n  ✖ Ошибка по {target}: {e}"))
    finally:
        ledger.add(result)
        await client.disconnect()
    icon = {"accepted": C.GREEN, "simulated": C.CYAN, "flood": C.YELLOW}.get(
        result["status"], C.RED)
    print(f"  {C.p(icon, '●')} {target}: {result['status']}")
    return result


async def cmd_report(cfg, targets, account, dry_run, do_block, do_photo,
                     comment_text, yes, ledger):
    mode = C.p(C.CYAN, "DRY-RUN (ничего не отправляется)") if dry_run \
        else C.p(C.RED, "LIVE (жалобы реально отправятся в Telegram)")
    print(C.p(C.BOLD, f"\n[*] Режим: {mode}"))
    print(f"  Целей: {len(targets)} · аккаунт: {account} · "
          f"суточный лимит: {cfg['daily_limit']}")
    if not dry_run and not yes:
        confirm = input(C.p(C.YELLOW, "\n  Отправить настоящие жалобы? Напишите "
                                      "ДА: ")).strip()
        if confirm != "ДА":
            die("Отменено пользователем.", code=0)
    results = []
    for row in progress(targets, "Обработка целей"):
        results.append(await run_report(
            cfg, row, account, dry_run, do_block, do_photo, comment_text, ledger))
    accepted = sum(1 for r in results if r and r["status"] in ("accepted", "simulated"))
    print(f"\n  {C.p(C.BOLD, 'Обработано:')} {accepted}/{len(targets)}")
    watermark_footer()
    return results


async def cmd_block(cfg, target, account):
    TelegramClient, functions, _, _ = load_telethon()
    client = await make_client(cfg, account)
    try:
        _, entity = await resolve_entity(client, target)
        res = await block_peer(client, functions, entity, dry_run=False)
        print(C.p(C.GREEN, f"\n[+] Блокировка {target}: {res['status']}"))
    finally:
        await client.disconnect()
    watermark_footer()


def cmd_draft(target, reason_key, limit):
    # драфты не требуют сессии Telegram — генерируются из офлайн-шаблона
    evidence = None
    EVID_DIR.mkdir(exist_ok=True)
    candidates = sorted(EVID_DIR.glob(f"{str(target).lstrip('@')}_*.json"))
    if candidates:
        evidence = json.loads(candidates[-1].read_text(encoding="utf-8"))
        print(C.p(C.DIM, f"  Подставил данные из {candidates[-1].name}"))
    drafts = build_drafts(target, evidence, reason_key)
    paths = save_drafts(target, drafts)
    print(C.p(C.GREEN, "\n[+] Черновики жалоб сохранены:"))
    for name, p in paths.items():
        kv(name, p)
    print(C.p(C.DIM, "\n  Письмо отправьте вручную с вашей почты на abuse@telegram.org"))
    watermark_footer()


def cmd_selftest():
    """Офлайн-самодиагностика без Telegram и сети — by @loomaxer."""
    print(C.p(C.BOLD, "\n[*] Самодиагностика TG Sentinel (@loomaxer)\n"))
    checks = []

    def check(name, cond):
        checks.append(bool(cond))
        print(f"  {C.p(C.GREEN, 'PASS') if cond else C.p(C.RED, 'FAIL')}  {name}")

    check("Водяной знак @loomaxer в константах", "@loomaxer" in WATERMARK and "loomaxer" in __telegram__)
    check("Имя инструмента и ASCII-баннер на месте",
          __title__ == "TG Sentinel" and len(BANNER) > 100 and "█" in BANNER)

    cases = {
        "@doxx_bot": ("username", "doxx_bot"),
        "https://t.me/doxx_bot": ("username", "doxx_bot"),
        "t.me/doxx_bot?start=1": ("username", "doxx_bot"),
        "123456789": ("id", 123456789),
    }
    for raw, (kind, value) in cases.items():
        got = parse_target(raw)
        check(f"parse_target({raw!r})", got["kind"] == kind and got["value"] == value)
    bad = False
    try:
        parse_target("это не цель")
    except ValueError:
        bad = True
    check("parse_target отклоняет мусор", bad)

    check("Все 10 причин жалоб на месте", len(REASONS) == 10 and "personal" in REASONS)

    class FakeTypes:
        InputReportReasonPersonalDetails = type("R", (), {})
        InputReportReasonOther = type("R", (), {})

    check("build_reason создаёт конструктор", build_reason(FakeTypes, "personal") is not None)

    hits, score = scan_pii("Моя почта test@mail.ru и паспорт 1234 567890, деанон тут")
    check("PII-сканер находит email+паспорт+деанон", score >= 10 and len(hits) >= 3)
    empty_hits, empty_score = scan_pii("обычное сообщение без данных")
    check("PII-сканер не шумит на чистом тексте", empty_score == 0)

    class Opt:
        def __init__(self, text): self.text, self.option = text, b"x"

    chosen = pick_report_option([Opt("Spam"), Opt("Personal data / dox"), Opt("Other")])
    check("Выбор динамической категории по ключевому слову", chosen.text.startswith("Personal"))
    check("pick_report_option фолбэк на первую опцию",
          pick_report_option([Opt("Abuse")]).text == "Abuse")

    import tempfile
    tmp = Path(tempfile.mkdtemp())
    led = Ledger(tmp / "ledger.json")
    led.add({"target": "@b", "target_key": "b", "account": "acc",
             "reason": "personal", "status": "accepted"})
    check("Леджер: дубликаты отсекаются", led.already_sent("@b", "acc", "personal"))
    check("Леджер: суточный счётчик = 1", led.today_count("acc") == 1)
    led2 = Ledger(tmp / "ledger.json")
    check("Леджер переживает перезагрузку", len(led2.data["entries"]) == 1)

    drafts = build_drafts("@b", {"brief": {"id": 1, "type": "User", "is_bot": True},
                                 "pii_messages": [{"id": 1}], "messages_scanned": 5})
    check("Драфт письма содержит цель и watermark",
          "@b" in drafts["telegram_email"] and "@loomaxer" in drafts["telegram_email"])
    check("GitHub-драфт содержит watermark", "@loomaxer" in drafts["github_form"])

    html_path = export_html(led2.data["entries"], str(tmp / "report.html"))
    html_text = Path(html_path).read_text(encoding="utf-8")
    check("HTML-отчёт с watermark @loomaxer", "@loomaxer" in html_text and "loomaxer" in html_text)

    # Прогон анимации в не-TTY не должен падать
    with Spinner("тест спиннера"):
        time.sleep(0.05)
    total = sum(1 for _ in progress([1, 2, 3], "тест прогресса"))
    check("Анимация (spinner/progress) устойчива", total == 3)

    # Сухой прогон ядра жалоб на фейковом клиенте
    class FakeMsg:
        def __init__(self, i): self.id, self.date, self.message = i, "2026-01-01", "test@mail.ru"

    class FakeEntity:
        id, username, bot, photo = 42, "b", True, None

    class FakeClient:
        def __init__(self): self.calls = []

        async def __call__(self, request):
            self.calls.append(type_name(request))
            n = type_name(request)
            if n == "ReportRequest" and not self.calls.count(n) > 1:
                return type("ReportResultChooseOption", (),
                            {"options": [Opt("Spam"), Opt("Personal details")]})()
            return type("ReportResultReported", (), {})()

        def iter_messages(self, entity, limit):
            class _AIter:
                async def __aiter__(_): return _

                async def __anext__(_):
                    if not hasattr(_, "n"):
                        _.n = 0
                    if _.n >= 2:
                        raise StopAsyncIteration
                    _.n += 1
                    return FakeMsg(_.n)
            return _AIter()

    class FakeFunctions:
        class account:
            class ReportPeerRequest:
                def __init__(self, peer, reason, message): pass

            class ReportProfilePhotoRequest:
                def __init__(self, peer, photo_id, reason, message): pass

        class messages:
            class ReportRequest:
                def __init__(self, peer, id, option=b"", message=""): pass

        class contacts:
            class BlockRequest:
                def __init__(self, id): pass

        class users:
            class GetFullUserRequest:
                def __init__(self, entity): pass

    async def fake_pipeline():
        fc = FakeClient()
        r1 = await report_peer(fc, FakeFunctions, FakeTypes, None, FakeEntity(),
                               "personal", "комментарий", 90, dry_run=True)
        r2 = await report_messages_flow(fc, FakeFunctions, FakeTypes, None,
                                        FakeEntity(), [1, 2], "personal",
                                        "комментарий", 90, dry_run=True)
        live = await report_messages_flow(fc, FakeFunctions, FakeTypes, None,
                                          FakeEntity(), [1, 2], "personal",
                                          "коммент", 90, dry_run=False)
        return r1, r2, live, fc.calls

    r1, r2, live, calls = asyncio.run(fake_pipeline())
    check("Dry-run reportPeer не вызывает сеть", r1["status"] == "simulated")
    check("Dry-run messages.report не вызывает сеть", r2["status"] == "simulated")
    check("Live флоу проходит динамический выбор option", live["status"] == "accepted")
    check("Live флоу делает 2 запроса categories→option", calls.count("ReportRequest") == 2)

    print(f"\n  {C.p(C.BOLD, 'Итог:')} {sum(checks)}/{len(checks)} проверок пройдено")
    watermark_footer()
    return {"passed": sum(checks), "total": len(checks),
            "creator": __author__, "watermark": WATERMARK}


# ============================================================================
#  CLI
# ============================================================================
def build_parser():
    p = argparse.ArgumentParser(
        prog="tg_sentinel.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{__title__} v{__version__} — жалобы на ботов, распространяющих "
                    f"персональные данные.\nСоздатель: {__author__} · {__telegram__}",
        epilog="Только правдивые доказательные жалобы. Ложные жалобы = бан аккаунта.\n"
               f"Создатель: @loomaxer · {__telegram__}")
    p.add_argument("--version", action="version",
                   version=f"TG Sentinel {__version__} · by @loomaxer · t.me/loomaxer")
    p.add_argument("--config", default=str(DEFAULT_CONFIG), help="путь к config.json")
    p.add_argument("--no-anim", action="store_true", help="отключить анимацию")
    p.add_argument("--no-color", action="store_true", help="отключить цвета")

    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("login", help="войти в аккаунт и сохранить сессию")
    s.add_argument("name", nargs="?", default="main", help="имя сессии (по умолчанию main)")

    s = sub.add_parser("accounts", help="список сохранённых сессий")

    s = sub.add_parser("check", help="проверить цель и найти PII в сообщениях (read-only)")
    s.add_argument("target")
    s.add_argument("--limit", type=int, default=EVIDENCE_LIMIT_DEFAULT)

    s = sub.add_parser("evidence", help="сохранить доказательства в папку evidence/")
    s.add_argument("target")
    s.add_argument("--limit", type=int, default=EVIDENCE_LIMIT_DEFAULT)

    s = sub.add_parser("report", help="подать жалобу (по умолчанию dry-run!)")
    s.add_argument("targets", nargs="+", help="@цель, t.me/ссылка, ID или файл targets.json")
    s.add_argument("--reason", choices=list(REASONS), default=DEFAULT_REASON)
    s.add_argument("--comment", help="свой текст комментария модератору")
    s.add_argument("--account", default="main", help="имя сессии для отправки")
    s.add_argument("--live", action="store_true", help="РЕАЛЬНАЯ отправка (иначе dry-run)")
    s.add_argument("--block", action="store_true", help="дополнительно заблокировать цель")
    s.add_argument("--photo", action="store_true", help="пожаловаться ещё и на аватар")
    s.add_argument("--yes", action="store_true", help="не спрашивать подтверждение")

    s = sub.add_parser("block", help="заблокировать цель")
    s.add_argument("target")
    s.add_argument("--account", default="main")

    s = sub.add_parser("draft", help="сгенерировать тексты жалоб (email/GitHub), без отправки")
    s.add_argument("target")
    s.add_argument("--reason", choices=list(REASONS), default=DEFAULT_REASON)

    s = sub.add_parser("ledger", help="показать журнал отправленных жалоб")

    s = sub.add_parser("html", help="экспортировать журнал в HTML-отчёт")
    s.add_argument("path", nargs="?", default=str(ROOT / "report.html"))

    sub.add_parser("selftest", help="офлайн-самодиагностика")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.no_anim:
        global ANIM_ON
        ANIM_ON = False
    if args.no_color:
        C.ON = False
    if args.command != "selftest":
        boot_sequence()

    if args.command == "selftest":
        result = cmd_selftest()
        return 0 if result["passed"] == result["total"] else 1
    if args.command == "accounts":
        sessions = list_sessions()
        print(C.p(C.BOLD, "\nСохранённые сессии:"))
        for s in sessions or ["<нет — выполните login>"]:
            print(f"  • {s}")
        watermark_footer()
        return 0
    if args.command == "ledger":
        Ledger().print_table()
        watermark_footer()
        return 0
    if args.command == "html":
        entries = Ledger().data["entries"]
        path = export_html(entries, args.path)
        print(C.p(C.GREEN, f"[+] HTML-отчёт: {path}"))
        watermark_footer()
        return 0
    if args.command == "draft":
        cmd_draft(args.target, args.reason, EVIDENCE_LIMIT_DEFAULT)
        return 0

    cfg = load_config(args.config)
    ledger = Ledger()

    if args.command == "login":
        asyncio.run(cmd_login(cfg, args.name))
    elif args.command == "check":
        asyncio.run(cmd_check(cfg, args.target, args.limit))
    elif args.command == "evidence":
        asyncio.run(cmd_evidence(cfg, args.target, args.limit))
    elif args.command == "block":
        asyncio.run(cmd_block(cfg, args.target, args.account))
    elif args.command == "report":
        rows = []
        for t in args.targets:
            if t.endswith(".json"):
                rows.extend(load_targets_file(t))
            else:
                rows.append({"target": t, "reason": args.reason,
                             "comment": args.comment, "message_ids": []})
        asyncio.run(cmd_report(cfg, rows, args.account, dry_run=not args.live,
                               do_block=args.block, do_photo=args.photo,
                               comment_text=args.comment, yes=args.yes, ledger=ledger))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Прервано пользователем. " + WATERMARK)
        sys.exit(130)
