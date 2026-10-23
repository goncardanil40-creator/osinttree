# 🌳 OSINT Tree

**Мощный CLI-комбайн для разведки по открытым источникам на чистом Python — без единой сторонней зависимости.**

<div align="center">

### 👤 Создатель: [@loomaxer](https://t.me/loomaxer)

**Telegram: [t.me/loomaxer](https://t.me/loomaxer)**

`© 2026 @loomaxer · все водяные знаки и упоминания автора сохраняются`

</div>

---

## ✨ Возможности

| Модуль | Что делает |
|---|---|
| `user` | Поиск никнейма на **46 площадках** (GitHub, GitLab, Telegram, TikTok, Steam, VK, Habr, Docker Hub, PyPI, npm…) с параллельными запросами и детекцией анти-бот страниц |
| `email` | Проверка синтаксиса, DNS/MX домена, Gravatar-профиль, готовые ссылки на HIBP, EmailRep, Hunter.io |
| `domain` | **Собственный DNS-клиент на сырых UDP-пакетах** (A/AAAA/MX/NS/TXT/SOA/CNAME), перебор 80+ поддоменов, Certificate Transparency (crt.sh), WHOIS |
| `ip` | Классификация адреса, геолокация, ISP/ASN, обратный DNS (PTR) |
| `phone` | Разбор телефона **без внешних API**: страна по коду, E.164, оператор РФ/Казахстана, ссылки на проверки |
| `meta` | Ручные парсеры **EXIF/GPS (JPEG), PNG, PDF, DOCX/XLSX** + хеши MD5/SHA-1/SHA-256 |
| `url` | Цепочка редиректов, security-заголовки с оценкой A–D, эвристика технологий, разбор TLS-сертификата |
| `selftest` | 15 встроенных офлайн-тестов для проверки работоспособности |

Любой результат экспортируется в **JSON**, **CSV** и красивый **HTML-отчёт** — в каждый файл встроен водяной знак автора.

## 🚀 Быстрый старт

Нужен только Python 3.8+. Никаких `pip install` — всё на стандартной библиотеке.

```bash
git clone https://github.com/goncardanil40-creator/osinttree.git
cd osinttree
python3 osinttree.py --help
python3 osinttree.py selftest          # быстрая самодиагностика
```

## 📖 Использование

### 1. Поиск никнейма по площадкам

```bash
python3 osinttree.py user loomaxer
python3 osinttree.py user loomaxer --html reports/loomaxer.html
```

### 2. Разбор email

```bash
python3 osinttree.py email john.doe+tag@gmail.com --json mail.json
```

### 3. Разведка домена

```bash
python3 osinttree.py domain example.com
python3 osinttree.py domain example.com --csv domains.csv --timeout 15
```

### 4. IP-адрес

```bash
python3 osinttree.py ip 8.8.8.8
```

### 5. Телефонный номер

```bash
python3 osinttree.py phone +77051234567
python3 osinttree.py phone 89112345678          # выход через 8 → +7
```

### 6. Метаданные файла

```bash
python3 osinttree.py meta photo.jpg
python3 osinttree.py meta document.pdf
python3 osinttree.py meta contract.docx --html meta.html
```

EXIF-модуль извлекает GPS-координаты и сразу строит ссылку на Google Карты.

### 7. Разведка веб-ресурса

```bash
python3 osinttree.py url https://example.com
```

### Экспорт отчётов (водяной знак @loomaxer внутри каждого)

```bash
python3 osinttree.py domain example.com --json out.json --csv out.csv --html out.html
```

Опции `--json`, `--csv`, `--html` работают с любым модулем и в любом порядке аргументов.
Дополнительно: `--timeout N`, `--no-banner`, `--version`.

## 🔧 Технические детали

- **DNS-резолвер написан с нуля**: сборка/разбор UDP-пакетов, компрессия имён, типы записей A, AAAA, NS, CNAME, MX, TXT, SOA — без `dnspython` и системного `dig`.
- **EXIF-парсер написан с нуля**: TIFF IFD0/Exif/GPS, рациональные числа, пересчёт DMS → десятичные координаты — без Pillow.
- **WHOIS-клиент** на сыром TCP/43 с автоопределением регистратора через `whois.iana.org`.
- Параллельные проверки через `ThreadPoolExecutor`, аккуратная обработка таймаутов и анти-бот челленджей (Cloudflare/Fastly → статус «н/д», без ложных срабатываний).
- HTML-отчёт содержит визуальный полупрозрачный водяной знак `@loomaxer` и подвал автора.

## ⚖️ Этика и правовые рамки

Инструмент работает **исключительно с публично доступными данными** и не выполняет:

- атак, эксплуатации уязвимостей и брутфорса;
- обхода аутентификации и капчи;
- скрытого сбора персональных данных.

Проверяйте Terms of Service каждой площадки и соблюдайте законодательство своей страны.
Ответственность за использование несёт пользователь.

## 🧪 Тесты

```bash
python3 osinttree.py selftest
# Итог: 15/15 проверок пройдено
```

## 📄 Лицензия

[MIT](LICENSE) · Copyright (c) 2026 **[@loomaxer](https://t.me/loomaxer)**

---

<div align="center">

### ◈ OSINT Tree · создатель [@loomaxer](https://t.me/loomaxer) · [t.me/loomaxer](https://t.me/loomaxer)

</div>
