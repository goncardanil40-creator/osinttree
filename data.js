/* ============================================================================
 * OSINT TREE — данные дерева публичных OSINT-сервисов.
 * Создатель: @loomaxer · https://t.me/loomaxer
 * Все сервисы легальны и работают с открытыми данными.
 * ========================================================================== */

const TREE = {
  name: "OSINT Tree",
  children: [
    {
      id: "search",
      name: "Поисковики и дорки",
      children: [
        { name: "Google", desc: "Главный поисковик: операторы site:, filetype:, intext:, кавычки.", url: "https://www.google.com/" },
        { name: "Яндекс", desc: "Сильный поиск по рунету, людям, картинкам и картам.", url: "https://yandex.ru/" },
        { name: "DuckDuckGo", desc: "Поиск без персонализации и слежки, оператор !bangs.", url: "https://duckduckgo.com/" },
        { name: "Bing", desc: "Второй движок мира: другая выдача и поиск по изображениям.", url: "https://www.bing.com/" },
        { name: "Brave Search", desc: "Независимый индекс, приватный поиск.", url: "https://search.brave.com/" },
        { name: "DorkSearch", desc: "Конструктор Google-дорков без запоминания операторов.", url: "https://dorksearch.com/" },
        { name: "Google Advanced", desc: "Расширенные фильтры Google в одном интерфейсе.", url: "https://www.google.com/advanced_search" },
        { name: "Yandex Wordstat", desc: "Частотность слов и тем — что и где ищут люди.", url: "https://wordstat.yandex.ru/" }
      ]
    },
    {
      id: "archives",
      name: "Архивы и кэш",
      children: [
        { name: "Wayback Machine", desc: "Архив интернета: старые версии страниц с 1996 года.", url: "https://web.archive.org/" },
        { name: "archive.today", desc: "Снимки страниц, включая удалённые и JS-сайты.", url: "https://archive.ph/" },
        { name: "Ghost Archive", desc: "Поиск удалённых видео и страниц в архивах.", url: "https://ghostarchive.org/" },
        { name: "CachedView", desc: "Доступ к кэшу Google и архиву в один клик.", url: "https://cachedview.nl/" },
        { name: "Old Web Today", desc: "Старые сайты в реальных исторических браузерах.", url: "https://oldweb.today/" },
        { name: "Library of Congress", desc: "Веб-архив Библиотеки Конгресса США.", url: "https://www.loc.gov/websites/" },
        { name: "Common Crawl", desc: "Петабайты открытых краул-пулов для исследования.", url: "https://commoncrawl.org/" },
        { name: "URLScan", desc: "Снимки, DOM и сеть: что происходило при загрузке URL.", url: "https://urlscan.io/" }
      ]
    },
    {
      id: "social",
      name: "Соцсети и никнеймы",
      children: [
        { name: "Namechk", desc: "Проверка ника на десятках площадок одновременно.", url: "https://namechk.com/" },
        { name: "KnowEm", desc: "Поиск бренда/ника по 500+ социальным сетям.", url: "https://knowem.com/" },
        { name: "Sherlock", desc: "Open-source CLI для поиска ника по сотням сайтов.", url: "https://github.com/sherlock-project/sherlock" },
        { name: "Maigret", desc: "Мощный форк Sherlock: сбор профилей и метаданных.", url: "https://github.com/soxoj/maigret" },
        { name: "Twitter / X поиск", desc: "Поиск постов, людей и упоминаний в реальном времени.", url: "https://x.com/search" },
        { name: "VK Поиск людей", desc: "Люди ВКонтакте: город, возраст, школа, работа.", url: "https://vk.com/search" },
        { name: "Telegram Search", desc: "Публичные каналы и посты через t.me/s.", url: "https://t.me/s" },
        { name: "Reddit Search", desc: "Комментарии и посты англоязычного сообщества.", url: "https://www.reddit.com/search/" },
        { name: "TikTok Search", desc: "Поиск аккаунтов, видео и звуков.", url: "https://www.tiktok.com/search" },
        { name: "LinkedIn People", desc: "Профессиональные профили и карьера.", url: "https://www.linkedin.com/search/results/people/" }
      ]
    },
    {
      id: "email",
      name: "Email и утечки",
      children: [
        { name: "Have I Been Pwned", desc: "Проверка email в известных утечках баз данных.", url: "https://haveibeenpwned.com/" },
        { name: "EmailRep", desc: "Репутация и публичные следы email-адреса.", url: "https://emailrep.io/" },
        { name: "Hunter.io", desc: "Корпоративные email по домену компании.", url: "https://hunter.io/" },
        { name: "holehe", desc: "Open-source: к каким сайтам привязан email.", url: "https://github.com/megadose/holehe" },
        { name: "DeHashed", desc: "Поиск по компиляциям утечек (часть функций платно).", url: "https://dehashed.com/" },
        { name: "Intelligence X", desc: "Архив утечек, документов и исторических данных.", url: "https://intelx.io/" },
        { name: "LeakCheck", desc: "Проверка адреса в базах утечек.", url: "https://leakcheck.io/" },
        { name: "Gravatar", desc: "Аватары и профили, привязанные к MD5 почты.", url: "https://gravatar.com/" }
      ]
    },
    {
      id: "infra",
      name: "Домены, DNS, WHOIS",
      children: [
        { name: "WHOIS (ICANN)", desc: "Официальная регистрационная информация домена.", url: "https://lookup.icann.org/" },
        { name: "ViewDNS", desc: "DNS, история, reverse IP, поиск по NS.", url: "https://viewdns.info/" },
        { name: "SecurityTrails", desc: "История DNS и поддомены (бесплатный тариф).", url: "https://securitytrails.com/" },
        { name: "DNSDumpster", desc: "Карта инфраструктуры домена в один клик.", url: "https://dnsdumpster.com/" },
        { name: "crt.sh", desc: "Certificate Transparency: все поддомены из TLS-сертификатов.", url: "https://crt.sh/" },
        { name: "Zone Vision", desc: "DNS-зоны, NS, MX и сводка по домену.", url: "https://zone.vision/" },
        { name: "ProjectDiscovery Chaos", desc: "База известных поддоменов для разведки.", url: "https://chaos.projectdiscovery.io/" },
        { name: "RiskIQ Community", desc: "История хостов, угрозы и пассивный DNS.", url: "https://community.riskiq.com/" }
      ]
    },
    {
      id: "net",
      name: "IP, сети и IoT",
      children: [
        { name: "Shodan", desc: "Поиск по подключённым устройствам и сервисам мира.", url: "https://www.shodan.io/" },
        { name: "Censys", desc: "Сканер интернета: сертификаты, хосты, порты.", url: "https://search.censys.io/" },
        { name: "ZoomEye", desc: "Китайский поисковик устройств и веб-сервисов.", url: "https://www.zoomeye.org/" },
        { name: "ip-api", desc: "Быстрая бесплатная геолокация IP без ключа.", url: "https://ip-api.com/" },
        { name: "ipinfo", desc: "Гео, ASN, компания и тип IP-адреса.", url: "https://ipinfo.io/" },
        { name: "BGP Toolkit", desc: "Автономные системы, пиры и маршруты (Hurricane Electric).", url: "https://bgp.he.net/" },
        { name: "GreyNoise", desc: "Отделяет интернет-фон сканеров от целевых атак.", url: "https://viz.greynoise.io/" },
        { name: "AbuseIPDB", desc: "Жалобы на вредоносную активность IP.", url: "https://www.abuseipdb.com/" }
      ]
    },
    {
      id: "meta",
      name: "Метаданные и файлы",
      children: [
        { name: "ExifTool", desc: "Эталон чтения/записи EXIF, XMP, IPTC (CLI).", url: "https://exiftool.org/" },
        { name: "Jeffrey's Exif Viewer", desc: "Онлайн-разбор EXIF с картой GPS-съёмки.", url: "https://exif.regex.info/" },
        { name: "Metapicz", desc: "Просмотр метаданных изображения в браузере.", url: "https://metapicz.com/" },
        { name: "Foredit", desc: "Редактор EXIF и GPS-координат онлайн.", url: "https://www.foredit.com/" },
        { name: "TinEye", desc: "Обратный поиск картинки: где ещё опубликована.", url: "https://tineye.com/" },
        { name: "Google Lens", desc: "Обратный поиск изображений и распознавание.", url: "https://lens.google/" },
        { name: "Яндекс Картинки", desc: "Сильнейший reverse image по лицам и рунету.", url: "https://yandex.ru/images/" },
        { name: "PimEyes", desc: "Поиск лица по открытым веб-страницам.", url: "https://pimeyes.com/" }
      ]
    },
    {
      id: "geo",
      name: "Карты, гео, код",
      children: [
        { name: "Google Maps", desc: "Спутник, панорамы Street View, организации.", url: "https://www.google.com/maps" },
        { name: "Яндекс Карты", desc: "Детальные карты СНГ, панорамы и организации.", url: "https://yandex.ru/maps/" },
        { name: "Wikimapia", desc: "Народная карта объектов всей планеты.", url: "https://wikimapia.org/" },
        { name: "SunCalc", desc: "Солнце и тени в дату/время — для геохронолокации.", url: "https://www.suncalc.org/" },
        { name: "GitHub Code Search", desc: "Поиск кода, ключей и секретов в репозиториях.", url: "https://github.com/search" },
        { name: "Grep.app", desc: "Кросс-репозиторный поиск по коду.", url: "https://grep.app/" },
        { name: "Searchcode", desc: "Поиск исходников по 20+ языкам.", url: "https://searchcode.com/" },
        { name: "Etherscan", desc: "Проводник Ethereum: кошельки, транзакции, контракты.", url: "https://etherscan.io/" },
        { name: "Blockchain Explorer", desc: "Транзакции и адреса Bitcoin.", url: "https://www.blockchain.com/explorer" }
      ]
    }
  ]
};

/* Водяной знак создателя: @loomaxer · https://t.me/loomaxer */
