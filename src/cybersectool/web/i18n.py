"""Kangalis arayüzü için i18n sözlüğü (TR/EN).

Uygulamaya özel sayfalar (Zamanlama, Kullanıcılar, Token'lar) için anahtarlar
içerir. Teknik token'lar (IP, CVE, CVSS, port) çevrilmez.
"""

from __future__ import annotations

from collections.abc import Callable

LANG_COOKIE = "kg_lang"
DEFAULT_LANG = "tr"
LANGS = ("tr", "en")

DICT: dict[str, dict[str, str]] = {
    # Brand
    "tagline": {"tr": "İç ağınızın bekçisi.", "en": "The guardian of your internal network."},
    "brand_sub": {"tr": "Güvenli operasyon konsolu", "en": "Secure operations console"},
    # Nav
    "nav_dashboard": {"tr": "Panel", "en": "Dashboard"},
    "nav_scans": {"tr": "Taramalar", "en": "Scans"},
    "nav_zones": {"tr": "IP Zone", "en": "IP Zones"},
    "nav_vault": {"tr": "Kimlikler", "en": "Credentials"},
    "nav_wordlists": {"tr": "Kelime Listeleri", "en": "Wordlists"},
    "nav_assets": {"tr": "Varlıklar", "en": "Assets"},
    "nav_vuln": {"tr": "Zafiyetler", "en": "Vulnerabilities"},
    "nav_trends": {"tr": "Trend", "en": "Trends"},
    "nav_exploit": {"tr": "Exploit DB", "en": "Exploit DB"},
    "nav_cve": {"tr": "Zafiyet Veritabanı", "en": "Vulnerability DB"},
    # Help / Docs (#A)
    "nav_help": {"tr": "Yardım", "en": "Help"},
    # — Sorumluluk reddi onay ekranı (/disclaimer) —
    "disclaimer_title": {
        "tr": "Sorumluluk Reddi ve Kullanım Koşulları",
        "en": "Disclaimer & Terms of Use",
    },
    "disclaimer_intro": {
        "tr": "Devam etmeden önce lütfen aşağıdaki koşulları okuyup kabul edin. "
        "Kabul edilmeden tarama başlatılamaz.",
        "en": "Before continuing, please read and accept the terms below. "
        "Scanning cannot start until you accept.",
    },
    "disclaimer_p1": {
        "tr": "Bu aracı yalnızca taramaya açıkça yetkili olduğum (sahibi olduğum ya da "
        "yazılı izin aldığım) sistemlerde kullanacağım.",
        "en": "I will use this tool only on systems I am explicitly authorized to scan "
        "(owned by me or with written permission).",
    },
    "disclaimer_p2": {
        "tr": "Aktif tarama, kimlik denemesi ve sömürü işlemleri hedef sistemlerde kesinti, "
        "çökme veya veri kaybına yol açabilir; bu riski kabul ediyorum.",
        "en": "Active scanning, credential testing and exploitation may cause downtime, "
        "crashes or data loss on target systems; I accept this risk.",
    },
    "disclaimer_p3": {
        "tr": "Araç 'olduğu gibi', garantisiz sunulur; doğabilecek zararlardan Lineup-NOAH "
        "ve katkıda bulunanlar sorumlu tutulamaz.",
        "en": "The tool is provided 'as is', without warranty; Lineup-NOAH and contributors "
        "are not liable for any resulting damage.",
    },
    "disclaimer_p4": {
        "tr": "İzinsiz kullanımın tüm yasal sorumluluğu bana aittir.",
        "en": "I am solely responsible for the legal consequences of any unauthorized use.",
    },
    "disclaimer_full": {
        "tr": "Tam metin: depodaki DISCLAIMER.md dosyası.",
        "en": "Full text: see DISCLAIMER.md in the repository.",
    },
    "disclaimer_ack_label": {
        "tr": "Yalnızca yetkili olduğum sistemleri taradığımı ve yukarıdaki Sorumluluk "
        "Reddi'ni kabul ettiğimi onaylıyorum.",
        "en": "I confirm that I only scan systems I am authorized to, and I accept the "
        "Disclaimer above.",
    },
    "disclaimer_accept_btn": {"tr": "Kabul et ve devam et", "en": "Accept and continue"},
    "disclaimer_logout": {"tr": "Reddet ve çıkış yap", "en": "Decline and log out"},
    "help_title": {"tr": "Yardım & Dokümanlar", "en": "Help & Documentation"},
    "help_sub": {
        "tr": "Kurulum, temel kullanım, tarama kapsamı ve eklentiler için kısa rehber.",
        "en": "A short guide to setup, basic usage, scan scope and plugins.",
    },
    "help_docs_note": {
        "tr": "Daha ayrıntılı kurulum ve kullanım için depo içindeki docs/ klasörüne bakın "
        "(INSTALL.md, PLUGINS.md, GUIDE.md).",
        "en": "For more detailed setup and usage, see the docs/ folder in the repository "
        "(INSTALL.md, PLUGINS.md, GUIDE.md).",
    },
    # AI Q&A (#B) — Yardım sayfasındaki "AI'ya sor" + Eklentiler kurulum adımları
    "ai_qa_title": {"tr": "AI'ya sor", "en": "Ask the AI"},
    "ai_qa_sub": {
        "tr": "Uygulamayı nasıl kullanacağınızı sorun; AI bu sayfadaki yardım içeriğinden "
        "yanıtlar (uygulama dışına çıkmaz).",
        "en": "Ask how to use the app; the AI answers from the help content on this page "
        "(it won't go outside the app).",
    },
    "ai_qa_placeholder": {
        "tr": "Örn. Nasıl tarama başlatırım?",
        "en": "e.g. How do I start a scan?",
    },
    "ai_qa_btn": {"tr": "Sor", "en": "Ask"},
    "ai_qa_loading": {
        "tr": "AI düşünüyor… (CPU'da birkaç dakika sürebilir)",
        "en": "The AI is thinking… (may take a few minutes on CPU)",
    },
    "ai_qa_empty": {"tr": "Lütfen bir soru yazın.", "en": "Please type a question."},
    "ai_setup_steps_title": {
        "tr": "Yerel AI'yı başlatma (sunucuda)",
        "en": "Starting the local AI (on the server)",
    },
    "ai_setup_steps_note": {
        "tr": "Bu komutları sunucuda çalıştırın (uygulama Docker'ı kendisi çalıştıramaz), "
        "sonra aşağıdan endpoint + modeli girip 'Bağlantıyı test et'.",
        "en": "Run these on the server (the app cannot run Docker itself), then enter the "
        "endpoint + model below and click 'Test connection'.",
    },
    "ai_setup_step1": {"tr": "1) AI konteynerini başlat:", "en": "1) Start the AI container:"},
    "ai_setup_step2": {
        "tr": "2) Modeli bir kez çek (~5 GB):",
        "en": "2) Pull the model once (~5 GB):",
    },
    "cvedb_sub": {
        "tr": "Yerel CVE/CPE bilgi bankası (NVD'den çekilen). Sızma cephaneliği olan Exploit "
        "DB'den AYRIDIR — burası 'hangi zafiyetler var' bilgisi, orası gerçek exploit/payload.",
        "en": "Local CVE/CPE knowledge base (pulled from NVD). Separate from the Exploit DB "
        "(pentest arsenal) — this is 'what vulnerabilities exist', that is real exploits/payloads.",
    },
    "cvedb_total_cve": {"tr": "Toplam CVE", "en": "Total CVEs"},
    "cvedb_total_cpe": {"tr": "CPE eşleşmesi", "en": "CPE matches"},
    "cvedb_filtered": {"tr": "Sonuç", "en": "Results"},
    "cvedb_search_label": {"tr": "Ara (CVE / anahtar kelime)", "en": "Search (CVE / keyword)"},
    "cvedb_per_page": {"tr": "Sayfa başına", "en": "Per page"},
    "cvedb_kev_only": {"tr": "Yalnız KEV (aktif sömürü)", "en": "KEV only (actively exploited)"},
    "cvedb_empty": {"tr": "Eşleşen CVE yok.", "en": "No matching CVE."},
    "cvedb_page_of": {"tr": "Sayfa {p} / {n}", "en": "Page {p} of {n}"},
    "cvedb_manage": {"tr": "Senkron / geçmiş yükleme", "en": "Sync / backfill"},
    "nav_reports": {"tr": "Rapor", "en": "Reports"},
    "nav_schedules": {"tr": "Zamanlama", "en": "Schedules"},
    "nav_users": {"tr": "Kullanıcılar", "en": "Users"},
    "nav_tokens": {"tr": "Token'larım", "en": "My Tokens"},
    "nav_audit": {"tr": "Denetim", "en": "Audit"},
    "nav_system": {"tr": "Sistem", "en": "System"},
    "nav_update": {"tr": "Güncelleme", "en": "Update"},
    "nav_plugins": {"tr": "Eklentiler", "en": "Plugins"},
    "nav_license": {"tr": "Lisans", "en": "License"},
    "nav_settings": {"tr": "Ayarlar", "en": "Settings"},
    # Güncelleme sayfası (sürüm bilgisi + yeni-sürüm denetimi + nasıl-güncellenir)
    "update_title": {"tr": "Güncelleme", "en": "Update"},
    "update_sub": {
        "tr": "Yüklü sürüm + bileşen sürümleri, yeni sürüm denetimi ve nasıl güncelleneceği.",
        "en": "Installed version + component versions, update check, and how to update.",
    },
    "update_versions_title": {"tr": "Sürüm Bilgisi", "en": "Version Info"},
    "update_component": {"tr": "Bileşen", "en": "Component"},
    "update_version": {"tr": "Sürüm", "en": "Version"},
    "update_unknown": {"tr": "bilinmiyor", "en": "unknown"},
    "update_v_app": {"tr": "Kangalis (ürün)", "en": "Kangalis (product)"},
    "update_v_nmap": {"tr": "nmap (tarama motoru)", "en": "nmap (scan engine)"},
    "update_v_python": {"tr": "Python", "en": "Python"},
    "update_v_postgres": {"tr": "PostgreSQL", "en": "PostgreSQL"},
    "update_v_redis": {"tr": "Redis", "en": "Redis"},
    "update_v_ai": {"tr": "Yerel AI modeli", "en": "Local AI model"},
    "update_check_title": {"tr": "Güncelleme Denetimi", "en": "Update Check"},
    "update_check_sub": {
        "tr": "Her gün otomatik denetlenir. Bu denetim İNTERNETE çıkar (tek dış-erişim); "
        "kapatabilir ya da kendi sürüm kaynağınızı verebilirsiniz (air-gap dostu).",
        "en": "Checked automatically every day. This check reaches the INTERNET (the only "
        "egress); you can disable it or point to your own source (air-gap friendly).",
    },
    "update_current": {"tr": "Yüklü sürüm", "en": "Installed version"},
    "update_latest": {"tr": "En güncel sürüm", "en": "Latest version"},
    "update_last_checked": {"tr": "Son denetim", "en": "Last checked"},
    "update_check_now": {"tr": "Şimdi denetle", "en": "Check now"},
    "update_uptodate": {"tr": "Günceldir", "en": "Up to date"},
    "update_available_badge": {"tr": "Yeni sürüm var!", "en": "Update available!"},
    "update_status_unreachable": {
        "tr": "Sürüm sunucusuna erişilemedi (internet yok ya da engelli).",
        "en": "Could not reach the version server (no internet or blocked).",
    },
    "update_status_no_release": {
        "tr": "Yayınlanmış sürüm bulunamadı (depo henüz public değil ya da release yok).",
        "en": "No published release found (repo not public yet or no releases).",
    },
    "update_status_error": {
        "tr": "Sürüm denetimi hata verdi (sunucu yanıtı beklenmedik).",
        "en": "Update check errored (unexpected server response).",
    },
    "update_status_disabled": {
        "tr": "Otomatik denetim kapalı. 'Şimdi denetle' ile elle bakabilirsiniz.",
        "en": "Automatic check is off. Use 'Check now' to check manually.",
    },
    "update_status_never": {
        "tr": "Henüz denetlenmedi.",
        "en": "Not checked yet.",
    },
    "update_how_title": {"tr": "Nasıl güncellerim?", "en": "How to update"},
    "update_how_sub": {
        "tr": "Aşağıdaki komutu sunucunun (host) terminalinde çalıştırın. Veriniz korunur "
        "(veritabanı ayrı bir Docker volume'unda durur); şema göçü otomatik uygulanır.",
        "en": "Run the command below in the server's (host) terminal. Your data is preserved "
        "(the database lives in a separate Docker volume); schema migration runs automatically.",
    },
    "update_how_image": {
        "tr": "Yayınlanmış imaj (pull) kullanıyorsanız:",
        "en": "If using the published image (pull):",
    },
    "update_how_source": {"tr": "Kaynaktan derliyorsanız:", "en": "If building from source:"},
    "update_backup_note": {
        "tr": "Büyük sürüm yükseltmeleri öncesi veritabanı yedeği (pg_dump) almanız önerilir.",
        "en": "Taking a database backup (pg_dump) before major upgrades is recommended.",
    },
    "update_copy": {"tr": "Kopyala", "en": "Copy"},
    "update_copied": {"tr": "Kopyalandı", "en": "Copied"},
    "update_settings_title": {"tr": "Denetim Ayarları", "en": "Check Settings"},
    "update_enabled_label": {
        "tr": "Günlük otomatik denetim (internet erişimi gerektirir)",
        "en": "Daily automatic check (requires internet access)",
    },
    "update_url_label": {"tr": "Sürüm kaynağı (URL)", "en": "Version source (URL)"},
    "update_url_hint": {
        "tr": "Varsayılan GitHub Releases. Kendi aynanız/sürüm sunucunuz için değiştirin.",
        "en": "Defaults to GitHub Releases. Change for your own mirror/version server.",
    },
    "update_save": {"tr": "Kaydet", "en": "Save"},
    "update_flash_checked": {"tr": "Güncelleme denetimi yapıldı.", "en": "Update check performed."},
    "update_flash_saved": {"tr": "Ayarlar kaydedildi.", "en": "Settings saved."},
    # Sistem / Servisler paneli (konteyner durum + CPU/RAM/disk)
    "sys_title": {"tr": "Sistem Servisleri", "en": "System Services"},
    "sys_sub": {
        "tr": "Platformu oluşturan konteynerlerin (uygulama, işçi, veritabanı, Redis, "
        "MCP…) anlık durumu, CPU/RAM kullanımı ve disk doluluğu. 5 sn'de bir yenilenir.",
        "en": "Live status of the platform's containers (app, worker, database, Redis, "
        "MCP…), their CPU/RAM usage and disk usage. Refreshes every 5s.",
    },
    "sys_loading": {"tr": "Sistem durumu yükleniyor…", "en": "Loading system status…"},
    "sys_unavailable": {
        "tr": "Konteyner durumu okunamıyor — Docker soketi (docker.sock) uygulamaya mount "
        "edilmemiş. Aşağıdaki host disk/RAM bilgisi yine de gösterilir.",
        "en": "Container status unavailable — the Docker socket (docker.sock) is not mounted "
        "into the app. Host disk/RAM below is still shown.",
    },
    "sys_disk": {"tr": "Disk doluluğu (host)", "en": "Disk usage (host)"},
    "sys_ram": {"tr": "RAM (host)", "en": "RAM (host)"},
    "sys_docker_disk": {"tr": "Docker veri (imaj+volume)", "en": "Docker data (images+volumes)"},
    "sys_image": {"tr": "İmaj / Servis", "en": "Image / Service"},
    "sys_status": {"tr": "Durum", "en": "Status"},
    "sys_cpu": {"tr": "CPU", "en": "CPU"},
    "sys_mem": {"tr": "RAM", "en": "RAM"},
    "sys_up": {"tr": "ayakta", "en": "up"},
    "sys_down": {"tr": "durdu", "en": "down"},
    "sys_no_containers": {"tr": "Konteyner bulunamadı.", "en": "No containers found."},
    "sys_used_of": {"tr": "{used} / {total}", "en": "{used} / {total}"},
    # Eklentiler paneli (data-only çekirdek: nmap + yerel AI; #218/#219)
    "plugins_title": {"tr": "Eklentiler", "en": "Plugins"},
    "plugins_sub": {
        "tr": "Çekirdek eklentilerin durumu ve nasıl etkinleştirilecekleri: yerel AI asistanı "
        "(on-prem, sıfır egress) ve nmap tarama motoru.",
        "en": "Status of the core add-ons and how to enable each: the local AI assistant "
        "(on-prem, zero egress) and the nmap scan engine.",
    },
    "plugin_status_active": {"tr": "Aktif", "en": "Active"},
    "plugin_status_inactive": {"tr": "Pasif", "en": "Inactive"},
    "plugin_status_installed": {"tr": "Kurulu", "en": "Installed"},
    "plugin_howto": {"tr": "Nasıl aktif edilir", "en": "How to enable"},
    "plugin_nmap_name": {"tr": "nmap tarama motoru", "en": "nmap scan engine"},
    "plugin_nmap_howto": {
        "tr": "İmaj derlemesiyle gelir (varsayılan açık). Kapatmak için "
        "INSTALL_NMAP=false derleme argümanı ile yeniden derleyin.",
        "en": "Ships with the image build (on by default). To disable, rebuild with the "
        "INSTALL_NMAP=false build argument.",
    },
    "plugin_addon_title": {"tr": "Sömürü eklentisi", "en": "Exploitation add-on"},
    "plugin_addon_body": {
        "tr": "Canlı sömürü (searchsploit/Metasploit/sandbox) ayrı ticari kangalis-exploit "
        "eklentisinde gelir; bu çekirdek yalnızca veri odaklıdır.",
        "en": "Live exploitation (searchsploit/Metasploit/sandbox) ships in the separate "
        "commercial kangalis-exploit add-on; this core is data-only.",
    },
    "plugin_exploit_install": {
        "tr": "Ticari eklentiyi edindiyseniz: (1) kangalis-exploit'i worker ortamına/imajına "
        "kurun, (2) worker'ı yeniden başlatın, (3) msfrpcd'yi yapılandırın (endpoint/parola). "
        "Eklenti import-edilebilir olunca bu kart 'Kurulu' gösterir.",
        "en": "If you have the commercial add-on: (1) install kangalis-exploit into the worker "
        "environment/image, (2) restart the worker, (3) configure msfrpcd (endpoint/password). "
        "This card shows 'Installed' once the add-on is importable.",
    },
    "plugin_exploit_setup_title": {"tr": "Kurulum sihirbazı", "en": "Setup wizard"},
    "plugin_exploit_step1": {
        "tr": "1) Ticari eklenti imajını worker ortamına kurun/başlatın "
        "(imaj adı + tam komut ticari pakette gelir; örnek):",
        "en": "1) Install/start the commercial add-on image in the worker environment "
        "(image name + exact command ship with the commercial package; example):",
    },
    "plugin_exploit_step2": {
        "tr": "2) Metasploit RPC (msfrpcd) bağlantısını yapılandırın (worker env):",
        "en": "2) Configure the Metasploit RPC (msfrpcd) connection (worker env):",
    },
    "plugin_exploit_step3": {
        "tr": "3) Lisans kodunu girin → bu kartta 'Kurulu' + 'Lisanslı' olunca sömürü açılır:",
        "en": "3) Enter the license code → exploitation unlocks once this card shows "
        "'Installed' + 'Licensed':",
    },
    "plugin_exploit_step3_btn": {"tr": "Lisans sayfası", "en": "License page"},
    "plugin_exploit_authorized": {
        "tr": "⚠️ Yalnız YETKİLİ sistemlerde çalıştırın. Sömürünün meşruiyeti araçtan değil, "
        "hedef-yetkisinden gelir; yetkisiz kullanım yasa dışı olabilir. Her deneme denetim "
        "günlüğüne yazılır. (Hukuki tavsiye değildir.)",
        "en": "⚠️ Run against AUTHORIZED systems only. Legitimacy comes from target authorization, "
        "not the tool; unauthorized use may be illegal. Every attempt is audit-logged. "
        "(Not legal advice.)",
    },
    # Sömürü ikinci kapısı: geçerli ``exploit`` lisansı (Lisans sekmesi) — eklentiden ayrı
    "plugin_exploit_licensed": {"tr": "Lisanslı", "en": "Licensed"},
    "plugin_exploit_unlicensed": {"tr": "Lisans gerekli", "en": "License required"},
    "logout": {"tr": "Çıkış", "en": "Logout"},
    # Topbar / common
    "search_ph": {"tr": "Ara: CVE, IP, varlık…", "en": "Search CVE, IP, asset…"},
    "theme_toggle": {"tr": "Tema değiştir", "en": "Toggle theme"},
    "sidebar_show": {"tr": "Menüyü göster", "en": "Show menu"},
    "lang_toggle": {"tr": "Dil", "en": "Language"},
    "role_admin": {"tr": "Yönetici", "en": "Admin"},
    "role_analyst": {"tr": "Analist", "en": "Analyst"},
    "role_viewer": {"tr": "İzleyici", "en": "Viewer"},
    # Login
    "login_user": {"tr": "Kullanıcı adı", "en": "Username"},
    "login_pass": {"tr": "Parola", "en": "Password"},
    "login_signin": {"tr": "Giriş", "en": "Sign in"},
    "login_err": {"tr": "Kullanıcı adı veya parola hatalı", "en": "Invalid username or password"},
    "login_ldap": {
        "tr": "Kurumsal (LDAP/AD) hesabınızla da giriş yapabilirsiniz.",
        "en": "You can also sign in with your corporate (LDAP/AD) account.",
    },
    # Generic actions
    "create": {"tr": "Oluştur", "en": "Create"},
    "delete": {"tr": "Sil", "en": "Delete"},
    "revoke": {"tr": "İptal et", "en": "Revoke"},
    "run": {"tr": "Çalıştır", "en": "Run"},
    "cancel": {"tr": "Vazgeç", "en": "Cancel"},
    "confirm": {"tr": "Onayla", "en": "Confirm"},
    "save": {"tr": "Kaydet", "en": "Save"},
    "view_all": {"tr": "Tümünü gör", "en": "View all"},
    "open": {"tr": "Aç", "en": "Open"},
    "export": {"tr": "Dışa aktar", "en": "Export"},
    "print": {"tr": "Yazdır", "en": "Print"},
    "new_scan": {"tr": "Yeni Tarama", "en": "New Scan"},
    "none_yet": {"tr": "Henüz kayıt yok.", "en": "Nothing here yet."},
    # Stat cards
    "stat_assets": {"tr": "Varlık", "en": "Assets"},
    "stat_open": {"tr": "Açık Zafiyet", "en": "Open Vulnerabilities"},
    "stat_resolved": {"tr": "Çözülen Zafiyet", "en": "Resolved Vulnerabilities"},
    "stat_scans": {"tr": "Tarama", "en": "Scans"},
    "stat_exploit": {"tr": "Exploit Kaydı", "en": "Exploit-DB Entries"},
    "stat_zones": {"tr": "IP Zone", "en": "IP Zones"},
    # Dashboard sections
    "sev_dist": {"tr": "Açık Önem Dağılımı", "en": "Open Severity Distribution"},
    "top_risky": {"tr": "En Riskli Bulgular", "en": "Top Riskiest Findings"},
    "top_risky_vuln": {"tr": "En Riskli Zafiyetler", "en": "Top Riskiest Vulnerabilities"},
    # Dashboard lifecycle band
    "lifecycle_title": {"tr": "Zafiyet Yaşam Döngüsü", "en": "Vulnerability Lifecycle"},
    "lc_new_7d": {"tr": "Yeni (7 gün)", "en": "New (7 days)"},
    "lc_resolved_7d": {"tr": "Çözülen (7 gün)", "en": "Resolved (7 days)"},
    "lc_regressions": {"tr": "Regresyon", "en": "Regressions"},
    "lc_aging_30d": {"tr": "30+ gün açık", "en": "Open 30+ days"},
    "lc_mttr": {"tr": "Ort. çözüm (gün)", "en": "Avg. resolve (days)"},
    # Trend page (VI-3)
    "trends_title": {"tr": "Zafiyet Trendi", "en": "Vulnerability Trends"},
    "trends_sub": {
        "tr": "Haftalık açık/yeni/çözülen zafiyetler ve yaş dağılımı — "
        "zafiyet geçmişinden türetilir.",
        "en": "Weekly open/new/resolved vulnerabilities and age distribution — "
        "derived from vulnerability history.",
    },
    "trend_weekly_open": {
        "tr": "Haftalık yeni açılan zafiyet (son 8 hafta)",
        "en": "Weekly newly-opened vulnerabilities (last 8 weeks)",
    },
    "trend_legend": {
        "tr": "Çubuk = o hafta YENİ açılan zafiyet (kümülatif değil, her hafta 0'dan) · "
        "−çözülen o hafta.",
        "en": "Bar = vulnerabilities newly opened that week (not cumulative, from 0 each "
        "week) · −resolved that week.",
    },
    "trend_aging": {"tr": "Açık Zafiyet Yaşı", "en": "Open Vulnerability Age"},
    "aging_fresh": {"tr": "≤ 7 gün", "en": "≤ 7 days"},
    "aging_recent": {"tr": "8–30 gün", "en": "8–30 days"},
    "aging_old": {"tr": "30+ gün (geciken)", "en": "30+ days (overdue)"},
    "exploit_db_summary": {
        "tr": "Exploit & Payload Veritabanı",
        "en": "Exploit & Payload Database",
    },
    "categories": {"tr": "Kategoriler", "en": "Categories"},
    "offline_cpe": {"tr": "Offline CPE", "en": "Offline CPE"},
    "total": {"tr": "Toplam", "en": "Total"},
    # Table headers
    "h_cve": {"tr": "CVE-ID", "en": "CVE-ID"},
    "h_title": {"tr": "Başlık", "en": "Title"},
    "h_cvss": {"tr": "CVSS", "en": "CVSS"},
    "h_compliance": {"tr": "Uyum", "en": "Compliance"},
    "h_exploitable": {"tr": "Sömürü", "en": "Exploit"},
    # Exploit→MSF köprüsü (sömürülebilirlik sinyalleri) — Zafiyet DB + Exploit DB
    "cve_exploitable_msf_tip": {
        "tr": (
            "Bu CVE için Metasploit modülü mevcut — agresif CVE taramasında otomatik denenebilir."
        ),
        "en": "A Metasploit module exists for this CVE — auto-attempted in aggressive CVE scans.",
    },
    "cve_exploitable_poc_tip": {
        "tr": "Bu CVE için yalnız Exploit-DB PoC referansı var (manuel inceleme/uyarlama).",
        "en": "Only an Exploit-DB PoC reference exists for this CVE (manual review/adaptation).",
    },
    "exploit_runnable": {"tr": "Otomatik çalışır", "en": "Auto-run"},
    "exploit_runnable_tip": {
        "tr": (
            "Metasploit modülü — agresif CVE taramasında msfrpcd üzerinden otomatik "
            "çalıştırılabilir (admin + onay + kapsam)."
        ),
        "en": (
            "Metasploit module — auto-run via msfrpcd in aggressive CVE scans "
            "(admin + ack + scope)."
        ),
    },
    "exploit_reference": {"tr": "Referans (manuel)", "en": "Reference (manual)"},
    "exploit_reference_tip": {
        "tr": "Exploit-DB PoC kaydı — çalıştırma motoru yok; operatör linki inceler/uyarlar.",
        "en": "Exploit-DB PoC entry — no run engine; operator reviews/adapts via the link.",
    },
    "exploit_verified": {"tr": "Doğrulanmış", "en": "Verified"},
    "exploit_verified_tip": {
        "tr": (
            "Exploit-DB bu PoC'yi doğruladı (OffSec işlevsel tekrar testi). DİKKAT: "
            "yalnız 'çalışıyor' demektir — güvenlik/zararsızlık denetimi DEĞİL; PoC kodu "
            "yine de kötü amaçlı olabilir, sömürme labda izole çalıştırılır."
        ),
        "en": (
            "Exploit-DB verified this PoC (OffSec functional reproduction test). NOTE: "
            "this only means it 'works' — NOT a safety/malware audit; the PoC code may "
            "still be malicious, so exploitation runs isolated in the lab."
        ),
    },
    "exploit_rank_label": {"tr": "Güvenilirlik", "en": "Reliability"},
    "exploit_bridge_note": {
        "tr": (
            "Metasploit kayıtları agresif CVE taramasında otomatik çalıştırılabilir; "
            "Exploit-DB kayıtları referans/istihbarattır (manuel inceleme)."
        ),
        "en": (
            "Metasploit entries are auto-runnable in aggressive CVE scans; "
            "Exploit-DB entries are reference/intel (manual review)."
        ),
    },
    "compliance_framework": {"tr": "Uyum çerçevesi", "en": "Compliance framework"},
    "remove_fw_filter": {"tr": "Çerçeve filtresini kaldır", "en": "Clear framework filter"},
    "cve_fw_tip": {
        "tr": "Bu zafiyet bu mevzuat/standart için önemli (heuristik eşleme).",
        "en": "This vulnerability matters for this regulation/standard (heuristic mapping).",
    },
    "h_severity": {"tr": "Önem", "en": "Severity"},
    "h_asset": {"tr": "Varlık", "en": "Asset"},
    "h_risk": {"tr": "Risk", "en": "Risk"},
    "h_exploit": {"tr": "Exploit", "en": "Exploit"},
    "h_status": {"tr": "Durum", "en": "Status"},
    "h_started": {"tr": "Başlangıç", "en": "Started"},
    "h_source": {"tr": "Kaynak", "en": "Source"},
    "h_when": {"tr": "Zaman", "en": "When"},
    "h_action": {"tr": "İşlem", "en": "Action"},
    # Severity
    "sev_critical": {"tr": "Kritik", "en": "Critical"},
    "sev_high": {"tr": "Yüksek", "en": "High"},
    "sev_medium": {"tr": "Orta", "en": "Medium"},
    "sev_low": {"tr": "Düşük", "en": "Low"},
    "sev_info": {"tr": "Bilgi", "en": "Info"},
    # Status
    "st_pending": {"tr": "Beklemede", "en": "Pending"},
    "st_running": {"tr": "Çalışıyor", "en": "Running"},
    "st_completed": {"tr": "Tamamlandı", "en": "Completed"},
    "st_failed": {"tr": "Başarısız", "en": "Failed"},
    "st_cancelled": {"tr": "İptal edildi", "en": "Cancelled"},
    # Vulnerability lifecycle status (FindingStatus)
    "st_open": {"tr": "Açık", "en": "Open"},
    "st_confirmed": {"tr": "Doğrulandı", "en": "Confirmed"},
    "st_resolved": {"tr": "Giderildi", "en": "Resolved"},
    "st_false_positive": {"tr": "Yanlış pozitif", "en": "False positive"},
    "st_accepted_risk": {"tr": "Riski kabul", "en": "Accepted risk"},
    # Vulnerabilities page
    "vuln_tab_active": {"tr": "Zafiyetli", "en": "Active"},
    "vuln_tab_resolved": {"tr": "Çözülenler", "en": "Resolved"},
    "vuln_tab_compliance": {"tr": "Uyum", "en": "Compliance"},
    # Zafiyet kategori filtresi
    "vuln_cat_filter": {"tr": "Kategori", "en": "Category"},
    "vuln_cat_all": {"tr": "Tümü", "en": "All"},
    "vcat_weak_credential": {"tr": "Zayıf Kimlik", "en": "Weak Credential"},
    "vcat_os_package": {"tr": "OS Paketi", "en": "OS Package"},
    "vcat_cve": {"tr": "CVE", "en": "CVE"},
    "vcat_web": {"tr": "Web", "en": "Web"},
    "vcat_config": {"tr": "Yapılandırma", "en": "Configuration"},
    "vcat_sca": {"tr": "Bağımlılık", "en": "Dependency"},
    "vcat_other": {"tr": "Diğer", "en": "Other"},
    "vuln_compliance_sub": {
        "tr": "Kimlikli denetimlerden türeyen çerçeve-bazlı uyum duruşu (tüm taramalar geneli).",
        "en": "Framework compliance posture derived from credentialed audits (all scans).",
    },
    "vuln_compliance_none": {
        "tr": "Henüz uyum verisi yok. Kimlikli (CIS) denetim çalıştırın.",
        "en": "No compliance data yet. Run a credentialed (CIS) audit.",
    },
    "vuln_failed_controls": {"tr": "En çok başarısız kontroller", "en": "Top failed controls"},
    "h_framework": {"tr": "Çerçeve", "en": "Framework"},
    "h_score": {"tr": "Skor", "en": "Score"},
    "h_pass": {"tr": "Geçti", "en": "Pass"},
    "h_fail": {"tr": "Kaldı", "en": "Fail"},
    "h_control": {"tr": "Kontrol", "en": "Control"},
    "h_fails": {"tr": "Başarısız", "en": "Fails"},
    "vuln_sub": {
        "tr": "Tekilleştirilmiş güncel zafiyet durumu — varlığa göre gruplu.",
        "en": "Deduplicated current vulnerability state — grouped by asset.",
    },
    "vuln_page_size": {"tr": "Sayfa boyutu", "en": "Page size"},
    "vuln_note_ph": {"tr": "Not (opsiyonel)", "en": "Note (optional)"},
    "vuln_regression": {"tr": "Regresyon", "en": "Regression"},
    "urgent": {"tr": "ACİL", "en": "URGENT"},
    "conf_validated": {"tr": "Doğrulandı (NSE)", "en": "Validated (NSE)"},
    "conf_inferred": {"tr": "Çıkarım", "en": "Inferred"},
    "conf_validated_hint": {
        "tr": "Agresif mod NSE vuln/exploit script'i bu zafiyeti AKTİF doğruladı.",
        "en": "An aggressive-mode NSE vuln/exploit script actively confirmed this.",
    },
    "conf_inferred_hint": {
        "tr": "Versiyon→CVE çıkarımı (aktif doğrulanmadı; false-positive olabilir).",
        "en": "Version→CVE inference (not actively validated; may be a false positive).",
    },
    "urgent_hint": {
        "tr": "Acil: aktif sömürü (KEV) veya yüksek EPSS (≥%50) veya Metasploit modülü var.",
        "en": "Urgent: active exploitation (KEV) or high EPSS (≥50%) or a Metasploit module.",
    },
    "vuln_first_seen": {"tr": "İlk görülme", "en": "First seen"},
    "vuln_last_seen": {"tr": "Son görülme", "en": "Last seen"},
    "vuln_triage": {"tr": "Triyaj", "en": "Triage"},
    "vuln_page_of": {"tr": "Sayfa", "en": "Page"},
    "vuln_none": {"tr": "Bu sekmede zafiyet yok.", "en": "No vulnerabilities in this tab."},
    "prev": {"tr": "Önceki", "en": "Previous"},
    "next": {"tr": "Sonraki", "en": "Next"},
    # Live scan tracking
    "live_title": {"tr": "Canlı Takip", "en": "Live Tracking"},
    "live_progress": {"tr": "İlerleme", "en": "Progress"},
    "live_track": {"tr": "Canlı takip", "en": "Live track"},
    "live_remaining": {"tr": "Kalan (tahmini)", "en": "Remaining (est.)"},
    "live_stop": {"tr": "Taramayı Durdur", "en": "Stop Scan"},
    "live_starting": {"tr": "Başlatılıyor…", "en": "Starting…"},
    "live_services": {"tr": "Bulunan servisler / portlar", "en": "Discovered services / ports"},
    "live_cves": {"tr": "Bulgular", "en": "Findings"},
    "live_no_services": {
        "tr": "Henüz servis bulunamadı (tarama sürüyor).",
        "en": "No services found yet (scan in progress).",
    },
    "live_no_cves": {"tr": "Henüz bulgu yok.", "en": "No findings yet."},
    "live_no_hosts": {
        "tr": "Henüz yanıt veren host yok (tarama sürüyor ya da hedef yanıt vermedi).",
        "en": "No responding hosts yet (scan in progress or target unresponsive).",
    },
    "view_report": {"tr": "Raporu görüntüle", "en": "View report"},
    "h_service": {"tr": "Servis", "en": "Service"},
    "h_product": {"tr": "Ürün", "en": "Product"},
    "scans_table_hint": {
        "tr": "Bir satıra tıklayarak taramanın canlı takibini aç.",
        "en": "Click a row to open the scan's live tracking.",
    },
    # Scans page
    "scan_target": {"tr": "Hedef (IP/CIDR veya URL)", "en": "Target (IP/CIDR or URL)"},
    "scan_targets": {
        "tr": "Hedef(ler) — IP / CIDR / URL",
        "en": "Target(s) — IP / CIDR / URL",
    },
    "scan_targets_sub": {
        "tr": "Bir ya da çok hedef gir; virgül veya yeni satırla ayır. Ağ taramasında "
        "kapsam dışı hedefler atlanır.",
        "en": "Enter one or many targets; separate with commas or newlines. Out-of-scope "
        "targets are skipped on network scans.",
    },
    "new_scan_title": {"tr": "Hızlı tarama", "en": "Quick scan"},
    # SCAN-MERGE: birleşik "Tarama" paneli + Hızlı↔Adım-adım görünüm anahtarı
    "scan_panel_title": {"tr": "Tarama", "en": "Scan"},
    "scan_panel_sub": {
        "tr": "Hedef yaz ya da envanterden seç; modu/portu belirle, istersen kimlik/kategori/"
        "zamanlama ekle. Hızlı (tek ekran) ya da Adım adım ilerle.",
        "en": "Type a target or pick from inventory; set mode/ports, optionally add "
        "credentials/categories/scheduling. Go Quick (one screen) or Step by step.",
    },
    "step_confirm": {"tr": "Onay", "en": "Confirm"},
    "target_inventory": {"tr": "Envanterden seç (IP zone / varlık)", "en": "Pick from inventory"},
    "sched_inventory_only": {
        "tr": "Zamanlı tarama yalnız envanter hedefiyle (IP zone / varlık) çalışır.",
        "en": "Scheduled scans require inventory targets (IP zone / asset).",
    },
    "new_scan_sub": {
        "tr": "Hedefleri doğrudan gir, türü/portu seç, istersen kimlik ekle ve hemen başlat.",
        "en": "Type targets directly, pick type/ports, optionally add credentials and start.",
    },
    "scan_type": {"tr": "Tür", "en": "Type"},
    "type_network": {"tr": "Ağ (nmap)", "en": "Network (nmap)"},
    "type_ping": {"tr": "Ping (host keşfi)", "en": "Ping (host discovery)"},
    "type_vuln": {"tr": "Zafiyet (CVE/KEV)", "en": "Vulnerability (CVE/KEV)"},
    "type_web": {"tr": "Web (başlık/TLS)", "en": "Web (headers/TLS)"},
    "scan_ports": {"tr": "Portlar", "en": "Ports"},
    "ports_top": {"tr": "Genel portlar (top-1000)", "en": "Common ports (top-1000)"},
    "ports_all": {"tr": "Tüm portlar (-p-)", "en": "All ports (-p-)"},
    "ports_custom": {"tr": "Elle port gir", "en": "Custom ports"},
    "ports_custom_ph": {"tr": "80,443,8000-8100", "en": "80,443,8000-8100"},
    "udp_scan_label": {"tr": "UDP servisleri de tara", "en": "Also scan UDP services"},
    "udp_scan_hint": {
        "tr": "Hedeflenmiş UDP servis taraması (SNMP/DNS/NTP/IPMI/NetBIOS…). Yavaştır; "
        "yalnız yüksek-değerli UDP portları taranır.",
        "en": "Targeted UDP service scan (SNMP/DNS/NTP/IPMI/NetBIOS…). Slow; only high-value "
        "UDP ports are scanned.",
    },
    "quick_name": {"tr": "Tarama adı", "en": "Scan name"},
    "quick_name_ph": {"tr": "boş = Hızlı tarama N", "en": "blank = Quick scan N"},
    "quick_creds_btn": {"tr": "Kimlik ekle (opsiyonel)", "en": "Add credentials (optional)"},
    "quick_ack": {
        "tr": "Uyarıyı okudum ve bu taramayı kabul ediyorum.",
        "en": "I read the warning and accept this scan.",
    },
    "intensity": {"tr": "Yoğunluk", "en": "Intensity"},
    "safe": {"tr": "Güvenli (yalnızca tespit)", "en": "Safe (detection only)"},
    "aggressive": {"tr": "Agresif (müdahaleci)", "en": "Aggressive (intrusive)"},
    "start_scan": {"tr": "Tarama Başlat", "en": "Start Scan"},
    # SR-1 sonrası: Agresif CVE artık SÖMÜRMEZ (içeri sızmaz) — yalnız müdahaleci TESPİT.
    # Onay kalır (NSE vuln scriptleri + varsayılan-kimlik denemesi kırılgan servisi düşürebilir);
    # metin "sömürmez"i netleştirir, gerçek sızmayı Sömürme moduna yönlendirir.
    "danger_title": {
        "tr": "Müdahaleci mod — Agresif CVE (tespit, sömürmez)",
        "en": "Intrusive mode — Aggressive CVE (detection, no exploitation)",
    },
    "danger_body": {
        "tr": "Bu mod nmap NSE vuln/exploit scriptlerini çalıştırarak zafiyetleri aktif "
        "DOĞRULAR ve hangi exploit'lerin kullanılabileceğini gösterir — ama hedefi SÖMÜRMEZ "
        "(içeri sızmaz). "
        "Yine de müdahalecidir: kırılgan/üretim servislerini kesintiye uğratabilir, hedefte iz/log "
        "bırakır ve varsayılan-kimlik (ör. root/toor) denemesi yapar. Gerçek sömürü (içeri sızma) "
        "ayrı 'Exploit / Sömürme' modundadır. Yalnızca yetkili ve yedeği alınmış sistemlerde "
        "kullanın; bu eylem denetim günlüğüne kaydedilir.",
        "en": "This mode runs nmap NSE vuln/exploit scripts to actively VERIFY vulnerabilities and "
        "show which exploits are usable — but does NOT exploit the target (no break-in). It is "
        "still intrusive: it may disrupt fragile/production services, leave traces/logs, and "
        "attempts default credentials (e.g. root/toor). Real exploitation (break-in) is the "
        "separate 'Exploit / Exploitation' mode. Use only on authorized, backed-up systems; this "
        "action is recorded in the audit log.",
    },
    # Web modu (DAST) onayı — nmap NSE değil, web uygulamasına müdahaleci payload (IX-2).
    # Web CVE (web_aggressive) modu onayı — aktif DAST. SR-3b: pasif "Web" modu artık uyarı/onay
    # İSTEMEZ (DAST bu moda taşındı). Sömürmez — gerçek web sömürüsü ayrı "Web Sömürü" modunda.
    "danger_web_title": {
        "tr": "Müdahaleci mod — Web CVE (aktif DAST, sömürmez)",
        "en": "Intrusive mode — Web CVE (active DAST, no exploitation)",
    },
    "danger_web_body": {
        "tr": "Bu mod web uygulamasına müdahaleci test payload'ları gönderir (SQL enjeksiyonu, "
        "XSS, açık yönlendirme, LFI vb.) ve web-yığını CVE'lerini tespit eder — ama hedefi "
        "SÖMÜRMEZ. Hedefte beklenmedik davranışlara, kayıt (log) girdilerine ve nadiren hizmet "
        "kesintisine yol açabilir. Gerçek web sömürüsü (içeri sızma) ayrı 'Web Sömürü' modundadır. "
        "Yalnızca yetkili ve yedeği alınmış sistemlerde kullanın; bu eylem denetim günlüğüne "
        "kaydedilir.",
        "en": "This mode sends intrusive test payloads to the web application (SQL injection, XSS, "
        "open redirect, LFI, etc.) and detects web-stack CVEs — but does NOT exploit the target. "
        "It may cause unexpected behavior, leave log entries, and rarely disrupt service. Real "
        "web exploitation (break-in) is the separate 'Web Exploitation' mode. Use only on "
        "authorized, backed-up systems; this action is recorded in the audit log.",
    },
    # Dış (public internet) web hedefi — iç-ağ kapsamını atlar (admin + açık onay).
    "web_external_label": {
        "tr": "Dış hedef (internet) — taramaya yetkili olduğumu onaylıyorum",
        "en": "External target (internet) — I confirm I'm authorized to scan it",
    },
    "web_external_hint": {
        "tr": "İç-ağ kapsamı atlanır ve yalnız public adresler taranır; loopback, iç/özel ağ ve "
        "link-local/bulut-metadata (169.254.x) adresleri yine reddedilir. Üçüncü taraf bir sistemi "
        "taramaya yetkili olduğunuzdan emin olun — bu eylem denetim günlüğüne kaydedilir.",
        "en": "Skips the internal-network scope and scans public addresses only; loopback, "
        "internal/private and link-local/cloud-metadata (169.254.x) addresses are still rejected. "
        "Make sure you are authorized to scan a third-party system — this action is audit-logged.",
    },
    # Dizin/içerik taraması — moddan bağımsız ayrı kutucuk (gobuster benzeri).
    "web_dirscan_label": {
        "tr": "Dizin taraması (içerik keşfi)",
        "en": "Directory scan (content discovery)",
    },
    "web_dirscan_hint": {
        "tr": "Kelime listesiyle yüzlerce yaygın dizin/dosya dener (admin, login, api, backup, "
        ".git…) ve erişilebilir olanları bulgu olarak listeler. Yıkıcı değildir ama çok sayıda "
        "istek üretir (hedefte log bırakır). Güvenli/agresif modundan bağımsız çalışır.",
        "en": "Probes hundreds of common directories/files from a wordlist (admin, login, api, "
        "backup, .git…) and reports the accessible ones. Non-destructive but generates many "
        "requests (leaves logs on the target). Independent of safe/aggressive mode.",
    },
    "web_wordlist_label": {"tr": "Kelime listesi", "en": "Wordlist"},
    "web_wordlist_builtin": {
        "tr": "Yerleşik liste (varsayılan ~210 yol)",
        "en": "Built-in list (default ~210 paths)",
    },
    "web_wordlist_hint": {
        "tr": "Kendi listeni Kimlikler → Kelime Listeleri'nden ekleyebilirsin (tür: Web dizin).",
        "en": "Add your own under Credentials → Wordlists (kind: Web directory).",
    },
    "zone_scan": {"tr": "IP Zone taraması", "en": "IP Zone Scan"},
    "zone_scan_sub": {
        "tr": "Bir IP bölgesi seç ve tüm bloklarını tek seferde tara.",
        "en": "Pick an IP zone and scan all its blocks at once.",
    },
    "scan_kind": {"tr": "Tarama tipi", "en": "Scan type"},
    "kind_safe_net": {"tr": "Güvenli (ağ)", "en": "Safe (network)"},
    "kind_aggr_net": {"tr": "Agresif (ağ)", "en": "Aggressive (network)"},
    "kind_ping_net": {"tr": "Ping (host keşfi)", "en": "Ping (host discovery)"},
    "wiz_ping_note": {
        "tr": "Ping seçilince yalnızca ayakta hostlar bulunur; kimlik, kategori ve "
        "port/CVE taraması yapılmaz, tarama hemen çalışır.",
        "en": "With Ping, only live hosts are discovered; credentials, categories and "
        "port/CVE scanning are skipped, and the scan runs immediately.",
    },
    # FAZ VIII — sihirbaz/hızlı tarama 5 modu (paylaşılan "mod seç").
    "wmode_network": {"tr": "Ağ taraması", "en": "Network scan"},
    "wmode_network_d": {
        "tr": "Açık port + servis/versiyon tespiti. Yanında port seçici belirir.",
        "en": "Open ports + service/version detection. Shows a port selector.",
    },
    "wmode_ping": {"tr": "Ping taraması", "en": "Ping scan"},
    "wmode_ping_d": {
        "tr": "Yalnızca ayakta hostları bulur (host keşfi). Port/CVE taraması yapmaz.",
        "en": "Finds only live hosts (discovery). No port/CVE scanning.",
    },
    "wmode_cve_safe": {"tr": "Güvenli CVE taraması", "en": "Safe CVE scan"},
    "wmode_cve_safe_d": {
        "tr": "Yüzeysel CVE taraması: kendi exploit veritabanımızdan eşleştirir, açık "
        "varsa bilgilendirir. Hedefe MÜDAHALE ETMEZ (sömürmez).",
        "en": "Surface CVE scan: matches against our exploit database and reports if a "
        "vulnerability exists. Does NOT touch the target (no exploitation).",
    },
    "wmode_cve_aggr": {"tr": "Agresif CVE (sömürmez)", "en": "Aggressive CVE (no exploit)"},
    "wmode_cve_aggr_d": {
        "tr": "CVE'leri aktif olarak doğrular (nmap NSE vuln/exploit) ve hangi exploit'lerin "
        "KULLANILABİLECEĞİNİ gösterir — ama SÖMÜRMEZ. Müdahaleci — yalnız admin + açık onay.",
        "en": "Actively verifies CVEs (nmap NSE vuln/exploit) and shows which exploits are "
        "USABLE — but does NOT exploit. Intrusive — admin only + explicit consent.",
    },
    # Web CVE / Web Sömürü modları (SR-3b) — ağ tarafının web karşılığı (banner→CVE + DAST).
    "wmode_web_cve": {"tr": "Web CVE (agresif)", "en": "Web CVE (aggressive)"},
    "wmode_web_cve_d": {
        "tr": "Aktif DAST (SQLi/XSS/LFI) + web-yığını CVE tespiti (Server/X-Powered-By banner) + "
        "kullanılabilir exploit'leri gösterir — SÖMÜRMEZ. Müdahaleci: admin + açık onay.",
        "en": "Active DAST (SQLi/XSS/LFI) + web-stack CVE detection (Server/X-Powered-By banner) "
        "+ shows usable exploits — does NOT exploit. Intrusive: admin + explicit consent.",
    },
    # SR-3c: hedef alanına URL girilince (CVE/sömürme modlarında) o adrese de web denetimi yapılır.
    "targets_url_hint": {
        "tr": "IP/CIDR + URL birlikte girebilirsin: CVE/sömürme modunda URL (https://...) "
        "verirsen IP'ler ağ taraması, URL'ler web denetimi olur (aynı tarama).",
        "en": "Mix IPs/CIDRs and URLs: in a CVE/exploit mode, IPs run a network scan and any "
        "URL (https://...) also runs a web check (same scan).",
    },
    "wmode_cred": {"tr": "Kimlikli tarama", "en": "Credentialed scan"},
    "wmode_cred_d": {
        "tr": "İçeriden kimlikli denetim (SSH/WinRM). Kimlik adımından en az bir kimlik seç.",
        "en": "Inside, credentialed audit (SSH/WinRM). Pick at least one credential.",
    },
    "wmode_cred_hint": {
        "tr": "Kimlik OPSİYONELDİR (Nessus modeli): 'Kimlikler' adımından kimlik seçersen "
        "tarama dışarıdan tekniğin yanı sıra İÇERİDEN de denetler (CIS + yetki yükseltme). "
        "Agresif CVE + kimlik + onay = exploitation + priv-esc denemesi.",
        "en": "Credentials are OPTIONAL (Nessus model): pick credentials in the 'Credentials' "
        "step and the scan also audits from INSIDE (CIS + privilege escalation) in addition to "
        "the outside technique. Aggressive CVE + credentials + consent = exploitation + priv-esc.",
    },
    "wmode_cred_note": {
        "tr": "Bu mod için 'Kimlikler' adımından en az bir kimlik (kimlik bölgesi ya da "
        "tekil) seçmelisin. Onay kutusunu işaretlersen ek olarak YETKİ YÜKSELTME DENEMESİ "
        "yapılır (opsiyonel); işaretlemezsen yalnız salt-okunur priv-esc enumerasyonu.",
        "en": "For this mode, pick at least one credential (credential zone or single) "
        "from the 'Credentials' step. Check the consent box to also ATTEMPT privilege "
        "escalation (optional); otherwise read-only priv-esc enumeration only.",
    },
    "kind_aggr_off": {"tr": "Agresif (kapalı)", "en": "Aggressive (off)"},
    "kind_credentialed": {
        "tr": "Credentialed (SSH/WinRM)",
        "en": "Credentialed (SSH/WinRM)",
    },
    "kind_credzone": {
        "tr": "Kimlik bölgesiyle (OS öncelikli)",
        "en": "By credential zone (OS-priority)",
    },
    "credential_zone": {"tr": "Kimlik bölgesi", "en": "Credential zone"},
    "credzone_note": {
        "tr": "Kimlikler saklanmaz. Açık porta göre: Linux → SSH, Windows → WinRM (NTLM) ile "
        "salt-okunur denetim denenir.",
        "en": "Credentials are not stored. By open port: Linux → SSH, Windows → WinRM (NTLM) "
        "read-only audit.",
    },
    "credzone_empty": {
        "tr": "Önce Kimlikler sayfasından bölge oluştur",
        "en": "First create a zone on the Credentials page",
    },
    "scan_zone_btn": {"tr": "Zone'u Tara", "en": "Scan Zone"},
    "no_zones": {"tr": "Henüz zone yok.", "en": "No zones yet."},
    "create_zone": {"tr": "Zone oluştur", "en": "Create zone"},
    # Bulk zone selection (dual-list modal)
    "zone_bulk_btn": {"tr": "Toplu zone seç ve tara", "en": "Bulk select & scan"},
    "zone_bulk_title": {"tr": "Toplu zone taraması", "en": "Bulk zone scan"},
    "zone_bulk_sub": {
        "tr": "Soldaki listeden zone'ları seçip sağa taşı; sağdakiler bu taramaya atanır. "
        "Birden çok IP zone seçebilirsin.",
        "en": "Move zones from the left list to the right; the right side is assigned to this "
        "scan. You can select multiple IP zones.",
    },
    "zones_available": {"tr": "Mevcut IP zone'lar", "en": "Available IP zones"},
    "zones_selected": {"tr": "Taranacak IP zone'lar", "en": "IP zones to scan"},
    "credzones_available": {"tr": "Mevcut kimlik bölgeleri", "en": "Available credential zones"},
    "credzones_selected": {"tr": "Seçili kimlik bölgeleri", "en": "Selected credential zones"},
    "credzone_hint": {
        "tr": "Kimlik bölgesi seçersen kasadaki kimliklerle OS-öncelikli (SSH/WinRM) kimlikli "
        "tarama yapılır; seçmezsen yoğunluğa göre ağ taraması.",
        "en": "If you pick credential zones, an OS-priority (SSH/WinRM) credentialed scan runs "
        "with vault credentials; otherwise a network scan by intensity.",
    },
    "bulk_scan_submit": {"tr": "Seçili zone'ları tara", "en": "Scan selected zones"},
    "move_right": {"tr": "Sağa taşı", "en": "Move right"},
    "move_left": {"tr": "Sola taşı", "en": "Move left"},
    "modal_close": {"tr": "Kapat", "en": "Close"},
    # Scan wizard (çok adımlı)
    "wiz_intro": {
        "tr": "Hedef, kimlik ve modu adım adım seçerek tarama başlat.",
        "en": "Start a scan by choosing targets, credentials and mode step by step.",
    },
    "wiz_btn": {"tr": "Tarama Sihirbazı", "en": "Scan Wizard"},
    "wiz_title": {"tr": "Tarama Sihirbazı", "en": "Scan Wizard"},
    "wiz_s1": {"tr": "Hedefler", "en": "Targets"},
    "wiz_s2": {"tr": "Kimlikler", "en": "Credentials"},
    "wiz_s3": {"tr": "Mod", "en": "Mode"},
    "wiz_s1_sub": {
        "tr": "Taranacak IP zone'larını ve/veya envanterden tekil IP varlıklarını seç.",
        "en": "Pick IP zones and/or individual IP assets from inventory to scan.",
    },
    "wiz_s2_sub": {
        "tr": "Opsiyonel: kimlik bölgesi ve/veya tekil kimlik seç. Seçersen OS-öncelikli "
        "(SSH/WinRM) kimlikli tarama yapılır; seçmezsen ağ taraması.",
        "en": "Optional: pick credential zones and/or individual credentials. If selected, an "
        "OS-priority (SSH/WinRM) credentialed scan runs; otherwise a network scan.",
    },
    "wiz_s3_sub": {"tr": "Tarama modunu seç.", "en": "Choose the scan mode."},
    "wiz_need_target": {
        "tr": "En az bir hedef (IP zone ya da tekil IP) seç.",
        "en": "Select at least one target (IP zone or individual IP).",
    },
    "wiz_no_creds": {"tr": "Henüz kimlik yok.", "en": "No credentials yet."},
    "wiz_creds_admin": {
        "tr": "Kimlikli tarama yalnızca admin içindir; bu adımı atlayabilirsin.",
        "en": "Credentialed scan is admin-only; you can skip this step.",
    },
    "wiz_ack": {
        "tr": "Riskleri okudum; onaylıyorum ve kabul ediyorum.",
        "en": "I have read the risks; I confirm and accept.",
    },
    "wiz_back": {"tr": "Geri", "en": "Back"},
    "wiz_next": {"tr": "İleri", "en": "Next"},
    "wiz_run": {"tr": "Taramayı Başlat", "en": "Start Scan"},
    "wiz_setup_sub": {
        "tr": "Her bölüm için Seç'e tıkla, açılan pencerede seçimini yap ve Onayla. "
        "Seçimlerin aşağıda görünür; sonra isim verip taramayı başlat.",
        "en": "Click Select for each section, choose in the pop-up and Confirm. Your choices "
        "appear below; then name it and start the scan.",
    },
    "wiz_select": {"tr": "Seç", "en": "Select"},
    "wiz_confirm": {"tr": "Onayla", "en": "Confirm"},
    "wiz_name": {"tr": "Tarama adı", "en": "Scan name"},
    "wiz_name_ph": {"tr": "örn. Haftalık iç ağ taraması", "en": "e.g. Weekly internal scan"},
    "wiz_sum_none": {"tr": "Seçilmedi", "en": "Not selected"},
    "wiz_sum_optnone": {"tr": "Opsiyonel — yok", "en": "Optional — none"},
    "wiz_sum_target": {"tr": "{n} hedef seçili", "en": "{n} targets selected"},
    "wiz_sum_cred": {"tr": "{n} kimlik seçili", "en": "{n} credentials selected"},
    "wiz_sum_cat": {"tr": "{n} kategori", "en": "{n} categories"},
    "optional": {"tr": "opsiyonel", "en": "optional"},
    "wiz_s4": {"tr": "Ürünler", "en": "Products"},
    "wiz_s4_sub": {
        "tr": "Hangi ürün/CVE kategorilerini taramak istiyorsun? Rapor seçtiğin "
        "kategorilere göre filtrelenir.",
        "en": "Which product/CVE categories do you want to scan? The report is filtered "
        "by your selection.",
    },
    "wiz_s5": {"tr": "Zamanlama", "en": "Scheduling"},
    "wiz_s5_sub": {
        "tr": "Bu taramayı hemen başlat ya da tekrarlı/ileri tarihli zamanla. Zamanlanan "
        "tarama, Zamanlama sayfasında görünür ve durdurulabilir.",
        "en": "Run this scan now, or schedule it (recurring/future). Scheduled scans appear "
        "on the Schedules page and can be paused.",
    },
    "sched_run_now": {"tr": "Hemen başlat (tek seferlik)", "en": "Run now (one-off)"},
    "sched_scheduled": {"tr": "Zamanla", "en": "Schedule"},
    "wiz_cat_all": {"tr": "Tümü", "en": "All"},
    "wiz_cat_note": {
        "tr": "Seçim yapılmazsa tüm kategoriler dahil edilir. Filtre, rapordaki "
        "CVE bulgularına uygulanır.",
        "en": "If nothing is selected, all categories are included. The filter applies "
        "to CVE findings in the report.",
    },
    "cat_windows": {"tr": "Windows", "en": "Windows"},
    "cat_linux": {"tr": "Linux", "en": "Linux"},
    "cat_macos": {"tr": "macOS", "en": "macOS"},
    "cat_web": {"tr": "Web", "en": "Web"},
    "cat_database": {"tr": "Veritabanı (SQL)", "en": "Database (SQL)"},
    "cat_network": {"tr": "Ağ", "en": "Network"},
    "cat_iot": {"tr": "IoT", "en": "IoT"},
    "cat_cloud": {"tr": "Bulut", "en": "Cloud"},
    "cat_mobile": {"tr": "Mobil", "en": "Mobile"},
    "report_cat_filter": {"tr": "Kategori filtresi", "en": "Category filter"},
    # Scan assignment + completion notification
    "assign_to_user": {"tr": "Kullanıcıya ata", "en": "Assign to user"},
    "no_assignment": {"tr": "— atama yok —", "en": "— no assignment —"},
    "notify_on_complete": {"tr": "Bitince e-posta ile bildir", "en": "Email on completion"},
    "attach_report": {"tr": "Raporu e-postaya ekle (PDF)", "en": "Attach report (PDF)"},
    "cred_note": {
        "tr": "Kimlik bilgileri saklanmaz; bölgedeki her host'a aynı kullanıcı/parola ile "
        "açık porta göre SSH (Linux) ya da WinRM/NTLM (Windows) denenir "
        "(girdiler tekil host olmalı).",
        "en": "Credentials are not stored; each host is tried with the same user/password — by "
        "open port SSH (Linux) or WinRM/NTLM (Windows). Entries must be single hosts.",
    },
    "sca_title": {"tr": "Bağımlılık (SCA) Taraması", "en": "Dependency (SCA) Scan"},
    "sca_desc": {
        "tr": "requirements.txt / package.json → OSV.dev ile bilinen paket açıkları",
        "en": "requirements.txt / package.json → known package CVEs via OSV.dev",
    },
    # Denetim/özel tarama kartları — ortak etiketler + bölüm başlığı
    "audit_section_title": {"tr": "Denetim & Özel Taramalar", "en": "Audits & Special Scans"},
    "audit_section_sub": {
        "tr": "Protokol/servis bazlı kimlikli denetimler ve özel tarama türleri. "
        "Çalıştırmak için ilgili kartı aç.",
        "en": "Protocol/service credentialed audits and special scan types. "
        "Expand a card to run it.",
    },
    # F-215: Denetim & Özel taramalar deneysel kapısı (varsayılan gizli + onay).
    "audit_experimental_warn": {
        "tr": "Bu alan deneyseldir ve yeterince test edilmemiştir.",
        "en": "This area is experimental and not fully tested.",
    },
    "audit_experimental_show": {"tr": "Yine de göster", "en": "Show anyway"},
    "audit_experimental_confirm": {
        "tr": "Bu özellikler test edilmemiştir. Devam edilsin mi?",
        "en": "These features are untested. Continue?",
    },
    "tag_readonly": {"tr": "Salt-okunur", "en": "Read-only"},
    "tag_credentialed": {"tr": "Kimlikli", "en": "Credentialed"},
    "tag_gated": {"tr": "Gated", "en": "Gated"},
    "sca_sub": {
        "tr": "requirements.txt (PyPI) veya package.json (npm) içeriğini yapıştır; OSV.dev ile "
        "bilinen paket açıkları taranır.",
        "en": "Paste requirements.txt (PyPI) or package.json (npm); scanned against OSV.dev for "
        "known package vulnerabilities.",
    },
    "ecosystem": {"tr": "Ekosistem", "en": "Ecosystem"},
    "sca_scan_btn": {"tr": "SCA Taraması", "en": "SCA Scan"},
    "sca_paste_label": {"tr": "Manifesti yapıştır", "en": "Paste manifest"},
    "sca_or": {"tr": "ya da", "en": "or"},
    "sca_upload_label": {
        "tr": "Dosya yükle (requirements.txt / package.json)",
        "en": "Upload file (requirements.txt / package.json)",
    },
    "db_audit_title": {"tr": "Veritabanı Denetimi", "en": "Database Audit"},
    "db_audit_desc": {
        "tr": "PostgreSQL · MySQL · MSSQL · Oracle — CIS güvenlik ayarları",
        "en": "PostgreSQL · MySQL · MSSQL · Oracle — CIS security settings",
    },
    "db_audit_sub": {
        "tr": "Seçilen veritabanına (PostgreSQL, MySQL/MariaDB, MSSQL, Oracle) salt-okunur "
        "bağlanıp güvenlik ayarlarını (SSL, günlük, parola şifreleme vb.) CIS'e göre denetler.",
        "en": "Connects read-only to the selected database (PostgreSQL, MySQL/MariaDB, MSSQL, "
        "Oracle) and audits its security settings (SSL, logging, password encryption, etc.) "
        "against CIS.",
    },
    "db_audit_no_cred": {
        "tr": "Önce 'postgres' tipinde bir kimlik ekleyin:",
        "en": "Add a 'postgres'-type credential first:",
    },
    "db_engine": {"tr": "Motor", "en": "Engine"},
    "db_host": {"tr": "DB host", "en": "DB host"},
    "db_port": {"tr": "Port", "en": "Port"},
    "db_name": {"tr": "Veritabanı", "en": "Database"},
    "db_name_hint": {
        "tr": "Bağlanılacak veritabanı/şema adı. PostgreSQL: bir veritabanı (örn. postgres) · "
        "MSSQL: master · Oracle: servis adı (örn. FREEPDB1) · MySQL/MariaDB: boş bırakılabilir "
        "(sunucu geneli ayarları denetlenir). Motor seçilince varsayılan otomatik dolar.",
        "en": "Database/schema name to connect to. PostgreSQL: a database (e.g. postgres) · "
        "MSSQL: master · Oracle: a service name (e.g. FREEPDB1) · MySQL/MariaDB: can be left "
        "empty (server-wide settings are audited). The default fills in when you pick an engine.",
    },
    "db_credential": {"tr": "Kimlik", "en": "Credential"},
    "db_audit_btn": {"tr": "DB Denetimi", "en": "DB Audit"},
    "snmp_audit_title": {"tr": "SNMP Denetimi", "en": "SNMP Audit"},
    "snmp_audit_desc": {
        "tr": "Ağ cihazı envanteri + varsayılan topluluk (public/private)",
        "en": "Network device inventory + default community (public/private)",
    },
    "snmp_audit_sub": {
        "tr": "Ağ cihazından (yazıcı/switch/router) SNMP ile envanter okur ve varsayılan "
        "topluluk (public/private) erişimini denetler. Yalnız okuma yapar.",
        "en": "Reads device inventory via SNMP (printer/switch/router) and checks for default "
        "community (public/private) access. Read-only.",
    },
    "snmp_host": {"tr": "Cihaz IP", "en": "Device IP"},
    "snmp_version": {"tr": "Sürüm", "en": "Version"},
    "snmp_auto_version_note": {
        "tr": "SNMP v1 ve v2c otomatik denenir (sürüm seçmeye gerek yok); dahili community "
        "wordlist'i + seçilen özel topluluk denenir. Tutan sürüm ve topluluk raporda yazar.",
        "en": "SNMP v1 and v2c are tried automatically (no version choice); a built-in community "
        "wordlist + any selected custom community are tried. The working version/community is "
        "shown in the report.",
    },
    "snmp_audit_btn": {"tr": "SNMP Denetimi", "en": "SNMP Audit"},
    "smb_audit_title": {"tr": "SMB Denetimi", "en": "SMB Audit"},
    "smb_audit_desc": {
        "tr": "Paylaşımlar · SMB imzalama · SMBv1 · anonim/misafir oturum",
        "en": "Shares · SMB signing · SMBv1 · anonymous/guest session",
    },
    "smb_audit_sub": {
        "tr": "Windows/Samba sunucusuna bağlanıp SMB imzalama, SMBv1, anonim (null) ve "
        "misafir oturum ile kimliksiz paylaşım listelemeyi denetler. Yalnız okuma yapar.",
        "en": "Connects to a Windows/Samba server and audits SMB signing, SMBv1, anonymous "
        "(null) and guest sessions, and unauthenticated share listing. Read-only.",
    },
    "smb_host": {"tr": "Sunucu IP", "en": "Server IP"},
    "smb_credential": {"tr": "SMB kimliği (opsiyonel)", "en": "SMB credential (optional)"},
    "smb_anon_only": {"tr": "Anonim (kimliksiz)", "en": "Anonymous (no credential)"},
    "smb_anon_note": {
        "tr": "Kimlik seçmek opsiyoneldir — anonim denetimde de imzalama, SMBv1, null/guest "
        "oturum ve kimliksiz paylaşım listeleme tespit edilir. Kimlik verilirse yetkili "
        "paylaşım envanteri eklenir. Hedefe yazılmaz.",
        "en": "Selecting a credential is optional — anonymous audit still detects signing, "
        "SMBv1, null/guest sessions and unauthenticated share listing. With a credential, "
        "the authenticated share inventory is added. Nothing is written to the target.",
    },
    "smb_audit_btn": {"tr": "SMB Denetimi", "en": "SMB Audit"},
    "smb_wordlist_label": {"tr": "Paylaşım listesi (ops.)", "en": "Share wordlist (opt.)"},
    "smb_wordlist_none": {"tr": "Yok (yalnız listeleme)", "en": "None (enumeration only)"},
    "smb_wordlist_hint": {
        "tr": "Paylaşım-adı kelime listesi seçilirse listelemede görünmeyen 'gizli' "
        "paylaşımlar da adıyla denenir (Kimlikler → Kelime Listeleri, tür: SMB paylaşım).",
        "en": "If a share-name wordlist is selected, 'hidden' shares not shown by enumeration "
        "are also probed by name (Credentials → Wordlists, kind: SMB share).",
    },
    "ldap_audit_title": {"tr": "LDAP / AD Denetimi", "en": "LDAP / AD Audit"},
    "ldap_audit_desc": {
        "tr": "Anonim erişim · şifreleme (LDAPS) · bağlama güvenliği",
        "en": "Anonymous access · encryption (LDAPS) · bind security",
    },
    "ldap_audit_sub": {
        "tr": "LDAP/Active Directory sunucusuna bağlanıp anonim bind, anonim dizin okuma "
        "(enumerasyon), şifreli taşıma (LDAPS/StartTLS) eksikliği ve AD parola politikasını "
        "denetler. Yalnız okuma yapar. (Ayarlar'daki LDAP girişinden ayrı bir denetimdir.)",
        "en": "Connects to an LDAP/Active Directory server and audits anonymous bind, anonymous "
        "directory read (enumeration), missing encrypted transport (LDAPS/StartTLS) and AD "
        "password policy. Read-only. (Separate from the LDAP login under Settings.)",
    },
    "ldap_host": {"tr": "Sunucu IP", "en": "Server IP"},
    "ldap_credential": {"tr": "LDAP kimliği (opsiyonel)", "en": "LDAP credential (optional)"},
    "ldap_anon_only": {"tr": "Anonim (kimliksiz)", "en": "Anonymous (no credential)"},
    "ldap_anon_note": {
        "tr": "Kimlik seçmek opsiyoneldir — anonim denetimde de anonim bind/okuma ve şifreleme "
        "tespit edilir. Kimlik (bind DN/UPN) verilirse AD parola politikası (asgari uzunluk, "
        "hesap kilitleme) best-effort okunur. Hedefe yazılmaz.",
        "en": "Selecting a credential is optional — anonymous audit still detects anonymous "
        "bind/read and encryption. With a credential (bind DN/UPN), AD password policy (min "
        "length, lockout) is read best-effort. Nothing is written to the target.",
    },
    "ldap_audit_btn": {"tr": "LDAP Denetimi", "en": "LDAP Audit"},
    "telnet_audit_title": {"tr": "Telnet / Cisco Denetimi", "en": "Telnet / Cisco Audit"},
    "telnet_audit_desc": {
        "tr": "Ağ cihazı CLI — Telnet açıklığı · banner · Cisco sertleştirme",
        "en": "Network device CLI — Telnet exposure · banner · Cisco hardening",
    },
    "telnet_audit_sub": {
        "tr": "Ağ cihazının (switch/router) Telnet yönetimini denetler: Telnet açık (şifresiz), "
        "uyarı banner eksikliği ve kimlik verilirse 'show running-config' ile Cisco "
        "sertleştirme (parola şifreleme, enable secret, VTY transport, HTTP). Yalnız okuma.",
        "en": "Audits a network device's (switch/router) Telnet management: Telnet open "
        "(cleartext), missing warning banner and — with a credential — Cisco hardening via "
        "'show running-config' (password encryption, enable secret, VTY, HTTP). Read-only.",
    },
    "telnet_host": {"tr": "Cihaz IP", "en": "Device IP"},
    "telnet_credential": {
        "tr": "Telnet kimliği (opsiyonel)",
        "en": "Telnet credential (optional)",
    },
    "telnet_anon_only": {"tr": "Yalnız açıklık/banner", "en": "Openness/banner only"},
    "telnet_anon_note": {
        "tr": "Kimlik seçmek opsiyoneldir — kimliksiz denetimde Telnet açıklığı ve uyarı banner "
        "kontrol edilir. Kimlik (telnet kullanıcı/parola) verilirse CLI'a girip 'show "
        "running-config' ile Cisco sertleştirme denetlenir. Hedefe yazılmaz.",
        "en": "Selecting a credential is optional — without one, Telnet openness and the warning "
        "banner are checked. With a credential, the CLI is accessed and Cisco hardening is "
        "audited via 'show running-config'. Nothing is written to the target.",
    },
    "telnet_audit_btn": {"tr": "Telnet Denetimi", "en": "Telnet Audit"},
    # VII-2d: Cisco IOS SSH denetimi (Telnet kapalı / SSH-only cihazlar)
    "cisco_audit_title": {"tr": "Cisco IOS SSH Denetimi", "en": "Cisco IOS SSH Audit"},
    "cisco_audit_desc": {
        "tr": "Cisco IOS CLI (SSH) — sertleştirme · SSHv2 · zayıf SNMP · AAA",
        "en": "Cisco IOS CLI (SSH) — hardening · SSHv2 · weak SNMP · AAA",
    },
    "cisco_audit_sub": {
        "tr": "Telnet kapalı (iyi) ama SSH ile yönetilen Cisco IOS/IOS-XE cihazlarının "
        "sertleştirmesini SSH üzerinden denetler: 'show running-config' ile parola şifreleme, "
        "enable secret, VTY transport, HTTP, SSHv2 zorunluluğu, zayıf SNMP community, AAA "
        "new-model. Yalnız okuma — hedefe yazılmaz.",
        "en": "Audits hardening of Cisco IOS/IOS-XE devices managed over SSH (Telnet closed): "
        "via 'show running-config' — password encryption, enable secret, VTY transport, HTTP, "
        "SSHv2 enforcement, weak SNMP community, AAA new-model. Read-only — nothing is written.",
    },
    "cisco_host": {"tr": "Cihaz IP", "en": "Device IP"},
    "cisco_credential": {"tr": "SSH kimliği (zorunlu)", "en": "SSH credential (required)"},
    "cisco_cred_placeholder": {"tr": "SSH kimliği seçin…", "en": "Select an SSH credential…"},
    "cisco_audit_btn": {"tr": "Cisco IOS Denetimi", "en": "Cisco IOS Audit"},
    "cisco_audit_note": {
        "tr": "Kimlik ZORUNLUDUR — 'show running-config' okumak için SSH ile giriş gerekir. "
        "Telnet açıklığı için ayrı Telnet/Cisco denetimini kullanın. Hedefe yazılmaz.",
        "en": "A credential is REQUIRED — SSH login is needed to read 'show running-config'. "
        "Use the separate Telnet/Cisco audit for Telnet exposure. Nothing is written.",
    },
    # VII-2c: VMware ESXi / vCenter kimliksiz HTTPS duruş denetimi
    "esxi_audit_title": {"tr": "ESXi / vCenter Denetimi", "en": "ESXi / vCenter Audit"},
    "esxi_audit_desc": {
        "tr": "VMware yönetim ucu (443) — kimliksiz: sürüm ifşası · MOB · TLS",
        "en": "VMware management endpoint (443) — unauth: version disclosure · MOB · TLS",
    },
    "esxi_audit_sub": {
        "tr": "VMware ESXi/vCenter 443 ucunu KİMLİKSİZ yoklar: ürün/sürüm tanımı, kimliksiz "
        "sürüm ifşası (/sdk), Managed Object Browser (/mob/) açıklığı ve TLS duruşu (zayıf "
        "protokol/şifre). Kimlik gerekmez — yalnız okuma, hedefe yazılmaz.",
        "en": "Unauthenticated probe of a VMware ESXi/vCenter 443 endpoint: product/version "
        "identification, unauth version disclosure (/sdk), Managed Object Browser (/mob/) "
        "exposure and TLS posture (weak protocol/cipher). No credential — read-only.",
    },
    "esxi_host": {"tr": "ESXi / vCenter IP", "en": "ESXi / vCenter IP"},
    "esxi_audit_btn": {"tr": "ESXi Denetimi", "en": "ESXi Audit"},
    "esxi_audit_note": {
        "tr": "Kimlik GEREKMEZ — 443 ucu kimliksiz yoklanır. Hedefe yazılmaz; yalnız GET "
        "istekleriyle duruş (sürüm ifşası, MOB, TLS) denetlenir.",
        "en": "No credential needed — the 443 endpoint is probed unauthenticated. Nothing is "
        "written; posture (version disclosure, MOB, TLS) is checked with GET requests only.",
    },
    # X-3: denetim panellerine IP zone + kimlik bölgesi toplu hedef seçimi
    "audit_zone_btn": {
        "tr": "Toplu hedef (IP zone / kimlik bölgesi)",
        "en": "Bulk targets (IP zone / credential zone)",
    },
    "audit_zone_title": {"tr": "Toplu hedef seçimi", "en": "Bulk target selection"},
    "audit_zone_edit": {"tr": "Bölgeleri düzenle", "en": "Edit zones"},
    "audit_zone_sub": {
        "tr": "Tekil host'a ek olarak IP zone (envanterdeki AYAKTA varlıklar) ve kimlik "
        "bölgesi seçin — denetim her host'a tipe uygun kimlikle çalışır. Boş bırakılırsa "
        "yalnız yukarıdaki tekil host taranır.",
        "en": "In addition to the single host, pick an IP zone (UP assets in inventory) and a "
        "credential zone — the audit runs against each host with the type-appropriate "
        "credential. Leave empty to scan only the single host above.",
    },
    "audit_zone_sum_none": {"tr": "Toplu hedef yok", "en": "No bulk targets"},
    "audit_zone_sum": {"tr": "{n} toplu seçim", "en": "{n} bulk selected"},
    "th_id": {"tr": "#", "en": "#"},
    "th_name": {"tr": "Tarama adı", "en": "Scan name"},
    "th_target": {"tr": "Hedef", "en": "Target"},
    "th_type": {"tr": "Tür", "en": "Type"},
    # Tarama türü insan-okunur etiketleri (ScanType enum değerleri → anlamlı ad).
    "scantype_network": {"tr": "Ağ taraması", "en": "Network scan"},
    "scantype_ping": {"tr": "Ping taraması", "en": "Ping scan"},
    "scantype_vuln": {"tr": "CVE taraması", "en": "CVE scan"},
    "scantype_web": {"tr": "Web (DAST)", "en": "Web (DAST)"},
    "scantype_sca": {"tr": "SCA (bağımlılık)", "en": "SCA (dependency)"},
    "scantype_hardening": {"tr": "Sıkılaştırma denetimi", "en": "Hardening audit"},
    "scantype_credentialed": {"tr": "Kimlikli denetim", "en": "Credentialed audit"},
    "rescan": {"tr": "Tekrar tara", "en": "Re-scan"},
    "scan_delete_confirm": {
        "tr": "Bu tarama ve bulguları kalıcı olarak silinsin mi?",
        "en": "Permanently delete this scan and its findings?",
    },
    "no_scans": {"tr": "Henüz tarama yok.", "en": "No scans yet."},
    "quick_scan": {"tr": "Hızlı tarama", "en": "Quick scan"},
    "quick_scan_sub": {
        "tr": "Zone oluşturmadan, virgül veya yeni satırla ayrılmış IP/blokları tek seferde tara.",
        "en": "Scan comma/newline-separated IPs/blocks at once, without creating a zone.",
    },
    "quick_targets": {
        "tr": "IP / CIDR'lar (virgül veya yeni satırla ayır)",
        "en": "IPs / CIDRs (separate with commas or newlines)",
    },
    "quick_scan_btn": {"tr": "Hızlı Tara", "en": "Quick Scan"},
    "credzone_optional": {"tr": "Kimlik bölgesi (opsiyonel)", "en": "Credential zone (optional)"},
    "credzone_none": {"tr": "— Kimliksiz —", "en": "— No credentials —"},
    # Zones page
    "zones_title": {"tr": "IP Zone'lar", "en": "IP Zones"},
    "zones_sub": {
        "tr": "Tarama yapılacak IP ve blokları bölgelere (zone) grupla; Taramalar sayfasından bir "
        "zone'u tek seferde tara.",
        "en": "Group target IPs and blocks into zones; scan a whole zone at once from the "
        "Scans page.",
    },
    "zone_name": {"tr": "Zone adı", "en": "Zone name"},
    "zone_desc": {"tr": "Açıklama (opsiyonel)", "en": "Description (optional)"},
    "zone_cidrs": {
        "tr": "IP / CIDR / URL (her satıra bir tane)",
        "en": "IP / CIDR / URL (one per line)",
    },
    "zone_cidrs_hint": {
        "tr": "IP, CIDR bloğu veya http(s) URL girebilirsiniz. URL'ler hem web denetimine "
        "hem (host'u çözülerek) ağ/CVE taramasına gider.",
        "en": "Enter an IP, CIDR block, or http(s) URL. URLs go to both web checks and "
        "(after host resolution) the network/CVE scan.",
    },
    "create_zone_btn": {"tr": "Zone Oluştur", "en": "Create Zone"},
    "blocks": {"tr": "blok", "en": "blocks"},
    "scan_in_scans": {"tr": "Taramalar'da tara", "en": "Scan in Scans"},
    "edit": {"tr": "Düzenle", "en": "Edit"},
    "edit_zone": {"tr": "Zone'u düzenle", "en": "Edit zone"},
    "edit_asset": {"tr": "Varlığı düzenle (Varlıklar)", "en": "Edit asset (Assets)"},
    "edit_zone_sub": {
        "tr": "Zone adını, açıklamasını ve içindeki IP/CIDR bloklarını güncelle.",
        "en": "Update the zone name, description, and its IP/CIDR blocks.",
    },
    "edit_cred": {"tr": "Kimliği düzenle", "en": "Edit credential"},
    "edit_cred_sub": {
        "tr": "Kullanıcı adı, port ve diğer alanları güncelle. Parola güvenlik için "
        "gösterilmez — boş bırakırsan değişmez.",
        "en": "Update username, port and other fields. The password is not shown for "
        "security — leave it blank to keep it unchanged.",
    },
    "pwd_keep_note": {
        "tr": "Boş bırakılırsa mevcut parola korunur.",
        "en": "Leave blank to keep the current password.",
    },
    "edit_credzone": {"tr": "Kimlik bölgesini düzenle", "en": "Edit credential zone"},
    "edit_credzone_sub": {
        "tr": "Bölge adını güncelle ve içindeki kimlikleri ekle/çıkar.",
        "en": "Update the zone name and add/remove its credentials.",
    },
    # Inventory page sections (zones / single IP assets / credentials)
    "inv_zones_section": {"tr": "IP Zone'ları", "en": "IP zones"},
    "inv_assets_title": {"tr": "Tekil IP varlıkları", "en": "Individual IP assets"},
    "inv_assets_sub": {
        "tr": "Tek tek IP/host ekle — taramada keşfedilenlere ek olarak envantere girer.",
        "en": "Add IPs/hosts one by one — added to inventory alongside scan-discovered ones.",
    },
    "asset_ip_label": {"tr": "IP adresi veya URL", "en": "IP address or URL"},
    "asset_name_label": {"tr": "Cihaz adı (opsiyonel)", "en": "Device name (optional)"},
    "asset_name_ph": {"tr": "ör. Muhasebe-PC", "en": "e.g. Accounting-PC"},
    "th_device_name": {"tr": "Cihaz adı", "en": "Device name"},
    "asset_hostname_label": {"tr": "Host adı (opsiyonel)", "en": "Hostname (optional)"},
    "add_asset_btn": {"tr": "Varlık Ekle", "en": "Add Asset"},
    "th_last_seen": {"tr": "Son görülme", "en": "Last seen"},
    "inv_creds_title": {"tr": "Kimlik bilgileri (tekil)", "en": "Credentials (individual)"},
    "inv_creds_sub": {
        "tr": "Tek tek kimlik ekle (kasaya, şifreli). Bölge (grup) yönetimi için "
        "Kimlikler sayfasını kullan.",
        "en": "Add credentials one by one (encrypted vault). Use the Credentials page for "
        "zone (group) management.",
    },
    "cred_port_num": {"tr": "Port (ops., sayı)", "en": "Port (opt., number)"},
    "manage_credzones": {"tr": "Kimlik bölgelerini yönet", "en": "Manage credential zones"},
    # Assets page
    "assets_title": {"tr": "Varlıklar", "en": "Assets"},
    "assets_sub": {
        "tr": "Taramalarda keşfedilen host'lar, açık servisleri ve elle eklenen IP'ler.",
        "en": "Hosts discovered by scans, their open services, and manually added IPs.",
    },
    "assets_moved_note": {
        "tr": "Tekil IP varlıkları artık burada yönetilir:",
        "en": "Individual IP assets are now managed here:",
    },
    "assets_hidden_note": {
        "tr": "Boş/karşılıksız IP'ler gizlendi",
        "en": "Empty/unmatched IPs hidden",
    },
    "assets_show_all": {"tr": "tümünü göster", "en": "show all"},
    "assets_showing_all": {
        "tr": "Tüm varlıklar gösteriliyor (filtre kapalı)",
        "en": "Showing all assets (filter off)",
    },
    "assets_show_real": {"tr": "yalnız gerçek cihazlar", "en": "real devices only"},
    "th_ip": {"tr": "IP", "en": "IP"},
    "th_hostname": {"tr": "Ana bilgisayar adı", "en": "Hostname"},
    "th_os": {"tr": "İşletim Sistemi", "en": "OS"},
    "th_services": {"tr": "Servisler", "en": "Services"},
    "th_port": {"tr": "Port", "en": "Port"},
    "th_service": {"tr": "Servis", "en": "Service"},
    "th_product": {"tr": "Ürün", "en": "Product"},
    "th_version": {"tr": "Versiyon", "en": "Version"},
    "services_label": {"tr": "servis", "en": "services"},
    "asset_no_services": {
        "tr": "Bu varlıkta açık servis kaydı yok.",
        "en": "No open services recorded for this asset.",
    },
    "no_assets": {
        "tr": "Henüz varlık yok. Bir tarama başlatın.",
        "en": "No assets yet. Start a scan.",
    },
    # Tokens page
    "tokens_title": {"tr": "API Token'larım", "en": "My API Tokens"},
    "tokens_sub": {
        "tr": "API ve uzak MCP bağlantısı için kişisel erişim token'ları.",
        "en": "Personal access tokens for API and remote MCP connections.",
    },
    "token_name": {"tr": "Token adı", "en": "Token name"},
    "token_expiry": {"tr": "Geçerlilik (gün)", "en": "Expiry (days)"},
    "token_create": {"tr": "Token Oluştur", "en": "Create Token"},
    # Findings page
    "findings_sub": {
        "tr": "Taramalarda bulunan zafiyetler — risk skoruna göre sıralı. CVE eşleşmeleri "
        "NVD'ye, exploit'ler yerel depoya bağlıdır.",
        "en": "Vulnerabilities found by scans — sorted by risk. CVE matches link to NVD; "
        "exploits link to the local database.",
    },
    "all": {"tr": "Tümü", "en": "All"},
    "exploitable_only": {"tr": "Sadece exploit'i olanlar", "en": "Only with exploits"},
    "filter": {"tr": "Filtrele", "en": "Filter"},
    "th_exploitation": {"tr": "Sömürü", "en": "Exploitation"},
    "no_findings": {
        "tr": "Henüz zafiyet bulgusu yok. Sürüm tespitli (-sV) bir tarama çalıştırın.",
        "en": "No vulnerability findings yet. Run a version-detection (-sV) scan.",
    },
    # Exploits page
    "exploits_sub": {
        "tr": "Sızma testi cephaneliği — Exploit-DB ve Metasploit'ten içe aktarılan gerçek "
        "exploit/payload'lar. CVE/CPE bilgi bankası ayrı sayfada (Zafiyet Veritabanı). "
        "Başlık, CVE veya ID ile ara.",
        "en": "Penetration-testing arsenal — real exploits/payloads imported from Exploit-DB "
        "and Metasploit. The CVE/CPE knowledge base is a separate page (Vulnerability DB). "
        "Search by title, CVE or ID.",
    },
    "update_db": {"tr": "Veritabanını Güncelle", "en": "Update Database"},
    "db_fresh_current": {"tr": "Veritabanı güncel", "en": "Database up to date"},
    "db_fresh_stale": {
        "tr": "Güncel değil — güncelleme önerilir",
        "en": "Out of date — update recommended",
    },
    "db_fresh_never": {"tr": "Veritabanı henüz senkronlanmadı", "en": "Database not synced yet"},
    "db_last_sync": {"tr": "son senkron", "en": "last sync"},
    "db_last_check": {"tr": "son kontrol", "en": "last check"},
    "update_db_q": {"tr": "Veritabanı güncellensin mi?", "en": "Update the database?"},
    "update_db_intro": {
        "tr": "Aşağıdaki kaynaklardan en güncel veriler indirilip içe aktarılacak:",
        "en": "The latest data will be pulled from the following sources:",
    },
    "src_edb": {"tr": "Exploit-DB — ~47.000 exploit", "en": "Exploit-DB — ~47,000 exploits"},
    "src_msf": {"tr": "Metasploit — ~6.600 modül", "en": "Metasploit — ~6,600 modules"},
    "update_db_bg": {
        "tr": "İşlem arka planda çalışır, birkaç dakika sürebilir. Bittiğinde sayfayı yenileyin.",
        "en": "The job runs in the background and may take a few minutes. Refresh when done.",
    },
    "yes_update": {"tr": "Evet, Güncelle", "en": "Yes, update"},
    "search_label": {"tr": "Ara (başlık / CVE / ID)", "en": "Search (title / CVE / ID)"},
    "search_btn": {"tr": "Ara", "en": "Search"},
    "criticality": {"tr": "Kritiklik", "en": "Criticality"},
    "label_category": {"tr": "Kategori", "en": "Category"},
    "label_source": {"tr": "Kaynak", "en": "Source"},
    "label_id": {"tr": "ID", "en": "ID"},
    "remove_cat_filter": {"tr": "Kategori filtresini kaldır", "en": "Clear category filter"},
    "db_empty": {"tr": "Veritabanı boş.", "en": "Database is empty."},
    "db_empty_admin": {
        "tr": "Yukarıdan “Veritabanını Güncelle” ile içe aktar.",
        "en": "Import via “Update Database” above.",
    },
    "results_note": {
        "tr": "En fazla 100 sonuç gösterilir — daraltmak için arama kullanın.",
        "en": "Up to 100 results shown — use search to narrow down.",
    },
    # Credentials page
    "vault_title": {"tr": "Kimlik Kasası", "en": "Credential Vault"},
    "vault_sub": {
        "tr": "Windows/Linux/farklı bağlantı kimliklerini önceden oluştur, kimlik bölgelerinde "
        "grupla. Parolalar şifreli saklanır ve panelde bir daha gösterilmez.",
        "en": "Pre-create Windows/Linux/other connection credentials and group them into zones. "
        "Passwords are stored encrypted and never shown again.",
    },
    "new_cred": {"tr": "Yeni Kimlik", "en": "New Credential"},
    "label_name": {"tr": "Ad", "en": "Name"},
    "label_type": {"tr": "Tip", "en": "Type"},
    "type_ssh": {"tr": "SSH (Linux)", "en": "SSH (Linux)"},
    "type_winrm": {"tr": "WinRM (Windows)", "en": "WinRM (Windows)"},
    "type_rdp": {"tr": "RDP (Windows)", "en": "RDP (Windows)"},
    "type_postgres": {"tr": "PostgreSQL (DB)", "en": "PostgreSQL (DB)"},
    "type_mysql": {"tr": "MySQL / MariaDB (DB)", "en": "MySQL / MariaDB (DB)"},
    "type_mssql": {"tr": "MSSQL / SQL Server (DB)", "en": "MSSQL / SQL Server (DB)"},
    "type_oracle": {"tr": "Oracle (DB)", "en": "Oracle (DB)"},
    "type_snmp": {"tr": "SNMP (ağ cihazı)", "en": "SNMP (network device)"},
    "type_smb": {"tr": "SMB (Windows/Samba)", "en": "SMB (Windows/Samba)"},
    "type_ldap": {"tr": "LDAP / AD (dizin)", "en": "LDAP / AD (directory)"},
    "type_telnet": {"tr": "Telnet (ağ cihazı CLI)", "en": "Telnet (network device CLI)"},
    "cred_domain": {"tr": "Domain (ops., Windows)", "en": "Domain (opt., Windows)"},
    "cred_port_opt": {"tr": "Port (ops.)", "en": "Port (opt.)"},
    "port_default": {
        "tr": "Varsayılan (tipin portu: 22/5985/3389)",
        "en": "Default (type port: 22/5985/3389)",
    },
    "port_custom_opt": {"tr": "Custom (elle gir)…", "en": "Custom (enter manually)…"},
    "port_custom_ph": {"tr": "Özel port (1-65535)", "en": "Custom port (1-65535)"},
    "add_cred": {"tr": "Kimlik Ekle", "en": "Add Credential"},
    "no_creds": {"tr": "Henüz kimlik yok.", "en": "No credentials yet."},
    "new_credzone": {"tr": "Yeni Kimlik Bölgesi", "en": "New Credential Zone"},
    "label_credentials": {"tr": "Kimlikler", "en": "Credentials"},
    "create_zone_short": {"tr": "Bölge Oluştur", "en": "Create Zone"},
    "add_cred_first": {
        "tr": "Önce en az bir kimlik ekleyin.",
        "en": "Add at least one credential first.",
    },
    "no_credzones": {"tr": "Henüz kimlik bölgesi yok.", "en": "No credential zones yet."},
    "cred_count": {"tr": "kimlik", "en": "credentials"},
    # Wordlist (kelime listeleri — dizin/SMB/brute force tek kaynak)
    "wl_title": {"tr": "Kelime Listeleri", "en": "Wordlists"},
    "wl_sub": {
        "tr": "Dizin taraması, SMB paylaşım keşfi ve brute force için yeniden kullanılabilir "
        "kelime listeleri. Türüne uygun tarama bu listeleri seçtirir.",
        "en": "Reusable wordlists for directory scanning, SMB share discovery and brute force. "
        "Scans of the matching kind let you pick these lists.",
    },
    "new_wl": {"tr": "Yeni Kelime Listesi", "en": "New Wordlist"},
    "wl_kind": {"tr": "Kullanım türü", "en": "Kind"},
    "wl_entries": {"tr": "Satırlar", "en": "Entries"},
    "wl_entries_hint": {
        "tr": "Her satıra bir kelime; ya da .txt yükle. '#' ile başlayan satırlar yorumdur.",
        "en": "One word per line, or upload a .txt. Lines starting with '#' are comments.",
    },
    "wl_upload": {"tr": "veya .txt yükle", "en": "or upload a .txt"},
    "wl_create": {"tr": "Liste Oluştur", "en": "Create List"},
    "wl_save": {"tr": "Listeyi Kaydet", "en": "Save List"},
    # --- Kullanıcı adı üretici ---
    "gen_user_title": {"tr": "Kullanıcı Adı Üretici", "en": "Username Generator"},
    "gen_user_sub": {
        "tr": "Hedef kurumun GERÇEK ad-soyad listesini girin → kurumsal kullanıcı-adı "
        "kalıplarında aday liste üretip kaydedin (AD/LDAP spray için).",
        "en": "Enter the target org's REAL full names → generate candidate usernames in "
        "common corporate patterns and save as a list (for AD/LDAP spray).",
    },
    "gen_names": {"tr": "Ad-soyad listesi", "en": "Full names"},
    "gen_names_hint": {
        "tr": "Her satıra bir kişi: 'Ahmet Yılmaz'. Tek kelime de olur (soyadsız kalıplar).",
        "en": "One person per line: 'Ahmet Yilmaz'. A single word works too (no-surname patterns).",
    },
    "gen_patterns": {"tr": "Kullanıcı adı kalıpları", "en": "Username patterns"},
    "gen_patterns_hint": {
        "tr": "Hiçbiri seçilmezse tüm kalıplar üretilir.",
        "en": "If none selected, all patterns are generated.",
    },
    "gen_custom_patterns": {"tr": "Özel kalıp(lar)", "en": "Custom pattern(s)"},
    "gen_custom_patterns_hint": {
        "tr": "Her satıra bir şablon. Token: {first} {last} {f} {l} (örn. {first}.{last}).",
        "en": "One template per line. Tokens: {first} {last} {f} {l} (e.g. {first}.{last}).",
    },
    "gen_normalize": {
        "tr": "Türkçe karakterleri ASCII'ye çevir (İ→i, ş→s, ğ→g, ü→u, ö→o, ç→c)",
        "en": "Normalize Turkish chars to ASCII (İ→i, ş→s, ğ→g, ü→u, ö→o, ç→c)",
    },
    "gen_preview_btn": {"tr": "Önizle", "en": "Preview"},
    "gen_user_save": {"tr": "Kullanıcı Adı Listesi Oluştur", "en": "Create Username List"},
    "gen_preview_count": {"tr": "aday üretilecek", "en": "candidates will be generated"},
    "gen_preview_first": {"tr": "ilk", "en": "first"},
    "gen_preview_empty": {
        "tr": "Önizleme için girdi verip seçenekleri belirleyin.",
        "en": "Provide input and set options to preview.",
    },
    # --- LDAP Kullanıcı Kasası ---
    "ldap_vault_title": {"tr": "LDAP Kullanıcı Kasası", "en": "LDAP User Vault"},
    "ldap_vault_sub": {
        "tr": "Hedef kurumun gerçek kullanıcı adlarını LDAP/AD dizininden çekip bir kullanıcı "
        "adı listesine kaydedin. Yalnız kullanıcı adı okur — tarama yapmaz, parola çekmez.",
        "en": "Pull the target org's real usernames from the LDAP/AD directory into a username "
        "list. Reads usernames only — does not scan or fetch passwords.",
    },
    "ldap_vault_not_configured": {
        "tr": "LDAP bağlantısı yapılandırılmamış (sunucu + base DN gerekli).",
        "en": "LDAP connection is not configured (server + base DN required).",
    },
    "ldap_vault_settings_link": {"tr": "Ayarlar → LDAP", "en": "Settings → LDAP"},
    "ldap_vault_query": {"tr": "Filtre (opsiyonel)", "en": "Filter (optional)"},
    "ldap_vault_query_ph": {"tr": "ör. kullanıcı adı parçası", "en": "e.g. username fragment"},
    "ldap_vault_query_hint": {
        "tr": "Boş bırakırsanız dizindeki tüm kullanıcılar çekilir.",
        "en": "Leave empty to pull all users in the directory.",
    },
    "ldap_vault_save": {"tr": "Çek ve Kaydet", "en": "Pull and Save"},
    # --- Parola üretici ---
    "gen_pass_title": {"tr": "Parola Üretici", "en": "Password Generator"},
    "gen_pass_sub": {
        "tr": "Taban kelimeler (kurum/şehir/sezon) + örnek parolalar girin, parola "
        "politikasını yanıtlayın → politikaya uyan aday parola listesi üretip kaydedin.",
        "en": "Enter base words (org/city/season) + example passwords, answer the password "
        "policy → generate and save a policy-compliant candidate password list.",
    },
    "gen_bases": {"tr": "Taban kelimeler", "en": "Base words"},
    "gen_bases_hint": {
        "tr": "Kurum adı, şehir, sezon, marka... her satıra bir kelime. Bunlardan türetilir.",
        "en": "Org name, city, season, brand... one word per line. Variants derive from these.",
    },
    "gen_examples": {"tr": "Örnek parolalar (opsiyonel)", "en": "Example passwords (optional)"},
    "gen_examples_hint": {
        "tr": "Örnek parolalar — politikaya uyanlar doğrudan eklenir + türetilir.",
        "en": "Real example passwords seen in use — compliant ones are added directly + mutated.",
    },
    "gen_policy": {"tr": "Parola politikası", "en": "Password policy"},
    "gen_min_len": {"tr": "En az uzunluk", "en": "Min length"},
    "gen_req_upper": {"tr": "Büyük harf zorunlu", "en": "Require uppercase"},
    "gen_req_lower": {"tr": "Küçük harf zorunlu", "en": "Require lowercase"},
    "gen_req_digit": {"tr": "Rakam zorunlu", "en": "Require digit"},
    "gen_req_special": {"tr": "Özel karakter zorunlu", "en": "Require special char"},
    "gen_capitalize": {
        "tr": "Baş harfi büyüt (sirket → Sirket)",
        "en": "Capitalize first letter (sirket → Sirket)",
    },
    "gen_leet": {
        "tr": "Leet ikamesi ekle (a→@, o→0, i→1, s→$, e→3)",
        "en": "Add leet substitutions (a→@, o→0, i→1, s→$, e→3)",
    },
    "gen_suffixes": {"tr": "Sona eklenecek özel karakterler", "en": "Trailing special chars"},
    "gen_years": {"tr": "Yıl ekle", "en": "Append year"},
    "gen_pass_save": {"tr": "Parola Listesi Oluştur", "en": "Create Password List"},
    "no_wls": {"tr": "Henüz kelime listesi yok.", "en": "No wordlists yet."},
    "wl_line_count": {"tr": "satır", "en": "lines"},
    "wl_builtin": {"tr": "yerleşik", "en": "built-in"},
    "wl_view": {"tr": "Görüntüle", "en": "View"},
    "wl_delete_confirm": {
        "tr": "Bu kelime listesini silmek istediğinize emin misiniz?",
        "en": "Delete this wordlist?",
    },
    "wl_view_sub": {
        "tr": "Salt-okunur görünüm — listenin tüm satırları (yerleşik listeler değiştirilemez).",
        "en": "Read-only view — all entries of the list (built-in lists are immutable).",
    },
    "wl_edit_title": {"tr": "Kelime Listesi Düzenle", "en": "Edit Wordlist"},
    "wl_entries_replace": {
        "tr": "Yeni satırlar mevcut listenin YERİNE geçer (yapıştır veya .txt yükle).",
        "en": "New entries REPLACE the current list (paste or upload a .txt).",
    },
    # Wordlist türleri
    "wlkind_web_dir": {"tr": "Web dizin/içerik keşfi", "en": "Web directory/content"},
    "wlkind_smb_share": {"tr": "SMB paylaşım adı", "en": "SMB share name"},
    "wlkind_username": {"tr": "Kullanıcı adı (brute force)", "en": "Username (brute force)"},
    "wlkind_password": {"tr": "Parola (brute force)", "en": "Password (brute force)"},
    "wlkind_snmp_community": {"tr": "SNMP topluluk", "en": "SNMP community"},
    "wlkind_subdomain": {"tr": "Subdomain/vhost", "en": "Subdomain/vhost"},
    # Report page
    "report_title": {"tr": "Güvenlik Raporu", "en": "Security Report"},
    "report_generated": {"tr": "Oluşturulma", "en": "Generated"},
    "pdf_download": {"tr": "PDF İndir", "en": "Download PDF"},
    # Report list (tarama-bazlı raporlar)
    "reports_title": {"tr": "Raporlar", "en": "Reports"},
    "reports_sub": {
        "tr": "Her tarama kendi raporudur. Bir taramayı seçip görüntüle ya da PDF indir.",
        "en": "Each scan is its own report. Pick a scan to view or download its PDF.",
    },
    "report_all_pdf": {"tr": "Tümünü PDF indir", "en": "Download all as PDF"},
    "report_delete_confirm": {
        "tr": "Bu rapor (ve taramaları/bulguları) kalıcı olarak silinecek. Emin misiniz?",
        "en": "This report (and its scans/findings) will be permanently deleted. Are you sure?",
    },
    "report_deleted": {"tr": "Rapor silindi.", "en": "Report deleted."},
    "back_to_reports": {"tr": "Raporlar", "en": "Reports"},
    "th_status": {"tr": "Durum", "en": "Status"},
    "th_date": {"tr": "Tarih", "en": "Date"},
    "view": {"tr": "Görüntüle", "en": "View"},
    "summary": {"tr": "Özet", "en": "Summary"},
    "total_findings": {"tr": "Toplam bulgu", "en": "Total findings"},
    "report_findings": {"tr": "Bulgular", "en": "Findings"},
    "rep_findings_sol": {"tr": "Bulgular ve Çözümler", "en": "Findings & Remediation"},
    # Dizin/içerik taraması — keşfedilen erişilebilir yollar (rapor + PDF'te ayrı bölüm).
    "rep_paths": {
        "tr": "Bulunan Yollar (dizin taraması)",
        "en": "Discovered Paths (directory scan)",
    },
    "rep_paths_sub": {
        "tr": "Dizin/içerik keşfiyle erişilebilir bulunan yollar. Hassas olanları (git/env/"
        "backup vb.) öncelikli inceleyin; gereksizleri kapatın ya da erişimi kısıtlayın.",
        "en": "Paths found accessible via directory/content discovery. Review the sensitive ones "
        "(git/env/backup, etc.) first; remove or restrict access to the unnecessary ones.",
    },
    "rep_path_col": {"tr": "Yol", "en": "Path"},
    "rep_description": {"tr": "Açıklama", "en": "Description"},
    "rep_cause": {"tr": "Neden", "en": "Cause"},
    # VIII-1 Güvenli CVE netleştirme — exploit varlığı (BİLGİ amaçlı, çalıştırılmaz).
    "rep_exploit_avail": {"tr": "Exploit mevcut", "en": "Exploit available"},
    "rep_ospkg_tip": {
        "tr": "Kimlikli taramada kurulu OS paketi (dpkg) OSV.dev ile eşleşti — işletim "
        "sistemi paket açığı.",
        "en": "An installed OS package (dpkg) matched OSV.dev during the credentialed scan — "
        "an operating-system package vulnerability.",
    },
    "rep_exploit_tip": {
        "tr": "Bu CVE için yerel exploit veritabanımızda kayıt var (Exploit-DB / Metasploit). "
        "Yalnız bilgi — güvenli CVE taramasında çalıştırılmaz.",
        "en": "Our local exploit database has a record for this CVE (Exploit-DB / Metasploit). "
        "Informational only — not executed in a safe CVE scan.",
    },
    "rep_exploited": {"tr": "EXPLOITED", "en": "EXPLOITED"},
    "rep_exploited_tip": {
        "tr": "Bu zafiyet agresif CVE taramasında GERÇEKTEN sömürüldü — Metasploit ile kod "
        "çalıştırma doğrulandı (oturum açıldı ve kapatıldı).",
        "en": "This vulnerability was ACTUALLY exploited in the aggressive CVE scan — code "
        "execution verified via Metasploit (session opened and closed).",
    },
    "rep_privesc": {"tr": "ROOT", "en": "ROOT"},
    "rep_privesc_tip": {
        "tr": "Kimlikli tarama sonrası yetki yükseltme DENEMESİ root'a yükseltmeyi DOĞRULADI "
        "(uid=0). Salt-okunur 'id' ile kanıtlandı, sistem değiştirilmedi.",
        "en": "Privilege-escalation attempt after credentialed login CONFIRMED root (uid=0). "
        "Proven with read-only 'id'; the system was not modified.",
    },
    "rep_exploit_modules": {"tr": "Metasploit modülleri", "en": "Metasploit modules"},
    "exploit_sources_label": {"tr": "Exploit kaynakları", "en": "Exploit sources"},
    "exploit_used_source": {"tr": "Kullanılan kaynak", "en": "Source used"},
    "rep_exploit_note": {
        "tr": "Bu modüller bilgi amaçlı listelenir (yerel exploit DB eşleşmesi = exploit MEVCUT). "
        "Gerçekten DENENİP denenmediği bulgudaki 'Denendi/Sömürüldü' rozetinde ve "
        "'Exploitation durumu'nda görünür.",
        "en": "Modules are listed for information (local exploit DB match = exploit AVAILABLE). "
        "Whether it was actually ATTEMPTED shows in the finding's 'Tried/Exploited' badge and the "
        "'Exploitation status'.",
    },
    "exploit_status_label": {"tr": "Exploitation durumu", "en": "Exploitation status"},
    "exploit_st_ran": {
        "tr": "Metasploit: {n} deneme, {s} başarılı (sömürüldü)",
        "en": "Metasploit: {n} attempts, {s} succeeded (exploited)",
    },
    "exploit_st_skipped": {
        "tr": "Metasploit çalışmadı — gerçek deneme kaydı yok (msfrpcd bağlanamadı ya da eşleşen "
        "exploit modülü yok). Aşağıdaki Exploit-DB PoC'leri yalnız HAZIRLANDI, çalıştırılmadı.",
        "en": "Metasploit did not run — no real attempts (msfrpcd unreachable or no matching "
        "exploit module). The Exploit-DB PoCs below were only STAGED, not executed.",
    },
    "exploit_st_na": {
        "tr": "Çalıştırılmadı — güvenli/normal tarama (yalnız tespit; gerçek exploit denenmez)",
        "en": "Not executed — safe/normal scan (detection only; no real exploit attempted)",
    },
    # Kullanılabilir exploit cephaneliği özet bandı (#172) — yalnız MEVCUDİYET, sömürmez
    "exploit_arsenal_label": {
        "tr": "Kullanılabilir exploit cephaneliği",
        "en": "Available exploit arsenal",
    },
    "exploit_arsenal_summary": {
        "tr": "{n} CVE'de exploit mevcut · {m} Metasploit modülü (otomatik silahlandırılabilir) "
        "· {p} yalnız Exploit-DB PoC (manuel)",
        "en": "{n} CVEs have an exploit · {m} Metasploit modules (auto-weaponizable) "
        "· {p} Exploit-DB PoC only (manual)",
    },
    "exploit_arsenal_verified": {"tr": " · {v} doğrulanmış", "en": " · {v} verified"},
    "exploit_arsenal_safe_note": {
        "tr": "DENENMEDİ — bu tarama yalnız tespit eder, exploit ÇALIŞTIRMAZ. Gerçek sömürü "
        "yalnız 'Sömürme' modunda yapılır (admin + onay + kapsam).",
        "en": "NOT ATTEMPTED — this scan only detects; it does NOT run exploits. Real "
        "exploitation happens only in 'Exploit' mode (admin + ack + scope).",
    },
    "exploit_arsenal_run_note": {
        "tr": "Sömürme modu — gerçek deneme durumu yukarıdaki Exploitation panelinde.",
        "en": "Exploit mode — real attempt status is in the Exploitation panel above.",
    },
    # EXDB-D: Exploit-DB PoC denemeleri (staged — operatör/sandbox labda dener)
    "exploitdb_staged_label": {
        "tr": "Exploit-DB denemeleri (PoC)",
        "en": "Exploit-DB attempts (PoC)",
    },
    "exploitdb_staged_sub": {
        "tr": (
            "Bu CVE'ler için yerel Exploit-DB'de PoC mevcut. Metasploit'ten farklı olarak "
            "otomatik çalıştırılmaz — operatör (ya da sandbox runner) labda dener. PoC kodu "
            "çalıştırmadan önce inceleyin (bazı PoC'ler tuzaklı olabilir)."
        ),
        "en": (
            "Local Exploit-DB has a PoC for these CVEs. Unlike Metasploit, these are NOT "
            "auto-run — the operator (or sandbox runner) tries them in the lab. Review PoC "
            "code before running (some PoCs may be booby-trapped)."
        ),
    },
    "exploitdb_run_cmd": {"tr": "Önerilen komut", "en": "Suggested command"},
    "exploitdb_output": {"tr": "Çıktı", "en": "Output"},
    "exploitdb_staged_cap": {
        "tr": "Bu sayı bulunan TÜM exploit'ler değil — yalnız denenmek üzere hazırlanan PoC'ler "
        "(CVE başına en çok 3). 'Kullanılabilir exploit' (MSF + Exploit-DB) sayısı daha yüksek "
        "olabilir.",
        "en": "This is NOT all available exploits — only PoCs staged to try (max 3 per CVE). "
        "The 'available exploits' count (MSF + Exploit-DB) may be higher.",
    },
    "h_host": {"tr": "Host", "en": "Host"},
    "exploit_tried": {"tr": "Denendi", "en": "Tried"},
    "exploit_tried_tip": {
        "tr": "Bu CVE için bu cihazda GERÇEK exploit denendi ama oturum açılamadı (başarısız).",
        "en": "A REAL exploit was attempted for this CVE on this host but no session opened "
        "(failed).",
    },
    "exploit_done": {"tr": "Sömürüldü", "en": "Exploited"},
    "exploit_done_tip": {
        "tr": "Bu CVE bu cihazda GERÇEKTEN sömürüldü — kod çalıştırma doğrulandı.",
        "en": "This CVE was ACTUALLY exploited on this host — code execution verified.",
    },
    "exploit_channel_reverse": {"tr": "Reverse", "en": "Reverse"},
    "exploit_channel_bind": {"tr": "Bind", "en": "Bind"},
    "exploit_channel_tip": {
        "tr": "Oturumu açan sömürü kanalı: Reverse (hedef geri bağlandı) / Bind (porta bağlandık).",
        "en": "Exploit channel that opened the session: Reverse (target called back) / Bind "
        "(we connected to a port).",
    },
    "rep_remediation": {"tr": "Çözüm", "en": "Remediation"},
    "rep_references": {"tr": "Referanslar", "en": "References"},
    "rep_compliance": {"tr": "Uyum (CIS)", "en": "Compliance (CIS)"},
    "rep_compliance_pdf": {
        "tr": "Uyum Raporu PDF (KVKK/ISO/PCI)",
        "en": "Compliance Report PDF (KVKK/ISO/PCI)",
    },
    "rep_score": {"tr": "Skor", "en": "Score"},
    "rep_passed": {"tr": "geçti", "en": "passed"},
    "rep_framework": {"tr": "Çerçeve", "en": "Framework"},
    "rep_control": {"tr": "Kontrol", "en": "Control"},
    "rep_pass": {"tr": "Geçti", "en": "Pass"},
    "rep_fail": {"tr": "Kaldı", "en": "Fail"},
    "rep_hosts": {"tr": "Bulunan Hostlar", "en": "Discovered Hosts"},
    "rep_hosts_sub": {
        "tr": "Tarama kapsamında ayakta bulunan cihazlar ve toplanan bilgileri.",
        "en": "Live hosts found in scan scope and the information collected.",
    },
    "rep_host_ip": {"tr": "IP", "en": "IP"},
    "rep_host_device": {"tr": "Cihaz / Hostname", "en": "Device / Hostname"},
    "rep_host_os": {"tr": "İşletim sistemi", "en": "OS"},
    "rep_host_ports": {"tr": "Açık portlar / servisler", "en": "Open ports / services"},
    "rep_host_noports": {
        "tr": "port taranmadı (yalnız keşif)",
        "en": "no port scan (discovery only)",
    },
    "rep_host_up": {"tr": "ayakta", "en": "up"},
    "rep_host_unassigned": {
        "tr": "Sunucu atanmamış (genel)",
        "en": "No host assigned (general)",
    },
    "stat_kev": {"tr": "Aktif sömürü (KEV)", "en": "Active exploit (KEV)"},
    "stat_exploits": {"tr": "Exploit'li bulgu", "en": "Findings w/ exploit"},
    "no_findings_short": {"tr": "Bulgu yok.", "en": "No findings."},
    # Schedules page
    "schedules_title": {"tr": "Zamanlanmış Taramalar", "en": "Scheduled Scans"},
    "schedules_sub": {
        "tr": "Tekrarlı taramalar — Celery beat her dakika kontrol eder ve zamanı gelenleri "
        "otomatik başlatır.",
        "en": "Recurring scans — Celery beat checks every minute and auto-starts due scans.",
    },
    "sched_create_hint": {
        "tr": "Yeni zamanlama buradan eklenmez; tarama sihirbazının son adımında "
        "(periyot + başlangıç) oluşturulur:",
        "en": "New schedules aren't added here; create them in the scan wizard's final step "
        "(period + start):",
    },
    "sched_interval": {"tr": "Aralık (dakika)", "en": "Interval (minutes)"},
    "sched_period": {"tr": "Periyot", "en": "Period"},
    "period_daily": {"tr": "Günlük", "en": "Daily"},
    "period_weekly": {"tr": "Haftalık", "en": "Weekly"},
    "period_monthly": {"tr": "Aylık", "en": "Monthly"},
    "period_once": {"tr": "Tek seferlik", "en": "One-time"},
    "period_interval": {"tr": "Özel aralık (dk)", "en": "Custom interval (min)"},
    "sched_start_at": {
        "tr": "Başlangıç tarih/saat (UTC, ops.)",
        "en": "Start date/time (UTC, opt.)",
    },
    "th_period": {"tr": "Periyot", "en": "Period"},
    "th_start": {"tr": "Başlangıç", "en": "Start"},
    "add_schedule": {"tr": "Zamanlama Ekle", "en": "Add Schedule"},
    "no_schedules": {"tr": "Henüz zamanlama yok.", "en": "No schedules yet."},
    "th_interval": {"tr": "Aralık", "en": "Interval"},
    "th_last_run": {"tr": "Son çalışma", "en": "Last run"},
    "never": {"tr": "hiç", "en": "never"},
    "min_short": {"tr": "dk", "en": "min"},
    "active": {"tr": "Aktif", "en": "Active"},
    "passive": {"tr": "Pasif", "en": "Inactive"},
    "pause": {"tr": "Duraklat", "en": "Pause"},
    "enable": {"tr": "Etkinleştir", "en": "Enable"},
    # LDAP (bağlantı → Ayarlar, kullanıcı arama/içe aktarma → Kullanıcılar)
    "ldap_conn_section": {"tr": "LDAP Bağlantısı", "en": "LDAP connection"},
    "ldap_import_section": {"tr": "LDAP'tan içe aktar", "en": "Import from LDAP"},
    "ldap_checking": {"tr": "Bağlantı kontrol ediliyor…", "en": "Checking connection…"},
    "ldap_connected": {"tr": "Bağlı", "en": "Connected"},
    "ldap_not_connected": {"tr": "Bağlı değil", "en": "Not connected"},
    "ldap_sub": {
        "tr": "LDAP/AD dizinine bağlan, kullanıcıları ara ve rol atayarak içe aktar. "
        "Giriş doğrulaması LDAP bind ile yapılır; parolalar uygulamada saklanmaz.",
        "en": "Connect to LDAP/AD, search users and import them with a role. Login is via "
        "LDAP bind; user passwords are never stored.",
    },
    "ldap_server_uri": {"tr": "Sunucu (URI)", "en": "Server (URI)"},
    "ldap_use_ssl": {"tr": "SSL/TLS (ldaps)", "en": "SSL/TLS (ldaps)"},
    "ldap_bind_dn": {"tr": "Bind DN (servis hesabı)", "en": "Bind DN (service account)"},
    "ldap_bind_pass": {"tr": "Bind parolası", "en": "Bind password"},
    "ldap_bind_pass_ph": {
        "tr": "Değiştirmiyorsan boş bırak",
        "en": "Leave blank to keep current",
    },
    "ldap_base_dn": {"tr": "Arama tabanı (Base DN)", "en": "Search base (Base DN)"},
    "ldap_user_filter": {"tr": "Kullanıcı filtresi", "en": "User filter"},
    "ldap_attr_username": {"tr": "Kullanıcı adı özniteliği", "en": "Username attribute"},
    "ldap_attr_email": {"tr": "E-posta özniteliği", "en": "Email attribute"},
    "ldap_attr_name": {"tr": "Görünen ad özniteliği", "en": "Display name attribute"},
    "ldap_default_role": {"tr": "İçe aktarma varsayılan rolü", "en": "Default import role"},
    "ldap_save": {"tr": "Ayarları Kaydet", "en": "Save Settings"},
    "ldap_test": {"tr": "Bağlantıyı Test Et", "en": "Test Connection"},
    "ldap_testing": {"tr": "Test ediliyor…", "en": "Testing…"},
    # X-6: LDAP periyodik kullanıcı senkron zamanlaması
    "ldap_sync_section": {"tr": "LDAP Kullanıcı Senkronu", "en": "LDAP user sync"},
    "ldap_sync_sub": {
        "tr": "LDAP dizininden kullanıcıları zamanlanmış olarak çek. Yeni üyeler PASİF gelir "
        "(admin etkinleştirir); var olan kullanıcıların rolü ve durumu korunur.",
        "en": "Pull users from the LDAP directory on a schedule. New members arrive INACTIVE "
        "(admin enables them); existing users' role and status are preserved.",
    },
    "ldap_sync_enable": {
        "tr": "Periyodik LDAP senkronunu etkinleştir",
        "en": "Enable periodic LDAP sync",
    },
    "ldap_sync_period": {"tr": "Sıklık", "en": "Frequency"},
    "ldap_sync_hourly": {"tr": "Saatlik", "en": "Hourly"},
    "ldap_sync_daily": {"tr": "Günlük", "en": "Daily"},
    "ldap_sync_weekly": {"tr": "Haftalık", "en": "Weekly"},
    "ldap_sync_hour": {"tr": "Saat (günlük/haftalık)", "en": "Hour (daily/weekly)"},
    "ldap_sync_last": {"tr": "Son senkron", "en": "Last sync"},
    "ldap_sync_never": {"tr": "Henüz çalışmadı", "en": "Never run"},
    "ldap_sync_note": {
        "tr": "Zamanlayıcı saatlik kontrol eder; sıklık ve saate göre tetiklenir.",
        "en": "The scheduler checks hourly and triggers per the frequency and hour.",
    },
    "ldap_search_ph": {"tr": "Kullanıcı adı / ad ara…", "en": "Search username / name…"},
    "ldap_search_btn": {"tr": "Ara", "en": "Search"},
    "ldap_no_results": {
        "tr": "Sonuç yok ya da henüz arama yapılmadı.",
        "en": "No results, or no search yet.",
    },
    "ldap_import": {"tr": "İçe Aktar", "en": "Import"},
    "ldap_advanced": {
        "tr": "Gelişmiş (öznitelik eşlemesi)",
        "en": "Advanced (attribute mapping)",
    },
    "ldap_see_groups": {"tr": "Grupları & OU'ları gör", "en": "View groups & OUs"},
    "ldap_groups_title": {"tr": "Güvenlik grupları", "en": "Security groups"},
    "ldap_ous_title": {"tr": "Organizasyon birimleri (OU)", "en": "Organizational units (OU)"},
    "ldap_group_import_note": {
        "tr": "Bir grubun tüm üyelerini içe aktar — kullanıcılar PASİF gelir; "
        "Kullanıcılar sayfasından etkinleştirip rol atarsın.",
        "en": "Import all members of a group — users arrive DISABLED; enable them and "
        "assign roles on the Users page.",
    },
    "ldap_no_groups": {"tr": "Grup bulunamadı.", "en": "No groups found."},
    "ldap_import_group": {"tr": "Üyeleri içe aktar", "en": "Import members"},
    "ldap_not_configured": {
        "tr": "LDAP henüz yapılandırılmadı. Önce bağlantı ayarlarını kaydet.",
        "en": "LDAP not configured yet. Save connection settings first.",
    },
    "th_username": {"tr": "Kullanıcı adı", "en": "Username"},
    "th_displayname": {"tr": "Görünen ad", "en": "Display name"},
    "th_email": {"tr": "E-posta", "en": "Email"},
    "th_role": {"tr": "Rol", "en": "Role"},
    # Users page
    "users_title": {"tr": "Kullanıcılar", "en": "Users"},
    "users_sub": {
        "tr": "Ekip üyelerini yönet — rol, erişim ve hesap durumu. Kendi hesabını "
        "silemez/pasifleştiremez veya rolünü değiştiremezsin.",
        "en": "Manage team members — role, access and account status. You cannot "
        "delete/deactivate or change the role of your own account.",
    },
    "label_role": {"tr": "Rol", "en": "Role"},
    "label_email": {"tr": "E-posta", "en": "Email"},
    "add_user": {"tr": "Kullanıcı Ekle", "en": "Add User"},
    "th_source": {"tr": "Kaynak", "en": "Source"},
    "you_label": {"tr": "(siz)", "en": "(you)"},
    "deactivate": {"tr": "Pasifleştir", "en": "Deactivate"},
    # Audit page
    "audit_title": {"tr": "Denetim Günlüğü", "en": "Audit Log"},
    "audit_sub": {
        "tr": "Sistem olayları — kim, neyi, ne zaman yaptı (anlamlı mesajlar).",
        "en": "System events — who did what and when (meaningful messages).",
    },
    "th_user": {"tr": "Kullanıcı", "en": "User"},
    "th_event": {"tr": "Olay", "en": "Event"},
    "th_target_col": {"tr": "Hedef", "en": "Target"},
    "th_event_id": {"tr": "Event ID", "en": "Event ID"},
    "th_category": {"tr": "Kategori", "en": "Category"},
    "th_when": {"tr": "Zaman", "en": "When"},
    "no_logs": {"tr": "Henüz kayıt yok.", "en": "No entries yet."},
    "audit_range_day": {"tr": "Günlük (24s)", "en": "Daily (24h)"},
    "audit_range_week": {"tr": "Haftalık (7g)", "en": "Weekly (7d)"},
    "audit_range_month": {"tr": "Aylık (30g)", "en": "Monthly (30d)"},
    "audit_range_all": {"tr": "Tümü", "en": "All"},
    "audit_time_range": {"tr": "Zaman dilimi", "en": "Time range"},
    "audit_download_csv": {"tr": "CSV indir", "en": "Download CSV"},
    "audit_download_json": {"tr": "JSON indir", "en": "Download JSON"},
    # Audit filtreleri (X-7b)
    "audit_date_from": {"tr": "Başlangıç tarihi", "en": "From date"},
    "audit_date_to": {"tr": "Bitiş tarihi", "en": "To date"},
    "audit_keyword": {"tr": "Anahtar kelime", "en": "Keyword"},
    "audit_keyword_ph": {
        "tr": "eylem / hedef / kullanıcı ara…",
        "en": "search action / target / user…",
    },
    "audit_event_id": {"tr": "Event ID", "en": "Event ID"},
    "audit_event_id_ph": {"tr": "ör. 1001", "en": "e.g. 1001"},
    "audit_search": {"tr": "Ara", "en": "Search"},
    "audit_clear": {"tr": "Temizle", "en": "Clear"},
    # Audit kategorileri (X-7a)
    "audit_cat_auth": {"tr": "Kimlik doğrulama", "en": "Authentication"},
    "audit_cat_scan": {"tr": "Tarama", "en": "Scan"},
    "audit_cat_exploit": {"tr": "Exploit", "en": "Exploit"},
    "audit_cat_user": {"tr": "Kullanıcı", "en": "User"},
    "audit_cat_compliance": {"tr": "Uyum", "en": "Compliance"},
    "audit_cat_system": {"tr": "Sistem", "en": "System"},
    # SIEM parser regex (X-7c)
    "audit_siem_title": {"tr": "SIEM Parser Regex", "en": "SIEM Parser Regex"},
    "audit_siem_desc": {
        "tr": "Syslog'a iletilen denetim satırlarını alanlarına (timestamp, host, "
        "event_id, category, action, user, target, message) ayıran adlandırılmış-grup "
        "regex'i. SIEM parser yapılandırmanıza kopyalayın.",
        "en": "Named-capture regex that parses the audit lines forwarded to syslog into "
        "fields (timestamp, host, event_id, category, action, user, target, message). "
        "Copy it into your SIEM parser configuration.",
    },
    "audit_siem_active": {"tr": "Etkin syslog biçimi", "en": "Active syslog format"},
    "audit_siem_active_badge": {"tr": "etkin", "en": "active"},
    # Tokens page (extra)
    "token_role_note": {
        "tr": "Token senin rolünle ({role}) çalışır.",
        "en": "The token runs with your role ({role}).",
    },
    "token_created_once": {
        "tr": "Token oluşturuldu — şimdi kopyala!",
        "en": "Token created — copy it now!",
    },
    "token_once_warn": {
        "tr": "Bu değer bir daha gösterilmeyecek. Güvenli bir yere kaydet; kaybedersen iptal "
        "edip yenisini oluştur.",
        "en": "This value will not be shown again. Save it safely; if lost, revoke it and create "
        "a new one.",
    },
    "copy": {"tr": "Kopyala", "en": "Copy"},
    "token_how": {"tr": "Nasıl kullanılır?", "en": "How to use?"},
    "token_how_intro": {
        "tr": "Bu tarayıcıyı Claude'a bağlamak için sunucu IP'sini gir, aşağıdaki hazır "
        "kodu kopyalayıp Claude'a ver — token zaten gömülü.",
        "en": "To connect this scanner to Claude, enter the server IP, then copy the ready "
        "snippet below and give it to Claude — the token is already embedded.",
    },
    "token_server_ip": {"tr": "Sunucu IP'si / adresi", "en": "Server IP / host"},
    "token_claude_code": {
        "tr": "Claude Code (terminal — tek satır)",
        "en": "Claude Code (terminal — one line)",
    },
    "token_claude_desktop": {
        "tr": "Claude Desktop (claude_desktop_config.json)",
        "en": "Claude Desktop (claude_desktop_config.json)",
    },
    "token_how_tools": {
        "tr": "Bağlandıktan sonra Claude varlıkları, zafiyetleri, CVE'leri listeleyebilir ve "
        "güvenli taramalar başlatabilir (rolünle sınırlı).",
        "en": "Once connected, Claude can list assets, vulnerabilities, CVEs and start safe "
        "scans (limited by your role).",
    },
    "token_empty_name": {"tr": "Token adı boş olamaz.", "en": "Token name cannot be empty."},
    "th_created": {"tr": "Oluşturuldu", "en": "Created"},
    "th_last_used": {"tr": "Son kullanım", "en": "Last used"},
    "th_expiry": {"tr": "Geçerlilik", "en": "Expiry"},
    "unlimited": {"tr": "süresiz", "en": "unlimited"},
    "token_revoked": {"tr": "İptal", "en": "Revoked"},
    "token_empty": {
        "tr": "Henüz token yok. Yukarıdan oluştur.",
        "en": "No tokens yet. Create one above.",
    },
    "token_expiry_ph": {"tr": "0 = süresiz", "en": "0 = unlimited"},
    # Report page
    "report_footer": {
        "tr": "Bu rapor {app} tarafından otomatik oluşturulmuştur. Yalnızca yetkili kapsamda "
        "yapılan taramaları içerir.",
        "en": "This report was generated automatically by {app}. It only covers scans performed "
        "within authorized scope.",
    },
    # Settings page
    "settings_title": {"tr": "Ayarlar", "en": "Settings"},
    "settings_sub": {
        "tr": "Güvenlik ve operasyon ayarları. Buradaki değerler ortam değişkenlerinin "
        "önüne geçer; sırlar şifreli saklanır.",
        "en": "Security and operations settings. Values here override environment variables; "
        "secrets are stored encrypted.",
    },
    "settings_saved": {"tr": "Ayarlar kaydedildi.", "en": "Settings saved."},
    "settings_enabled": {"tr": "Etkin", "en": "Enabled"},
    # — Rate-limit
    "set_rl_title": {"tr": "Giriş kaba-kuvvet koruması", "en": "Login brute-force protection"},
    "set_rl_desc": {
        "tr": "Belirli sürede çok sayıda başarısız girişten sonra hesabı/IP'yi geçici kilitler.",
        "en": "Temporarily locks the account/IP after too many failed logins in a window.",
    },
    "set_rl_max": {"tr": "Maksimum başarısız deneme", "en": "Max failed attempts"},
    "set_rl_window": {"tr": "Zaman penceresi (sn)", "en": "Window (sec)"},
    "set_rl_lockout": {"tr": "Kilitleme süresi (sn)", "en": "Lockout duration (sec)"},
    # — SMTP
    "set_smtp_title": {"tr": "SMTP ve e-posta uyarıları", "en": "SMTP & email alerts"},
    "set_smtp_desc": {
        "tr": "Kritik bulgu uyarıları ve (etkinse) e-posta OTP için kullanılır.",
        "en": "Used for critical-finding alerts and (if enabled) email OTP.",
    },
    "set_smtp_host": {"tr": "Sunucu (host)", "en": "Server (host)"},
    "set_smtp_port": {"tr": "Port", "en": "Port"},
    "set_smtp_user": {"tr": "Kullanıcı adı", "en": "Username"},
    "set_smtp_pass": {"tr": "Parola", "en": "Password"},
    "set_smtp_pass_ph": {"tr": "değiştirmemek için boş bırakın", "en": "leave blank to keep"},
    "set_smtp_from": {"tr": "Gönderen adresi (From)", "en": "From address"},
    "set_smtp_tls": {"tr": "STARTTLS kullan", "en": "Use STARTTLS"},
    "set_smtp_alert_to": {"tr": "Uyarı alıcısı (e-posta)", "en": "Alert recipient (email)"},
    "set_smtp_test": {"tr": "Test e-postası gönder", "en": "Send test email"},
    # — Syslog
    "set_syslog_title": {"tr": "Syslog / SIEM forward", "en": "Syslog / SIEM forwarding"},
    "set_syslog_desc": {
        "tr": "Denetim olaylarını bir syslog/SIEM toplayıcıya iletir.",
        "en": "Forwards audit events to a syslog/SIEM collector.",
    },
    "set_syslog_host": {"tr": "Toplayıcı host", "en": "Collector host"},
    "set_syslog_port": {"tr": "Port", "en": "Port"},
    "set_syslog_proto": {"tr": "Protokol", "en": "Protocol"},
    "set_syslog_fmt": {"tr": "Biçim", "en": "Format"},
    # — Hardening
    "set_hard_title": {"tr": "Oturum, parola ve LDAPS", "en": "Session, password & LDAPS"},
    "set_hard_desc": {
        "tr": "Oturum zaman aşımı, parola politikası ve LDAPS sertifika doğrulama.",
        "en": "Session timeout, password policy and LDAPS certificate validation.",
    },
    "set_session_timeout": {
        "tr": "Oturum zaman aşımı (dk, 0=kapalı)",
        "en": "Session timeout (min, 0=off)",
    },
    "set_pw_min": {"tr": "Min. parola uzunluğu", "en": "Min password length"},
    "set_pw_complex": {
        "tr": "Karmaşıklık zorunlu (harf+rakam)",
        "en": "Require complexity (letter+digit)",
    },
    "set_ldaps_verify": {"tr": "LDAPS sertifikasını doğrula", "en": "Validate LDAPS certificate"},
    "set_ldaps_ca": {
        "tr": "CA sertifikası (PEM, opsiyonel)",
        "en": "CA certificate (PEM, optional)",
    },
    # Network / DNS (VI-6)
    "set_network_section": {"tr": "Ağ / DNS", "en": "Network / DNS"},
    "set_network_sub": {
        "tr": "Taramalarda hostname çözümünü etkiler — özel DNS sunucusu ve reverse-DNS (PTR).",
        "en": "Affects hostname resolution in scans — custom DNS server and reverse-DNS (PTR).",
    },
    "set_dns_servers": {
        "tr": "DNS sunucu(ları) (virgülle, opsiyonel)",
        "en": "DNS server(s) (comma-separated, optional)",
    },
    "set_reverse_dns": {
        "tr": "Reverse-DNS (PTR) çözümü açık",
        "en": "Reverse-DNS (PTR) resolution enabled",
    },
    "set_dns_hint": {
        "tr": "Boş DNS = sistem çözücü. Reverse-DNS kapalıyken nmap -n kullanır "
        "(daha hızlı, hostname yok). Yalnızca geçerli IP'ler kabul edilir.",
        "en": "Empty DNS = system resolver. With reverse-DNS off, nmap uses -n "
        "(faster, no hostnames). Only valid IPs are accepted.",
    },
    # Tarama hızı (SCAN-SPEED): nmap paralellik
    "set_scan_speed": {"tr": "Tarama hızı", "en": "Scan speed"},
    "set_scan_speed_normal": {
        "tr": "Normal — en doğru (paralellik zorlamasız)",
        "en": "Normal — most accurate (no forced parallelism)",
    },
    "set_scan_speed_fast": {
        "tr": "Hızlı — daha çok paralel (önerilen)",
        "en": "Fast — more parallelism (recommended)",
    },
    "set_scan_speed_insane": {
        "tr": "Çok hızlı — en agresif (paket-kaybı riski)",
        "en": "Insane — most aggressive (packet-loss risk)",
    },
    "set_scan_speed_slow": {
        "tr": "Uzak / VPN — yavaş ama kayıpsız (yüksek gecikme)",
        "en": "Remote / VPN — slow but lossless (high latency)",
    },
    "set_scan_speed_hint": {
        "tr": "nmap ağ-bound'dur; hız RAM/CPU değil PARALELLİKLE artar. Hızlı, boştaki "
        "kaynağı çok-hostlu taramalarda kullanır (düşük risk). Çok hızlı en hızlısıdır "
        "ama paket kaybı → kaçırılan port/servis riskini artırır. Uzak/VPN, yüksek gecikmeli "
        "hatlar içindir: paralellik yok + nazik zamanlama → tek uzak hedefte 'tcpwrapped' "
        "(sürüm okunamadı) sorununu önler.",
        "en": "nmap is network-bound; speed comes from PARALLELISM, not RAM/CPU. Fast uses "
        "idle resources on multi-host scans (low risk). Insane is fastest but raises the "
        "risk of packet loss → missed ports/services. Remote/VPN is for high-latency links: "
        "no parallelism + gentle timing → avoids 'tcpwrapped' (no version read) on a single "
        "remote target.",
    },
    # Tarama bölümü (hız + worker dağıtımı) — DNS'ten ayrı; hover tooltip'ler (SCAN-SETTINGS-UX)
    "set_scan_section": {"tr": "Tarama hızı ve dağıtımı", "en": "Scan speed & distribution"},
    "set_scan_sub": {
        "tr": "nmap/CVE taramasının hızı + tek taramanın kaç worker'a bölüneceği. DNS'ten ayrıdır; "
        "alanların üzerine geldiğinizde ne yaptıklarını gösterir.",
        "en": "Speed of nmap/CVE scans + how many workers one scan splits across. Separate "
        "from DNS; hover a field to see what it does.",
    },
    "set_dns_servers_tip": {
        "tr": "nmap'in kullanacağı DNS sunucuları (virgülle). Boş = sistem çözücü.",
        "en": "DNS servers nmap uses (comma-separated). Empty = system resolver.",
    },
    "set_reverse_dns_tip": {
        "tr": "Açık: IP'lerden hostname çözer (yavaşlatır). Kapalı: nmap -n (hızlı, hostname yok).",
        "en": "On: resolves hostnames from IPs (slower). Off: nmap -n (faster, no hostnames).",
    },
    "set_scan_speed_tip": {
        "tr": "nmap zamanlama/paralellik profili. Uzak/VPN = nazik (tcpwrapped'i önler); "
        "Çok hızlı = paket-kaybı riski. Worker bölmeden BAĞIMSIZDIR.",
        "en": "nmap timing/parallelism profile. Remote/VPN = gentle (avoids tcpwrapped); "
        "Insane = packet-loss risk. INDEPENDENT of worker splitting.",
    },
    "set_scan_fanout": {"tr": "Worker'lara böl (fan-out)", "en": "Split across workers (fan-out)"},
    "set_scan_fanout_tip": {
        "tr": "Açık: tek tarama bloklara bölünüp worker'lara dağıtılır (~N× hız). Kapalı: tek "
        "worker. Tarama hızından bağımsızdır; her child yine seçilen hızı kullanır.",
        "en": "On: one scan is split into blocks across workers (~N× faster). Off: single worker. "
        "Independent of scan speed; each child still uses the selected speed.",
    },
    "set_fanout_workers": {"tr": "Worker bölme sayısı", "en": "Worker split count"},
    "set_fanout_workers_tip": {
        "tr": "Tek host'un tüm-port (-p-) taraması en çok kaç port-bloğuna (worker) bölünür "
        "(1-32; 1 = bölme yok). Büyük ağ (CIDR) taramaları ayrıca /27 bloklara bölünür.",
        "en": "How many port-blocks (workers) a single host's full-port (-p-) scan splits into "
        "(1-32; 1 = no split). Large network (CIDR) scans also split into /27 blocks.",
    },
    "set_fanout_info_title": {"tr": "Bu tarama kaça bölünür?", "en": "How is a scan split?"},
    "set_fanout_info_single": {
        "tr": "Tek host, varsayılan portlar (top-1000) → {n} worker'a bölünür.",
        "en": "Single host, default ports (top-1000) → split across {n} workers.",
    },
    "set_fanout_info_bigport": {
        "tr": "Tek host, tüm portlar (-p-) → {n} port bloğu (worker).",
        "en": "Single host, all ports (-p-) → {n} port blocks (workers).",
    },
    "set_fanout_info_cidr": {
        "tr": "Büyük ağ (CIDR) → /27 bloklara, hedef boyutuna göre (örn. /24 → 8 blok).",
        "en": "Large network (CIDR) → /27 blocks, by target size (e.g. /24 → 8 blocks).",
    },
    # Varlık kapsamı (F1)
    "set_asset_scope_section": {"tr": "Varlık kapsamı", "en": "Asset scope"},
    "set_asset_scope_sub": {
        "tr": "Yalnız bu aralıklardaki IP'ler envantere (Varlıklar) eklenir. Dış/kapsam-dışı "
        "hedeflere yapılan taramalar Varlıklar'ı kirletmez (bulgular yine raporda görünür).",
        "en": "Only IPs in these ranges are added to the inventory (Assets). Scans of external/"
        "out-of-scope targets won't pollute Assets (findings still appear in the report).",
    },
    "set_asset_scope_label": {
        "tr": "Varlık kapsamı CIDR'leri (her satıra bir; IP veya CIDR)",
        "en": "Asset-scope CIDRs (one per line; IP or CIDR)",
    },
    "set_asset_scope_hint": {
        "tr": "Varsayılan: özel/iç ağlar (RFC1918) + loopback. Dış bir IP/aralığı izlemek "
        "isterseniz buraya ekleyin. Boş bırakırsanız kapsam zorlanmaz (tüm IP'ler varlık olur).",
        "en": "Default: private/internal networks (RFC1918) + loopback. Add an external IP/range "
        "here to track it. Leave empty to disable enforcement (all IPs become assets).",
    },
    # Yetkili tarama kapsamı (ScopePolicy, #C)
    "set_scope_section": {"tr": "Yetkili tarama kapsamı", "en": "Authorized scan scope"},
    "set_scope_sub": {
        "tr": "Yalnızca bu izinli CIDR'lerin alt kümesi olan (ve yasaklarla çakışmayan) hedefler "
        "taranabilir. Taramaya YETKİLİ olduğunuz ağları tanımlar (set_scope CLI yerine).",
        "en": "Only targets within these allowed CIDRs (and not overlapping denies) can be "
        "scanned. Defines the networks you are AUTHORIZED to scan (replaces the set_scope CLI).",
    },
    "set_scope_current": {"tr": "Aktif politika", "en": "Active policy"},
    "set_scope_none": {
        "tr": "Tanımlı kapsam yok — hiçbir tarama çalışmaz. Aşağıdan en az bir izinli CIDR girin.",
        "en": "No scope defined — no scan will run. Enter at least one allowed CIDR below.",
    },
    "set_scope_name_label": {"tr": "Politika adı", "en": "Policy name"},
    "set_scope_allowed_label": {"tr": "İzinli CIDR'ler", "en": "Allowed CIDRs"},
    "set_scope_denied_label": {"tr": "Yasak CIDR'ler", "en": "Denied CIDRs"},
    "set_scope_hint": {
        "tr": "Her satıra bir CIDR ya da IP (IP → /32). Yasak izinden önce gelir (deny kazanır). "
        "Yalnız taramaya yetkili olduğunuz ağları girin; geçersiz satırlar atlanır.",
        "en": "One CIDR or IP per line (IP → /32). Deny wins over allow. Enter only networks you "
        "are authorized to scan; invalid lines are skipped.",
    },
    "set_scope_error_empty": {
        "tr": "En az bir geçerli izinli CIDR gerekli (boş = tüm hedefler reddedilir).",
        "en": "At least one valid allowed CIDR is required (empty = all targets denied).",
    },
    # Ticari lisans (çevrimdışı, imza-temelli) — ``exploit`` özelliğini açar
    "set_license_section": {"tr": "Lisans", "en": "License"},
    "set_license_sub": {
        "tr": "Ticari lisans kodunu yapıştırın — sömürü (exploit) özelliğini açar. Çevrimdışı "
        "imzayla doğrulanır (sunucu gerekmez). Sömürü için ayrıca ticari eklenti de kurulu olmalı.",
        "en": "Paste your commercial license code — unlocks the exploit feature. Verified offline "
        "via signature (no server). The commercial add-on must also be installed to exploit.",
    },
    "set_license_label": {"tr": "Lisans kodu", "en": "License code"},
    "set_license_status": {"tr": "Durum", "en": "Status"},
    "license_status_valid": {"tr": "Geçerli", "en": "Valid"},
    "license_status_expired": {"tr": "Süresi dolmuş", "en": "Expired"},
    "license_status_invalid": {"tr": "Geçersiz", "en": "Invalid"},
    "license_status_none": {"tr": "Yok", "en": "None"},
    "license_status_disabled": {"tr": "Devre dışı", "en": "Disabled"},
    "set_license_customer": {"tr": "Müşteri", "en": "Customer"},
    "set_license_expires": {"tr": "Bitiş", "en": "Expires"},
    "set_license_features": {"tr": "Özellikler", "en": "Features"},
    "license_two_layer": {
        "tr": "Not: Bu doğrulama yalnız arayüz kilidini açar. Gerçek sömürü ayrıca worker'a "
        "kurulu ticari eklentinin kendi lisans kapısından da geçmek zorundadır (iki katmanlı).",
        "en": "Note: This verification only unlocks the UI. Actual exploitation must also pass the "
        "commercial add-on's own license gate installed on the worker (two layers).",
    },
    "license_plugins_link": {"tr": "Eklenti durumu", "en": "Add-on status"},
    "license_saved": {"tr": "Lisans kaydedildi.", "en": "License saved."},
    "license_pubkey_label": {
        "tr": "Doğrulama açık anahtarı (public key)",
        "en": "Verification public key",
    },
    "license_pubkey_hint": {
        "tr": "Patronun Ed25519 AÇIK anahtarı (base64) — GİZLİ DEĞİLDİR. Lisans imzaları bununla "
        "doğrulanır. Boş bırakılırsa ortam değişkeni (LICENSE_PUBLIC_KEY) kullanılır.",
        "en": "The vendor's Ed25519 PUBLIC key (base64) — NOT secret. License signatures are "
        "verified with it. If left blank, the environment variable (LICENSE_PUBLIC_KEY) is used.",
    },
    "license_pubkey_env_active": {
        "tr": "Şu an ortam değişkeninden (LICENSE_PUBLIC_KEY) geliyor. "
        "Buraya girersen onu geçersiz kılar.",
        "en": "Currently provided via the environment (LICENSE_PUBLIC_KEY). "
        "Entering one here overrides it.",
    },
    # Zafiyet veritabanı (CVE-COVERAGE FE)
    "set_vulndb_section": {"tr": "Zafiyet veritabanı", "en": "Vulnerability database"},
    "set_vulndb_sub": {
        "tr": "Yerel CVE/CPE indeksi ve NVD senkron kapsamı. Pencere genişledikçe daha çok "
        "bilinen açık eşleştirilir; günlük arka plan görevi otomatik tazeler.",
        "en": "Local CVE/CPE index and NVD sync coverage. A wider window matches more known "
        "vulnerabilities; a daily background job refreshes it automatically.",
    },
    "set_vulndb_cve_count": {"tr": "Kayıtlı CVE", "en": "Stored CVEs"},
    "set_vulndb_cpe_count": {"tr": "CPE eşleşmesi", "en": "CPE matches"},
    "set_vulndb_window": {"tr": "Senkron penceresi", "en": "Sync window"},
    "set_vulndb_days": {"tr": "gün", "en": "days"},
    "set_vulndb_last_sync": {"tr": "Son senkron", "en": "Last sync"},
    "set_vulndb_fresh": {"tr": "Güncel", "en": "Up to date"},
    "set_vulndb_stale": {"tr": "Güncel değil", "en": "Stale"},
    "set_nvd_days_label": {"tr": "Senkron penceresi (gün)", "en": "Sync window (days)"},
    "set_nvd_key_label": {"tr": "NVD API anahtarı (opsiyonel)", "en": "NVD API key (optional)"},
    "set_nvd_key_set": {
        "tr": "•••• kayıtlı (değiştirmek için yenisini girin)",
        "en": "•••• set (enter a new one to change)",
    },
    "set_nvd_key_empty": {
        "tr": "Anahtarsız da çalışır (daha yavaş)",
        "en": "Works without a key (slower)",
    },
    "set_nvd_hint": {
        "tr": "Pencere 120 günü aşarsa istek otomatik 120-günlük parçalara bölünür (NVD "
        "sınırı). API anahtarı rate-limit'i 5/30sn'den 50/30sn'ye çıkarır — anahtar boş "
        "bırakılırsa mevcut korunur.",
        "en": "If the window exceeds 120 days the request is auto-split into 120-day chunks "
        "(NVD limit). An API key raises the rate limit from 5/30s to 50/30s — leave blank to "
        "keep the current key.",
    },
    # NVD tek seferlik geçmiş yükleme (backfill)
    "set_nvd_backfill_title": {
        "tr": "Tek seferlik geçmiş yükleme",
        "en": "One-time historical backfill",
    },
    "set_nvd_backfill_sub": {
        "tr": "Günlük 120-günlük pencereye dokunmadan, bir kerede çok daha geniş aralıktan "
        "geçmiş CVE/CPE çeker (arka planda). İlk derin yükleme için idealdir.",
        "en": "Pulls a much wider historical range of CVE/CPE once (in the background) without "
        "touching the daily 120-day window. Ideal for the initial deep load.",
    },
    "set_nvd_backfill_years": {"tr": "Geriye dönük süre", "en": "Look-back period"},
    "set_nvd_backfill_year": {"tr": "yıl", "en": "yr"},
    "set_nvd_backfill_btn": {"tr": "Geçmişi yükle", "en": "Backfill history"},
    "set_nvd_backfill_hint": {
        "tr": "Arka planda çalışır; sayılar zamanla artar (sayfayı yenileyin). API anahtarı "
        "olmadan onlarca dakika sürebilir ve derin (5 yıl) çekimde rate-limit'e takılabilir.",
        "en": "Runs in the background; counts grow over time (refresh the page). Without an API "
        "key it can take tens of minutes and a deep (5-year) pull may hit rate limits.",
    },
    # Geçmiş yükleme (backfill) canlı durum + iptal (BACKFILL-PROGRESS)
    "bf_running": {"tr": "Geçmiş yükleniyor", "en": "Backfilling history"},
    "bf_queued": {"tr": "Başlatılıyor…", "en": "Starting…"},
    "bf_done": {"tr": "Tamamlandı", "en": "Completed"},
    "bf_cancelled": {"tr": "İptal edildi", "en": "Cancelled"},
    "bf_cancelling": {
        "tr": "İptal ediliyor (mevcut pencere bitince durur)…",
        "en": "Cancelling (stops after current window)…",
    },
    "bf_error": {"tr": "Hata", "en": "Error"},
    "bf_windows": {"tr": "Pencere", "en": "Windows"},
    "bf_cves_added": {"tr": "Eklenen CVE", "en": "CVEs added"},
    "bf_cpe": {"tr": "CPE eşleşme", "en": "CPE matches"},
    "bf_current": {"tr": "Aralık", "en": "Range"},
    "bf_cancel_btn": {"tr": "İptal et", "en": "Cancel"},
    # Yerel AI asistanı (OpenAI-uyumlu motor, on-prem; #182)
    "set_ai_section": {"tr": "Yerel AI asistanı", "en": "Local AI assistant"},
    "set_ai_sub": {
        "tr": "On-prem (kurulum-içi) AI: zafiyetleri açıklar ve raporlara yönetici özeti üretir. "
        "Veri müşteri ağından ÇIKMAZ (sıfır egress) — yerel OpenAI-uyumlu motor CPU'da koşar.",
        "en": "On-prem AI: explains findings and writes executive summaries for reports. Data "
        "never leaves your network (zero egress) — runs locally on CPU (OpenAI-compatible).",
    },
    "set_ai_enabled": {"tr": "AI asistanını etkinleştir", "en": "Enable AI assistant"},
    "set_ai_enabled_tip": {
        "tr": "Kapalıyken AI butonları görünmez; mevcut statik çözüm önerileri çalışır.",
        "en": "When off, AI buttons are hidden and existing static remediation continues to work.",
    },
    "set_ai_endpoint": {"tr": "Endpoint (OpenAI taban URL)", "en": "Endpoint (OpenAI base URL)"},
    "set_ai_endpoint_tip": {
        "tr": "Yerel OpenAI-uyumlu motorun URL'i (Ollama/LM Studio/LocalAI). Boş→varsayılan "
        "(http://ollama:11434/v1). Host motoru için http://host.docker.internal:<port>/v1.",
        "en": "URL of the local OpenAI-compatible engine (Ollama/LM Studio/LocalAI). Blank→"
        "default (http://ollama:11434/v1). Host engine: http://host.docker.internal:<port>/v1.",
    },
    "set_ai_model": {"tr": "Model", "en": "Model"},
    "set_ai_model_tip": {
        "tr": "Model adı/etiketi. Varsayılan qwen3:8b (çok-dilli+akıl; CPU'da ~6GB). Ollama "
        "tek-model sunar (etiket); LM Studio'da yüklü model id'siyle eşleşmeli.",
        "en": "Model name/label. Default qwen3:8b (multilingual+reasoning; ~6GB CPU). Ollama "
        "serves a single model (label); for LM Studio it must match the loaded model id.",
    },
    "set_ai_timeout": {"tr": "Zaman aşımı (sn)", "en": "Timeout (s)"},
    "set_ai_timeout_tip": {
        "tr": "Üretim üst süresi. CPU çıkarımı yavaştır (~10-40 sn) → cömert tutun (5-600).",
        "en": "Generation upper bound. CPU inference is slow (~10-40s) → keep it generous (5-600).",
    },
    "set_ai_privacy": {
        "tr": "Gizlilik: istemler ve veriler yalnız iç ağdaki yerel motora gider; hiçbir bulut "
        "API'si kullanılmaz. AI çıktıları üretkendir — uygulamadan önce doğrulayın.",
        "en": "Privacy: prompts and data go only to the internal local engine; no cloud API is "
        "used. AI output is generative — verify before acting on it.",
    },
    "set_ai_hint": {
        "tr": "Container: docker compose --profile ai up -d ollama (ilk açılıştan sonra modeli "
        "docker compose exec ollama ollama pull qwen3:8b ile çekin; air-gap için ön-paketli imaj "
        "zaten var). Ya da host'ta LM Studio/Ollama çalıştırıp endpoint'i ona yöneltin. Sonra "
        "test edin.",
        "en": "Container: docker compose --profile ai up -d ollama (after first start, pull the "
        "model with docker compose exec ollama ollama pull qwen3:8b; a pre-packaged image already "
        "exists for air-gap). Or run LM Studio/Ollama on the host and point the endpoint at it. "
        "Then test.",
    },
    "set_ai_test": {"tr": "Bağlantıyı test et", "en": "Test connection"},
    # Yerel AI kurulum sihirbazı (Faz 1 çatısı) — ortam algılama + önerilen motor yolu
    "set_ai_detect": {"tr": "Ortamı algıla", "en": "Detect environment"},
    "set_ai_detect_tip": {
        "tr": "Host-native (Ollama/LM Studio) + gömülü container + kayıtlı endpoint'i eşzamanlı "
        "yoklar ve önerilen yolu işaretler. Salt-okuma; sıfır egress (hepsi iç ağda).",
        "en": "Concurrently probes host-native (Ollama/LM Studio) + bundled container + saved "
        "endpoint and marks the recommended path. Read-only; zero egress (all internal).",
    },
    "set_ai_detect_result": {
        "tr": "Algılanan yerel-AI motorları",
        "en": "Detected local-AI engines",
    },
    "set_ai_detect_recommended": {"tr": "önerilen", "en": "recommended"},
    "set_ai_detect_use": {"tr": "Bu endpoint'i kullan", "en": "Use this endpoint"},
    "set_ai_detect_ok": {"tr": "Erişilebilir", "en": "Reachable"},
    "set_ai_detect_down": {"tr": "Erişilemiyor", "en": "Unreachable"},
    "set_ai_detect_install_hint": {
        "tr": "Host erişilebilir ama motor bulunamadı — Windows için Kangalis AI Companion "
        "kurucusunu çalıştırın (host-native motor; container storage sorunlarını baypas eder).",
        "en": "Host reachable but no engine found — run the Kangalis AI Companion installer "
        "(Windows) for a host-native engine (bypasses container storage issues).",
    },
    "set_ai_detect_none_hint": {
        "tr": "Erişilebilir motor yok. Linux'ta gömülü profili açın "
        "(docker compose --profile ai up -d ollama) ya da kurumsal LLM endpoint'inizi girin.",
        "en": "No reachable engine. On Linux enable the bundled profile "
        "(docker compose --profile ai up -d ollama) or enter your enterprise LLM endpoint.",
    },
    # Yerel AI açıklama / özet (per-bulgu + rapor; #183-184)
    "ai_explain_btn": {"tr": "AI ile açıkla", "en": "Explain with AI"},
    "ai_generating": {"tr": "AI üretiyor… (~10-40 sn)", "en": "AI generating… (~10-40s)"},
    "ai_explanation_label": {"tr": "AI açıklaması", "en": "AI explanation"},
    "ai_cached": {"tr": "önbellekten", "en": "cached"},
    "ai_cached_tip": {
        "tr": "Daha önce üretildi — yeniden hesaplanmadı (CPU tasarrufu).",
        "en": "Generated earlier — not recomputed (saves CPU).",
    },
    "ai_verify_note": {
        "tr": "AI üretti — uygulamadan önce doğrulayın.",
        "en": "AI-generated — verify before acting.",
    },
    "ai_disabled": {
        "tr": "AI asistanı kapalı. Eklentiler > Yerel AI'dan etkinleştirin.",
        "en": "AI assistant is off. Enable it in Plugins > Local AI.",
    },
    "ai_finding_missing": {
        "tr": "Bulgu/CVE bulunamadı.",
        "en": "Finding/CVE not found.",
    },
    "ai_generate_failed": {
        "tr": "AI üretimi başarısız (model erişilemedi ya da zaman aşımı). Eklentiler > Yerel "
        "AI'dan bağlantıyı test edin.",
        "en": "AI generation failed (model unreachable or timed out). Test the connection in "
        "Plugins > Local AI.",
    },
    "ai_rate_limited": {
        "tr": "AI istek sınırına ulaşıldı — yaklaşık {sec} sn sonra tekrar deneyin "
        "(CPU'yu korumak için).",
        "en": "AI request limit reached — try again in about {sec}s (to protect the CPU).",
    },
    "ai_summary_btn": {"tr": "AI yönetici özeti üret", "en": "Generate AI executive summary"},
    "ai_summary_label": {"tr": "AI Yönetici Özeti", "en": "AI Executive Summary"},
    "ai_summary_exec_btn": {
        "tr": "AI müşteri özeti üret",
        "en": "Generate AI customer summary",
    },
    "ai_summary_exec_label": {
        "tr": "AI Müşteri Özeti (teslim)",
        "en": "AI Customer Summary (deliverable)",
    },
    "ai_priorities_btn": {
        "tr": "AI düzeltme önceliklendirmesi",
        "en": "Generate AI remediation priorities",
    },
    "ai_priorities_label": {"tr": "AI Düzeltme Önceliği", "en": "AI Remediation Priorities"},
    # Sömürü-zinciri özeti (Dalga 3) — bulgu+sömürü verisinden saldırı-zinciri anlatısı; komut yok.
    "ai_exploit_chain_btn": {"tr": "AI: sömürü zinciri", "en": "AI: exploit chain"},
    "ai_exploit_chain_label": {"tr": "AI Sömürü Zinciri", "en": "AI Exploit Chain"},
    "ai_chain_no_data": {
        "tr": "Zincirlenecek bulgu/sömürü verisi yok.",
        "en": "No findings or exploitation data to chain.",
    },
    "ai_remscript_btn": {"tr": "AI çözüm scripti", "en": "AI remediation script"},
    "ai_story_btn": {"tr": "AI risk hikâyesi", "en": "AI risk story"},
    # Tarama-trendi anlatısı (Dalga 3) — trend sayılarından yönetici özeti; komut/CVE üretmez.
    "ai_trend_btn": {"tr": "AI trend anlatısı", "en": "AI trend narrative"},
    "ai_trend_label": {"tr": "AI Trend Anlatısı", "en": "AI Trend Narrative"},
    "ai_trend_no_data": {
        "tr": "Trend için yeterli zafiyet verisi yok.",
        "en": "Not enough vulnerability data for a trend.",
    },
    # Uyum anlatısı (Dalga 3) — CIS + KVKK/ISO/PCI skorlarından yönetici özeti; skor üretmez.
    "ai_compliance_btn": {"tr": "AI uyum anlatısı", "en": "AI compliance narrative"},
    "ai_compliance_label": {"tr": "AI Uyum Anlatısı", "en": "AI Compliance Narrative"},
    "ai_compliance_no_data": {
        "tr": "Uyum anlatısı için kontrol verisi yok (kimlikli denetim gerekir).",
        "en": "No compliance check data for a narrative (a credentialed audit is required).",
    },
    "ai_no_findings": {
        "tr": "Özetlenecek bulgu yok.",
        "en": "No findings to summarize.",
    },
    # Saat dilimi (IX-1)
    "set_tz_section": {"tr": "Saat dilimi", "en": "Timezone"},
    "set_tz_sub": {
        "tr": "Tüm tarih/saat gösterimleri bu dilime çevrilir. Veriler UTC saklanır.",
        "en": "All date/time displays are shown in this timezone. Data is stored in UTC.",
    },
    "set_tz_label": {"tr": "Uygulama saat dilimi", "en": "Application timezone"},
    "set_tz_hint": {
        "tr": "Küresel kullanımda zamanların doğru görünmesi için yerel saat dilimini seçin.",
        "en": "Select the local timezone so times display correctly for global use.",
    },
    # User edit / MFA (admin-managed)
    "user_edit_title": {"tr": "Kullanıcı düzenle", "en": "Edit user"},
    "user_manage": {"tr": "Durum ve yönetim", "en": "Status & management"},
    "user_manage_sub": {
        "tr": "Hesabı pasifleştir/etkinleştir veya kalıcı olarak sil.",
        "en": "Deactivate/activate or permanently delete the account.",
    },
    "user_status_label": {"tr": "Hesap durumu", "en": "Account status"},
    "user_delete_confirm": {
        "tr": "Bu kullanıcı kalıcı olarak silinsin mi?",
        "en": "Permanently delete this user?",
    },
    "user_self_manage_note": {
        "tr": "Kendi hesabınızı pasifleştiremez veya silemezsiniz.",
        "en": "You cannot deactivate or delete your own account.",
    },
    "mfa_panel": {"tr": "MFA (çok adımlı doğrulama)", "en": "MFA"},
    "account_password_title": {"tr": "Parolam", "en": "My Password"},
    "account_password_sub": {
        "tr": "Hesap parolanızı buradan değiştirin.",
        "en": "Change your account password here.",
    },
    "account_password_ldap_note": {
        "tr": "Bu hesap dizin (LDAP) ile doğrulanır; parola dizin tarafında yönetilir.",
        "en": "This account authenticates via directory (LDAP); manage the password there.",
    },
    "current_password": {"tr": "Mevcut parola", "en": "Current password"},
    "new_password": {"tr": "Yeni parola", "en": "New password"},
    "new_password_confirm": {"tr": "Yeni parola (tekrar)", "en": "New password (again)"},
    "change_password": {"tr": "Parolayı değiştir", "en": "Change password"},
    "admin_reset_password": {"tr": "Parola sıfırla", "en": "Reset password"},
    "admin_reset_password_sub": {
        "tr": "Bu kullanıcı için yeni bir parola belirleyin (parola politikası uygulanır).",
        "en": "Set a new password for this user (password policy applies).",
    },
    "admin_reset_password_ldap": {
        "tr": "Dizin (LDAP) kullanıcısının parolası buradan değiştirilemez.",
        "en": "A directory (LDAP) user's password cannot be changed here.",
    },
    "reset_password": {"tr": "Parolayı sıfırla", "en": "Reset password"},
    "mfa_enabled_label": {"tr": "MFA etkin", "en": "MFA enabled"},
    "mfa_disabled_label": {"tr": "MFA kapalı", "en": "MFA disabled"},
    "mfa_setup_totp": {"tr": "TOTP kur (authenticator)", "en": "Set up TOTP"},
    "mfa_enable": {"tr": "Etkinleştir", "en": "Enable"},
    "mfa_remove": {"tr": "MFA'yı kaldır", "en": "Remove MFA"},
    "mfa_email_enable": {"tr": "E-posta OTP'yi aç", "en": "Enable email OTP"},
    "mfa_relay_qr": {
        "tr": "QR'ı çalışana iletin, sonra Etkinleştir'e basın.",
        "en": "Share the QR with the user, then click Enable.",
    },
    "mfa_need_email": {"tr": "Kullanıcının e-postası yok.", "en": "User has no email."},
    "mfa_need_smtp": {
        "tr": "SMTP yapılandırılmamış (Ayarlar).",
        "en": "SMTP not configured (Settings).",
    },
    "mfa_resend": {"tr": "Kodu tekrar gönder", "en": "Resend code"},
    "mfa_secret_label": {"tr": "Gizli anahtar", "en": "Secret key"},
    "mfa_code_label": {"tr": "6 haneli kod", "en": "6-digit code"},
    # Login MFA step
    "login_mfa_title": {"tr": "İkinci doğrulama", "en": "Second verification"},
    "login_mfa_totp_hint": {
        "tr": "Authenticator uygulamanızdaki 6 haneli kodu girin.",
        "en": "Enter the 6-digit code from your authenticator app.",
    },
    "login_mfa_email_hint": {
        "tr": "E-posta adresinize gönderilen 6 haneli kodu girin.",
        "en": "Enter the 6-digit code sent to your email.",
    },
    "login_mfa_verify": {"tr": "Doğrula", "en": "Verify"},
    "login_mfa_err": {"tr": "Kod hatalı. Tekrar deneyin.", "en": "Invalid code. Try again."},
}


def t(lang: str, key: str) -> str:
    """Anahtarı verilen dile çevirir; yoksa İngilizce'ye, o da yoksa anahtara düşer."""
    entry = DICT.get(key)
    if entry is None:
        return key
    return entry.get(lang) or entry.get("en") or key


def normalize_lang(value: str | None) -> str:
    return value if value in LANGS else DEFAULT_LANG


def translator(lang: str) -> Callable[[str], str]:
    """Belirli bir dile bağlı t() döndürür (şablon bağlamına enjekte edilir)."""
    return lambda key: t(lang, key)
