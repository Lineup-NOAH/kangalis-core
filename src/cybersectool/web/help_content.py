"""Uygulama-içi Yardım/Dokümanlar içeriği — TEK KAYNAK (öz + basit).

help.html bu bölümleri render eder. İleride (#2c) yerel AI Q&A ekranı AYNI içeriği
grounding/RAG bağlamı olarak kullanacak (fine-tune DEĞİL) → kullanıcı "bu uygulamada
X nasıl yapılır" sorduğunda AI buradan yanıtlar. Bu yüzden içerik yapısal + erişilebilir
tutulur. Teknik token'lar (CVE, nmap, IP, qwen3) çevrilmez.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HelpItem:
    """Tek bir soru/başlık + kısa yanıt (TR/EN) + opsiyonel komut/snippet (dil-bağımsız)."""

    q_tr: str
    q_en: str
    a_tr: str
    a_en: str
    code: str = ""

    def q(self, lang: str) -> str:
        return self.q_tr if lang == "tr" else self.q_en

    def a(self, lang: str) -> str:
        return self.a_tr if lang == "tr" else self.a_en


@dataclass(frozen=True)
class HelpSection:
    """İkon + başlık (TR/EN) + madde listesi."""

    id: str
    icon: str
    title_tr: str
    title_en: str
    items: tuple[HelpItem, ...]

    def title(self, lang: str) -> str:
        return self.title_tr if lang == "tr" else self.title_en


HELP_SECTIONS: tuple[HelpSection, ...] = (
    HelpSection(
        id="basics",
        icon="info",
        title_tr="Başlangıç",
        title_en="Getting started",
        items=(
            HelpItem(
                q_tr="Kangalis nedir?",
                q_en="What is Kangalis?",
                a_tr="İç ağınız için on-prem (yerel) bir zafiyet tarama platformu. "
                "Tüm tarama ve veriler kendi sunucunuzda kalır; dışarıya veri "
                "gönderilmez (sıfır egress).",
                a_en="An on-prem vulnerability scanning platform for your internal "
                "network. All scanning and data stay on your own server; nothing is "
                "sent outside (zero egress).",
            ),
        ),
    ),
    HelpSection(
        id="scanning",
        icon="scans",
        title_tr="Tarama",
        title_en="Scanning",
        items=(
            HelpItem(
                q_tr="Nasıl tarama başlatırım?",
                q_en="How do I start a scan?",
                a_tr="Taramalar sayfasında hedefi (IP, CIDR ya da URL) girip bir tarama "
                "modu seçin ve onaylayın. Canlı ilerleme yüzdesi ile bulunan port/CVE "
                "gösterilir.",
                a_en="On the Scans page, enter a target (IP, CIDR or URL), pick a scan "
                "mode and confirm. Live progress percentage with discovered ports/CVEs "
                "is shown.",
            ),
            HelpItem(
                q_tr="Hangi tarama modları var?",
                q_en="Which scan modes are there?",
                a_tr="Seçilebilen modlar: host keşfi (ping), ağ + port/servis, CVE "
                "taraması (güvenli ya da agresif) ve URL hedefte web denetimi (eksik "
                "güvenlik başlıkları/TLS). CVE taraması yerel veritabanından eşleşir, "
                "hedefi sömürmez; agresif kontroller 'kabul ediyorum' onayı ister. "
                "Ayrıca herhangi bir moda KİMLİK ekleyerek (opsiyonel) SSH/WinRM/DB ile "
                "derin denetim yapabilirsiniz — kimlik ayrı bir mod değildir.",
                a_en="Selectable modes: host discovery (ping), network + port/service, "
                "CVE scan (safe or aggressive) and a web check on URL targets (missing "
                "security headers/TLS). The CVE scan matches from the local DB and does "
                "not exploit the target; aggressive checks ask for an 'I accept' "
                "confirmation. You can also add CREDENTIALS (optional) to any mode for a "
                "deeper audit over SSH/WinRM/DB — credentials are not a separate mode.",
            ),
            HelpItem(
                q_tr="Tarama 'kapsam dışı' diyor / çalışmıyor.",
                q_en="Scan says 'out of scope' / does not run.",
                a_tr="Yetkili tarama kapsamı tanımlı olmalıdır (aşağıdaki Kapsam "
                "bölümüne bakın). Tarama motoru nmap'tir ve imaj derlemesinde otomatik "
                "kurulur; ayrıca kurmanız gerekmez.",
                a_en="An authorized scan scope must be defined (see the Scope section "
                "below). The scan engine is nmap, installed automatically during the "
                "image build; you do not need to install it separately.",
            ),
        ),
    ),
    HelpSection(
        id="scope",
        icon="shield",
        title_tr="Yetkili tarama kapsamı",
        title_en="Authorized scan scope",
        items=(
            HelpItem(
                q_tr="Tarama kapsamını nasıl ayarlarım?",
                q_en="How do I set the scan scope?",
                a_tr="Kurulum sihirbazı ilk yetkili kapsamı (izinli CIDR'ler) sorar. "
                "Eklemek ya da değiştirmek için (admin) sunucuda aşağıdaki komutu "
                "çalıştırın; yeni çağrı önceki kapsamı pasifleştirip yenisini "
                "etkinleştirir.",
                a_en="The setup wizard asks for the first authorized scope (allowed "
                "CIDRs). To add or change it (admin), run the command below on the "
                "server; a new call deactivates the previous scope and activates the "
                "new one.",
                code="docker compose exec app python -m "
                "cybersectool.scripts.set_scope --name ic-ag --allow 192.168.1.0/24",
            ),
            HelpItem(
                q_tr="Kapsam neden zorunlu?",
                q_en="Why is scope mandatory?",
                a_tr="Tüm tarama yüzeyleri bir kapsam koruyucusuyla korunur; yalnız "
                "taramaya YETKİLİ olduğunuz ağları girin. İzinsiz tarama birçok ülkede "
                "yasa dışıdır ve tüm sorumluluk operatöre aittir.",
                a_en="All scan surfaces are protected by a scope guard; enter only "
                "networks you are AUTHORIZED to scan. Unauthorized scanning is illegal "
                "in many countries and all responsibility lies with the operator.",
            ),
        ),
    ),
    HelpSection(
        id="vulndb",
        icon="shield",
        title_tr="Zafiyet veritabanı (NVD)",
        title_en="Vulnerability database (NVD)",
        items=(
            HelpItem(
                q_tr="CVE verisi nereden geliyor?",
                q_en="Where does CVE data come from?",
                a_tr="Uygulama CVE/CPE verisini NVD'den düzenli senkronla yerel bir "
                "indekse çeker (artı Exploit-DB metadata'sı); gigabaytlık gömülü bir "
                "veritabanı GÖNDERİLMEZ (bayatlamaması için). Durumu ve son senkronu "
                "Ayarlar > Zafiyet veritabanı'nda görürsünüz.",
                a_en="The app regularly syncs CVE/CPE data from NVD into a local index "
                "(plus Exploit-DB metadata); no gigabytes-large embedded database is "
                "shipped (so it never goes stale). See the status and last sync under "
                "Settings > Vulnerability database.",
            ),
            HelpItem(
                q_tr="NVD API anahtarı nasıl alınır?",
                q_en="How do I get an NVD API key?",
                a_tr="nvd.nist.gov üzerinden ÜCRETSİZ bir API anahtarı isteyin (e-posta "
                "ile gelir), sonra Ayarlar > Zafiyet veritabanı alanına girin. Anahtar "
                "rate-limit'i ciddi yükseltir → toplu/geçmiş CVE çekme çok daha hızlı "
                "olur. Opsiyoneldir ama önerilir.",
                a_en="Request a FREE API key at nvd.nist.gov (it arrives by email), then "
                "enter it under Settings > Vulnerability database. The key greatly "
                "raises the rate limit → bulk/historical CVE fetching is much faster. "
                "Optional but recommended.",
                code="https://nvd.nist.gov/developers/request-an-api-key",
            ),
        ),
    ),
    HelpSection(
        id="plugins",
        icon="plug",
        title_tr="Eklentiler & AI",
        title_en="Plugins & AI",
        items=(
            HelpItem(
                q_tr="Yerel AI'yı nasıl açarım?",
                q_en="How do I enable the local AI?",
                a_tr="Eklentiler sayfasından (admin). Önce AI konteynerini başlatıp "
                "modeli bir kez çekin (aşağıdaki komutlar), sonra Eklentiler > AI "
                "kartında endpoint + modeli girip 'Bağlantıyı test et'. CPU'da çalışır, "
                "sıfır egress. AI yalnız taslak/öneri HAZIRLAR; eylemi her zaman insan "
                "tetikler.",
                a_en="From the Plugins page (admin). First start the AI container and "
                "pull the model once (commands below), then on Plugins > AI enter the "
                "endpoint + model and click 'Test connection'. It runs on CPU, zero "
                "egress. The AI only PREPARES drafts/suggestions; a human always "
                "triggers the action.",
                code="docker compose --profile ai up -d ollama\n"
                "docker compose exec ollama ollama pull qwen3:8b",
            ),
            HelpItem(
                q_tr="Sömürü (exploit) eklentisi var mı?",
                q_en="Is there an exploitation plugin?",
                a_tr="Açık-kaynak çekirdek exploit ÇALIŞTIRMAZ; yalnız 'bu CVE için "
                "exploit var mı' sinyalini gösterir. Canlı sömürü, kendi kurduğunuz "
                "Metasploit/searchsploit'e bağlanan ayrı ticari kangalis-exploit "
                "eklentisindedir (yetki onayı + EULA ister).",
                a_en="The open-source core does NOT run exploits; it only shows the 'is "
                "there an exploit for this CVE' signal. Live exploitation lives in the "
                "separate commercial kangalis-exploit add-on that connects to your own "
                "Metasploit/searchsploit (requires authorization acknowledgement + EULA).",
            ),
        ),
    ),
)


def grounding_text(lang: str = "tr") -> str:
    """Yardım içeriğini düz metne çevirir — (ileride) AI Q&A grounding bağlamı için (#2c).

    Tek-kaynak ilkesi: ekranda görünen içerik ile AI'ya beslenen içerik AYNIDIR.
    """
    q_label, a_label = ("Soru", "Yanıt") if lang == "tr" else ("Q", "A")
    lines: list[str] = []
    for sec in HELP_SECTIONS:
        lines.append(f"## {sec.title(lang)}")
        for item in sec.items:
            lines.append(f"{q_label}: {item.q(lang)}")
            lines.append(f"{a_label}: {item.a(lang)}")
            if item.code:
                lines.append(item.code)
        lines.append("")
    return "\n".join(lines).strip()
