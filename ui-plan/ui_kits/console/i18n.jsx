/* Kangalis — i18n dictionary. Default language: Turkish ('tr').
   t(lang, key) returns the string; technical tokens are never translated. */
(function () {
  const DICT = {
    // Brand
    tagline:        { tr: 'İç ağınızın bekçisi.',            en: 'The guardian of your internal network.' },

    // Nav
    nav_dashboard:  { tr: 'Panel',                en: 'Dashboard' },
    nav_scans:      { tr: 'Taramalar',            en: 'Scans' },
    nav_zones:      { tr: 'IP Zone',              en: 'IP Zones' },
    nav_vault:      { tr: 'Kimlik Kasası',        en: 'Credential Vault' },
    nav_vuln:       { tr: 'Zafiyetler',           en: 'Vulnerabilities' },
    nav_exploit:    { tr: 'Zafiyet & Exploit DB', en: 'Exploit DB' },
    nav_reports:    { tr: 'Rapor',                en: 'Reports' },
    nav_audit:      { tr: 'Denetim',              en: 'Audit' },
    logout:         { tr: 'Çıkış',                en: 'Logout' },

    // Topbar
    search_ph:      { tr: 'Ara: CVE, IP, varlık…',  en: 'Search CVE, IP, asset…' },
    role_admin:     { tr: 'Yönetici',             en: 'Admin' },
    role_analyst:   { tr: 'Analist',              en: 'Analyst' },

    // Login
    login_user:     { tr: 'Kullanıcı adı',        en: 'Username' },
    login_pass:     { tr: 'Parola',               en: 'Password' },
    login_signin:   { tr: 'Giriş',                en: 'Sign in' },
    login_sub:      { tr: 'Güvenli operasyon konsolu', en: 'Secure operations console' },

    // Generic
    new_scan:       { tr: 'Yeni Tarama',          en: 'New Scan' },
    new_zone:       { tr: 'Yeni Zone',            en: 'New Zone' },
    add_cred:       { tr: 'Kimlik Ekle',          en: 'Add Credential' },
    run:            { tr: 'Çalıştır',             en: 'Run' },
    cancel:         { tr: 'Vazgeç',               en: 'Cancel' },
    confirm:        { tr: 'Onayla',               en: 'Confirm' },
    save:           { tr: 'Kaydet',               en: 'Save' },
    view_all:       { tr: 'Tümünü gör',           en: 'View all' },
    export:         { tr: 'Dışa aktar',           en: 'Export' },
    print:          { tr: 'Yazdır',               en: 'Print' },

    // Scan form
    target:         { tr: 'Hedef',                en: 'Target' },
    type:           { tr: 'Tür',                  en: 'Type' },
    intensity:      { tr: 'Yoğunluk',             en: 'Intensity' },
    safe:           { tr: 'Güvenli',              en: 'Safe' },
    aggressive:     { tr: 'Agresif',              en: 'Aggressive' },
    credentialed:   { tr: 'Kimlikli',             en: 'Credentialed' },
    t_network:      { tr: 'Ağ',                   en: 'Network' },
    t_web:          { tr: 'Web',                  en: 'Web' },
    zone_scan:      { tr: 'IP Zone Taraması',     en: 'IP Zone Scan' },
    select_zone:    { tr: 'Zone seçin',           en: 'Select zone' },

    // Danger box
    danger_title:   { tr: 'Agresif tarama uyarısı', en: 'Aggressive scan warning' },
    danger_body:    { tr: 'Agresif taramalar üretim servislerini kesintiye uğratabilir ve IDS/IPS tetikleyebilir.', en: 'Aggressive scans may disrupt production services and trip IDS/IPS.' },

    // Stat cards
    stat_assets:    { tr: 'Varlık',               en: 'Assets' },
    stat_open:      { tr: 'Açık Zafiyet',         en: 'Open Vulnerabilities' },
    stat_scans:     { tr: 'Tarama',               en: 'Scans' },
    stat_exploit:   { tr: 'Exploit Kaydı',        en: 'Exploit-DB Entries' },

    // Dashboard sections
    sev_dist:       { tr: 'Önem Dağılımı',        en: 'Severity Distribution' },
    recent_scans:   { tr: 'Son Taramalar',        en: 'Recent Scans' },
    top_risky:      { tr: 'En Riskli 5 Bulgu',    en: 'Top 5 Riskiest Findings' },
    active_scans:   { tr: 'aktif tarama',         en: 'active scans' },

    // Table headers
    h_cve:          { tr: 'CVE-ID',               en: 'CVE-ID' },
    h_title:        { tr: 'Başlık',               en: 'Title' },
    h_cvss:         { tr: 'CVSS',                 en: 'CVSS' },
    h_severity:     { tr: 'Önem',                 en: 'Severity' },
    h_asset:        { tr: 'Varlık / Servis',      en: 'Asset / Service' },
    h_status:       { tr: 'Durum',                en: 'Status' },
    h_progress:     { tr: 'İlerleme',             en: 'Progress' },
    h_started:      { tr: 'Başlangıç',            en: 'Started' },
    h_source:       { tr: 'Kaynak',               en: 'Source' },
    h_id:           { tr: 'ID',                   en: 'ID' },
    h_when:         { tr: 'Zaman',                en: 'When' },
    h_actor:        { tr: 'Kullanıcı',            en: 'User' },
    h_action:       { tr: 'İşlem',                en: 'Action' },
    h_user:         { tr: 'Kullanıcı',            en: 'User' },
    h_port:         { tr: 'Port',                 en: 'Port' },
    h_zone:         { tr: 'Zone',                 en: 'Zone' },
    h_cidr:         { tr: 'CIDR',                 en: 'CIDR' },

    // Severity
    sev_critical:   { tr: 'Kritik',               en: 'Critical' },
    sev_high:       { tr: 'Yüksek',               en: 'High' },
    sev_medium:     { tr: 'Orta',                 en: 'Medium' },
    sev_low:        { tr: 'Düşük',                en: 'Low' },
    sev_info:       { tr: 'Bilgi',                en: 'Info' },

    // Status
    st_pending:     { tr: 'Beklemede',            en: 'Pending' },
    st_running:     { tr: 'Çalışıyor',            en: 'Running' },
    st_completed:   { tr: 'Tamamlandı',           en: 'Completed' },
    st_failed:      { tr: 'Başarısız',            en: 'Failed' },

    // Vuln indicators
    kev:            { tr: 'KEV',                  en: 'KEV' },
    kev_full:       { tr: 'Aktif istismar ediliyor', en: 'Actively exploited' },
    epss:           { tr: 'EPSS',                 en: 'EPSS' },
    epss_full:      { tr: 'İstismar olasılığı',   en: 'Exploit probability' },

    // Exploit DB
    total:          { tr: 'Toplam',               en: 'Total' },
    update_db:      { tr: 'Veritabanını Güncelle', en: 'Update Database' },
    update_db_q:    { tr: 'Veritabanı güncellensin mi?', en: 'Update the database?' },
    update_db_body: { tr: 'NVD, Exploit-DB ve Metasploit kaynaklarından en son kayıtlar indirilecek. Bu işlem birkaç dakika sürebilir.', en: 'The latest entries will be pulled from NVD, Exploit-DB and Metasploit. This may take a few minutes.' },
    all_sources:    { tr: 'Tüm kaynaklar',        en: 'All sources' },
    db_updated:     { tr: 'Veritabanı güncellendi', en: 'Database updated' },

    // Credential vault
    cred_enc:       { tr: 'Parolalar şifreli saklanır', en: 'Passwords are stored encrypted' },
    cred_zones:     { tr: 'Kimlik Zone\'ları',    en: 'Credential Zones' },

    // IP Zones
    zone_hosts:     { tr: 'host',                 en: 'hosts' },
    zone_name:      { tr: 'Zone adı',             en: 'Zone name' },
    add_cidr:       { tr: 'CIDR ekle',            en: 'Add CIDR' },

    // Reports
    report_title:   { tr: 'Operasyon Özeti',      en: 'Operations Summary' },
    report_period:  { tr: 'Dönem',                en: 'Period' },
    findings:       { tr: 'Bulgular',             en: 'Findings' },

    // Empty
    empty_title:    { tr: 'Kayıt yok',            en: 'Nothing here yet' },
    empty_body:     { tr: 'Bu görünümde gösterilecek veri bulunamadı.', en: 'No data to show in this view.' },

    // Audit
    audit_only:     { tr: 'Yalnızca yönetici',    en: 'Admin only' },
  };

  function t(lang, key) {
    const e = DICT[key];
    if (!e) return key;
    return e[lang] || e.en || key;
  }
  window.KDICT = DICT;
  window.t = t;
})();
