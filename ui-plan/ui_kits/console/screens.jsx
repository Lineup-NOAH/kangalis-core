/* Kangalis — screens. Reads globals: t, Icon, Logo, KDATA and all primitives. */
(function () {
  const { useState } = React;
  const D = window.KDATA;

  function PageHeader({ lang, title, subtitle, actions }) {
    return React.createElement('div', { className: 'flex items-end justify-between gap-4 mb-6 flex-wrap' },
      React.createElement('div', null,
        React.createElement('h1', { className: 'font-semibold text-fg', style: { fontSize: 26, lineHeight: 1.15 } }, title),
        subtitle ? React.createElement('p', { className: 'text-fg2 text-[14px] mt-1' }, subtitle) : null),
      actions ? React.createElement('div', { className: 'flex items-center gap-2' }, actions) : null);
  }
  function Chip({ children, mono = true }) {
    return React.createElement('span', { className: `inline-flex items-center rounded-md px-2 py-0.5 text-[12px] ${mono ? 'font-mono' : ''} bg-app border border-line text-fg2` }, children);
  }
  const Mono = ({ children, className = '' }) => React.createElement('span', { className: `font-mono text-fg ${className}` }, children);

  /* ============================ DASHBOARD ============================ */
  function Dashboard({ lang, notify }) {
    const top5 = [...D.vulns].sort((a, b) => b.cvss - a.cvss).slice(0, 5);
    return React.createElement('div', null,
      React.createElement(PageHeader, { lang, title: t(lang, 'nav_dashboard'), subtitle: t(lang, 'tagline'),
        actions: React.createElement(Button, { icon: 'plus', onClick: () => notify(t(lang, 'new_scan')) }, t(lang, 'new_scan')) }),
      React.createElement('div', { className: 'grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 mb-5' },
        React.createElement(StatCard, { icon: 'server',  label: t(lang, 'stat_assets'),  value: D.stats.assets }),
        React.createElement(StatCard, { icon: 'vuln',    label: t(lang, 'stat_open'),    value: D.stats.open, delta: { up: true, v: 12 } }),
        React.createElement(StatCard, { icon: 'scans',   label: t(lang, 'stat_scans'),   value: D.stats.scans }),
        React.createElement(StatCard, { icon: 'exploit', label: t(lang, 'stat_exploit'), value: D.stats.exploit })),
      React.createElement('div', { className: 'grid grid-cols-1 xl:grid-cols-5 gap-4 mb-5' },
        React.createElement(Card, { className: 'p-5 xl:col-span-2' },
          React.createElement(SectionLabel, { className: 'mb-4' }, t(lang, 'sev_dist')),
          React.createElement(Donut, { counts: D.sevCounts, lang })),
        React.createElement(Card, { className: 'p-5 xl:col-span-3' },
          React.createElement('div', { className: 'flex items-center justify-between mb-4' },
            React.createElement(SectionLabel, null, t(lang, 'top_risky')),
            React.createElement('button', { className: 'text-[12px] text-accent hover:underline font-medium' }, t(lang, 'view_all'))),
          React.createElement('div', { className: 'flex flex-col' },
            top5.map((v, i) => React.createElement('div', { key: v.cve, className: `flex items-center gap-3 py-2.5 ${i ? 'border-t border-line' : ''}` },
              React.createElement(CvssMeter, { score: v.cvss }),
              React.createElement('div', { className: 'min-w-0 flex-1' },
                React.createElement('div', { className: 'text-fg text-[13.5px] truncate font-medium' }, v.title),
                React.createElement('div', { className: 'text-fg2 text-[12px] font-mono' }, v.cve, ' · ', v.asset)),
              v.kev ? React.createElement(KevBadge, { lang, active: true }) : null,
              React.createElement(SeverityBadge, { sev: v.sev, lang }))))) ),
      React.createElement(Card, { className: 'p-5' },
        React.createElement('div', { className: 'flex items-center justify-between mb-4' },
          React.createElement(SectionLabel, null, t(lang, 'recent_scans')),
          React.createElement('span', { className: 'text-[12px] text-fg2' }, '2 ', t(lang, 'active_scans'))),
        React.createElement(ScansTable, { lang, rows: D.scans.slice(0, 4) })));
  }

  /* ============================ SCANS TABLE ============================ */
  function ScansTable({ lang, rows }) {
    const cols = [
      { label: t(lang, 'h_id') }, { label: t(lang, 'target') }, { label: t(lang, 'type') },
      { label: t(lang, 'h_progress') }, { label: t(lang, 'h_started') }, { label: t(lang, 'h_status'), align: 'right' },
    ];
    return React.createElement(DataTable, { columns: cols, rows, render: (r) => [
      React.createElement('td', { key: 'id', className: 'px-4 py-3 font-mono text-[13px] text-fg2' }, r.id),
      React.createElement('td', { key: 'tg', className: 'px-4 py-3' }, React.createElement(Mono, { className: 'text-[13px]' }, r.target)),
      React.createElement('td', { key: 'ty', className: 'px-4 py-3 text-fg2 text-[13px]' }, t(lang, r.type)),
      React.createElement('td', { key: 'pr', className: 'px-4 py-3' },
        React.createElement('div', { className: 'flex items-center gap-2' },
          React.createElement('div', { className: 'rounded-full overflow-hidden', style: { width: 90, height: 6, background: 'var(--bg2)' } },
            React.createElement('div', { style: { width: r.pct + '%', height: '100%', background: r.status === 'failed' ? '#EF4444' : 'var(--accent)', borderRadius: 99 } })),
          React.createElement('span', { className: 'font-mono text-[12px] text-fg2 tabular-nums' }, r.pct + '%'))),
      React.createElement('td', { key: 'sd', className: 'px-4 py-3 font-mono text-[13px] text-fg2' }, r.started),
      React.createElement('td', { key: 'st', className: 'px-4 py-3 text-right' }, React.createElement(StatusPill, { status: r.status, lang })),
    ] });
  }

  /* ============================ VULNERABILITIES ============================ */
  function Vulnerabilities({ lang }) {
    const [q, setQ] = useState('');
    const [sev, setSev] = useState('all');
    const filters = [
      { value: 'all', label: t(lang, 'all_sources').replace(t(lang, 'h_source'), '').trim() || 'All' },
    ];
    const sevOpts = [
      { value: 'all', label: 'All' },
      { value: 'critical', label: t(lang, 'sev_critical') },
      { value: 'high', label: t(lang, 'sev_high') },
      { value: 'medium', label: t(lang, 'sev_medium') },
      { value: 'low', label: t(lang, 'sev_low') },
    ];
    let rows = [...D.vulns].sort((a, b) => b.cvss - a.cvss);
    if (sev !== 'all') rows = rows.filter(r => r.sev === sev);
    if (q) rows = rows.filter(r => (r.cve + r.title + r.asset).toLowerCase().includes(q.toLowerCase()));
    const cols = [
      { label: t(lang, 'h_cve') }, { label: t(lang, 'h_title') }, { label: t(lang, 'h_cvss') },
      { label: t(lang, 'h_severity') }, { label: 'KEV' }, { label: 'EPSS' }, { label: t(lang, 'h_asset') },
    ];
    return React.createElement('div', null,
      React.createElement(PageHeader, { lang, title: t(lang, 'nav_vuln'), subtitle: rows.length + ' / ' + D.vulns.length }),
      React.createElement('div', { className: 'flex items-center gap-3 mb-4 flex-wrap' },
        React.createElement(SearchBox, { value: q, onChange: setQ, placeholder: t(lang, 'search_ph'), className: 'w-full sm:w-80' }),
        React.createElement(Segmented, { options: sevOpts, value: sev, onChange: setSev })),
      rows.length === 0
        ? React.createElement(Card, { className: 'p-0' }, React.createElement(EmptyState, { title: t(lang, 'empty_title'), body: t(lang, 'empty_body') }))
        : React.createElement(DataTable, { columns: cols, rows, render: (r) => [
            React.createElement('td', { key: 'c', className: 'px-4 py-3 whitespace-nowrap' },
              React.createElement('a', { href: '#', className: 'font-mono text-[13px] text-steel hover:underline' }, r.cve)),
            React.createElement('td', { key: 't', className: 'px-4 py-3 text-fg text-[13.5px] max-w-sm' }, React.createElement('span', { className: 'line-clamp-1' }, r.title)),
            React.createElement('td', { key: 'v', className: 'px-4 py-3' }, React.createElement(CvssMeter, { score: r.cvss })),
            React.createElement('td', { key: 's', className: 'px-4 py-3' }, React.createElement(SeverityBadge, { sev: r.sev, lang })),
            React.createElement('td', { key: 'k', className: 'px-4 py-3' }, React.createElement(KevBadge, { lang, active: r.kev })),
            React.createElement('td', { key: 'e', className: 'px-4 py-3' }, React.createElement(EpssGauge, { value: r.epss, lang })),
            React.createElement('td', { key: 'a', className: 'px-4 py-3' },
              React.createElement('div', { className: 'font-mono text-[12.5px] text-fg' }, r.asset),
              React.createElement('div', { className: 'font-mono text-[11.5px] text-fg2' }, r.svc)),
          ] }));
  }

  /* ============================ EXPLOIT DB ============================ */
  function ExploitDB({ lang, notify }) {
    const [q, setQ] = useState('');
    const [src, setSrc] = useState('all');
    const [modal, setModal] = useState(false);
    const c = D.exploitCounts;
    const srcOpts = [
      { value: 'all', label: t(lang, 'all_sources') },
      { value: 'NVD', label: 'NVD' }, { value: 'Exploit-DB', label: 'Exploit-DB' }, { value: 'Metasploit', label: 'Metasploit' },
    ];
    let rows = D.exploits;
    if (src !== 'all') rows = rows.filter(r => r.src === src);
    if (q) rows = rows.filter(r => (r.id + r.title + r.cves.join()).toLowerCase().includes(q.toLowerCase()));
    const cols = [
      { label: t(lang, 'h_source') }, { label: t(lang, 'h_id') }, { label: t(lang, 'h_title') }, { label: 'CVE' },
    ];
    return React.createElement('div', null,
      React.createElement(PageHeader, { lang, title: t(lang, 'nav_exploit'),
        actions: React.createElement(Button, { icon: 'refresh', onClick: () => setModal(true) }, t(lang, 'update_db')) }),
      React.createElement('div', { className: 'grid grid-cols-2 lg:grid-cols-4 gap-4 mb-5' },
        [['total', c.total, 'exploit'], ['NVD', c.NVD, 'reports'], ['Exploit-DB', c['Exploit-DB'], 'flame'], ['Metasploit', c.Metasploit, 'target']]
          .map(([k, v, ic]) => React.createElement(Card, { key: k, className: 'p-5' },
            React.createElement('div', { className: 'flex items-center gap-2 text-fg2' },
              React.createElement(Icon, { name: ic, size: 16 }),
              React.createElement('span', { className: 'text-[12px] uppercase font-semibold', style: { letterSpacing: '0.05em' } }, k === 'total' ? t(lang, 'total') : k)),
            React.createElement('div', { className: 'k-stat text-fg mt-3', style: { fontSize: 28 } }, v.toLocaleString())))),
      React.createElement('div', { className: 'flex items-center gap-3 mb-4 flex-wrap' },
        React.createElement(SearchBox, { value: q, onChange: setQ, placeholder: t(lang, 'search_ph'), className: 'w-full sm:w-80' }),
        React.createElement(Segmented, { options: srcOpts, value: src, onChange: setSrc, size: 'sm' })),
      rows.length === 0
        ? React.createElement(Card, { className: 'p-0' }, React.createElement(EmptyState, { title: t(lang, 'empty_title'), body: t(lang, 'empty_body') }))
        : React.createElement(DataTable, { columns: cols, rows, render: (r) => [
            React.createElement('td', { key: 's', className: 'px-4 py-3' }, React.createElement(SourceBadge, { src: r.src })),
            React.createElement('td', { key: 'i', className: 'px-4 py-3 whitespace-nowrap' },
              React.createElement('a', { href: '#', className: 'inline-flex items-center gap-1 font-mono text-[13px] text-steel hover:underline' },
                r.id, React.createElement(Icon, { name: 'external', size: 12 }))),
            React.createElement('td', { key: 't', className: 'px-4 py-3 text-fg text-[13.5px]' }, r.title),
            React.createElement('td', { key: 'c', className: 'px-4 py-3' },
              React.createElement('div', { className: 'flex flex-wrap gap-1' }, r.cves.map(cv => React.createElement(Chip, { key: cv }, cv)))),
          ] }),
      React.createElement(Modal, { open: modal, onClose: () => setModal(false), title: t(lang, 'update_db_q'),
        footer: [
          React.createElement(Button, { key: 'c', variant: 'ghost', onClick: () => setModal(false) }, t(lang, 'cancel')),
          React.createElement(Button, { key: 'o', icon: 'refresh', onClick: () => { setModal(false); notify(t(lang, 'db_updated')); } }, t(lang, 'update_db')),
        ] }, t(lang, 'update_db_body')));
  }

  /* ============================ SCANS ============================ */
  function Scans({ lang, notify }) {
    const [type, setType] = useState('t_network');
    const [intensity, setIntensity] = useState('safe');
    const [zoneIntensity, setZoneIntensity] = useState('safe');
    return React.createElement('div', null,
      React.createElement(PageHeader, { lang, title: t(lang, 'nav_scans') }),
      React.createElement('div', { className: 'grid grid-cols-1 lg:grid-cols-2 gap-4 mb-5' },
        React.createElement(Card, { className: 'p-5' },
          React.createElement('div', { className: 'flex items-center gap-2 mb-4' },
            React.createElement('span', { className: 'text-accent' }, React.createElement(Icon, { name: 'plus', size: 18 })),
            React.createElement('h3', { className: 'font-semibold text-fg text-[15px]' }, t(lang, 'new_scan'))),
          React.createElement('div', { className: 'flex flex-col gap-4' },
            React.createElement(Field, { label: t(lang, 'target') + ' (IP / CIDR)', placeholder: '10.20.4.0/24', mono: true, defaultValue: '10.20.4.0/24' }),
            React.createElement('div', null,
              React.createElement('div', { className: 'text-[13px] font-medium text-fg2 mb-1.5' }, t(lang, 'type')),
              React.createElement(Segmented, { options: [{ value: 't_network', label: t(lang, 't_network') }, { value: 't_web', label: t(lang, 't_web') }], value: type, onChange: setType })),
            React.createElement('div', null,
              React.createElement('div', { className: 'text-[13px] font-medium text-fg2 mb-1.5' }, t(lang, 'intensity')),
              React.createElement(Segmented, { options: [{ value: 'safe', label: t(lang, 'safe') }, { value: 'aggressive', label: t(lang, 'aggressive') }], value: intensity, onChange: setIntensity })),
            intensity === 'aggressive' ? React.createElement(DangerBox, { title: t(lang, 'danger_title'), body: t(lang, 'danger_body') }) : null,
            React.createElement('div', { className: 'flex justify-end pt-1' },
              React.createElement(Button, { icon: 'play', onClick: () => notify(t(lang, 'run') + ' · ' + t(lang, 'st_running')) }, t(lang, 'run'))))),
        React.createElement(Card, { className: 'p-5' },
          React.createElement('div', { className: 'flex items-center gap-2 mb-4' },
            React.createElement('span', { className: 'text-accent' }, React.createElement(Icon, { name: 'zones', size: 18 })),
            React.createElement('h3', { className: 'font-semibold text-fg text-[15px]' }, t(lang, 'zone_scan'))),
          React.createElement('div', { className: 'flex flex-col gap-4' },
            React.createElement('label', { className: 'block' },
              React.createElement('div', { className: 'text-[13px] font-medium text-fg2 mb-1.5' }, t(lang, 'nav_zones')),
              React.createElement('select', { className: 'w-full h-10 px-3 rounded-[10px] bg-app border border-line text-fg text-[14px] focus:outline-none focus:border-accent' },
                D.zones.map(z => React.createElement('option', { key: z.name }, z.name)))),
            React.createElement('div', null,
              React.createElement('div', { className: 'text-[13px] font-medium text-fg2 mb-1.5' }, t(lang, 'type')),
              React.createElement(Segmented, { options: [{ value: 'safe', label: t(lang, 'safe') }, { value: 'aggressive', label: t(lang, 'aggressive') }, { value: 'credentialed', label: t(lang, 'credentialed') }], value: zoneIntensity, onChange: setZoneIntensity })),
            zoneIntensity === 'aggressive' ? React.createElement(DangerBox, { title: t(lang, 'danger_title'), body: t(lang, 'danger_body') }) : null,
            zoneIntensity === 'credentialed' ? React.createElement('div', { className: 'flex items-center gap-2 text-[13px] text-fg2 rounded-xl px-3 py-2.5', style: { background: 'var(--accent-weak)' } },
              React.createElement('span', { className: 'text-accent' }, React.createElement(Icon, { name: 'vault', size: 16 })), t(lang, 'cred_enc')) : null,
            React.createElement('div', { className: 'flex justify-end pt-1' },
              React.createElement(Button, { icon: 'play', onClick: () => notify(t(lang, 'zone_scan')) }, t(lang, 'run'))))) ),
      React.createElement(Card, { className: 'p-5' },
        React.createElement(SectionLabel, { className: 'mb-4' }, t(lang, 'recent_scans')),
        React.createElement(ScansTable, { lang, rows: D.scans })));
  }

  /* ============================ IP ZONES ============================ */
  function IPZones({ lang, notify }) {
    return React.createElement('div', null,
      React.createElement(PageHeader, { lang, title: t(lang, 'nav_zones'),
        actions: React.createElement(Button, { icon: 'plus', onClick: () => notify(t(lang, 'new_zone')) }, t(lang, 'new_zone')) }),
      React.createElement('div', { className: 'grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4' },
        D.zones.map(z => React.createElement(Card, { key: z.name, className: 'p-5' },
          React.createElement('div', { className: 'flex items-center justify-between mb-3' },
            React.createElement('div', { className: 'flex items-center gap-2.5' },
              React.createElement('span', { className: 'flex items-center justify-center rounded-[10px]', style: { width: 34, height: 34, background: 'var(--accent-weak)', color: 'var(--accent)' } },
                React.createElement(Icon, { name: 'zones', size: 17 })),
              React.createElement('h3', { className: 'font-semibold text-fg text-[15px]' }, z.name)),
            React.createElement('span', { className: 'font-mono text-[12px] text-fg2' }, z.hosts, ' ', t(lang, 'zone_hosts'))),
          React.createElement('div', { className: 'flex flex-wrap gap-1.5' },
            z.cidrs.map(c => React.createElement(Chip, { key: c }, c))))),
        React.createElement(Card, { className: 'p-5 border-dashed flex flex-col gap-3 justify-center' },
          React.createElement('div', { className: 'text-[13px] font-medium text-fg2' }, t(lang, 'new_zone')),
          React.createElement('input', { placeholder: t(lang, 'zone_name'), className: 'w-full h-10 px-3 rounded-[10px] bg-app border border-line text-fg text-[14px] placeholder:text-fg2 focus:outline-none focus:border-accent' }),
          React.createElement('input', { placeholder: '10.20.0.0/24', className: 'w-full h-10 px-3 rounded-[10px] bg-app border border-line text-fg text-[14px] font-mono placeholder:text-fg2 focus:outline-none focus:border-accent' }),
          React.createElement(Button, { variant: 'ghost', icon: 'plus', onClick: () => notify(t(lang, 'new_zone')) }, t(lang, 'add_cidr')))));
  }

  /* ============================ CREDENTIAL VAULT ============================ */
  function Vault({ lang, notify }) {
    const TB = { SSH: '#1F9D6B', WinRM: '#3B82F6', RDP: '#E0A458' };
    return React.createElement('div', null,
      React.createElement(PageHeader, { lang, title: t(lang, 'nav_vault'),
        actions: React.createElement(Button, { icon: 'plus', onClick: () => notify(t(lang, 'add_cred')) }, t(lang, 'add_cred')) }),
      React.createElement('div', { className: 'flex items-center gap-2 text-[13px] text-fg2 rounded-xl px-4 py-3 mb-5', style: { background: 'var(--accent-weak)', border: '1px solid var(--accent-line)' } },
        React.createElement('span', { className: 'text-accent' }, React.createElement(Icon, { name: 'lock', size: 16 })),
        React.createElement('span', { className: 'text-fg font-medium' }, t(lang, 'cred_enc'))),
      React.createElement('div', { className: 'grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4' },
        D.creds.map((cr, i) => React.createElement(Card, { key: i, className: 'p-5' },
          React.createElement('div', { className: 'flex items-center justify-between mb-3' },
            React.createElement('div', { className: 'flex items-center gap-2.5 min-w-0' },
              React.createElement('span', { className: 'flex items-center justify-center rounded-full flex-none', style: { width: 34, height: 34, background: 'var(--bg2)', color: 'var(--fg2)' } },
                React.createElement(Icon, { name: 'user', size: 17 })),
              React.createElement('span', { className: 'font-mono text-[14px] text-fg truncate' }, cr.user)),
            React.createElement('span', { className: 'inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[11px] font-semibold font-mono', style: { color: TB[cr.type], background: window.hexA(TB[cr.type], 0.12), border: `1px solid ${window.hexA(TB[cr.type], 0.28)}` } }, cr.type, ' ', cr.port)),
          React.createElement('div', { className: 'flex items-center justify-between rounded-[10px] bg-app border border-line px-3 py-2' },
            React.createElement(MaskedPassword, null),
            React.createElement('span', { className: 'text-[11px] text-fg2 font-mono' }, cr.zone))))));
  }

  /* ============================ REPORTS ============================ */
  function Reports({ lang, notify }) {
    const bars = ['critical', 'high', 'medium', 'low', 'info'].map(k => ({ label: t(lang, 'sev_' + k), value: D.sevCounts[k], color: window.KSEV[k] }));
    const top = [...D.vulns].sort((a, b) => b.cvss - a.cvss).slice(0, 8);
    return React.createElement('div', null,
      React.createElement(PageHeader, { lang, title: t(lang, 'nav_reports'),
        actions: [
          React.createElement(Button, { key: 'e', variant: 'ghost', icon: 'download', onClick: () => notify(t(lang, 'export')) }, t(lang, 'export')),
          React.createElement(Button, { key: 'p', icon: 'reports', onClick: () => window.print() }, t(lang, 'print')),
        ] }),
      React.createElement(Card, { className: 'p-6' },
        React.createElement('div', { className: 'flex items-start justify-between border-b border-line pb-5 mb-5' },
          React.createElement('div', { className: 'flex items-center gap-3' },
            React.createElement('span', { className: 'text-accent' }, React.createElement(Logo, { size: 34, bg: 'var(--card)' })),
            React.createElement('div', null,
              React.createElement('div', { className: 'font-semibold text-fg text-[18px]' }, t(lang, 'report_title')),
              React.createElement('div', { className: 'text-fg2 text-[13px]' }, t(lang, 'report_period'), ': 2026-05 · KANGALIS'))),
          React.createElement('div', { className: 'text-right font-mono text-[12px] text-fg2' }, 'R-2026-22')),
        React.createElement('div', { className: 'grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6' },
          [['stat_assets', D.stats.assets], ['stat_open', D.stats.open], ['nav_scans', 128], ['kev', 9]].map(([k, v]) =>
            React.createElement('div', { key: k, className: 'rounded-xl bg-app border border-line p-4' },
              React.createElement('div', { className: 'k-stat text-fg', style: { fontSize: 24 } }, v.toLocaleString()),
              React.createElement('div', { className: 'text-fg2 text-[12px] mt-1' }, t(lang, k))))),
        React.createElement(SectionLabel, { className: 'mb-3' }, t(lang, 'sev_dist')),
        React.createElement('div', { className: 'mb-6 max-w-lg' }, React.createElement(BarChart, { data: bars })),
        React.createElement(SectionLabel, { className: 'mb-3' }, t(lang, 'findings')),
        React.createElement('div', { className: 'flex flex-col' },
          top.map((v, i) => React.createElement('div', { key: v.cve, className: `flex items-center gap-3 py-2 ${i ? 'border-t border-line' : ''}` },
            React.createElement('span', { className: 'font-mono text-[13px] text-steel w-32' }, v.cve),
            React.createElement('span', { className: 'flex-1 text-fg text-[13px] truncate' }, v.title),
            React.createElement(CvssMeter, { score: v.cvss }),
            React.createElement(SeverityBadge, { sev: v.sev, lang }))))));
  }

  /* ============================ AUDIT ============================ */
  function Audit({ lang }) {
    const cols = [{ label: t(lang, 'h_when') }, { label: t(lang, 'h_actor') }, { label: t(lang, 'h_action') }];
    return React.createElement('div', null,
      React.createElement(PageHeader, { lang, title: t(lang, 'nav_audit'),
        actions: React.createElement('span', { className: 'inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[12px] font-semibold', style: { color: 'var(--accent)', background: 'var(--accent-weak)', border: '1px solid var(--accent-line)' } },
          React.createElement(Icon, { name: 'lock', size: 13 }), t(lang, 'audit_only')) }),
      React.createElement(DataTable, { columns: cols, rows: D.audit, render: (r) => [
        React.createElement('td', { key: 'w', className: 'px-4 py-3 font-mono text-[13px] text-fg2 whitespace-nowrap' }, r.when),
        React.createElement('td', { key: 'a', className: 'px-4 py-3' },
          React.createElement('div', { className: 'flex items-center gap-2' },
            React.createElement('span', { className: 'font-mono text-[13px] text-fg' }, r.actor),
            React.createElement('span', { className: 'text-[11px] text-fg2' }, '· ', t(lang, r.role)))),
        React.createElement('td', { key: 'x', className: 'px-4 py-3 text-fg text-[13px]' }, r.action),
      ] }));
  }

  window.KSCREENS = { Dashboard, Vulnerabilities, ExploitDB, Scans, IPZones, Vault, Reports, Audit };
})();
