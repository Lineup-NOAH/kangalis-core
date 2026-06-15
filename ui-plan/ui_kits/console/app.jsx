/* Kangalis — app shell: login, sidebar, topbar, theme + i18n state, routing. */
(function () {
  const { useState, useEffect } = React;
  const S = window.KSCREENS;

  function applyTheme(theme) { document.documentElement.setAttribute('data-theme', theme); }

  /* ---- small round icon button (toggles) ---- */
  function IconBtn({ name, onClick, label, active }) {
    return React.createElement('button', { onClick, 'aria-label': label, title: label,
      className: `flex items-center justify-center rounded-[10px] border transition-colors h-10 w-10 ${active ? 'text-accent border-line bg-surface' : 'text-fg2 border-line hover:text-fg hover:bg-surface'}` },
      React.createElement(Icon, { name, size: 18 }));
  }

  /* ---- language toggle (TR / EN) ---- */
  function LangToggle({ lang, setLang }) {
    return React.createElement('div', { className: 'inline-flex items-center rounded-[10px] border border-line overflow-hidden h-10' },
      ['tr', 'en'].map(l => React.createElement('button', { key: l, onClick: () => setLang(l),
        className: `px-3 h-full text-[13px] font-semibold uppercase transition-colors ${lang === l ? 'text-[#1a1206]' : 'text-fg2 hover:text-fg'}`,
        style: lang === l ? { background: 'var(--accent)' } : {} }, l)));
  }

  /* ================= LOGIN ================= */
  function Login({ lang, setLang, theme, setTheme, onAuth }) {
    return React.createElement('div', { className: 'min-h-screen flex items-center justify-center p-4 relative overflow-hidden', style: { background: 'var(--bg)' } },
      React.createElement('div', { className: 'absolute inset-0 pointer-events-none', style: { background: 'radial-gradient(900px 500px at 50% -10%, var(--accent-weak), transparent 70%)' } }),
      React.createElement('div', { className: 'absolute inset-0 pointer-events-none', style: { backgroundImage: 'linear-gradient(var(--border) 1px, transparent 1px), linear-gradient(90deg, var(--border) 1px, transparent 1px)', backgroundSize: '46px 46px', opacity: 0.25, maskImage: 'radial-gradient(600px 400px at 50% 30%, black, transparent)' } }),
      React.createElement('div', { className: 'absolute top-5 right-5 flex items-center gap-2 z-10' },
        React.createElement(LangToggle, { lang, setLang }),
        React.createElement(IconBtn, { name: theme === 'dark' ? 'sun' : 'moon', onClick: () => setTheme(theme === 'dark' ? 'light' : 'dark'), label: 'Theme' })),
      React.createElement('div', { className: 'relative w-full max-w-[400px] bg-card border border-line rounded-2xl p-8 z-10', style: { boxShadow: 'var(--shadow-md)' } },
        React.createElement('div', { className: 'flex flex-col items-center text-center mb-7' },
          React.createElement('span', { className: 'text-accent mb-4' }, React.createElement(Logo, { size: 52, bg: 'var(--card)' })),
          React.createElement('div', { className: 'font-bold text-fg', style: { fontSize: 24, letterSpacing: '0.14em' } }, 'KANGALIS'),
          React.createElement('div', { className: 'text-fg2 text-[13px] mt-2' }, t(lang, 'tagline'))),
        React.createElement('form', { onSubmit: e => { e.preventDefault(); onAuth(); }, className: 'flex flex-col gap-4' },
          React.createElement(Field, { label: t(lang, 'login_user'), placeholder: 'm.demir', defaultValue: 'm.demir', autoComplete: 'off', name: 'k-user', readOnly: true, onFocus: e => e.target.removeAttribute('readonly') }),
          React.createElement(Field, { label: t(lang, 'login_pass'), type: 'password', defaultValue: 'password', autoComplete: 'new-password', name: 'k-pass', readOnly: true, onFocus: e => e.target.removeAttribute('readonly') }),
          React.createElement(Button, { type: 'submit', className: 'w-full justify-center mt-1', icon: 'lock' }, t(lang, 'login_signin'))),
        React.createElement('div', { className: 'text-center text-[12px] text-fg2 mt-6' }, t(lang, 'login_sub'))));
  }

  /* ================= SIDEBAR ================= */
  const NAV = [
    ['dashboard', 'nav_dashboard', 'dashboard'],
    ['scans', 'nav_scans', 'scans'],
    ['zones', 'nav_zones', 'zones'],
    ['vault', 'nav_vault', 'vault'],
    ['vuln', 'nav_vuln', 'vuln'],
    ['exploit', 'nav_exploit', 'exploit'],
    ['reports', 'nav_reports', 'reports'],
    ['audit', 'nav_audit', 'audit'],
  ];
  function Sidebar({ lang, route, setRoute, collapsed, onLogout }) {
    return React.createElement('aside', {
      className: `flex flex-col border-r border-line bg-card overflow-hidden`,
      style: { boxShadow: 'var(--shadow-sm)', flex: `0 0 ${collapsed ? 68 : 232}px`, minWidth: 0 } },
      React.createElement('div', { className: `flex items-center gap-2.5 h-16 border-b border-line ${collapsed ? 'justify-center px-0' : 'px-5'}` },
        React.createElement('span', { className: 'text-accent flex-none' }, React.createElement(Logo, { size: 30, bg: 'var(--card)' })),
        collapsed ? null : React.createElement('span', { className: 'font-bold text-fg', style: { fontSize: 17, letterSpacing: '0.14em' } }, 'KANGALIS')),
      React.createElement('nav', { className: 'flex-1 p-3 flex flex-col gap-1 overflow-y-auto' },
        NAV.map(([key, lbl, ic]) => {
          const active = route === key;
          return React.createElement('button', { key, onClick: () => setRoute(key), title: t(lang, lbl),
            className: `relative flex items-center gap-3 rounded-[10px] h-10 transition-colors ${collapsed ? 'justify-center px-0' : 'px-3'} ${active ? 'text-fg font-medium' : 'text-fg2 hover:text-fg hover:bg-surface'}`,
            style: active ? { background: 'var(--accent-weak)' } : {} },
            active ? React.createElement('span', { className: 'absolute left-0 top-1/2 -translate-y-1/2 rounded-r', style: { width: 3, height: 20, background: 'var(--accent)' } }) : null,
            React.createElement('span', { style: active ? { color: 'var(--accent)' } : {} }, React.createElement(Icon, { name: ic, size: 19 })),
            collapsed ? null : React.createElement('span', { className: 'text-[14px]' }, t(lang, lbl)));
        })),
      React.createElement('div', { className: 'p-3 border-t border-line' },
        React.createElement('button', { onClick: onLogout, title: t(lang, 'logout'),
          className: `flex items-center gap-3 rounded-[10px] h-10 w-full text-fg2 hover:text-fg hover:bg-surface transition-colors ${collapsed ? 'justify-center px-0' : 'px-3'}` },
          React.createElement(Icon, { name: 'logout', size: 19 }),
          collapsed ? null : React.createElement('span', { className: 'text-[14px]' }, t(lang, 'logout')))));
  }

  /* ================= TOPBAR ================= */
  function Topbar({ lang, setLang, theme, setTheme, onToggleSidebar }) {
    const [q, setQ] = useState('');
    return React.createElement('header', { className: 'flex items-center gap-3 h-16 px-5 border-b border-line flex-none sticky top-0 z-20',
      style: { background: 'color-mix(in srgb, var(--card) 88%, transparent)', backdropFilter: 'blur(8px)' } },
      React.createElement('button', { onClick: onToggleSidebar, 'aria-label': 'Toggle sidebar',
        className: 'flex items-center justify-center rounded-[10px] h-10 w-10 text-fg2 hover:text-fg hover:bg-surface transition-colors' },
        React.createElement(Icon, { name: 'panel', size: 18 })),
      React.createElement(SearchBox, { value: q, onChange: setQ, placeholder: t(lang, 'search_ph'), className: 'w-full max-w-md' }),
      React.createElement('div', { className: 'flex-1' }),
      React.createElement(LangToggle, { lang, setLang }),
      React.createElement(IconBtn, { name: theme === 'dark' ? 'sun' : 'moon', onClick: () => setTheme(theme === 'dark' ? 'light' : 'dark'), label: 'Theme' }),
      React.createElement('button', { className: 'relative flex items-center justify-center rounded-[10px] h-10 w-10 text-fg2 hover:text-fg hover:bg-surface transition-colors border border-line' },
        React.createElement(Icon, { name: 'bell', size: 18 }),
        React.createElement('span', { className: 'absolute top-2 right-2.5', style: { width: 6, height: 6, borderRadius: 99, background: 'var(--accent)' } })),
      React.createElement('div', { className: 'flex items-center gap-2.5 pl-2 ml-1 border-l border-line h-10' },
        React.createElement('span', { className: 'flex items-center justify-center rounded-full', style: { width: 34, height: 34, background: 'var(--accent-weak)', color: 'var(--accent)' } },
          React.createElement(Icon, { name: 'user', size: 18 })),
        React.createElement('div', { className: 'hidden sm:block leading-tight' },
          React.createElement('div', { className: 'text-[13px] font-medium text-fg' }, 'm.demir'),
          React.createElement('div', { className: 'text-[11px] text-fg2' }, t(lang, 'role_admin')))));
  }

  /* ================= APP ================= */
  function App() {
    const [theme, setThemeS] = useState(() => localStorage.getItem('k-theme') || 'dark');
    const [lang, setLangS] = useState(() => localStorage.getItem('k-lang') || 'tr');
    const [authed, setAuthed] = useState(false); // always start at login on a fresh load
    const [route, setRoute] = useState(() => localStorage.getItem('k-route') || 'dashboard');
    const [collapsed, setCollapsed] = useState(false);
    const [toast, setToast] = useState(null);

    useEffect(() => { applyTheme(theme); localStorage.setItem('k-theme', theme); }, [theme]);
    useEffect(() => { localStorage.setItem('k-lang', lang); document.documentElement.lang = lang; }, [lang]);
    useEffect(() => { localStorage.setItem('k-route', route); }, [route]);
    useEffect(() => {
      const onResize = () => setCollapsed(window.innerWidth < 1024);
      onResize(); window.addEventListener('resize', onResize); return () => window.removeEventListener('resize', onResize);
    }, []);

    const setTheme = setThemeS, setLang = setLangS;
    function notify(msg) { setToast(msg); clearTimeout(window.__kt); window.__kt = setTimeout(() => setToast(null), 2600); }

    if (!authed) return React.createElement(React.Fragment, null,
      React.createElement(Login, { lang, setLang, theme, setTheme, onAuth: () => setAuthed(true) }));

    const Screen = {
      dashboard: S.Dashboard, scans: S.Scans, zones: S.IPZones, vault: S.Vault,
      vuln: S.Vulnerabilities, exploit: S.ExploitDB, reports: S.Reports, audit: S.Audit,
    }[route] || S.Dashboard;

    return React.createElement('div', { className: 'flex h-screen overflow-hidden', style: { background: 'var(--bg)' } },
      React.createElement(Sidebar, { lang, route, setRoute, collapsed, onLogout: () => setAuthed(false) }),
      React.createElement('div', { className: 'flex flex-col flex-1 min-w-0' },
        React.createElement(Topbar, { lang, setLang, theme, setTheme, onToggleSidebar: () => setCollapsed(c => !c) }),
        React.createElement('main', { className: 'flex-1 overflow-y-auto', id: 'k-main' },
          React.createElement('div', { className: 'max-w-[1280px] mx-auto px-5 sm:px-8 py-7' },
            React.createElement(Screen, { lang, notify })))),
      React.createElement(Toast, { toast }));
  }

  ReactDOM.createRoot(document.getElementById('root')).render(React.createElement(App));
})();
