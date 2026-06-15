/* Kangalis — UI primitives. Tailwind classes + CSS-var tokens.
   Severity colors are constant hex (see colors_and_type.css). */
(function () {
  const SEV = {
    critical: '#EF4444', high: '#F97316', medium: '#F59E0B', low: '#3B82F6', info: '#64748B',
  };
  const SRC = {
    'NVD':        { color: '#3B82F6', short: 'NVD' },
    'Exploit-DB': { color: '#E0A458', short: 'EDB' },
    'Metasploit': { color: '#EF4444', short: 'MSF' },
  };
  function hexA(hex, a) {
    const n = parseInt(hex.slice(1), 16);
    return `rgba(${(n>>16)&255},${(n>>8)&255},${n&255},${a})`;
  }

  /* ---- Buttons ---- */
  function Button({ variant = 'primary', icon, children, className = '', ...rest }) {
    const base = 'inline-flex items-center gap-2 font-medium rounded-[10px] px-4 h-10 text-[14px] transition-colors select-none disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-app';
    const styles = {
      primary: { className: 'text-[#1a1206] hover:brightness-105 active:brightness-95', style: { background: 'var(--accent)' } },
      ghost:   { className: 'text-fg border border-line bg-transparent hover:bg-surface', style: {} },
      subtle:  { className: 'text-fg2 hover:text-fg hover:bg-surface', style: {} },
      danger:  { className: 'text-white hover:brightness-110 active:brightness-95', style: { background: '#EF4444' } },
    }[variant];
    return React.createElement('button', { className: `${base} ${styles.className} ${className}`, style: styles.style, ...rest },
      icon ? React.createElement(Icon, { name: icon, size: 17 }) : null, children);
  }

  /* ---- Card ---- */
  function Card({ className = '', children, ...rest }) {
    return React.createElement('div', {
      className: `bg-card border border-line rounded-xl ${className}`,
      style: { boxShadow: 'var(--shadow-sm)' }, ...rest }, children);
  }

  function SectionLabel({ children, className = '' }) {
    return React.createElement('div', {
      className: `text-fg2 font-semibold uppercase text-[12px] ${className}`,
      style: { letterSpacing: '0.06em' } }, children);
  }

  /* ---- Severity badge ---- */
  function SeverityBadge({ sev, lang, withDot = true }) {
    const c = SEV[sev];
    return React.createElement('span', {
      className: 'inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[12px] font-semibold',
      style: { color: c, background: hexA(c, 0.13), border: `1px solid ${hexA(c, 0.30)}` } },
      withDot ? React.createElement('span', { style: { width: 6, height: 6, borderRadius: 99, background: c } }) : null,
      t(lang, 'sev_' + sev));
  }

  /* ---- Status pill ---- */
  function StatusPill({ status, lang }) {
    const map = {
      pending:   { c: '#64748B', pulse: false },
      running:   { c: '#3B82F6', pulse: true },
      completed: { c: '#1F9D6B', pulse: false },
      failed:    { c: '#EF4444', pulse: false },
    };
    const { c, pulse } = map[status];
    return React.createElement('span', {
      className: 'inline-flex items-center gap-2 rounded-full px-2.5 py-1 text-[12px] font-medium',
      style: { color: c, background: hexA(c, 0.12), border: `1px solid ${hexA(c, 0.28)}` } },
      React.createElement('span', { className: pulse ? 'k-pulse' : '', style: { width: 7, height: 7, borderRadius: 99, background: c } }),
      t(lang, 'st_' + status));
  }

  /* ---- Source badge ---- */
  function SourceBadge({ src }) {
    const s = SRC[src] || { color: '#64748B', short: src };
    return React.createElement('span', {
      className: 'inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[11px] font-semibold font-mono',
      style: { color: s.color, background: hexA(s.color, 0.12), border: `1px solid ${hexA(s.color, 0.28)}` } },
      React.createElement('span', { style: { width: 6, height: 6, borderRadius: 2, background: s.color } }), src);
  }

  /* ---- KEV badge ---- */
  function KevBadge({ lang, active }) {
    if (!active) return React.createElement('span', { className: 'text-fg2 text-[13px]' }, '—');
    return React.createElement('span', {
      className: 'inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-semibold',
      style: { color: '#EF4444', background: hexA('#EF4444', 0.12), border: `1px solid ${hexA('#EF4444', 0.3)}` },
      title: t(lang, 'kev_full') },
      React.createElement(Icon, { name: 'flame', size: 13, strokeWidth: 2 }), 'KEV');
  }

  /* ---- EPSS gauge ---- */
  function EpssGauge({ value, lang }) {
    const pct = Math.round(value * 100);
    const c = value >= 0.7 ? '#EF4444' : value >= 0.4 ? '#F59E0B' : '#3B82F6';
    return React.createElement('div', { className: 'flex items-center gap-2', title: t(lang, 'epss_full') },
      React.createElement('div', { className: 'rounded-full overflow-hidden', style: { width: 44, height: 6, background: 'var(--bg2)' } },
        React.createElement('div', { style: { width: pct + '%', height: '100%', background: c, borderRadius: 99 } })),
      React.createElement('span', { className: 'font-mono text-[12px] text-fg2 tabular-nums' }, pct + '%'));
  }

  /* ---- CVSS meter ---- */
  function CvssMeter({ score }) {
    const c = score >= 9 ? '#EF4444' : score >= 7 ? '#F97316' : score >= 4 ? '#F59E0B' : '#3B82F6';
    return React.createElement('span', {
      className: 'inline-flex items-center justify-center font-mono font-semibold text-[12px] rounded-md',
      style: { color: c, background: hexA(c, 0.13), border: `1px solid ${hexA(c, 0.28)}`, minWidth: 38, height: 24 } },
      score.toFixed(1));
  }

  /* ---- Masked password ---- */
  function MaskedPassword() {
    const [show, set] = React.useState(false);
    return React.createElement('span', { className: 'inline-flex items-center gap-2 font-mono text-[13px] text-fg' },
      React.createElement('span', { className: 'tracking-widest' }, show ? 'Tr0ub4dor&3' : '•••••••••••'),
      React.createElement('button', { onClick: () => set(!show), className: 'text-fg2 hover:text-fg transition-colors', 'aria-label': 'toggle' },
        React.createElement(Icon, { name: 'eye', size: 15 })));
  }

  /* ---- Search box ---- */
  function SearchBox({ value, onChange, placeholder, className = '' }) {
    return React.createElement('div', { className: `relative ${className}` },
      React.createElement('span', { className: 'absolute left-3 top-1/2 -translate-y-1/2 text-fg2 pointer-events-none' },
        React.createElement(Icon, { name: 'search', size: 16 })),
      React.createElement('input', {
        value, onChange: e => onChange(e.target.value), placeholder,
        className: 'w-full h-10 pl-9 pr-3 rounded-[10px] bg-app border border-line text-fg text-[14px] placeholder:text-fg2 focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent transition' }));
  }

  /* ---- Field (label + input) ---- */
  function Field({ label, mono, ...rest }) {
    return React.createElement('label', { className: 'block' },
      React.createElement('div', { className: 'text-[13px] font-medium text-fg2 mb-1.5' }, label),
      React.createElement('input', {
        className: `w-full h-10 px-3 rounded-[10px] bg-app border border-line text-fg text-[14px] placeholder:text-fg2 focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent transition ${mono ? 'font-mono' : ''}`,
        ...rest }));
  }

  /* ---- Segmented control ---- */
  function Segmented({ options, value, onChange, size = 'md' }) {
    const h = size === 'sm' ? 'h-8 text-[12px]' : 'h-9 text-[13px]';
    return React.createElement('div', { className: 'inline-flex p-1 rounded-[10px] bg-app border border-line gap-1' },
      options.map(o => {
        const active = o.value === value;
        return React.createElement('button', {
          key: o.value, onClick: () => onChange(o.value),
          className: `px-3 ${h} rounded-[7px] font-medium transition-colors ${active ? 'text-[#1a1206]' : 'text-fg2 hover:text-fg'}`,
          style: active ? { background: 'var(--accent)' } : {} }, o.label);
      }));
  }

  /* ---- Data table ---- */
  function DataTable({ columns, rows, render, sticky = true, zebra = true }) {
    return React.createElement('div', { className: 'overflow-auto rounded-xl border border-line', style: { boxShadow: 'var(--shadow-sm)' } },
      React.createElement('table', { className: 'w-full border-collapse text-[14px]' },
        React.createElement('thead', null,
          React.createElement('tr', null, columns.map((c, i) =>
            React.createElement('th', { key: i,
              className: `text-left font-semibold text-fg2 text-[12px] uppercase px-4 py-3 bg-card border-b border-line ${sticky ? 'sticky top-0 z-10' : ''} ${c.align === 'right' ? 'text-right' : ''}`,
              style: { letterSpacing: '0.05em', backdropFilter: 'blur(6px)' } }, c.label)))),
        React.createElement('tbody', null, rows.map((r, ri) =>
          React.createElement('tr', { key: ri,
            className: `border-b border-line last:border-0 transition-colors hover:bg-surface ${zebra && ri % 2 ? 'k-zebra' : ''}` },
            render(r, ri))))));
  }

  /* ---- Danger box ---- */
  function DangerBox({ title, body }) {
    return React.createElement('div', { className: 'flex gap-3 rounded-xl p-4', role: 'alert',
      style: { background: 'var(--danger-bg)', border: '1px solid var(--danger-line)' } },
      React.createElement('span', { style: { color: '#EF4444', flex: '0 0 auto', marginTop: 1 } },
        React.createElement(Icon, { name: 'alert', size: 20, strokeWidth: 2 })),
      React.createElement('div', null,
        React.createElement('div', { className: 'font-semibold text-[14px] mb-0.5', style: { color: '#F87171' } }, title),
        React.createElement('div', { className: 'text-[13px] text-fg2 leading-relaxed' }, body)));
  }

  /* ---- Empty state ---- */
  function EmptyState({ title, body, icon = 'search' }) {
    return React.createElement('div', { className: 'flex flex-col items-center justify-center text-center py-16 px-6' },
      React.createElement('div', { className: 'flex items-center justify-center rounded-2xl mb-4', style: { width: 56, height: 56, background: 'var(--bg2)', color: 'var(--fg2)' } },
        React.createElement(Icon, { name: icon, size: 24 })),
      React.createElement('div', { className: 'font-semibold text-fg text-[15px] mb-1' }, title),
      React.createElement('div', { className: 'text-fg2 text-[13px] max-w-xs' }, body));
  }

  /* ---- Modal ---- */
  function Modal({ open, onClose, title, children, footer, danger }) {
    if (!open) return null;
    return React.createElement('div', { className: 'fixed inset-0 z-50 flex items-center justify-center p-4 k-fade',
      style: { background: 'var(--scrim)', backdropFilter: 'blur(3px)' }, onClick: onClose },
      React.createElement('div', { className: 'w-full max-w-md bg-card border border-line rounded-2xl k-pop', style: { boxShadow: 'var(--shadow-md)' }, onClick: e => e.stopPropagation() },
        React.createElement('div', { className: 'flex items-start gap-3 p-5 border-b border-line' },
          danger ? React.createElement('span', { style: { color: '#EF4444', marginTop: 1 } }, React.createElement(Icon, { name: 'alert', size: 20, strokeWidth: 2 })) : null,
          React.createElement('h3', { className: 'font-semibold text-[16px] text-fg flex-1' }, title),
          React.createElement('button', { onClick: onClose, className: 'text-fg2 hover:text-fg transition-colors' }, React.createElement(Icon, { name: 'x', size: 18 }))),
        React.createElement('div', { className: 'p-5 text-[14px] text-fg2 leading-relaxed' }, children),
        footer ? React.createElement('div', { className: 'flex justify-end gap-2 p-4 border-t border-line' }, footer) : null));
  }

  /* ---- Toast ---- */
  function Toast({ toast }) {
    if (!toast) return null;
    return React.createElement('div', { className: 'fixed bottom-6 right-6 z-50 k-toast' },
      React.createElement('div', { className: 'flex items-center gap-3 bg-card border border-line rounded-xl px-4 py-3', style: { boxShadow: 'var(--shadow-md)' } },
        React.createElement('span', { className: 'flex items-center justify-center rounded-full', style: { width: 24, height: 24, background: 'rgba(31,157,107,0.15)', color: '#1F9D6B' } },
          React.createElement(Icon, { name: 'check', size: 15, strokeWidth: 2.5 })),
        React.createElement('span', { className: 'text-[14px] text-fg font-medium' }, toast)));
  }

  /* ---- Donut chart (inline SVG) ---- */
  function Donut({ counts, lang, size = 168 }) {
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    const total = order.reduce((s, k) => s + (counts[k] || 0), 0) || 1;
    const r = 62, c = 2 * Math.PI * r, cx = 84, cy = 84;
    let off = 0;
    const segs = order.map(k => {
      const frac = (counts[k] || 0) / total;
      const seg = React.createElement('circle', { key: k, cx, cy, r, fill: 'none', stroke: SEV[k], strokeWidth: 18,
        strokeDasharray: `${frac * c} ${c}`, strokeDashoffset: -off * c, transform: `rotate(-90 ${cx} ${cy})`, strokeLinecap: 'butt' });
      off += frac;
      return seg;
    });
    return React.createElement('div', { className: 'flex items-center gap-6' },
      React.createElement('div', { className: 'relative', style: { width: size, height: size } },
        React.createElement('svg', { width: 168, height: 168, viewBox: '0 0 168 168' },
          React.createElement('circle', { cx, cy, r, fill: 'none', stroke: 'var(--bg2)', strokeWidth: 18 }), segs),
        React.createElement('div', { className: 'absolute inset-0 flex flex-col items-center justify-center' },
          React.createElement('div', { className: 'k-stat text-fg', style: { fontSize: 30 } }, total),
          React.createElement('div', { className: 'text-fg2 text-[12px] uppercase font-semibold', style: { letterSpacing: '0.05em' } }, t(lang, 'nav_vuln')))),
      React.createElement('div', { className: 'flex flex-col gap-2' },
        order.map(k => React.createElement('div', { key: k, className: 'flex items-center gap-2.5 text-[13px]' },
          React.createElement('span', { style: { width: 10, height: 10, borderRadius: 3, background: SEV[k] } }),
          React.createElement('span', { className: 'text-fg2 flex-1' }, t(lang, 'sev_' + k)),
          React.createElement('span', { className: 'font-mono text-fg font-medium tabular-nums' }, counts[k])))));
  }

  /* ---- Horizontal bar chart ---- */
  function BarChart({ data, accent = 'var(--accent)' }) {
    const max = Math.max(...data.map(d => d.value)) || 1;
    return React.createElement('div', { className: 'flex flex-col gap-3' },
      data.map((d, i) => React.createElement('div', { key: i, className: 'flex items-center gap-3' },
        React.createElement('div', { className: 'w-28 text-[13px] text-fg2 truncate text-right' }, d.label),
        React.createElement('div', { className: 'flex-1 rounded-full overflow-hidden', style: { height: 10, background: 'var(--bg2)' } },
          React.createElement('div', { style: { width: (d.value / max * 100) + '%', height: '100%', background: d.color || accent, borderRadius: 99, transition: 'width .4s ease' } })),
        React.createElement('div', { className: 'w-14 text-[13px] font-mono text-fg text-right tabular-nums' }, d.value.toLocaleString()))));
  }

  /* ---- Stat card ---- */
  function StatCard({ icon, label, value, delta, tint = 'var(--accent)' }) {
    return React.createElement(Card, { className: 'p-5' },
      React.createElement('div', { className: 'flex items-start justify-between' },
        React.createElement('div', { className: 'flex items-center justify-center rounded-[10px]', style: { width: 38, height: 38, background: 'var(--accent-weak)', color: tint } },
          React.createElement(Icon, { name: icon, size: 19 })),
        delta ? React.createElement('span', { className: 'text-[12px] font-mono font-medium', style: { color: delta.up ? '#EF4444' : '#1F9D6B' } }, (delta.up ? '+' : '') + delta.v) : null),
      React.createElement('div', { className: 'k-stat text-fg mt-4', style: { fontSize: 30 } }, typeof value === 'number' ? value.toLocaleString() : value),
      React.createElement('div', { className: 'text-fg2 text-[13px] mt-1' }, label));
  }

  Object.assign(window, {
    KSEV: SEV, hexA, Button, Card, SectionLabel, SeverityBadge, StatusPill, SourceBadge,
    KevBadge, EpssGauge, CvssMeter, MaskedPassword, SearchBox, Field, Segmented, DataTable,
    DangerBox, EmptyState, Modal, Toast, Donut, BarChart, StatCard,
  });
})();
