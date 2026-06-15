# Kangalis Console — UI Kit

A high-fidelity, interactive recreation of the **Kangalis security operations console**: React + Tailwind, dual theme (dark/light), bilingual (Turkish/English), with realistic mock data across all nine screens.

`index.html` is the entry point. It is a **generated self-contained file** — the JSX modules and design tokens below are inlined into it so the only network requests are the pinned CDN libraries (React, ReactDOM, Babel, Tailwind, Google Fonts). Open it directly.

## Run it
Open `index.html`. Default state is **Turkish + Dark**. Demo credentials are pre-filled — click **Giriş / Sign in**. Theme (sun/moon) and language (TR/EN) toggles are top-right and on the login screen. State (theme, language, auth, current screen) persists across reloads via `localStorage`.

## Source files (edit these, then re-bundle)
| File | Responsibility |
|---|---|
| `icons.jsx` | `Icon` (Lucide-style inline SVG set) and `Logo` (geometric Kangal mark). |
| `i18n.jsx` | `KDICT` dictionary + `t(lang, key)`. Every string lives here in TR + EN. Technical tokens (IP, CVE, port) are intentionally identical in both. |
| `data.jsx` | `KDATA` — mock vulns, scans, zones, credentials, exploits, audit, stats. |
| `components.jsx` | Primitives: `Button, Card, SeverityBadge, StatusPill, SourceBadge, KevBadge, EpssGauge, CvssMeter, MaskedPassword, SearchBox, Field, Segmented, DataTable, DangerBox, EmptyState, Modal, Toast, Donut, BarChart, StatCard`. |
| `screens.jsx` | `KSCREENS` — the nine screens (Dashboard, Scans, IPZones, Vault, Vulnerabilities, ExploitDB, Reports, Audit). |
| `app.jsx` | Shell: Login, Sidebar, Topbar, theme + i18n state, routing, mount. |

Each file is a plain `<script type="text/babel">` IIFE that assigns its exports onto `window`, so later files read earlier ones by bare name. **To rebuild `index.html`** after editing a `.jsx`, re-concatenate the six files (in the order above) into the single `data-presets="react"` script block in `index.html`, and inline `../../colors_and_type.css` (minus its `@import`).

## How theming works
All color is driven by CSS variables defined in `colors_and_type.css` under `[data-theme="dark"]` (default) and `[data-theme="light"]`. The theme toggle flips `document.documentElement[data-theme]`. Tailwind is configured (in `index.html`) with semantic color names (`app, surface, card, line, fg, fg2, accent, steel`) mapped to those vars, plus fixed `crit/high/med/low/info`. Severity colors never change between themes.

## How i18n works
A flat dictionary keyed by string id, each with `{ tr, en }`. `t(lang, key)` resolves at render time, so flipping `lang` re-renders every label instantly with no reload. Default language is `tr`.

## Screens
Login · Dashboard (stat cards, severity donut, top-5 findings, recent scans) · Scans (new-scan form with aggressive→danger reveal, IP-zone scan, live status table) · IP Zones (zone cards + new-zone form) · Credential Vault (masked credential cards, encrypted notice) · Vulnerabilities (risk-sorted CVE table with CVSS/KEV/EPSS) · Exploit DB (counters, source filter, source-badged table, Update-Database modal) · Reports (print-friendly summary) · Audit (admin-only log).

## Known substitutions
- **Icons:** Lucide-style geometry, hand-authored inline (no external icon set was provided). Swap freely in `icons.jsx`.
- **Fonts:** Inter + JetBrains Mono via Google Fonts (named in the brief).
