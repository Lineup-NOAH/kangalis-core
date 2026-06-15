# Kangalis — Design System

> **The guardian of your internal network.** — *İç ağınızın bekçisi.*

Kangalis is an **internal-network vulnerability scanning and exploit-intelligence platform** — an on-prem operations console for SOC analysts and security teams. It is not a SaaS marketing product; it is a serious, control-room tool that lives inside the perimeter it protects.

This repository is the **design system + brand kit** for Kangalis: brand foundations, color & type tokens, logo assets, reusable UI components, and a fully working, bilingual, dual-theme console prototype.

---

## Brand at a glance

- **Name:** KANGALIS — after the **Kangal**, Anatolia's legendary livestock-guardian dog: loyal, vigilant, protective.
- **Metaphor:** *the guardian of the network.* The flock = your internal network; Kangalis = the dog that guards it.
- **Logo:** a minimal, geometric Kangal head rendered as a shield silhouette with alert ears, set eyes, and a dark muzzle. Single-color, legible to ~16px. See `assets/`.
- **Tagline:** "The guardian of your internal network." / "İç ağınızın bekçisi."
- **Tone:** professional, quietly powerful, no gimmicks. Military/SOC discipline, but clean, calm and spacious.

## Sources

This system was created from a **written product brief** (no external codebase or Figma was provided). There are therefore **no GitHub repos, Figma links, or imported codebase paths** behind it — the brief itself is the design context. The brand mark, palette interpretation, component set, and i18n dictionary in this repo are the canonical reference going forward.

---

## Index — what's in this repo

| Path | What it is |
|---|---|
| `README.md` | This file — brand context, content + visual foundations, iconography. |
| `colors_and_type.css` | CSS custom properties: dark + light theme color tokens, type scale, font stacks, radii, shadows. The single source of truth for tokens. |
| `assets/` | Logo mark, full lockup, favicon. Single-color, theme-adaptive SVGs. |
| `preview/` | Small HTML specimen cards that populate the **Design System** tab (colors, type, components, spacing). |
| `ui_kits/console/` | The flagship **working prototype**: React + Tailwind, all 9 screens, dual theme + bilingual (TR/EN), realistic mock data. `index.html` is the entry point; logic is split into small JSX files. |
| `SKILL.md` | Agent-Skill manifest so this system can be used as a downloadable Claude skill. |

To run the console: open `ui_kits/console/index.html`.

---

## CONTENT FUNDAMENTALS

How Kangalis writes.

- **Voice:** calm authority. It is an operator's tool, so copy is **terse, precise, and declarative** — never salesy, never cute. "3 scans running." not "You've got 3 awesome scans going!"
- **Person:** addresses the user as **"you"** sparingly; mostly the UI labels objects and states neutrally (nouns and short verbs: *Scans, New Scan, Update Database, Run, Pause*). The tagline is the one place "you/your" appears for warmth.
- **Casing:** **Title Case for nav items and buttons** (New Scan, Update Database, Credential Vault). **Sentence case for descriptions and helper text** (Passwords are stored encrypted.). Severity and status labels are **single capitalized words** (Critical, Running, Completed).
- **Technical tokens stay literal & monospaced and are never translated:** IP addresses, CIDR ranges, CVE-IDs (`CVE-2024-3094`), ports (`:22`), CVSS scores, EPSS percentages, hostnames. They read identically in Turkish and English.
- **Numbers carry meaning, not decoration.** A stat is shown because an operator acts on it (open vulnerabilities, scans running). No vanity metrics.
- **Severity language is fixed** and consistent everywhere: Critical · High · Medium · Low · Info (Kritik · Yüksek · Orta · Düşük · Bilgi).
- **Danger is explicit.** Aggressive / destructive actions get a plain-spoken warning ("Aggressive scans may disrupt production services and trip IDS/IPS."), never softened.
- **Emoji:** **never.** This is a SOC tool. Status and meaning are carried by color, iconography, and short words — not emoji.
- **No exclamation marks** in product copy except in genuine danger warnings, and even then sparingly.

Examples (EN / TR):
- "The guardian of your internal network." / "İç ağınızın bekçisi."
- "Passwords are stored encrypted." / "Parolalar şifreli saklanır."
- "Update Database" / "Veritabanını Güncelle"
- "Aggressive" / "Agresif" — reveals a red danger box.

---

## VISUAL FOUNDATIONS

The look: a **calm control room.** Dark by default, spacious, low-chroma surfaces with a single warm guardian accent and a steel-blue support color. Information density is high but never cramped — generous padding and clear hierarchy do the work.

### Color
- **Two themes, driven entirely by CSS variables** (`--bg, --bg2, --card, --border, --fg, --fg2, --accent, --steel`). Nothing is hard-coded except severity colors.
- **Dark (default):** near-black slate backgrounds (`#0b0f14` / `#11161d`), cards a touch lighter (`#161c25`), hairline borders (`#232b36`), primary text `#e6edf3`, secondary `#9aa7b4`.
- **Light:** soft paper (`#f6f8fa`), white cards, `#e3e8ee` borders, ink text `#0b0f14`, secondary `#5b6671`.
- **Brand accent — Kangal amber/bronze `#E0A458`** (deepened to ~`#BC7A2C` on light for contrast). Used for the logo, primary actions, active nav, focus rings, and chart highlights. Used **sparingly** — it should feel like a single warm light in a dark room.
- **Secondary accent — steel blue `#3B82F6`** (`#2563EB` on light) for links, secondary data series, "Low" severity.
- **Severity (constant across themes):** Critical `#EF4444` · High `#F97316` · Medium `#F59E0B` · Low `#3B82F6` · Info `#64748B`. These never change between themes so an analyst reads severity by hue instinctively.

### Type
- **UI / sans:** Inter, falling back to system-ui. Semibold (600) for headings and key labels, regular (400) for body, medium (500) for buttons and nav.
- **Technical data / mono:** JetBrains Mono / ui-monospace for IPs, CVE-IDs, ports, scores, hashes — anything machine-literal.
- **Hierarchy:** large semibold page titles, quiet uppercase tracked-out section labels (`.06em` letter-spacing, `--fg2`), regular body, monospace for data. Numbers in stat cards are large and tabular.

### Spacing, radii, elevation
- **Generous, rhythmic spacing** on a 4px base; cards padded 20–24px; comfortable gaps between groups.
- **Corner radii:** `rounded-xl` (12px) for cards and modals, `rounded-lg` (8–10px) for inputs/buttons, full pills for status/severity badges, `rounded-md` (6px) for small chips.
- **Cards:** filled surface (`--card`) + 1px hairline border (`--border`) + a **soft, low, diffuse shadow**. On dark the shadow is subtle (depth from the border + slight lift); on light it's a gentle `0 1px 2px / 0 8px 24px` stack. No heavy drop shadows, no neumorphism.
- **Borders** carry a lot of the structure — hairline `--border` everywhere; severity/danger elements may add a colored 1px border at low opacity.

### Backgrounds & texture
- **Flat, near-solid backgrounds.** No photographic imagery in-app, no busy patterns. The login screen may carry a very subtle radial vignette / faint topographic-grid motif behind the card (low opacity) to evoke a perimeter map — kept whisper-quiet.
- **No bluish-purple gradients, no rainbow.** Any gradient is a single-hue, low-opacity wash (amber or slate) used only behind the login card or chart fills.

### Motion
- **Restrained and fast.** Theme/language swaps are instant (no reload). Transitions are short (120–180ms ease-out) for hovers, panel opens, and toast entry. Modals fade + scale up slightly (from 0.97). **No bounce, no parallax, no decorative looping animation** — this is monitoring software; motion must never distract from a live status change.
- `prefers-reduced-motion` is respected.

### Interaction states
- **Hover:** subtle surface lift — backgrounds shift one step lighter (dark) / one step toward accent-tint (light); table rows get a faint `--bg2` wash; primary buttons brighten the amber slightly.
- **Active/press:** quick darken + ~1px translate-down; no large scale changes.
- **Focus:** 2px amber focus ring (`--accent` at full) with offset — always visible, keyboard nav is first-class.
- **Selected/active nav:** amber left indicator + tinted background + amber icon.

### Transparency & blur
- Used **sparingly**: modal scrim is a dark blur-backdrop (`backdrop-blur` + 60–70% black); sticky table headers and the topbar use a translucent surface with slight blur so content scrolls under them. Elsewhere surfaces are solid.

### Imagery vibe
- The only "imagery" is the **logo** and **inline SVG data-viz** (donut, bars). Data-viz uses the severity palette + amber/steel — **warm accent on cool slate.** No stock photography.

---

## ICONOGRAPHY

- **System:** a single, consistent **line-icon set in the Lucide style** — 24×24 viewBox, ~1.75px stroke, round caps/joins, no fills. This stroke weight matches the clean, technical SOC aesthetic and keeps icons legible in the sidebar at 20px.
- **Implementation in the prototype:** icons are hand-authored **inline SVG React components** (`ui_kits/console/icons.jsx`) using Lucide-equivalent path data so the kit is fully self-contained with **no CDN dependency and no icon font**. They inherit `currentColor`, so they recolor automatically with theme and active state.
- **⚠️ Substitution flag:** there was no provided icon set, so we standardized on **Lucide-style** geometry. If you have a preferred licensed icon set, drop it in and we'll swap — the components are isolated in one file.
- **Color:** icons are monochrome (`currentColor`); active nav and key actions tint them amber. Severity is never shown by icon color alone — it's paired with a text label and a colored badge.
- **Emoji / unicode glyphs as icons:** **never used.** All iconography is vector SVG.
- **Usage:** one icon per nav item, leading icons on primary buttons and stat cards, small inline indicators (KEV flame, EPSS gauge, source badges). Icons support labels; they rarely stand alone.

---

*See `colors_and_type.css` for the exact tokens and `ui_kits/console/` for the components in action.*
