---
name: kangalis-design
description: Use this skill to generate well-branded interfaces and assets for Kangalis (an on-prem internal-network vulnerability-scanning & exploit-intelligence console for SOC teams), either for production or throwaway prototypes/mocks. Contains essential design guidelines, colors, type, fonts, the logo, a Lucide-style icon set, an i18n (Turkish/English) dictionary, and a full dual-theme React + Tailwind UI kit for prototyping.
user-invocable: true
---

Read the `README.md` file within this skill, and explore the other available files.

If creating visual artifacts (slides, mocks, throwaway prototypes, etc.), copy assets out and create static HTML files for the user to view. If working on production code, you can copy assets and read the rules here to become an expert in designing with this brand.

Key files:
- `README.md` — brand context, content fundamentals, visual foundations, iconography.
- `colors_and_type.css` — the token source of truth (dark + light themes, type scale, radii, shadows).
- `assets/` — logo mark, favicon (single-color, theme-adaptive).
- `ui_kits/console/` — the working React + Tailwind console: dual theme, bilingual (TR/EN), nine screens. Reuse its `components.jsx` / `screens.jsx` patterns and the `i18n.jsx` dictionary.
- `preview/` — small specimen cards for every token and component.

Non-negotiables when designing for Kangalis: calm "control-room" feel; dark by default; one warm Kangal-amber accent used sparingly over low-chroma slate; severity colors are fixed (Critical #EF4444 · High #F97316 · Medium #F59E0B · Low #3B82F6 · Info #64748B) and identical in both themes; Inter for UI, JetBrains Mono for all machine-literal data (IP, CVE, port, CVSS); technical tokens are never translated; **no emoji**, no gimmicks, generous spacing.

If the user invokes this skill without any other guidance, ask them what they want to build or design, ask a few focused questions (surface, theme, language, audience), and act as an expert designer who outputs HTML artifacts _or_ production code, depending on the need.
