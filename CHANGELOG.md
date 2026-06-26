# Changelog

All notable changes to Kangalis are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project follows
[Semantic Versioning](https://semver.org/).

## [1.2.0] - 2026-06-27

### Added
- **Exploitation scan mode (plugin- and license-gated)** — when the commercial
  `kangalis-exploit` plugin is installed **and** a valid `exploit` license is active, an
  "Exploitation" mode appears in the scan form (admin only, explicit consent required). It
  scans like the aggressive mode but applies matching Metasploit / Exploit-DB exploits to the
  target — real exploitation. Without both the plugin **and** the license the option stays
  hidden and the core never exploits.

## [1.1.0] - 2026-06-26

### Added
- **AI generation is queued** — Kangalis never runs two AI analyses at once, so the
  single-slot local AI is never overloaded; click several "Explain with AI" buttons and
  they run one after another.
- **All AI analyses embedded in the PDF report** — executive summary, remediation priority,
  per-finding explanations and remediation scripts now appear in the downloadable report.
- **Bundled CVE seed, auto-imported on first install** (fetched from the `cve-seed` release)
  — fast first run with offline CVE data; live backfill progress and cancel.

### Changed
- Modernized the PDF security report design.
- **README is now bilingual (English + Turkish)** with a language switcher.
- **Documented all scan modes** (detection-only; aggressive modes are admin-only and require
  an explicit consent checkbox) and clarified that real exploitation lives in a separate,
  optional, license-gated plugin — the core never runs an exploit.
- Reverse-DNS (PTR) resolution now defaults to **OFF**.
- Added a **System Requirements** section and clarified local-AI CPU behavior.
- Hid the 5-year NVD backfill panel (the bundled CVE seed is sufficient).

### Security
- Vulnerability reports now go through **GitHub Private Vulnerability Reporting** (no contact
  email exposed).
- Removed third-party scanner names from user-facing docs and UI.

### Fixed
- Hardened the CVE seed export/import path; made version-string tests version-resilient.

## [1.0.1] - 2026-06-24

- In-app disclaimer-acceptance gate before any scan; `reset` scripts for a clean reinstall;
  security and infrastructure hardening (SSRF/CSRF/CSP, fail-closed MCP).

## [1.0.0] - 2026-06-24

- Initial public release: on-prem internal-network vulnerability scanning with offline CVE/CPE
  database, exploit-aware prioritization (KEV/EPSS/Exploit-DB), local defensive AI (Ollama),
  compliance mapping, and credentialed audits.
