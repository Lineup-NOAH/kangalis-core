# Changelog

All notable changes to Kangalis are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project follows
[Semantic Versioning](https://semver.org/).

## [1.5.2] - 2026-07-03

### Fixed
- **Report & live panel: the "destructive (DoS) PoC blocked" chip now shows text.** The
  `exploitdb_dos_blocked` label was missing from the translation table, so the critical-severity
  chip shown on destructive Exploit-DB PoCs rendered blank; added Turkish + English strings.

## [1.5.1] - 2026-06-27

### Fixed
- **Update page: the manual update commands no longer use `&&`.** They are now shown one per
  line, so they work in Windows PowerShell 5.1 (where `&&` is a parse error) as well as bash.
- **Update page: added guidance for non-git-clone installs.** If `git pull` reports "not a git
  repository", the page now explains the offline path (download the release ZIP, copy it over
  the existing folder — `.env` and the database volume are preserved — then rebuild).

## [1.5.0] - 2026-06-27

### Added
- **Optional in-app auto-update.** On the Update page, admins can enable "Allow in-app
  auto-update". When it's on and an update is available, the **Update** button performs the
  update itself: it launches a one-shot updater container (via the mounted Docker socket) that
  runs `git pull` + rebuild + restart on the host, and the page tracks progress and reloads on
  the new version. **Off by default** — when off, or when the Docker socket isn't mounted, the
  page still just shows the manual host commands, preserving the prior security boundary. It is
  admin-only, requires an explicit consent prompt, and every trigger is written to the audit log.
  Requires a git-clone install with internet access.

## [1.4.0] - 2026-06-27

### Changed
- **Exploitation is now behind a top-right "Exploit attempts" button, not a scan mode.**
  When the commercial `kangalis-exploit` plugin **and** a valid `exploit` license are active,
  admins see an "Exploit attempts" button in the top-right of the scan panel. Clicking it
  shows a consent prompt; on accept it reveals the (otherwise hidden) "Exploitation" mode plus
  a warning banner, and clicking again returns to the safe default. The mode no longer appears
  directly in the scan-mode dropdown and cannot be selected without this explicit opt-in. This
  restores the earlier "safe area + Exploit tab" design. Without both the plugin and the license,
  neither the button nor the mode is shown.

## [1.3.0] - 2026-06-27

### Added
- **"Update" button + release notes on the Update page.** After "Check now", when a newer
  version is available, the page shows an **Update** button (jumps to the host update command)
  and a **Release notes** link to the matching GitHub release — so admins can see what changed
  and update in one place. The app still never runs the update itself (you run the shown command
  on the host); the security boundary is preserved. If the exploit plugin is installed, the page
  reminds you to re-run the plugin installer after updating (so the rebuild doesn't drop it).

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
