# Changelog

All notable changes to Patchy. Versions follow [semantic versioning](https://semver.org/).

## 1.1.0 - 2026-11-21

### Added
- Themes: 8 colour schemes, each with day and night modes (or follow the system), 6 font styles and a compact density option. Saved per browser.
- Redesigned interface: collapsible sidebar with icons, quick search (Ctrl+K), breadcrumbs, tabbed host, repository and asset pages, toast messages and loading skeletons.
- Tables: click any column header to sort ascending or descending, choose which columns to show, change rows per page and filter in place.
- Fix plans ("How to fix"): open findings grouped into the fewest upgrade steps per host, repository and manifest, with a copy-paste command where one is safe to give, plus end-of-life upgrade advice.
- New sources:
  - **NVD product matching**: checks servers, runtimes and manual assets that OSV can't (nginx, OpenSSH, OpenSSL, Python, Node.js, Postgres and others) using NVD's CPE version ranges. Shown as *possible* because distros backport fixes.
  - **FIRST EPSS**: likelihood each CVE is exploited in the next 30 days, used for a new *Priority* sort.
  - **endoflife.date**: support and end-of-life dates for runtimes, frameworks, servers and host operating systems.
  - **GitHub Dependabot**: cross-checks each scanned repository's Dependabot alerts against Patchy's findings.
- Settings: switch each source on or off and set how often it refreshes, or refresh one source now.
- Settings: version and changelog.
- Optional CPE (`vendor:product`) on manual assets for NVD matching.
- Hosts page flags agents older than the bundled agent.

### Changed
- `FEED_REFRESH_HOURS` is now the default schedule; the Settings page overrides it per source.
- The install script asks before allowing plain HTTP when given an `http://` server URL.

### Fixed
- Feed refresh failed on PostgreSQL for advisories with only a CVSS v4 vector (label longer than its column).
- A rate-limited repository scan no longer marks every component missing; any GitHub error now stops the scan.
- Remediation commands never include package names with unusual characters.

## 1.0.0 - 2026-11-21

First release: inventory, GitHub repository discovery, Linux agent, OSV matching with CISA KEV and optional NVD severity, finding workflow, audit log, Docker Compose deployment.
