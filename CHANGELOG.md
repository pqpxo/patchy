# Changelog

All notable changes to Patchy. Versions follow [semantic versioning](https://semver.org/).

## 1.2.0 - 2026-11-22

### Added
- Docker containers on the host page: name, image and version, state, published ports, and volume and bind mount locations. The agent reads the Docker API socket; environment variables and labels are never sent. Opt in at install time (it needs the docker group, which is root-equivalent).
- Added software on the host page: packages someone chose to install on top of the base OS, plus Snap and Flatpak apps. Snap and Flatpak apps also become assets.
- Rescan button on the host page. It re-checks the host's findings straight away, and agents from 1.2 check in every 5 minutes and send a fresh report when a rescan is waiting. The page shows the request until the report arrives.

### Changed
- Agent 1.2.0. Hosts on 1.1.0 show the update command on their Agent card; re-running it keeps the token and settings. The installer adds a second timer, `patchy-agent-poll.timer`.
- A source that failed to refresh now retries after an hour instead of waiting a full schedule.
- Host page: more space between the agent details and its buttons, and a tidier OS support line.
- Scans: the # column no longer wraps, Kind and Target get more room and long progress text is clipped.

## 1.1.1 - 2026-11-21

### Added
- 10 more colour schemes: Steel, Indigo, Midnight, Ocean, Mint, Forest, Moss, Copper, Rose and Berry.
- Live status banner for repository scans and source refreshes on the page where they were started.

### Changed
- "How to fix" is now called "Fixes".
- Page content is centred and up to 80% of the window wide. Wider table cell padding, and cells are centred vertically.
- Host, Agent and Listening ports cards share a height; the ports list scrolls.
- The agent install commands start in the home folder and no longer open a file viewer.

### Fixed
- EPSS and NVD severity refreshes failed on PostgreSQL.
- Copy buttons did nothing when Patchy was served over plain HTTP.
- The Assets table could need a horizontal scroll bar.

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
- Host and repository lists show open findings as a severity strip, marked when any are known exploited.
- Overview page: a *Fix first* queue ranked by known and likely exploitation, end-of-life counts and source health.

### Changed
- `FEED_REFRESH_HOURS` is now the default schedule; the Settings page overrides it per source.
- The install script asks before allowing plain HTTP when given an `http://` server URL.

### Fixed
- Feed refresh failed on PostgreSQL for advisories with only a CVSS v4 vector (label longer than its column).
- A rate-limited repository scan no longer marks every component missing; any GitHub error now stops the scan.
- Remediation commands never include package names with unusual characters.

## 1.0.0 - 2026-11-21

First release: inventory, GitHub repository discovery, Linux agent, OSV matching with CISA KEV and optional NVD severity, finding workflow, audit log, Docker Compose deployment.
