# Changelog

All notable changes to Patchy. Versions follow [semantic versioning](https://semver.org/).

## 1.9.0 - 2026-11-23

### Added
- **Security news** on the Overview, above End of life: the 5 newest posts from security news feeds, linked to the full article. The worker fetches the feeds hourly, so your browser never contacts them. The Hacker News by default; set `NEWS_FEEDS` to a comma-separated list of https RSS or Atom feeds, or leave it empty to turn the card off.

## 1.8.0 - 2026-11-23

### Added
- When a pull or rebuild gives a scanned image's tag a new image ID, the new image is queued for a scan automatically, once. Before, its scan was lost until someone pressed Scan again. No agent update needed (1.4 or later).
- **Scan all** on the host's Containers card queues every image not yet scanned.
- Each scanned container image shows when it was scanned.
- Database migration 0006 adds one nullable column recording which images were scanned and when. Nothing is changed or dropped.

## 1.7.2 - 2026-11-23

### Fixed
- The AI assistant card on Fixes kept showing the previous host's or repository's prompt after switching. It now starts empty for each one.

## 1.7.1 - 2026-11-23

### Fixed
- Badges now have an 8 px gap from the text before them, such as KEV next to an advisory ID. Badges that start a table cell or sit in a row that already spaces its items are unchanged.

## 1.7.0 - 2026-11-23

### Added
- **Get help from an AI assistant** on the Fixes tab of a host or repository. **Create prompt** writes a prompt for ChatGPT or Claude and a Markdown report to attach: system details, containers, every upgrade step with installed and fixed versions, file locations, and advisory details. Text from scans is flattened and marked as data so it can't steer the assistant. Each report is recorded in the audit log.

## 1.6.2 - 2026-11-23

### Changed
- New logo in the sidebar, sign-in page, browser tab and README. Adds an icon for phones' home screens.

## 1.6.1 - 2026-11-23

### Fixed
- The worker's 5-minute alert check loaded every open finding with its full advisory record. On a host with many container images that took gigabytes of memory and pushed the server into swap. It now reads only exploited or critical findings, and only the few fields an alert needs.

## 1.6.0 - 2026-11-23

### Added
- Alert destinations can be added, changed and removed in **Settings > Alerts**: webhook, ntfy, Pushover and email, plus the Patchy address used for links. Passwords, tokens and webhook URLs are write-only once saved and never sent back to the browser. Anything set in `.env` still takes priority and shows as locked.
- Pushover as an alert destination (`PUSHOVER_TOKEN` and `PUSHOVER_USER`, or Settings). Alerts about known exploited vulnerabilities are sent at high priority.

## 1.5.0 - 2026-11-22

### Added
- Alerts. Patchy sends one message to a webhook (eg Home Assistant), ntfy or email when a known exploited or critical vulnerability is found, a host stops reporting, or software nears end of life. Destinations go in `.env` (see `.env.example`); choose events and send a test from **Settings > Alerts**. Each thing alerts once, and the first check doesn't replay what's already there.
- Database migration 0005 adds a table recording what has been alerted. Nothing is changed or dropped.

## 1.4.0 - 2026-11-22

### Changed
- Container images are scanned when you ask. Each container on the host page has a **Scan** button; the agent picks the request up at its next 5-minute check-in and scans just that image. Images already scanned stay cached and keep being checked against new advisories without rescanning. To scan every new image automatically, as 1.3 did, set `"image_scan": "auto"` under `collect` in the agent config.
- Syft runs on one CPU core (`GOMAXPROCS=1`), so a scan no longer loads every core on the host.
- Agent 1.4.0. Hosts on older agents show the Update badge; the Scan button appears once a host reports from 1.4.

### Added
- Database migration 0004 adds one nullable column for pending scan requests. Nothing is changed or dropped.

## 1.3.5 - 2026-11-22

### Fixed
- The Rescan banner said any agent older than the server's "only reports on its 6-hour schedule". Only agents before 1.2 lack the 5-minute check-in; newer ones now get the "waiting for the agent" message.

## 1.3.4 - 2026-11-22

### Fixed
- Agent 1.3.3 collects one report at a time. Pressing Rescan while the 6-hour run is still scanning container images no longer starts a second scan alongside it; the run already going answers the Rescan.

## 1.3.3 - 2026-11-22

### Fixed
- Agent 1.3.2 waits up to 5 minutes for Patchy to store a report, instead of the 30 second check-in timeout, so a large report with container image packages isn't abandoned. A failed send logs one line instead of a traceback.
- The agent service runs at low CPU and disk priority, and memory above 1 GB is reclaimed from it first, so scanning many container images doesn't compete with the host's own services. Re-run the update on each host to apply it.

## 1.3.2 - 2026-11-22

### Fixed
- A large agent report, such as one with container image packages, no longer freezes Patchy while it is stored. The work runs off the web server's event loop, so the UI and health checks keep answering, and the app container no longer turns unhealthy.
- Storing a report and re-checking its findings now takes a handful of database queries instead of several per package, so a report with thousands of image packages is several times faster.

## 1.3.1 - 2026-11-22

### Fixed
- Agent 1.3.1: installing or updating no longer waits for the first report, which can take minutes while Syft reads container images. It now runs in the background and the installer says how to follow it.
- Agent 1.3.1: each image's package list is saved as soon as it is scanned, and new scans stop starting after 10 minutes. Before, a host with several large images could hit systemd's 30 minute limit before anything was saved, start again every run and never send a report.
- Agent 1.3.1: the journal shows which image is being scanned. Updating the agent no longer throws away cached image scans.

## 1.3.0 - 2026-11-22

### Added
- Container image scanning. With containers turned on, the agent can list the packages inside each running container's image with [Syft](https://github.com/anchore/syft) and Patchy checks them against OSV like any other package. Distro packages (Debian, Ubuntu, Alpine, Rocky, Alma) and app libraries (npm, PyPI, Go, Cargo, RubyGems, Composer, Maven, NuGet) are covered.
- The Docker containers table on the host page shows each image's open findings, and findings and assets say which image a package is in.
- Fixes groups image findings per image, with a `docker pull` command and advice to recreate the containers.
- Settings, Sources warns when the worker container runs a different version from the app, with the command to fix it.

### Changed
- Agent 1.3.0. The installer offers Syft 1.56.0 once, when containers are on. It is downloaded from GitHub and its SHA-256 checked against a pinned value. Each image is scanned once and cached by image ID, at most 10 new images per run.
- The worker service now builds from the Dockerfile too, so `docker compose up -d --build` always recreates it with the new code. An old worker was the cause of a FIRST EPSS error that stayed after 1.1.1 fixed it.
- `AGENT_MAX_REPORT_BYTES` defaults to 32 MB (was 10 MB) to fit image package lists.

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
