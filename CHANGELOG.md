# Changelog

All notable changes to Patchy. Versions follow [semantic versioning](https://semver.org/).

## 1.26.0 - 2026-11-26

### Added
- **Runs under a path prefix**, eg `https://example.lan/patchy/`. Patchy reads `X-Forwarded-Prefix` from the reverse proxy and sets the page's `<base href>`, so one build works at a site root and under a prefix. Links, API calls, downloads, agent install commands and the Home Assistant example all include the prefix.
- `SUITE_ASSETS_PATH`: when set (eg `/suite`), every page loads that path's `theme.css` and `theme-init.js`, and Patchy takes its colours, font and day/night from them. Settings then hides the scheme, font and mode choices. Used by SWSuite.
- `AUTH_DISABLED`: no sign-in. Everyone who can reach Patchy uses it as one shared user called `local`, and Sign out and Change password are hidden. Off by default; only for when something else already controls who can reach it. Requests that change things still need the CSRF token, so other sites can't make them. Agent and integration tokens are unaffected.
- Inside SWSuite (`SUITE_ASSETS_PATH` set) the app calls itself **SWPatch** on screen.

### Changed
- Framing: `X-Frame-Options` is now `SAMEORIGIN` and the CSP has `frame-ancestors 'self'` (was `DENY`/`'none'`), so a portal on the same origin can show Patchy in a frame. Other sites still can't. `base-uri` is now `'self'` to allow the `<base>` tag.

### Upgrade notes
- No database migration.

## 1.25.0 - 2026-11-25

### Added
- **Change status** on Vulnerabilities: set every finding the current filters match to Open, Acknowledged, Resolved or False positive in one go, with a note. Up to 1,000 at a time. Findings an accepted-risk rule covers are skipped, and if the list changed since you loaded it, nothing is changed.
- **Timeline** on each finding page: when it was found and every status change since, oldest first, by a person, by Patchy (auto-resolved, reopened, set aside as minor or not booted) or by an accepted-risk rule.
- `SESSION_IDLE_MINUTES`: sign out after a set time without activity, on top of the `SESSION_HOURS` limit. Off by default.

### Changed
- Status changes Patchy makes itself, and ones made by accepted-risk rules, are now in the audit log (`finding.auto_status`). New findings aren't logged, so a first scan doesn't flood it.

### Fixed
- Agent 1.7.1: a CA file chosen in the agent menu is copied next to the config, so the agent service can read it. Before, a file under `/root` or a home directory worked in the menu's connection test but not for the service.

### Upgrade notes
- Database migration `0013` only adds a column. Nothing is changed or removed.
- Status changes from before 1.25 that Patchy made itself weren't recorded, so older timelines may jump straight to the current status.

## 1.24.0 - 2026-11-25

### Added
- **Agent menu**: `sudo patchy-agent` on a host opens a menu to see the agent's status (last report, what it found, next run), send a report now or preview one, switch what it collects, manage app directories, allow or stop Run upgrade, test the connection, replace the token after a Rotate, change the server address or CA file, read the logs, update the agent and remove it. Agent 1.7.0.
- Settings that change services (Run upgrade, Docker containers, Syft) are applied by re-running the installer, which now stays on the host in `/usr/local/lib/patchy-agent`.

### Fixed
- A Run upgrade request more than a day old is now failed when the agent checks in, instead of waiting for someone to open the host page. Before, a host that came back after a long time could still be upgraded.
- If apt fails to list updates on a host (for example, unmet dependencies), the Updates tab keeps the last list and marks it out of date instead of showing "Up to date".

### Upgrade notes
- Update the agent on each host from its Agent card to get the menu. From then on, the menu's **Update the agent** does it for you.

## 1.23.0 - 2026-11-25

### Added
- **Updates** tab on each host page: pending apt updates, which are security updates, how many open findings each one fixes, packages apt is keeping back, and whether a reboot is waiting. The hosts list has an optional Updates column (under Columns).
- **Run upgrade**: runs `apt-get update && apt-get upgrade` on the host and shows apt's output and the result. Off unless you allow it on the host: the installer asks once. Saying yes adds a root service that runs only that command, and only when Patchy asks.
- Agent 1.6.0 reports pending apt updates (from a simulation that changes nothing) and passes on Run upgrade. On hosts that allow upgrades it checks in every minute instead of every 5.

### Upgrade notes
- Database migration `0012` only adds a column and a table. Nothing is changed or removed.
- Update the agent on each host from its Agent card to see pending updates. The installer asks whether to allow Run upgrade; the default is no.

## 1.22.0 - 2026-11-25

### Added
- `BLOCKED_URL` (`DEMO_BLOCKED_URL` for the demo): a page to send visitors to when a proxy or CDN in front of Patchy rate-limits them, such as a Cloudflare rate limiting rule. Patchy's own rate limits still show their usual message.

### Changed
- The demo's banner puts "Get Patchy on GitHub" on its own line.
- On a host page, the agent update command is folded away under the "Update available" note. Open it to copy the command.
- The README links to the live demo instead of explaining how to host one. `docker-compose.demo.yml`'s comments cover that.

## 1.21.1 - 2026-11-25

### Fixed
- The demo listened on the wrong port when started in a folder that also has a real install's `.env`, because Compose filled in `$PORT` from it. It now always listens on `DEMO_PORT` (8081 by default).
- The demo now runs as its own stack, `patchy-demo`, so it never shares a network with a real Patchy's database in the same folder.

### Upgrade notes
- If you started the 1.21.0 demo, remove it first with `docker rm -f patchy-demo-1`, then start it again.

## 1.21.0 - 2026-11-25

### Added
- **Public demo**: `docker-compose.demo.yml` runs a read-only Patchy with no sign-in, showing a made-up home lab matched against a bundled snapshot of real, public vulnerability data (OSV.dev, CISA KEV, FIRST EPSS, endoflife.date). It keeps nothing: the database is rebuilt on tmpfs at every start, and it makes no outbound connections.
- `python -m app.cli demo-build` refreshes the snapshot, and `demo-load` fills an empty database with the demo. A `DEMO_MODE` setting turns on the demo's sign-in and read-only guard; it does nothing on a database the demo didn't make.

### Upgrade notes
- No migration and nothing changes on a normal install.

## 1.20.1 - 2026-11-25

### Fixed
- The weekly digest's **Send now** shared a limit with **Send test**, so after a few test alerts it answered "Too many requests". Each now has its own limit of 5 sends per 5 minutes.

## 1.20.0 - 2026-11-25

### Added
- **Weekly digest**: one message every Monday at 08:00 UTC to the alert destinations, with open findings by severity, known exploited, overdue, what was found and fixed that week, and the five hosts with most to fix. Turn it on in **Settings > Alerts**. Off by default.
- A **Send now** button to see the digest straight away.

### Upgrade notes
- No migration.

## 1.19.0 - 2026-11-25

### Added
- **Running or not**: agent 1.5 reports which packages running programs come from, including the shared libraries they load at start. Findings in packages nothing running comes from show a **Not running** badge and rank lower in the Priority sort and fix plans, but stay open and counted. A *Running* filter on Vulnerabilities and a count on the Overview.
- **Old kernels set aside**: findings in an installed kernel that isn't the booted one get a new automatic status, **Not booted**, and leave the open counts, alerts and fix plans. They reopen by themselves if that kernel is booted and resolve when it's removed. This works from `uname -r`, so it needs no agent update.

### Upgrade notes
- Adds one nullable column (`components.in_use`). The migration runs on start and changes no existing data.
- Update agents to 1.5.0 for the running check (re-run the install script, or copy `agent/patchy_agent.py`). Older agents keep working; their packages show as unknown and rank as before.
- Old-kernel findings are set aside on the next match after the next report from each host.

## 1.18.0 - 2026-11-25

### Added
- **Fix-by deadlines**: days per severity (critical 7, high 30, medium 90, low 180 by default), set in **Settings > Fix-by deadlines**. Known-exploited findings get the critical deadline, counted from when CISA listed them if that's later. 0 turns a deadline off.
- A due date on every open finding (a new *Due* column and on the finding page), an **Overdue** count on the Overview and filter on Vulnerabilities, and `overdue` in the Home Assistant summary with a ready-made sensor.
- A **Past the fix-by deadline** alert, off by default. Findings already overdue when it's turned on aren't sent.
- On the Overview: findings fixed in the last 90 days, the typical time to fix, and the share fixed by their deadline.

### Upgrade notes
- No migration. Deadlines are counted from when each finding was first found, so long-standing findings may show as overdue straight away.

## 1.17.1 - 2026-11-25

### Changed
- A host's SBOM download moved from the page header to the host's **Reports** tab.

### Fixed
- Saving a note on a *Minor* or *Risk accepted* finding without changing its status failed with an error. The note now saves and the status stays with Patchy or its rule. These statuses still can't be chosen by hand for other findings.

## 1.17.0 - 2026-11-24

### Added
- **Accepted risk**: rules that set findings aside until a date you choose (at most a year). A rule covers an advisory or CVE, a package, or both, optionally on one host, and needs a reason. Covered findings get the status *Risk accepted* and leave the open counts, alerts, fix plans and Home Assistant sensors. When a rule expires or is revoked, its findings reopen by themselves.
- An *Accept risk…* button on each finding, a new **Settings > Accepted risk** section, and a *Risk accepted* status filter. Creating and revoking rules is audit-logged.

### Upgrade notes
- Adds one table (`risk_rules`). The migration runs on start and changes no existing data.

## 1.16.0 - 2026-11-24

### Added
- **Distro ratings**: Patchy now keeps Debian's urgency and Ubuntu's priority for each advisory. Findings rated *unimportant* or *negligible* get a new automatic status, **Minor**, and leave the open counts, alerts, fix plans, trend and Home Assistant sensors. Known-exploited advisories are never set aside, a raised rating reopens the finding, and setting it to Open by hand keeps it open.
- A *Minor (distro rating)* status filter, the rating on each finding, and a link on the Overview to the findings set aside.

### Fixed
- A full feed refresh with more advisories than `OSV_MAX_ADVISORY_FETCH_PER_REFRESH` re-fetched the same ones every time. It now re-fetches the oldest first, so every advisory is refreshed in turn.

### Upgrade notes
- Adds one nullable column (`findings.vendor_priority`). The migration runs on start and changes no existing data.
- Expect the open count to drop over the next few refreshes as ratings arrive. The trend chart will show the drop.

## 1.15.0 - 2026-11-23

### Added
- **Home Assistant**: a new Settings section to create read-only API tokens, and a ready-to-paste `rest:` configuration for sensors: open, critical, high, known exploited and network-exposed findings, end of life, hosts not reporting, newer images, plus feeds-stale and alerts-paused binary sensors.
- `GET /api/integrations/summary`: the counts behind those sensors. It accepts a signed-in session or a read-only token; a token can read nothing else. Tokens are stored as a hash, record when and where they were last used, and their creation and revocation are audit-logged.

### Upgrade notes
- Adds one table (`api_tokens`). The migration runs on start and changes no existing data.

## 1.14.0 - 2026-11-23

### Added
- **Pause alerts**: a bell at the bottom of the sidebar (and a switch in Settings > Alerts) stops all alerts. What turns up while paused isn't sent later.

### Changed
- Settings moved into the main sidebar list, below Scans.
- Bigger logo and name at the top of the sidebar.
- A new agent token has the same copy button as the install commands.

## 1.13.0 - 2026-11-23

### Added
- **Security news feeds in Settings**: under Sources and schedule, list up to 10 https RSS or Atom feeds, or leave it empty to hide the news card. The worker fetches the new list straight away. **Use NEWS_FEEDS** goes back to the environment variable.
- **NuGet**: repository scans read `packages.lock.json`, `packages.config`, and `PackageReference`/`PackageVersion` items in `.csproj`, `.fsproj`, `.vbproj` and `Directory.Packages.props`, and check them against OSV.
- **Container image updates** (off by default): a new source that asks public registries (Docker Hub, GHCR, lscr.io, Quay and others) once a day whether each running container's tag points at a newer build, and shows **Newer image** on the host's Containers card. Switch it on in Settings or with `IMAGE_UPDATES_ENABLED=true`. Diun and Watchtower do this too, so leave it off if you already run one.

## 1.12.0 - 2026-11-23

### Added
- **Export CSV** on Vulnerabilities and on host and repository Findings tabs: the findings with the current filters and order (up to 50,000 rows), including KEV, EPSS, exposure, location and fixed versions. Cells that a spreadsheet would run as a formula are escaped.
- **SBOM** on host and repository pages, and per scanned container image: a CycloneDX 1.5 JSON file with package URLs (deb, apk, rpm, npm, PyPI, Maven, Go, Cargo and more), file locations, exposure, and open vulnerabilities linked to the affected components.
- Both exports are recorded in the audit log.

## 1.11.0 - 2026-11-23

### Added
- **Open findings trend** on the Overview, under Fix first: open confirmed and possible findings at the end of each of the last 90 days, with the change over 30 days. Hover for a day's critical and high counts. It's rebuilt from when each finding was detected and resolved, so it covers history from before this version; a new install starts where tracking began.

## 1.10.0 - 2026-11-23

### Added
- **Exposure ranking.** Components on agent hosts are marked **Network** when their process listens beyond loopback or their container publishes a port, and **Local** when only on loopback. The Priority sort, Fix first, the Fix plan and the AI prompt now put exposed findings ahead of ones nothing can reach (after known exploited). Findings tables have a sortable Exposure column. Takes effect from each host's next report.
- Database migration 0007 adds two nullable columns to components. Nothing is changed or dropped.

## 1.9.1 - 2026-11-23

### Fixed
- The Findings and Assets tabs on a host or repository only showed the first 200 rows. They now page through everything, 200 per page. Changing the sort goes back to page 1.

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
