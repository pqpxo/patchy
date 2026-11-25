"""Runtime configuration, read from environment variables only."""
import os


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    return int(os.getenv(name, str(default)))


class Settings:
    def __init__(self) -> None:
        self.database_url = os.getenv("DATABASE_URL", "sqlite:///./data/patchy.db")
        self.port = _int("PORT", 8080)
        self.cookie_secure = _bool("COOKIE_SECURE", True)
        self.session_hours = _int("SESSION_HOURS", 12)
        # Public demo: everyone is the demo user and every change is refused. See app/demo.py.
        self.demo_mode = _bool("DEMO_MODE", False)
        # A page to send visitors to when a proxy or CDN in front of Patchy rate-limits them. http(s) only.
        blocked = os.getenv("BLOCKED_URL", "").strip()
        self.blocked_url = blocked if blocked.startswith(("https://", "http://")) else ""
        # Secrets: never returned by the API, never logged.
        self.github_token = os.getenv("GITHUB_TOKEN", "").strip()
        self.nvd_api_key = os.getenv("NVD_API_KEY", "").strip()
        # Feeds
        self.osv_enabled = _bool("OSV_ENABLED", True)
        self.kev_enabled = _bool("KEV_ENABLED", True)
        self.nvd_enabled = _bool("NVD_ENABLED", False)
        self.nvd_cpe_enabled = _bool("NVD_CPE_ENABLED", True)
        self.epss_enabled = _bool("EPSS_ENABLED", True)
        self.eol_enabled = _bool("EOL_ENABLED", True)
        self.dependabot_enabled = _bool("DEPENDABOT_ENABLED", True)
        self.image_updates_enabled = _bool("IMAGE_UPDATES_ENABLED", False)
        # Default schedule; each source's schedule can then be changed on the Settings page.
        self.feed_refresh_hours = _int("FEED_REFRESH_HOURS", 24)  # 0 = manual refresh only
        self.feed_stale_hours = _int("FEED_STALE_HOURS", 72)
        # Security news on the Overview: comma-separated https RSS/Atom feeds, empty to turn it off.
        # The Settings page can replace this list.
        self.news_feeds = os.getenv("NEWS_FEEDS", "https://feeds.feedburner.com/TheHackersNews")
        self.osv_max_queries = _int("OSV_MAX_QUERIES_PER_REFRESH", 5000)
        self.osv_max_vulns_per_package = _int("OSV_MAX_VULNS_PER_PACKAGE", 200)
        self.osv_max_fetch = _int("OSV_MAX_ADVISORY_FETCH_PER_REFRESH", 2000)
        self.nvd_max_per_refresh = _int("NVD_MAX_PER_REFRESH", 50)
        self.nvd_cpe_max_per_refresh = _int("NVD_CPE_MAX_PER_REFRESH", 100)
        self.osv_api = os.getenv("OSV_API_URL", "https://api.osv.dev")
        self.kev_url = os.getenv(
            "KEV_URL",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        )
        self.nvd_api = os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
        self.epss_api = os.getenv("EPSS_API_URL", "https://api.first.org/data/v1/epss")
        self.eol_api = os.getenv("EOL_API_URL", "https://endoflife.date/api/v1")
        # Repository scan limits
        self.repo_max_file_bytes = _int("REPO_MAX_FILE_BYTES", 5 * 1024 * 1024)
        self.repo_max_total_bytes = _int("REPO_MAX_TOTAL_BYTES", 50 * 1024 * 1024)
        self.repo_max_manifests = _int("REPO_MAX_MANIFESTS", 300)
        self.repo_scan_timeout = _int("REPO_SCAN_TIMEOUT_SECONDS", 180)
        # Alerts: destinations are read by app/alerts.py (from .env or Settings > Alerts).
        # Agent
        self.agent_max_report_bytes = _int("AGENT_MAX_REPORT_BYTES", 32 * 1024 * 1024)


settings = Settings()
