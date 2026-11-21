"""v1.1 sources: end-of-life, NVD CPE matching, Dependabot cross-check and schedules (mocked HTTP)."""
from datetime import date, timedelta

import httpx

from app import cpe, dependabot, eol, sources, vulns
from app.db import utcnow
from app.models import Advisory, Component, FeedStatus, Finding, Host, Repository

TODAY = date(2026, 11, 21)
EOL_DUMP = {"result": [
    {"name": "django", "label": "Django", "aliases": [], "identifiers": [{"type": "purl", "id": "pkg:pypi/django"}],
     "releases": [{"name": "5.2", "isEol": False, "eolFrom": "2028-04-30", "latest": {"name": "5.2.8"}},
                  {"name": "3.2", "isEol": True, "eolFrom": "2024-04-01", "latest": {"name": "3.2.25"}}]},
    {"name": "python", "label": "Python", "aliases": [], "identifiers": [],
     "releases": [{"name": "3.12", "isEol": False, "eolFrom": "2028-10-31", "latest": {"name": "3.12.12"}},
                  {"name": "3.10", "isEol": False, "eolFrom": (TODAY + timedelta(days=30)).isoformat()}]},
    {"name": "nginx", "label": "nginx", "aliases": [],
     "identifiers": [{"type": "cpe", "id": "cpe:2.3:a:f5:nginx"}, {"type": "purl", "id": "pkg:generic/nginx"}],
     "releases": [{"name": "1.22", "isEol": True, "eolFrom": "2023-05-01"}]},
    {"name": "debian", "label": "Debian", "aliases": [], "identifiers": [{"type": "cpe", "id": "cpe:2.3:o:debian:debian_linux"}],
     "releases": [{"name": "12", "isEol": False, "eolFrom": "2028-06-30"}, {"name": "11", "isEol": True, "eolFrom": "2026-08-31"}]},
]}

NGINX_CVE = {"id": "CVE-2023-44487", "published": "2023-10-10T14:15:10.883", "lastModified": "2025-01-01T00:00:00",
             "vulnStatus": "Analyzed",
             "descriptions": [{"lang": "en", "value": "The HTTP/2 protocol allows a denial of service. More text."}],
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N/AC:L"}}]},
             "references": [{"url": "https://nginx.org/x"}, {"url": "ftp://bad"}],
             "configurations": [{"nodes": [{"cpeMatch": [
                 {"vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                  "versionStartIncluding": "1.9.5", "versionEndExcluding": "1.25.3"},
                 {"vulnerable": True, "criteria": "cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*"}]}]}]}


# nginx appears only as a non-vulnerable platform, so this CVE must not become a finding.
PLATFORM_ONLY = {"id": "CVE-2020-0001", "descriptions": [], "configurations": [{"nodes": [{"cpeMatch": [
    {"vulnerable": True, "criteria": "cpe:2.3:a:acme:plugin:1.0:*:*:*:*:*:*:*"},
    {"vulnerable": False, "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}]}]}]}


def handler(calls):
    def h(req: httpx.Request):
        calls.append(req)
        if req.url.path == "/api/v1/products/full":
            return httpx.Response(200, json=EOL_DUMP)
        if req.url.path == "/rest/json/cves/2.0":
            match = req.url.params["virtualMatchString"]
            vulns_ = [{"cve": NGINX_CVE}, {"cve": PLATFORM_ONLY}] if match == "cpe:2.3:a:f5:nginx:1.22.1" else []
            return httpx.Response(200, json={"totalResults": len(vulns_), "vulnerabilities": vulns_})
        return httpx.Response(404)
    return h


def add(db, **kw):
    c = Component(**{"component_type": "library", "version_status": "exact", "source": "manual", **kw})
    db.add(c)
    db.flush()
    return c


def test_eol_states_for_components_and_host_os(db):
    host = Host(name="pi", os_id="debian", os_version="11")
    db.add(host)
    db.flush()
    django = add(db, name="Django", ecosystem="PyPI", version="3.2.1")
    py = add(db, name="python", component_type="language", version="3.12.4")
    old_py = add(db, name="python3", component_type="language", version="3.10.2")
    image = add(db, name="python", component_type="container_image", version="3.12-slim")
    probe = add(db, name="nginx", component_type="web_server", version="1.22.1", source="agent", host_id=host.id)
    add(db, name="nginx", component_type="os_package", ecosystem="Debian:11", version="1.18.0-6", source="agent",
        host_id=host.id, details={"binaries": ["nginx", "nginx-common"]})
    unknown_lib = add(db, name="django-extensions", ecosystem="PyPI", version="3.2.1")
    eol.refresh_eol(db, httpx.Client(transport=httpx.MockTransport(handler([]))))
    eol.apply(db, db.query(Component).all(), today=TODAY)
    assert django.eol_state == "eol" and django.eol["newest_supported"] == "5.2"
    assert py.eol_state == "supported" and py.eol["latest_in_cycle"] == "3.12.12"
    assert old_py.eol_state == "eol_soon"  # python3 maps to python; under 90 days left
    assert image.eol_state is None  # image purl not listed for this product in the fixture
    assert probe.eol_state is None  # distro-packaged: Debian supports it, not upstream nginx
    assert unknown_lib.eol_state is None  # libraries only match by package URL, never by name
    assert host.os_eol_state == "eol" and host.os_eol["cycle"] == "11"


def test_cpe_targets_and_possible_match(db):
    calls = []
    client = httpx.Client(transport=httpx.MockTransport(handler(calls)))
    nginx = add(db, name="nginx", component_type="web_server", version="1.22.1")
    ssh = add(db, name="openssh", component_type="other", version="9.2p1")
    lib = add(db, name="requests", ecosystem="PyPI", version="2.0.0")
    image = add(db, name="nginx", component_type="container_image", version="1.22.1")
    assert cpe.targets_for(ssh, {}, None) == [("openbsd:openssh", "9.2:p1")]
    assert cpe.targets_for(lib, {}, None) == [] and cpe.targets_for(image, {}, None) == []
    summary = cpe.refresh_cpe(db, client, "full", sleep=lambda s: None)
    assert summary["cves_found"] == 1  # the platform-only CVE is dropped
    assert cpe.covers({"start_incl": "1.9.5", "end_excl": "1.25.3"}, "1.22.1")
    assert not cpe.covers({"start_incl": "3.11.0", "end_excl": "3.11.10"}, "3.10.12")
    assert cpe.covers({"version": "9.2:p1"}, "9.2:p1")
    assert {c.url.params["virtualMatchString"] for c in calls} == {
        "cpe:2.3:a:f5:nginx:1.22.1", "cpe:2.3:a:nginx:nginx:1.22.1", "cpe:2.3:a:openbsd:openssh:9.2:p1"}
    vulns.rematch(db)
    db.commit()
    f = db.query(Finding).filter_by(component_id=nginx.id).one()
    assert f.match_status == "possible" and f.fixed_versions == ["1.25.3"]
    assert "backport" in f.evidence and "NVD product data" in f.remediation
    assert f.affected_ranges == [">= 1.9.5, < 1.25.3"]
    adv = db.get(Advisory, "CVE-2023-44487")
    assert adv.severity == "high" and [r["url"] for r in adv.references] == ["https://nginx.org/x"]
    db.refresh(nginx)
    assert nginx.vuln_checked_at is not None
    # An OSV record for the same id keeps the NVD product entry, so the match survives.
    vulns.upsert_advisory(db, {"id": "CVE-2023-44487", "affected": []})
    vulns.rematch(db)
    db.refresh(f)
    assert f.currently_matching and f.status == "open"
    # Upgrading past the fix resolves it once NVD no longer lists the new version.
    nginx.version = "1.25.3"
    db.commit()
    cpe.refresh_cpe(db, client, "pending", sleep=lambda s: None)
    vulns.rematch(db)
    db.refresh(f)
    assert f.status == "resolved" and f.status_changed_by == "system"


def test_dependabot_cross_check(db):
    repo = Repository(url="https://github.com/octo/app", owner="octo", name="app")
    other = Repository(url="https://github.com/octo/locked", owner="octo", name="locked")
    db.add_all([repo, other])
    db.flush()
    c = add(db, name="lodash", ecosystem="npm", version="4.17.20", repository_id=repo.id, source="repo")
    adv = Advisory(id="GHSA-aaaa-bbbb-cccc", aliases=["CVE-2021-23337"], cve_ids=["CVE-2021-23337"], affected=[])
    db.add(adv)
    db.flush()
    db.add(Finding(component_id=c.id, advisory_id=adv.id, match_status="confirmed", evidence="x", remediation="r",
                   currently_matching=True, first_detected_at=utcnow()))
    db.commit()

    def gh(req):
        if req.url.path == "/repos/octo/locked/dependabot/alerts":
            return httpx.Response(403)
        return httpx.Response(200, json=[
            {"number": 1, "html_url": "https://github.com/octo/app/security/dependabot/1",
             "security_advisory": {"ghsa_id": "GHSA-aaaa-bbbb-cccc", "cve_id": "CVE-2021-23337", "summary": "s"},
             "security_vulnerability": {"severity": "high", "vulnerable_version_range": "< 4.17.21",
                                        "first_patched_version": {"identifier": "4.17.21"}},
             "dependency": {"package": {"ecosystem": "npm", "name": "lodash"}, "manifest_path": "package-lock.json"}},
            {"number": 2, "html_url": "javascript:alert(1)", "security_advisory": {"ghsa_id": "GHSA-zzzz-zzzz-zzzz"},
             "security_vulnerability": {}, "dependency": {"package": {"name": "minimist"}}}])

    summary = dependabot.refresh_dependabot(db, httpx.Client(transport=httpx.MockTransport(gh)))
    assert summary == {"repositories_checked": 1, "repositories_failed": 1}
    assert repo.dependabot["also_in_patchy"] == 1 and repo.dependabot["total"] == 2
    assert repo.dependabot["alerts"][1]["url"] is None  # only github.com links are kept
    assert "Dependabot alerts: read" in other.dependabot["error"]
    f = db.query(Finding).one()
    assert dependabot.for_finding(f)["number"] == 1


def test_schedule_defaults_overrides_and_due(db):
    s = sources.schedule(db)
    assert s["osv"]["enabled"] and s["osv"]["hours"] == 24 and s["eol"]["hours"] == 168
    assert s["dependabot"]["enabled"]  # conftest sets GITHUB_TOKEN
    assert sources.due(db)[0] == "kev"  # never run: everything enabled is due, in dependency order
    sources.save(db, {"osv": {"hours": 6}, "kev": {"enabled": False}})
    now = utcnow()
    for key in sources.ORDER:
        db.add(FeedStatus(source=key, last_attempt_at=now - timedelta(hours=7)))
    db.flush()
    s = sources.schedule(db)
    assert s["osv"]["hours"] == 6 and not s["kev"]["enabled"]
    assert sources.due(db) == ["osv"]  # 7h since last attempt: only the 6-hourly source is due
