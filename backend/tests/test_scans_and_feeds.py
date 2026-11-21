"""Repo scanning and feed refresh with mocked HTTP (no live network)."""
import json

import httpx

from app import repo_scanner, vulns, worker
from app.models import Advisory, Component, FeedStatus, Finding, Repository, ScanRun
from app.config import settings

SHA = "a" * 40
LOCK = json.dumps({"packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}}})


def github_handler(calls):
    def handler(req: httpx.Request):
        calls.append(req)
        path = req.url.path
        if path == "/repos/octo/app":
            return httpx.Response(200, json={"default_branch": "main", "private": False})
        if path == "/repos/octo/app/languages":
            return httpx.Response(200, json={"JavaScript": 1000})
        if path == "/repos/octo/app/commits/main":
            return httpx.Response(200, text=SHA)
        if path == f"/repos/octo/app/git/trees/{SHA}":
            return httpx.Response(200, json={"truncated": False, "tree": [
                {"path": "package-lock.json", "type": "blob", "size": 100},
                {"path": "package.json", "type": "blob", "size": 50},
                {"path": "huge/package-lock.json", "type": "blob", "size": 10**9},
                {"path": "bad/pom.xml", "type": "blob", "size": 10},
                {"path": "node_modules/x/package.json", "type": "blob", "size": 10},
                {"path": "src/index.js", "type": "blob", "size": 10},
            ]})
        if path == "/repos/octo/app/contents/package-lock.json":
            return httpx.Response(200, text=LOCK)
        if path == "/repos/octo/app/contents/package.json":
            return httpx.Response(200, text=json.dumps({"dependencies": {"lodash": "^4.17.0", "express": "^4"}}))
        if path == "/repos/octo/app/contents/bad/pom.xml":
            return httpx.Response(200, text="<!DOCTYPE x [<!ENTITY secret SYSTEM 'file:///etc/passwd'>]><project/>")
        return httpx.Response(404)
    return handler


def test_repo_scan_records_provenance_and_limits(db):
    repo = Repository(url="https://github.com/octo/app", owner="octo", name="app")
    db.add(repo)
    db.flush()
    run, _ = worker.enqueue(db, "repo", repository_id=repo.id)
    db.commit()
    calls = []
    run = worker.claim(db)
    worker.execute(db, run, gh_client=repo_scanner.github_client(httpx.MockTransport(github_handler(calls))))
    db.refresh(run)
    assert run.status == "partial" and run.revision == SHA
    reasons = {s["path"]: s["reason"] for s in run.summary["skipped"]}
    assert "REPO_MAX_FILE_BYTES" in reasons["huge/package-lock.json"]
    assert reasons["bad/pom.xml"] == "could not parse (ValueError)"  # no content echoed
    assert not any("node_modules/x" in c.url.path for c in calls)
    comps = {c.name: c for c in db.query(Component).filter_by(repository_id=repo.id)}
    assert comps["lodash"].version == "4.17.20" and comps["lodash"].version_status == "exact"
    assert [p.path for p in comps["lodash"].paths] == ["package-lock.json"]
    assert comps["express"].version_status == "constraint"
    assert comps["JavaScript"].component_type == "language"
    # Token is sent to GitHub but never stored.
    assert calls[0].headers["authorization"] == f"Bearer {settings.github_token}"
    assert settings.github_token not in json.dumps(run.summary)
    # A pending feed refresh was queued for the new inventory.
    assert db.query(ScanRun).filter_by(kind="feed", status="queued").count() == 1


def test_repo_scan_not_found_gives_clear_error(db):
    repo = Repository(url="https://github.com/octo/private", owner="octo", name="private")
    db.add(repo)
    db.flush()
    worker.enqueue(db, "repo", repository_id=repo.id)
    db.commit()
    run = worker.claim(db)
    worker.execute(db, run, gh_client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(404))))
    db.refresh(run)
    assert run.status == "failed" and "GITHUB_TOKEN" in run.error


def test_duplicate_scan_requests_are_idempotent(db):
    repo = Repository(url="https://github.com/octo/app", owner="octo", name="app")
    db.add(repo)
    db.flush()
    a, created_a = worker.enqueue(db, "repo", repository_id=repo.id)
    b, created_b = worker.enqueue(db, "repo", repository_id=repo.id)
    assert created_a and not created_b and a.id == b.id


OSV_RECORD = {
    "id": "GHSA-test-0001", "aliases": ["CVE-2021-23337"], "summary": "Command injection in lodash",
    "published": "2021-02-15T00:00:00Z", "modified": "2024-01-01T00:00:00Z",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                  "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
    "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-test-0001"},
                   {"type": "WEB", "url": "javascript:alert(1)"}],
}


def osv_handler(fail=False):
    def handler(req: httpx.Request):
        if "cisa.gov" in req.url.host:
            return httpx.Response(200, json={"catalogVersion": "t", "vulnerabilities": [
                {"cveID": "CVE-2021-23337", "dateAdded": "2024-01-01", "dueDate": "2024-01-22",
                 "requiredAction": "Apply updates per vendor instructions."}]})
        if fail:
            return httpx.Response(503)
        if req.url.path == "/v1/querybatch":
            qs = json.loads(req.content)["queries"]
            return httpx.Response(200, json={"results": [
                {"vulns": [{"id": "GHSA-test-0001"}]} if q["package"]["name"] == "lodash" and q.get("version") != "4.17.21" else {} for q in qs]})
        if req.url.path == "/v1/vulns/GHSA-test-0001":
            return httpx.Response(200, json=OSV_RECORD)
        return httpx.Response(404)
    return handler


def _component(db, name="lodash", version="4.17.20", status="exact"):
    c = Component(name=name, component_type="library", ecosystem="npm", version=version, version_status=status,
                  source="manual")
    db.add(c)
    db.commit()
    return c


def test_feed_refresh_matches_flags_kev_and_resolves_on_upgrade(db):
    c = _component(db)
    unknown = _component(db, version=None, status="unknown")
    other = _component(db, name="left-pad", version="1.3.0")
    client = httpx.Client(transport=httpx.MockTransport(osv_handler()))
    summary = vulns.run_feed_refresh(db, client, "full")
    assert summary["failed_sources"] == []
    adv = db.get(Advisory, "GHSA-test-0001")
    assert adv.kev and adv.severity == "high" and adv.cvss_score == 7.2
    assert [r["url"] for r in adv.references] == ["https://github.com/advisories/GHSA-test-0001"]  # unsafe scheme dropped
    f = db.query(Finding).filter_by(component_id=c.id).one()
    assert f.match_status == "confirmed" and f.fixed_versions == ["4.17.21"]
    assert "4.17.21" in f.remediation and "CISA KEV" in f.remediation
    assert db.query(Finding).filter_by(component_id=unknown.id).one().match_status == "unknown_version"
    assert db.query(Finding).filter_by(component_id=other.id).count() == 0
    db.refresh(other)
    assert other.vuln_checked_at is not None  # checked and clean, distinguishable from unchecked

    c.version = "4.17.21"
    db.commit()
    vulns.run_feed_refresh(db, client, "pending")
    db.refresh(f)
    assert f.status == "resolved" and f.status_changed_by == "system" and not f.currently_matching


def test_feed_failure_is_recorded_and_not_reported_as_clean(db):
    c = _component(db)
    summary = vulns.run_feed_refresh(db, httpx.Client(transport=httpx.MockTransport(osv_handler(fail=True))), "full")
    assert summary["failed_sources"] == ["osv"]
    st = db.get(FeedStatus, "osv")
    assert st.last_error and st.last_success_at is None
    db.refresh(c)
    assert c.vuln_checked_at is None and vulns.feed_is_stale(db)
