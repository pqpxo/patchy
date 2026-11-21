import pytest

from app import matching as m


@pytest.mark.parametrize("a,b,expected", [
    ("1.2.3", "1.2.4", -1), ("1.10.0", "1.9.0", 1), ("v1.2.3", "1.2.3", 0),
    ("1.0.0-alpha", "1.0.0", -1), ("1.0.0-alpha.1", "1.0.0-alpha.beta", -1), ("1.0.0-rc.1", "1.0.0-beta.11", 1),
])
def test_semver(a, b, expected):
    assert m.cmp_semver(a, b) == expected


def test_semver_unparseable_is_none():
    assert m.cmp_semver("1.2", "1.2.0") is None


@pytest.mark.parametrize("a,b,expected", [
    ("2.0.0", "2.0.0rc1", 1), ("1.0.post1", "1.0", 1), ("1.0", "1.0.0", 0), ("1!0.1", "2.0", 1),
])
def test_pep440(a, b, expected):
    assert m.cmp_pypi(a, b) == expected


@pytest.mark.parametrize("a,b,expected", [
    ("3.0.11-1~deb12u2", "3.0.11-1", -1),  # tilde sorts before anything
    ("1:1.0-1", "2.0-1", 1),               # epoch wins
    ("1.2.3-1", "1.2.3-1+deb12u1", -1),
    ("2.36-9+deb12u4", "2.36-9+deb12u10", -1),
    ("1.0", "1.0", 0), ("1.0a", "1.0", 1),
])
def test_dpkg(a, b, expected):
    assert m.cmp_dpkg(a, b) == expected


def _aff(eco, name, events, rtype="ECOSYSTEM", versions=None):
    entry = {"package": {"ecosystem": eco, "name": name}, "ranges": [{"type": rtype, "events": events}]}
    if versions:
        entry["versions"] = versions
    return [entry]


RANGE = [{"introduced": "0"}, {"fixed": "2.31.0"}]


def test_confirmed_inside_range():
    r = m.evaluate(_aff("PyPI", "requests", RANGE), "PyPI", "requests", "2.30.0")
    assert r.status == m.CONFIRMED and r.fixed_versions == ["2.31.0"] and "2.30.0" in r.evidence


def test_fixed_version_not_affected():
    assert m.evaluate(_aff("PyPI", "requests", RANGE), "PyPI", "requests", "2.31.0").status == m.NOT_AFFECTED


def test_multiple_ranges_and_last_affected():
    events = [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}, {"introduced": "2.0.0"}, {"last_affected": "2.1.0"}]
    aff = _aff("npm", "lib", events, "SEMVER")
    assert m.evaluate(aff, "npm", "lib", "0.9.0").status == m.NOT_AFFECTED
    assert m.evaluate(aff, "npm", "lib", "1.1.5").status == m.CONFIRMED
    assert m.evaluate(aff, "npm", "lib", "1.5.0").status == m.NOT_AFFECTED
    assert m.evaluate(aff, "npm", "lib", "2.1.0").status == m.CONFIRMED
    assert m.evaluate(aff, "npm", "lib", "2.1.1").status == m.NOT_AFFECTED


def test_unknown_version_is_not_dismissed():
    r = m.evaluate(_aff("PyPI", "requests", RANGE), "PyPI", "requests", None, "unknown")
    assert r.status == m.UNKNOWN_VERSION


def test_constraint_is_unknown_version_not_confirmed():
    r = m.evaluate(_aff("PyPI", "requests", RANGE), "PyPI", "requests", ">=2.0", "constraint")
    assert r.status == m.UNKNOWN_VERSION and "constraint" in r.evidence


def test_non_matching_package_and_similar_names():
    aff = _aff("PyPI", "requests", RANGE)
    assert m.evaluate(aff, "PyPI", "requests-oauthlib", "1.0.0") is None
    assert m.evaluate(aff, "npm", "requests", "1.0.0") is None  # same name, different ecosystem


def test_pypi_name_normalisation():
    aff = _aff("PyPI", "Foo_Bar", RANGE)
    assert m.evaluate(aff, "PyPI", "foo-bar", "1.0").status == m.CONFIRMED


def test_distro_release_must_match():
    aff = _aff("Debian:12", "openssl", [{"introduced": "0"}, {"fixed": "3.0.11-1~deb12u2"}])
    assert m.evaluate(aff, "Debian:11", "openssl", "1.1.1n-0+deb11u5") is None
    assert m.evaluate(aff, "Debian:12", "openssl", "3.0.11-1~deb12u1").status == m.CONFIRMED
    assert m.evaluate(aff, "Debian:12", "openssl", "3.0.11-1~deb12u2").status == m.NOT_AFFECTED


def test_explicit_versions_list():
    aff = _aff("Maven", "org.x:lib", [{"introduced": "0"}, {"fixed": "2.0"}], versions=["1.0", "1.5"])
    assert m.evaluate(aff, "Maven", "org.x:lib", "1.5").status == m.CONFIRMED


def test_unsupported_ecosystem_relies_on_osv_or_stays_possible():
    aff = _aff("Maven", "org.x:lib", [{"introduced": "0"}, {"fixed": "2.0"}])
    assert m.evaluate(aff, "Maven", "org.x:lib", "1.7").status == m.POSSIBLE
    assert m.evaluate(aff, "Maven", "org.x:lib", "1.7", osv_hit=True).status == m.CONFIRMED
    assert m.evaluate(aff, "Maven", "org.x:lib", "2.1", osv_hit=False).status == m.NOT_AFFECTED


def test_git_only_ranges_are_possible():
    aff = _aff("Go", "example.com/x", [{"introduced": "0"}, {"fixed": "abc123"}], "GIT")
    assert m.evaluate(aff, "Go", "example.com/x", "v1.0.0").status == m.POSSIBLE


def test_local_vs_osv_disagreement_is_flagged():
    r = m.evaluate(_aff("PyPI", "requests", RANGE), "PyPI", "requests", "2.32.0", osv_hit=True)
    assert r.status == m.POSSIBLE


@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss3(vector, score):
    assert m.cvss3_base_score(vector) == score


def test_severity_never_guessed():
    assert m.severity_from_osv({}) == ("unknown", None, None, None)
    assert m.severity_from_osv({"database_specific": {"severity": "MODERATE"}})[0] == "medium"


def test_fixed_versions_sorted_by_version_not_string():
    aff = [{"package": {"ecosystem": "npm", "name": "x"}, "ranges": [{"type": "SEMVER", "events": [
        {"introduced": "0"}, {"fixed": "10.0.0"}, {"introduced": "3.0.0"}, {"fixed": "2.5.4"}]}]}]
    assert m.evaluate(aff, "npm", "x", "1.0.0").fixed_versions == ["2.5.4", "10.0.0"]
