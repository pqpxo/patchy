import json

import pytest

from app import parsers as p
from app.repo_scanner import parse_github_url, safe_repo_path, validate_branch


def names(items):
    return {(i.name, i.version, i.version_status) for i in items}


def test_package_json_constraints_vs_exact():
    out = p.parse_package_json(json.dumps({"dependencies": {"express": "^4.18.0", "left-pad": "1.3.0"},
                                           "engines": {"node": ">=18"}}))
    assert ("express", None, "constraint") in names(out)
    assert ("left-pad", "1.3.0", "exact") in names(out)
    assert any(i.name == "node" and i.component_type == "language" for i in out)


def test_package_lock_v3_and_v1():
    v3 = {"packages": {"": {"name": "app"}, "node_modules/lodash": {"version": "4.17.20"},
                       "node_modules/a/node_modules/lodash": {"version": "3.10.1"},
                       "node_modules/linked": {"link": True}}}
    assert names(p.parse_package_lock(json.dumps(v3))) == {("lodash", "4.17.20", "exact"), ("lodash", "3.10.1", "exact")}
    v1 = {"dependencies": {"a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}}}
    assert names(p.parse_package_lock(json.dumps(v1))) == {("a", "1.0.0", "exact"), ("b", "2.0.0", "exact")}


def test_yarn_v1_and_berry():
    v1 = '"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.22.5"\n  resolved "x"\n'
    berry = '"lodash@npm:^4.17.0":\n  version: 4.17.21\n'
    assert names(p.parse_yarn_lock(v1)) == {("@babel/core", "7.22.5", "exact")}
    assert names(p.parse_yarn_lock(berry)) == {("lodash", "4.17.21", "exact")}


def test_pnpm_lock_versions():
    text = "lockfileVersion: '9.0'\npackages:\n  '@types/node@20.1.0':\n    resolution: {}\n  lodash@4.17.21:\n" \
           "    resolution: {}\n  /react@18.2.0(x@1):\n    x: 1\nsnapshots:\n  lodash@4.17.21: {}\n"
    assert names(p.parse_pnpm_lock(text)) == {("@types/node", "20.1.0", "exact"), ("lodash", "4.17.21", "exact"),
                                              ("react", "18.2.0", "exact")}


def test_requirements():
    text = "# c\nDjango==4.2.1  # pinned\nrequests>=2.0\n-r other.txt\ngit+https://x/y.git\nflask[async]==2.3.2 ; python_version>'3'\n"
    out = names(p.parse_requirements(text))
    assert ("Django", "4.2.1", "exact") in out and ("flask", "2.3.2", "exact") in out
    assert ("requests", None, "constraint") in out and len(out) == 3


def test_pyproject_and_locks():
    pp = '[project]\nrequires-python=">=3.11"\ndependencies=["fastapi==0.110.0","httpx>=0.27"]\n' \
         '[tool.poetry.dependencies]\npython="^3.11"\nrich="^13"\n'
    out = names(p.parse_pyproject(pp))
    assert ("fastapi", "0.110.0", "exact") in out and ("rich", None, "constraint") in out
    lock = '[[package]]\nname="me"\nversion="0.1"\nsource={editable="."}\n[[package]]\nname="idna"\nversion="3.7"\n'
    assert names(p.parse_toml_lock_packages(lock, "PyPI")) == {("idna", "3.7", "exact")}
    pl = {"default": {"urllib3": {"version": "==2.0.4"}}, "develop": {"pytest": {"version": "*"}}}
    assert ("urllib3", "2.0.4", "exact") in names(p.parse_pipfile_lock(json.dumps(pl)))


def test_go_mod():
    text = "module x\n\ngo 1.21\n\nrequire golang.org/x/net v0.17.0\nrequire (\n\tgithub.com/a/b v1.2.3 // indirect\n)\n"
    out = names(p.parse_go_mod(text))
    assert ("golang.org/x/net", "v0.17.0", "exact") in out and ("github.com/a/b", "v1.2.3", "exact") in out


def test_cargo_and_composer():
    lock = '[[package]]\nname="me"\nversion="0.1.0"\n[[package]]\nname="serde"\nversion="1.0.190"\nsource="registry+x"\n'
    assert names(p.parse_toml_lock_packages(lock, "crates.io")) == {("serde", "1.0.190", "exact")}
    cl = {"packages": [{"name": "symfony/http-kernel", "version": "v6.3.1"}], "packages-dev": []}
    assert names(p.parse_composer_lock(json.dumps(cl))) == {("symfony/http-kernel", "6.3.1", "exact")}
    cj = {"require": {"php": ">=8.1", "ext-json": "*", "monolog/monolog": "^3.0"}}
    assert {i.name for i in p.parse_composer_json(json.dumps(cj))} == {"php", "monolog/monolog"}


def test_pom_resolves_properties_and_refuses_entities():
    pom = """<project xmlns="http://maven.apache.org/POM/4.0.0"><properties><log4j.version>2.14.1</log4j.version>
    </properties><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId>
    <version>${log4j.version}</version></dependency><dependency><groupId>g</groupId><artifactId>managed</artifactId>
    </dependency></dependencies></project>"""
    out = names(p.parse_pom(pom))
    assert ("org.apache.logging.log4j:log4j-core", "2.14.1", "exact") in out
    assert ("g:managed", None, "unknown") in out
    evil = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><project>&a;</project>'
    with pytest.raises(ValueError):
        p.parse_pom(evil)


def test_gradle_gemfile_docker():
    assert ("com.google.guava:guava", "31.1-jre", "exact") in names(
        p.parse_gradle('implementation "com.google.guava:guava:31.1-jre"'))
    gl = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.7)\n      x (>= 1)\n\nPLATFORMS\n"
    assert names(p.parse_gemfile_lock(gl)) == {("rack", "2.2.7", "exact")}
    df = "FROM python:3.12-slim AS build\nFROM build\nFROM --platform=$X nginx:latest\nFROM scratch\n"
    out = names(p.parse_dockerfile(df))
    assert ("python", "3.12-slim", "exact") in out and ("nginx", None, "unknown") in out and len(out) == 2


def test_lockfile_supersedes_manifest_constraint():
    items = [p.Parsed("lodash", "library", "npm", version_spec="^4", version_status="constraint", path="web/package.json"),
             p.Parsed("lodash", "library", "npm", version="4.17.21", version_status="exact", path="web/package-lock.json"),
             p.Parsed("axios", "library", "npm", version_spec="^1", version_status="constraint", path="web/package.json")]
    assert {(i.name, i.version_status) for i in p.drop_constraints_covered_by_lockfiles(items)} == \
        {("lodash", "exact"), ("axios", "constraint")}


def test_parser_dispatch():
    assert p.parser_for("api/requirements-dev.txt") is p.parse_requirements
    assert p.parser_for("deploy/nginx/site.conf") is not None
    assert p.parser_for("src/main.py") is None


@pytest.mark.parametrize("path,ok", [("a/b/package.json", True), ("../etc/passwd", False), ("/abs", False),
                                     ("a/./b", False), ("a\\b", False), ("a/../b", False), ("a\x00b", False)])
def test_safe_repo_path(path, ok):
    assert safe_repo_path(path) is ok


def test_github_url_validation():
    assert parse_github_url("https://github.com/pqpxo/patchy.git") == ("pqpxo", "patchy")
    for bad in ("http://github.com/a/b", "https://evil.com/a/b", "https://github.com/a/b/c", "https://github.com/../b",
                "https://github.com/a/..", "git@github.com:a/b.git"):
        with pytest.raises(ValueError):
            parse_github_url(bad)
    with pytest.raises(ValueError):
        validate_branch("../../x")
