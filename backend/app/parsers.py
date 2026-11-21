"""Dependency/manifest parsers for repository scanning.

All input is untrusted text. Parsers only read structured data: no code is executed, no network,
no filesystem. XML with DOCTYPE/ENTITY declarations is refused outright.
"""
from __future__ import annotations

import json
import posixpath
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from packaging.requirements import InvalidRequirement, Requirement


@dataclass
class Parsed:
    name: str
    component_type: str
    ecosystem: str | None
    version: str | None = None
    version_status: str = "unknown"  # exact|constraint|unknown
    version_spec: str | None = None
    path: str = ""
    path_kind: str = "manifest"
    details: dict = field(default_factory=dict)


def _exact(name, eco, version, ctype="library", **kw) -> Parsed:
    return Parsed(name=name, component_type=ctype, ecosystem=eco, version=version, version_status="exact", **kw)


def _spec(name, eco, spec, ctype="library", **kw) -> Parsed:
    spec = (spec or "").strip() or None
    return Parsed(name=name, component_type=ctype, ecosystem=eco, version_spec=spec,
                  version_status="constraint" if spec else "unknown", **kw)


_NPM_EXACT = re.compile(r"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")


# ---------- JavaScript ----------

def parse_package_json(text: str) -> list[Parsed]:
    data = json.loads(text)
    out = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in (data.get(section) or {}).items():
            if not isinstance(spec, str):
                continue
            if _NPM_EXACT.match(spec):
                out.append(_exact(name, "npm", spec.lstrip("v"), details={"section": section}))
            else:
                out.append(_spec(name, "npm", spec, details={"section": section}))
    node = (data.get("engines") or {}).get("node")
    if isinstance(node, str):
        out.append(_spec("node", None, node, "language"))
    return out


def parse_package_lock(text: str) -> list[Parsed]:
    data = json.loads(text)
    out = []
    if isinstance(data.get("packages"), dict):  # lockfile v2/v3
        for key, meta in data["packages"].items():
            if not key or "node_modules/" not in key or not isinstance(meta, dict):
                continue
            if meta.get("link") or not meta.get("version"):
                continue
            name = meta.get("name") or key.rsplit("node_modules/", 1)[1]
            out.append(_exact(name, "npm", meta["version"], details={"install_path": key}))
        return out

    def walk(deps):  # lockfile v1
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict) and meta.get("version"):
                out.append(_exact(name, "npm", meta["version"]))
                walk(meta.get("dependencies"))
    walk(data.get("dependencies"))
    return out


def _split_at_version(spec: str) -> tuple[str, str]:
    at = spec.rfind("@")
    return (spec[:at], spec[at + 1:]) if at > 0 else (spec, "")


def parse_yarn_lock(text: str) -> list[Parsed]:
    out, name = [], None
    for line in text.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":") and not line.startswith("#"):
            first = line.rstrip(":").split(",")[0].strip().strip('"')
            name = None if "@workspace:" in first or "@patch:" in first else _split_at_version(first)[0]
        elif name and (m := re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)):
            out.append(_exact(name, "npm", m.group(1)))
            name = None
    return out


def parse_pnpm_lock(text: str) -> list[Parsed]:
    out, in_packages = [], False
    for line in text.splitlines():
        if line and not line[0].isspace():
            in_packages = line.startswith("packages:")
            continue
        m = re.match(r"^  (['\"]?)(/?[^\s'\"]+)\1:\s*$", line) if in_packages else None
        if not m:
            continue
        key = re.sub(r"\(.*$", "", m.group(2)).lstrip("/")
        name, version = _split_at_version(key)
        if not version:  # pnpm v5: /name/1.2.3
            name, _, version = key.rpartition("/")
        version = version.split("_")[0]
        if name and version:
            out.append(_exact(name, "npm", version))
    return out


# ---------- Python ----------

def _from_pep508(line: str) -> Parsed | None:
    try:
        req = Requirement(line)
    except InvalidRequirement:
        return None
    specs = list(req.specifier)
    if len(specs) == 1 and specs[0].operator in ("==", "===") and "*" not in specs[0].version:
        return _exact(req.name, "PyPI", specs[0].version)
    return _spec(req.name, "PyPI", str(req.specifier))


def parse_requirements(text: str) -> list[Parsed]:
    out = []
    for raw in text.splitlines():
        line = re.split(r"\s+#", raw.strip(), maxsplit=1)[0].strip()
        if not line or line.startswith(("#", "-", "git+", "http:", "https:", "file:", ".")):
            continue
        line = line.split(" --hash", 1)[0].rstrip("\\ ").strip()
        p = _from_pep508(line)
        if p:
            out.append(p)
    return out


def parse_pyproject(text: str) -> list[Parsed]:
    data = tomllib.loads(text)
    out = []
    project = data.get("project") or {}
    lines = list(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():
        lines += group
    for group in (data.get("dependency-groups") or {}).values():
        lines += [g for g in group if isinstance(g, str)]
    out += [p for p in map(_from_pep508, lines) if p]
    if project.get("requires-python"):
        out.append(_spec("python", None, project["requires-python"], "language"))
    poetry = ((data.get("tool") or {}).get("poetry") or {})
    for name, spec in (poetry.get("dependencies") or {}).items():
        if isinstance(spec, dict):
            spec = spec.get("version", "")
        if name.lower() == "python":
            out.append(_spec("python", None, spec, "language"))
        elif isinstance(spec, str):
            out.append(_spec(name, "PyPI", spec))
    return out


def parse_toml_lock_packages(text: str, eco: str) -> list[Parsed]:
    """poetry.lock, uv.lock, Cargo.lock: [[package]] tables with name + version."""
    out = []
    for pkg in tomllib.loads(text).get("package") or []:
        src = pkg.get("source")
        if isinstance(src, dict) and ({"editable", "virtual", "path", "workspace"} & src.keys()):
            continue  # the project itself, not a dependency
        if eco == "crates.io" and src is None:
            continue  # local workspace crate
        if pkg.get("name") and pkg.get("version"):
            out.append(_exact(pkg["name"], eco, str(pkg["version"])))
    return out


def parse_pipfile_lock(text: str) -> list[Parsed]:
    data = json.loads(text)
    out = []
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            v = (meta or {}).get("version", "") if isinstance(meta, dict) else ""
            out.append(_exact(name, "PyPI", v[2:]) if v.startswith("==") else _spec(name, "PyPI", v))
    return out


# ---------- Go ----------

def parse_go_mod(text: str) -> list[Parsed]:
    out, in_block = [], False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        m = re.match(r"^(?:require\s+)?(\S+)\s+(v\S+)$", line) if (in_block or line.startswith("require ")) else None
        if m:
            out.append(_exact(m.group(1), "Go", m.group(2)))
        elif m := re.match(r"^go\s+(\d+\.\d+(?:\.\d+)?)$", line):
            out.append(_spec("go", None, ">=" + m.group(1), "language"))
    return out


# ---------- Rust ----------

def parse_cargo_toml(text: str) -> list[Parsed]:
    data = tomllib.loads(text)
    out = []
    tables = [data.get(k) or {} for k in ("dependencies", "dev-dependencies", "build-dependencies")]
    tables.append(((data.get("workspace") or {}).get("dependencies")) or {})
    for table in tables:
        for name, spec in table.items():
            if isinstance(spec, dict):
                if "path" in spec or "git" in spec:
                    continue
                name, spec = spec.get("package", name), spec.get("version", "")
            if isinstance(spec, str):
                out.append(_spec(name, "crates.io", spec))
    return out


# ---------- PHP ----------

def _composer_skip(name: str) -> bool:
    return name in ("php", "composer") or name.startswith(("ext-", "lib-", "composer-"))


def parse_composer_json(text: str) -> list[Parsed]:
    data = json.loads(text)
    out = []
    for section in ("require", "require-dev"):
        for name, spec in (data.get(section) or {}).items():
            if name == "php":
                out.append(_spec("php", None, spec, "language"))
            elif not _composer_skip(name) and isinstance(spec, str):
                out.append(_spec(name, "Packagist", spec))
    return out


def parse_composer_lock(text: str) -> list[Parsed]:
    data = json.loads(text)
    return [_exact(p["name"], "Packagist", str(p["version"]).lstrip("v"))
            for section in ("packages", "packages-dev") for p in data.get(section) or []
            if p.get("name") and p.get("version")]


# ---------- Java ----------

def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_pom(text: str) -> list[Parsed]:
    if re.search(r"<!\s*(DOCTYPE|ENTITY)", text, re.IGNORECASE):
        raise ValueError("XML DOCTYPE/ENTITY declarations are not allowed")
    root = ET.fromstring(text)
    props = {}
    for el in root.iter():
        if _strip_ns(el.tag) == "properties":
            props.update({_strip_ns(c.tag): (c.text or "").strip() for c in el})
    out = []
    for dep in root.iter():
        if _strip_ns(dep.tag) != "dependency":
            continue
        f = {_strip_ns(c.tag): (c.text or "").strip() for c in dep}
        if not f.get("groupId") or not f.get("artifactId"):
            continue
        name = f"{f['groupId']}:{f['artifactId']}"
        v = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), f.get("version", ""))
        if not v or "${" in v:
            out.append(Parsed(name, "library", "Maven", details={"note": "version managed elsewhere or unresolved"}))
        elif v[0] in "[(":
            out.append(_spec(name, "Maven", v))
        else:
            out.append(_exact(name, "Maven", v))
    return out


_GRADLE = re.compile(r"""["']([\w.\-]+):([\w.\-]+):([\w.\-+\[\](),]+)["']""")


def parse_gradle(text: str) -> list[Parsed]:
    out = []
    for g, a, v in _GRADLE.findall(text):
        if "+" in v or v[0] in "[(" or v.startswith("latest."):
            out.append(_spec(f"{g}:{a}", "Maven", v))
        else:
            out.append(_exact(f"{g}:{a}", "Maven", v))
    return out


def parse_gradle_lockfile(text: str) -> list[Parsed]:
    out = []
    for line in text.splitlines():
        m = re.match(r"^([\w.\-]+):([\w.\-]+):([^=\s]+)=", line)
        if m:
            out.append(_exact(f"{m.group(1)}:{m.group(2)}", "Maven", m.group(3)))
    return out


# ---------- Ruby ----------

def parse_gemfile_lock(text: str) -> list[Parsed]:
    out, in_specs = [], False
    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if line and not line[0].isspace():
            in_specs = False
        m = re.match(r"^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)$", line) if in_specs else None
        if m:
            out.append(_exact(m.group(1), "RubyGems", m.group(2)))
    return out


# ---------- containers, runtimes, config ----------

def _image(ref: str, kind: str) -> Parsed | None:
    ref = ref.strip().strip("'\"")
    if not ref or ref == "scratch" or "$" in ref and ":" not in ref:
        return None
    ref = ref.split("@", 1)[0]
    last = ref.rsplit("/", 1)[-1]
    name, tag = (ref.rsplit(":", 1) if ":" in last else (ref, None))
    if tag and "$" not in tag and tag != "latest":
        return _exact(name, None, tag, "container_image", path_kind=kind)
    return Parsed(name, "container_image", None, version_spec=tag, path_kind=kind,
                  details={"note": "tag missing, 'latest' or set by build argument"})


def parse_dockerfile(text: str) -> list[Parsed]:
    out, stages = [], set()
    for line in text.splitlines():
        m = re.match(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", line, re.IGNORECASE)
        if not m:
            continue
        if m.group(1).lower() not in stages and (p := _image(m.group(1), "manifest")):
            out.append(p)
        if m.group(2):
            stages.add(m.group(2).lower())
    return out


def parse_compose(text: str) -> list[Parsed]:
    return [p for ref in re.findall(r"^\s*image:\s*['\"]?([^\s'\"#]+)", text, re.MULTILINE)
            if (p := _image(ref, "config"))]


def _runtime(name: str, version: str) -> Parsed:
    version = version.strip().lstrip("v")
    if re.match(r"^\d+\.\d+\.\d+$", version):
        return _exact(name, None, version, "language", path_kind="config")
    return _spec(name, None, version, "language", path_kind="config")


def parse_tool_versions(text: str) -> list[Parsed]:
    out = []
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2:
            out.append(_runtime({"nodejs": "node"}.get(parts[0], parts[0]), parts[1]))
    return out


def _single_runtime(name):
    def parse(text: str) -> list[Parsed]:
        first = text.strip().splitlines()[0] if text.strip() else ""
        return [_runtime(name, first)] if first and not first.startswith("#") else []
    return parse


def parse_runtime_txt(text: str) -> list[Parsed]:
    m = re.match(r"^\s*(python|ruby|php|node)-(\S+)", text)
    return [_runtime(m.group(1), m.group(2))] if m else []


def _config_marker(name):
    def parse(text: str) -> list[Parsed]:
        return [Parsed(name, "web_server", None, path_kind="config",
                       details={"note": "configuration file detected; server version not determinable from repo"})]
    return parse


EXACT_FILES = {
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "pyproject.toml": parse_pyproject,
    "poetry.lock": lambda t: parse_toml_lock_packages(t, "PyPI"),
    "uv.lock": lambda t: parse_toml_lock_packages(t, "PyPI"),
    "pipfile.lock": parse_pipfile_lock,
    "go.mod": parse_go_mod,
    "go.sum": lambda t: [],  # recorded as a manifest; go.mod holds the selected versions
    "cargo.toml": parse_cargo_toml,
    "cargo.lock": lambda t: parse_toml_lock_packages(t, "crates.io"),
    "composer.json": parse_composer_json,
    "composer.lock": parse_composer_lock,
    "pom.xml": parse_pom,
    "build.gradle": parse_gradle,
    "build.gradle.kts": parse_gradle,
    "gradle.lockfile": parse_gradle_lockfile,
    "gemfile.lock": parse_gemfile_lock,
    "dockerfile": parse_dockerfile,
    "docker-compose.yml": parse_compose,
    "docker-compose.yaml": parse_compose,
    "compose.yml": parse_compose,
    "compose.yaml": parse_compose,
    ".nvmrc": _single_runtime("node"),
    ".node-version": _single_runtime("node"),
    ".python-version": _single_runtime("python"),
    ".ruby-version": _single_runtime("ruby"),
    ".tool-versions": parse_tool_versions,
    "runtime.txt": parse_runtime_txt,
    "nginx.conf": _config_marker("nginx"),
    "httpd.conf": _config_marker("apache-httpd"),
    "apache2.conf": _config_marker("apache-httpd"),
    ".htaccess": _config_marker("apache-httpd"),
    "caddyfile": _config_marker("caddy"),
}

LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
             "uv.lock", "pipfile.lock", "cargo.lock", "composer.lock", "gradle.lockfile", "gemfile.lock"}


def parser_for(path: str):
    base = posixpath.basename(path).lower()
    if base in EXACT_FILES:
        return EXACT_FILES[base]
    if re.match(r"^requirements[\w.\-]*\.(txt|in)$", base):
        return parse_requirements
    if base.startswith("dockerfile.") or base.endswith(".dockerfile"):
        return parse_dockerfile
    if base.endswith(".conf") and "/nginx/" in f"/{path.lower()}":
        return _config_marker("nginx")
    return None


def drop_constraints_covered_by_lockfiles(items: list[Parsed]) -> list[Parsed]:
    """If a lockfile in the same directory pins a package, drop the looser manifest entry."""
    pinned = {(posixpath.dirname(p.path), p.ecosystem, p.name) for p in items
              if p.version_status == "exact" and posixpath.basename(p.path).lower() in LOCKFILES}
    return [p for p in items if p.version_status == "exact"
            or (posixpath.dirname(p.path), p.ecosystem, p.name) not in pinned]
