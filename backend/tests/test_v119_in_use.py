"""v1.19: findings in software that isn't running rank lower; installed kernels that aren't booted are set aside."""
import struct

from app import inuse, vulns
from app.db import utcnow
from app.models import Advisory, Component, Finding
from tests.test_api import _enroll, _report, agent_mod


def test_kernel_detection():
    old, cur = ["linux-image-6.1.0-17-amd64"], ["linux-image-6.1.0-18-amd64", "linux-headers-6.1.0-18-amd64"]
    assert inuse.in_use(old, "6.1.69+1", "6.1.0-18-amd64", None) is False
    assert inuse.in_use(cur, "6.1.76+1", "6.1.0-18-amd64", None) is True
    # Ubuntu: linux-headers-6.8.0-45 has no flavour; "6.8.0-4" must not match "6.8.0-45-generic".
    assert inuse.in_use(["linux-headers-6.8.0-45"], "6.8.0-45.45", "6.8.0-45-generic", None) is True
    assert inuse.in_use(["linux-modules-6.8.0-4-generic"], "6.8.0-4.4", "6.8.0-45-generic", None) is False
    # RPM: uname -r is version-release.arch.
    assert inuse.in_use(["kernel-core"], "5.14.0-427.13.1.el9_4", "5.14.0-427.13.1.el9_4.x86_64", None) is True
    assert inuse.in_use(["kernel-core"], "5.14.0-362.el9", "5.14.0-427.13.1.el9_4.x86_64", set()) is False
    # The booted kernel stays running even when its group also holds linux-libc-dev; an old one with it falls back.
    assert inuse.in_use(["linux-headers-6.1.0-18-amd64", "linux-libc-dev"], "6.1.76-1", "6.1.0-18-amd64", None)
    assert not inuse.is_kernel(["linux-headers-6.1.0-17-amd64", "linux-libc-dev"])
    # Metapackages and everything else: from the agent's list, or unknown without one.
    assert not inuse.is_kernel(["linux-image-generic"]) and not inuse.is_kernel(["kernel-tools"])
    assert inuse.in_use(["nginx"], "1.22.1-9", "6.1.0-18-amd64", None) is None
    assert inuse.in_use(["libssl3", "openssl"], "3.0.11", "6.1.0-18-amd64", {"libssl3"}) is True
    assert inuse.in_use(["tar"], "1.34", "6.1.0-18-amd64", {"libssl3"}) is False


def _kernel(name, ver):
    return {"manager": "dpkg", "name": name, "version": ver, "source_name": "linux-signed-amd64",
            "source_version": ver, "arch": "arm64"}


def _send(client, token, **over):
    rep = _report(**over)
    rep["packages"] += [_kernel("linux-image-6.1.0-sample", "6.1.76+1"), _kernel("linux-image-6.1.0-17-arm64", "6.1.69+1"),
                        {"manager": "dpkg", "name": "tar", "version": "1.34+dfsg-1.2", "source_name": "tar",
                         "source_version": "1.34+dfsg-1.2", "arch": "arm64"}]
    assert client.post("/api/agent/report", json=rep, headers={"Authorization": f"Bearer {token}"}).status_code == 200


def _comps(db, host):
    return {(c.name, c.version): c for c in db.query(Component).filter_by(host_id=host.id, component_type="os_package")}


def test_ingest_ranks_idle_software_lower(auth_client, client, host, db):
    token = _enroll(auth_client, host.id)
    _send(client, token)
    comps = _comps(db, host)
    assert comps[("nginx", "1.22.1-9")].in_use is True
    assert comps[("openssl", "3.0.11-1~deb12u1")].in_use is True  # libssl3 is loaded
    assert comps[("tar", "1.34+dfsg-1.2")].in_use is False
    assert comps[("linux-signed-amd64", "6.1.76+1")].in_use is True  # the booted kernel
    assert comps[("linux-signed-amd64", "6.1.69+1")].in_use is False

    for adv, comp, epss in (("CVE-IDLE", ("tar", "1.34+dfsg-1.2"), 0.9), ("CVE-RUN", ("nginx", "1.22.1-9"), 0.1)):
        db.add(Advisory(id=adv, severity="high", epss=epss, affected=[]))
        db.add(Finding(component_id=comps[comp].id, advisory_id=adv, match_status="confirmed", evidence="e",
                       remediation="r", fixed_versions=["99"], currently_matching=True, first_detected_at=utcnow()))
    db.commit()
    items = auth_client.get("/api/findings", params={"sort": "priority"}).json()["items"]
    assert [(i["advisory"]["id"], i["in_use"]) for i in items] == [("CVE-RUN", True), ("CVE-IDLE", False)]
    idle = auth_client.get("/api/findings", params={"in_use": "false"}).json()["items"]
    assert [i["advisory"]["id"] for i in idle] == ["CVE-IDLE"]
    assert auth_client.get("/api/dashboard").json()["not_running"] == 1
    plan = auth_client.get("/api/fix-plan", params={"host_id": host.id}).json()
    assert [i["name"] for g in plan["groups"] for i in g["items"]][:2] == ["nginx", "tar"]

    # An agent older than 1.5 doesn't say: unknown, except for kernels, which come from uname -r.
    _send(client, token, in_use=None)
    db.expire_all()
    comps = _comps(db, host)
    assert comps[("nginx", "1.22.1-9")].in_use is None
    assert comps[("linux-signed-amd64", "6.1.69+1")].in_use is False


def test_old_kernel_findings_are_set_aside_and_come_back(db, auth_client, host):
    c = Component(name="linux", version="6.1.69-1", ecosystem="Debian:12", component_type="os_package",
                  version_status="exact", source="agent", host_id=host.id, in_use=False,
                  details={"binaries": ["linux-headers-6.1.0-17-amd64", "linux-headers-6.1.0-17-common"]})
    db.add(c)
    for i in (1, 2):
        vulns.upsert_advisory(db, {"id": f"DEBIAN-CVE-K{i}", "affected": [{
            "package": {"ecosystem": "Debian:12", "name": "linux"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]})
    db.commit()
    assert vulns.rematch(db)["not_booted"] == 2
    db.commit()
    f = {x.advisory_id: x for x in db.query(Finding)}
    assert f["DEBIAN-CVE-K1"].status == "not_booted" and "isn't the one running" in f["DEBIAN-CVE-K1"].status_note
    d = auth_client.get("/api/dashboard").json()
    assert d["status"]["not_booted"] == 2 and sum(d["severity"].values()) == 0  # not counted as open

    # Can't be chosen by hand, but a person can keep it (to edit the note) or take it back.
    k1, k2 = f["DEBIAN-CVE-K1"].id, f["DEBIAN-CVE-K2"].id
    r = auth_client.post(f"/api/findings/{k1}/status", json={"status": "not_booted", "note": "Removing it Friday"})
    assert r.status_code == 200 and r.json()["status_changed_by"] == "system"
    assert auth_client.post(f"/api/findings/{k2}/status", json={"status": "acknowledged"}).status_code == 200
    assert auth_client.post(f"/api/findings/{k2}/status", json={"status": "not_booted"}).status_code == 422

    # Booted after all: the set-aside one reopens; the acknowledged one is left as the person set it.
    db.expire_all()  # the API changed them in its own session
    c.in_use = True
    db.commit()
    vulns.rematch(db)
    db.commit()
    for x in f.values():
        db.refresh(x)
    assert f["DEBIAN-CVE-K1"].status == "open" and f["DEBIAN-CVE-K1"].status_changed_by == "system"
    assert f["DEBIAN-CVE-K2"].status == "acknowledged"

    # Removed: resolved like anything else.
    c.in_use, f["DEBIAN-CVE-K1"].status = False, "not_booted"
    c.missing_since = utcnow()
    db.commit()
    vulns.rematch(db)
    db.commit()
    db.refresh(f["DEBIAN-CVE-K1"])
    assert f["DEBIAN-CVE-K1"].status == "resolved"


def _elf(is64, big, needed):
    end = ">" if big else "<"
    strtab, offs = b"\0", []
    for n in needed:
        offs.append(len(strtab))
        strtab += n.encode() + b"\0"
    entry = end + ("qQ" if is64 else "iI")
    dyn = b"".join(struct.pack(entry, 1, o) for o in offs) + struct.pack(entry, 5, 0) + struct.pack(entry, 0, 0)
    sec = end + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII")
    ehsize = 64 if is64 else 52
    str_at, dyn_at = ehsize, ehsize + len(strtab)
    sh_at = dyn_at + len(dyn)
    sh = (struct.pack(sec, *[0] * 10) + struct.pack(sec, 0, 3, 0, 0, str_at, len(strtab), 0, 0, 1, 0)
          + struct.pack(sec, 0, 6, 0, 0, dyn_at, len(dyn), 1, 0, 8, 16))
    ident = b"\x7fELF" + bytes([2 if is64 else 1, 2 if big else 1, 1]) + bytes(9)
    word = "Q" if is64 else "I"
    hdr = ident + struct.pack(end + f"HHI{word}{word}{word}IHHHHHH", 3, 0xB7, 1, 0, 0, sh_at, 0, ehsize, 0, 0,
                              struct.calcsize(sec), 3, 0)
    assert len(hdr) == ehsize
    return hdr + strtab + dyn + sh


def test_agent_reads_needed_libraries_from_elf_headers(tmp_path):
    for is64, big in ((True, False), (False, True)):
        p = tmp_path / f"prog{is64}{big}"
        p.write_bytes(_elf(is64, big, ["libssl.so.3", "libc.so.6"]))
        assert agent_mod.elf_needed(str(p)) == ["libssl.so.3", "libc.so.6"]
    (tmp_path / "script").write_text("#!/bin/sh\necho hi\n")
    (tmp_path / "short").write_bytes(b"\x7fELF\x02\x01")
    assert agent_mod.elf_needed(str(tmp_path / "script")) == [] == agent_mod.elf_needed(str(tmp_path / "short"))
    assert agent_mod.elf_needed(str(tmp_path / "missing")) == []
    assert agent_mod._usr_variants(["/lib/x.so"]) == {"/lib/x.so", "/usr/lib/x.so"}
    assert agent_mod.DEFAULTS["collect"]["in_use"] is True
