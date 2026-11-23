"""v1.8: replaced images are rescanned automatically, Scan all, and when each image was scanned."""
from tests.test_api import _enroll, _report

OLD, NEW = "sha256:" + "5a" * 32, "sha256:" + "6b" * 32  # the sample report's nginx:1.27, then a pulled update


def _with_image(image_id, scanned=True, **over):
    rep = _report(**over)
    rep["containers"][0]["image_id"] = image_id
    rep["images"] = [{**rep["images"][0], "image_id": image_id}] if scanned else []
    return rep


def test_a_replaced_image_is_queued_once(auth_client, client, host, db):
    h = {"Authorization": f"Bearer {_enroll(auth_client, host.id)}"}
    send = lambda rep: client.post("/api/agent/report", json=rep, headers=h).status_code == 200  # noqa: E731
    assert send(_report())
    first = auth_client.get(f"/api/hosts/{host.id}").json()["host"]["image_scans"]["nginx:1.27"]
    assert first["image_id"] == OLD and first["scanned_at"]

    assert send(_with_image(NEW, scanned=False))  # pulled: the agent no longer has a scan of the image in use
    host_out = auth_client.get(f"/api/hosts/{host.id}").json()["host"]
    assert host_out["image_scan_requests"] == [NEW] and host_out["image_scans"]["nginx:1.27"]["requested"] == NEW
    assert client.get("/api/agent/poll", headers=h).json() == {"report": True, "scan_images": [NEW]}

    assert send(_with_image(NEW, scanned=False, image_requests_done=[NEW]))  # answered but the scan failed
    assert client.get("/api/agent/poll", headers=h).json() == {"report": False, "scan_images": []}  # no loop

    assert send(_with_image(NEW))
    now = auth_client.get(f"/api/hosts/{host.id}").json()["host"]["image_scans"]["nginx:1.27"]
    assert now["image_id"] == NEW and "requested" not in now

    rep = _with_image(OLD, scanned=False, agent_version="1.3.3")  # too old to scan on request: nothing queued
    rep.pop("image_requests_done")
    assert send(rep) and client.get("/api/agent/poll", headers=h).json()["report"] is False

    rep = _report()
    rep["containers"] = []
    assert send(rep) and auth_client.get(f"/api/hosts/{host.id}").json()["host"]["image_scans"] is None


def test_scan_all_queues_only_unscanned_images(auth_client, client, host, db):
    h = {"Authorization": f"Bearer {_enroll(auth_client, host.id)}"}
    rep = _report()
    rep["containers"] += [{**rep["containers"][0], "name": "cache", "image": "redis:7", "image_id": NEW},
                          {**rep["containers"][0], "name": "cache2", "image": "redis:7", "image_id": NEW},
                          {**rep["containers"][0], "name": "odd", "image": "x", "image_id": None}]
    assert client.post("/api/agent/report", json=rep, headers=h).status_code == 200
    r = auth_client.post(f"/api/hosts/{host.id}/images/scan-all")
    assert r.status_code == 200 and r.json()["image_scan_requests"] == [NEW]
    assert auth_client.post(f"/api/hosts/{host.id}/images/scan-all").json()["image_scan_requests"] == [NEW]
    assert [a["action"] for a in auth_client.get("/api/audit").json()["items"][:2]] == ["host.image_scan_all"] * 2

    old = _report(agent_version="1.3.3")
    old.pop("image_requests_done")
    client.post("/api/agent/report", json=old, headers=h)
    assert auth_client.post(f"/api/hosts/{host.id}/images/scan-all").status_code == 409
