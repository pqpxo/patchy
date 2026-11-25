"""Admin CLI.

  python -m app.cli create-admin [--username admin]     prompt for a password, create the single admin
  python -m app.cli reset-password [--username admin]   set a new password, sign out all sessions
  python -m app.cli seed-demo                           load clearly-labelled DEMO data
  python -m app.cli clear-demo                          remove demo data
  python -m app.cli demo-build                          fetch the public demo's data snapshot (needs internet)
  python -m app.cli demo-load                           fill an EMPTY database with the public demo
"""
import argparse
import getpass
import sys

from sqlalchemy import delete, select

from . import vulns
from .db import SessionLocal, utcnow
from .models import Advisory, Component, Host, Repository, ScanRun, User, UserSession
from .security import audit, hash_password, validate_new_password
from .inventory import sync_components

DEMO_ADVISORY = {
    "id": "DEMO-2024-0001",
    "summary": "DEMO DATA: fictional advisory for trying out Patchy. Not a real vulnerability.",
    "details": "This record was created by `python -m app.cli seed-demo`. It does not describe a real issue "
               "and must not be acted on. Remove it with `python -m app.cli clear-demo`.",
    "published": "2024-01-01T00:00:00Z", "modified": "2024-01-01T00:00:00Z",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [{"package": {"ecosystem": "PyPI", "name": "patchy-demo-lib"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}],
    "references": [],
}


def _password(prompt_twice=True) -> str:
    pw = getpass.getpass("New password (min 12 chars): ")
    if prompt_twice and pw != getpass.getpass("Repeat password: "):
        sys.exit("Passwords do not match.")
    try:
        validate_new_password(pw)
    except ValueError as e:
        sys.exit(str(e))
    return pw


def create_admin(username: str) -> None:
    with SessionLocal() as db:
        if db.scalar(select(User)):
            sys.exit("An administrator already exists. Use reset-password instead.")
        db.add(User(username=username, password_hash=hash_password(_password())))
        audit(db, "cli", "auth.admin_created", "user", username)
        db.commit()
    print(f"Administrator '{username}' created.")


def reset_password(username: str) -> None:
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == username))
        if not user:
            sys.exit(f"No user named '{username}'.")
        user.password_hash = hash_password(_password())
        db.execute(delete(UserSession).where(UserSession.user_id == user.id))
        audit(db, "cli", "auth.password_reset", "user", username)
        db.commit()
    print("Password updated; all sessions signed out.")


def seed_demo() -> None:
    with SessionLocal() as db:
        if db.scalar(select(Host).where(Host.is_demo.is_(True))):
            sys.exit("Demo data already loaded.")
        host = Host(name="demo-host", ip="192.0.2.10", is_demo=True, os_name="DEMO Debian 12",
                    notes="DEMO DATA. Remove with `python -m app.cli clear-demo`.")
        repo = Repository(url="https://github.com/example/demo", owner="example", name="demo", is_demo=True,
                          notes="DEMO DATA. Not a real repository scan.")
        db.add_all([host, repo])
        db.flush()
        run = ScanRun(kind="agent", status="succeeded", host_id=host.id, started_at=utcnow(), finished_at=utcnow(),
                      progress="Demo", summary={"note": "DEMO DATA"})
        db.add(run)
        db.flush()
        rows = [
            {"identity": "demo|vuln", "name": "patchy-demo-lib", "component_type": "library", "ecosystem": "PyPI",
             "version": "1.4.0", "version_status": "exact", "paths": [("/opt/demo/requirements.txt", "manifest")]},
            {"identity": "demo|fixed", "name": "patchy-demo-lib-fixed", "component_type": "library",
             "ecosystem": "PyPI", "version": "2.1.0", "version_status": "exact", "paths": []},
            {"identity": "demo|unknown", "name": "patchy-demo-lib", "component_type": "library", "ecosystem": "PyPI",
             "version": None, "version_status": "unknown", "install_path": "/opt/demo2",
             "paths": [("/opt/demo2", "install")]},
            {"identity": "demo|nginx", "name": "nginx", "component_type": "web_server", "ecosystem": None,
             "version": "1.24.0", "version_status": "exact", "port": 443, "protocol": "tcp",
             "listen_ip": "0.0.0.0", "install_path": "/usr/sbin/nginx", "paths": [("/usr/sbin/nginx", "executable")]},
        ]
        ids = sync_components(db, run, f"host:{host.id}", rows, source="demo", host_id=host.id)
        for c in db.scalars(select(Component).where(Component.id.in_(ids))):
            c.notes = "DEMO DATA"
        vulns.upsert_advisory(db, DEMO_ADVISORY, source="demo")
        vulns.rematch(db, ids)
        audit(db, "cli", "demo.seed")
        db.commit()
    print("Demo data loaded (host 'demo-host', advisory DEMO-2024-0001). All of it is labelled DEMO.")


def clear_demo() -> None:
    with SessionLocal() as db:
        for h in db.scalars(select(Host).where(Host.is_demo.is_(True))):
            db.delete(h)
        for r in db.scalars(select(Repository).where(Repository.is_demo.is_(True))):
            db.delete(r)
        db.execute(delete(Advisory).where(Advisory.source == "demo"))
        audit(db, "cli", "demo.clear")
        db.commit()
    print("Demo data removed.")


def main(argv=None) -> None:
    p = argparse.ArgumentParser(prog="python -m app.cli")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("create-admin", "reset-password"):
        sp = sub.add_parser(name)
        sp.add_argument("--username", default="admin")
    sub.add_parser("seed-demo")
    sub.add_parser("clear-demo")
    sub.add_parser("demo-build")
    sub.add_parser("demo-load")
    a = p.parse_args(argv)
    if a.cmd.startswith("demo-"):
        from . import demo
        return (demo.build_cli if a.cmd == "demo-build" else demo.load_cli)()
    {"create-admin": lambda: create_admin(a.username), "reset-password": lambda: reset_password(a.username),
     "seed-demo": seed_demo, "clear-demo": clear_demo}[a.cmd]()


if __name__ == "__main__":
    main()
