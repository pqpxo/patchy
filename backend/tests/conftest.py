import os
import pathlib
import tempfile

_DB = pathlib.Path(tempfile.mkdtemp()) / "test.db"
os.environ["DATABASE_URL"] = f"sqlite:///{_DB.as_posix()}"
os.environ["COOKIE_SECURE"] = "false"
os.environ["GITHUB_TOKEN"] = "ghp_TESTSECRETTOKEN000000000000000000"
os.environ["NVD_API_KEY"] = ""

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import JSON, String, event, inspect  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.db import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Host, User  # noqa: E402
from app.security import hash_password, limiter  # noqa: E402

PASSWORD = "correct horse battery"


@event.listens_for(Session, "before_flush")
def _enforce_varchar_lengths(session, _ctx, _instances):
    """SQLite ignores VARCHAR(n) but Postgres rejects overlong values, so fail tests the way production would."""
    for obj in [*session.new, *session.dirty]:
        for attr in inspect(obj).mapper.column_attrs:
            col, value = attr.columns[0], getattr(obj, attr.key, None)
            if isinstance(col.type, String) and col.type.length and isinstance(value, str)                     and len(value) > col.type.length:
                raise AssertionError(f"{col.table.name}.{col.name} is VARCHAR({col.type.length}) "
                                     f"but got {len(value)} characters")


JSON_COLUMNS = {f"{col.table.name}.{col.name}" for table in Base.metadata.tables.values() for col in table.columns
                if isinstance(col.type, JSON)}


@event.listens_for(engine, "before_cursor_execute")
def _refuse_distinct_on_json(_conn, _cursor, statement, _params, _context, _many):
    """Postgres can't SELECT DISTINCT over json columns (SQLite can), so fail tests the way production would."""
    head = statement.split(" FROM ", 1)[0]
    if head.lstrip().upper().startswith("SELECT DISTINCT"):
        bad = [c for c in JSON_COLUMNS if c in head]
        if bad:
            raise AssertionError(f"SELECT DISTINCT over JSON columns fails on Postgres: {sorted(bad)[:3]}")


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    limiter.reset()
    yield


@pytest.fixture
def db():
    with SessionLocal() as s:
        yield s


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin(db):
    db.add(User(username="admin", password_hash=hash_password(PASSWORD)))
    db.commit()


@pytest.fixture
def auth_client(client, admin):
    r = client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
    assert r.status_code == 200
    client.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return client


@pytest.fixture
def host(db):
    h = Host(name="pi4")
    db.add(h)
    db.commit()
    return h
