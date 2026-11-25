"""Passwords, sessions, CSRF, rate limiting, agent tokens, audit."""
import base64
import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import timedelta

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .db import get_db, utcnow
from .models import Agent, AppSetting, AuditLog, User, UserSession

SESSION_COOKIE = "patchy_session"
_SCRYPT = {"n": 2**15, "r": 8, "p": 1, "maxmem": 64 * 1024 * 1024}


# ---------- passwords (stdlib scrypt) ----------

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, dklen=32, **_SCRYPT)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt, dk = stored.split("$")
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), dklen=32, **_SCRYPT)
        return hmac.compare_digest(got, base64.b64decode(dk))
    except (ValueError, TypeError):
        return False


def validate_new_password(password: str) -> None:
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters.")
    if len(password) > 256:
        raise ValueError("Password is too long.")


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# ---------- rate limiting ----------

class RateLimiter:
    # ponytail: in-memory, per process. Fine for the single uvicorn worker; move to the DB if you scale out.
    def __init__(self):
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window: int) -> None:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                raise HTTPException(429, "Too many requests. Try again shortly.")
            q.append(now)

    def reset(self):
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()


def client_ip(request: Request) -> str:
    # uvicorn --proxy-headers rewrites request.client from X-Forwarded-For for trusted proxies only.
    return request.client.host if request.client else "unknown"


# ---------- sessions + CSRF ----------

def create_session(db: Session, user: User) -> tuple[str, UserSession]:
    token = secrets.token_urlsafe(32)
    s = UserSession(token_hash=sha256(token), csrf_token=secrets.token_urlsafe(24), user_id=user.id,
                    expires_at=utcnow() + timedelta(hours=settings.session_hours))
    db.add(s)
    db.commit()
    return token, s


def current_session(request: Request, db: Session = Depends(get_db)) -> UserSession:
    if settings.demo_mode and db.get(AppSetting, "demo"):  # only a database `demo-load` made: everyone is the demo
        # user, and the read-only guard in main.py refuses every change
        s = db.scalar(select(UserSession).join(User).where(User.username == "demo"))
        if s:
            return s
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(401, "Not signed in.")
    s = db.scalar(select(UserSession).where(UserSession.token_hash == sha256(token)))
    now = utcnow()
    if not s or s.expires_at < now:
        raise HTTPException(401, "Session expired. Sign in again.")
    idle = settings.session_idle_minutes
    if idle and (s.last_seen_at or s.created_at) < now - timedelta(minutes=idle):
        db.delete(s)
        db.commit()
        raise HTTPException(401, f"Signed out after {idle} minutes without activity. Sign in again.")
    if idle and (s.last_seen_at is None or s.last_seen_at < now - timedelta(minutes=1)):
        s.last_seen_at = now
        db.commit()
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        sent = request.headers.get("x-csrf-token", "")
        if not hmac.compare_digest(sent, s.csrf_token):
            raise HTTPException(403, "Missing or invalid CSRF token.")
    return s


def require_user(s: UserSession = Depends(current_session)) -> User:
    return s.user


# ---------- agent tokens ----------

def new_agent_token(agent_id: int) -> str:
    return f"pa_{agent_id}_{secrets.token_urlsafe(32)}"


def authenticate_agent(db: Session, request: Request) -> Agent:
    ip = client_ip(request)
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    try:
        _, agent_id, _ = token.split("_", 2)
        agent = db.get(Agent, int(agent_id))
    except ValueError:
        agent = None
    if not agent or agent.revoked_at or not hmac.compare_digest(agent.token_hash, sha256(token)):
        limiter.check(f"agent-fail:{ip}", 10, 300)  # slow down guessing
        raise HTTPException(401, "Invalid or revoked agent credential.")
    return agent


# ---------- audit ----------

def audit(db: Session, actor: str, action: str, target_type: str | None = None,
          target_id=None, detail: dict | None = None, ip: str | None = None) -> None:
    """Record an action. Callers must never pass secret values in detail."""
    if settings.demo_mode:  # the audit log is public in the demo: never show one visitor's address to another
        ip = None
    db.add(AuditLog(actor=actor, action=action, target_type=target_type,
                    target_id=None if target_id is None else str(target_id), detail=detail, ip=ip))


def scrub(text: str) -> str:
    """Remove configured secrets from error text before storing or returning it."""
    for secret in (settings.github_token, settings.nvd_api_key):
        if secret:
            text = text.replace(secret, "***")
    return text[:2000]
