from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db, utcnow
from ..models import AppSetting, User, UserSession
from ..schemas import LoginIn, MeOut, PasswordChangeIn
from ..security import (SESSION_COOKIE, audit, client_ip, create_session, current_session, hash_password,
                        limiter, validate_new_password, verify_password)

router = APIRouter(prefix="/api/auth", tags=["auth"])
_DUMMY_HASH = hash_password("timing-equaliser-not-a-password")


@router.post("/login", response_model=MeOut)
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = client_ip(request)
    limiter.check(f"login:{ip}", 10, 60)
    user = db.scalar(select(User).where(User.username == body.username))
    ok = verify_password(body.password, user.password_hash if user else _DUMMY_HASH)
    if not user or not ok:
        audit(db, body.username[:64], "auth.login_failed", ip=ip)
        db.commit()
        raise HTTPException(401, "Incorrect username or password.")
    db.execute(delete(UserSession).where(UserSession.expires_at < utcnow()))
    token, s = create_session(db, user)
    user.last_login_at = utcnow()
    audit(db, user.username, "auth.login", ip=ip)
    db.commit()
    response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=settings.cookie_secure, samesite="strict",
                        max_age=settings.session_hours * 3600, path="/")
    return MeOut(username=user.username, csrf_token=s.csrf_token)


@router.post("/logout", status_code=204)
def logout(response: Response, s: UserSession = Depends(current_session), db: Session = Depends(get_db)):
    db.delete(db.merge(s))
    db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")


@router.get("/me", response_model=MeOut)
def me(s: UserSession = Depends(current_session), db: Session = Depends(get_db)):
    demo = db.get(AppSetting, "demo") if settings.demo_mode else None
    return MeOut(username=s.user.username, csrf_token=s.csrf_token, demo=demo.value.get("snapshot") if demo else None)


@router.post("/password", status_code=204)
def change_password(body: PasswordChangeIn, request: Request, s: UserSession = Depends(current_session),
                    db: Session = Depends(get_db)):
    limiter.check(f"password:{client_ip(request)}", 5, 300)
    user = db.get(User, s.user_id)
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(400, "Current password is incorrect.")
    try:
        validate_new_password(body.new_password)
    except ValueError as e:
        raise HTTPException(422, str(e))
    user.password_hash = hash_password(body.new_password)
    # Sign out every other session.
    db.execute(delete(UserSession).where(UserSession.user_id == user.id, UserSession.id != s.id))
    audit(db, user.username, "auth.password_changed", ip=client_ip(request))
    db.commit()
