"""Single-admin authentication."""

from __future__ import annotations

import hmac
import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlmodel import Session

from .. import audit
from ..config import get_settings
from ..db import get_session
from ..deps import client_ip, current_user
from ..security import login_throttle, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginPayload(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=512)


class SessionInfo(BaseModel):
    authenticated: bool
    username: str | None = None


def _credentials_valid(username: str, password: str) -> bool:
    settings = get_settings()
    if not hmac.compare_digest(username.strip().lower(), settings.admin_username.lower()):
        return False
    if settings.admin_password_hash:
        return verify_password(password, settings.admin_password_hash)
    if settings.admin_password:
        return hmac.compare_digest(password, settings.admin_password)
    return False


@router.get("/me", response_model=SessionInfo)
def me(request: Request) -> SessionInfo:
    user = request.session.get("user")
    return SessionInfo(authenticated=bool(user), username=str(user) if user else None)


@router.post("/login", response_model=SessionInfo)
def login(
    payload: LoginPayload,
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
) -> SessionInfo:
    settings = get_settings()
    if not settings.has_credentials:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "No admin credentials configured. Set ADMIN_PASSWORD or ADMIN_PASSWORD_HASH "
                "(generate one with `python -m app.cli hash-password`)."
            ),
        )

    key = client_ip(request)
    blocked_for = login_throttle.is_blocked(key)
    if blocked_for:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again in {blocked_for // 60 + 1} minutes.",
            headers={"Retry-After": str(blocked_for)},
        )

    if not _credentials_valid(payload.username, payload.password):
        login_throttle.register_failure(key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password"
        )

    login_throttle.reset(key)
    request.session.clear()
    request.session["user"] = settings.admin_username
    request.session["auth_at"] = int(time.time())
    audit.record(
        session,
        "auth.login",
        actor=settings.admin_username,
        detail={"ip": client_ip(request)},
    )
    session.commit()
    response.headers["Cache-Control"] = "no-store"
    return SessionInfo(authenticated=True, username=settings.admin_username)


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
) -> dict[str, bool]:
    user = str(request.session.get("user") or "admin")
    if request.session.get("user"):
        audit.record(session, "auth.logout", actor=user, detail={"ip": client_ip(request)})
        session.commit()
    request.session.clear()
    response.headers["Cache-Control"] = "no-store"
    return {"ok": True}


@router.get("/session")
def session_info(user: str = current_user) -> dict[str, object]:
    settings = get_settings()
    return {
        "username": user,
        "jmap_enabled": settings.jmap_enabled,
        "mailbox": settings.jmap_mailbox,
        "geoip": bool(settings.geoip_db),
    }
