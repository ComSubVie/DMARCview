"""Shared FastAPI dependencies."""

from __future__ import annotations

from fastapi import HTTPException, Request, status


def current_user(request: Request) -> str:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return str(user)


def client_ip(request: Request) -> str:
    # Do not trust X-Forwarded-For here: the login throttle is per socket peer,
    # which is what we can verify without knowing the proxy topology.
    return request.client.host if request.client else "unknown"
