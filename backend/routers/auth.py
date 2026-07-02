"""
Authentication routes for TriageMate.

Endpoints:
  POST /api/auth/login    — authenticate with username/password → TokenResponse
  POST /api/auth/refresh  — exchange a valid refresh token → new access TokenResponse
"""

from fastapi import APIRouter, HTTPException, status

from auth import (
    AUTH_DISABLED,
    ADMIN_USER,
    ADMIN_PASS,
    create_access_token,
    create_refresh_token,
    verify_token,
)
from models import LoginRequest, RefreshRequest, TokenResponse

router = APIRouter(tags=["Auth"])


@router.post("/api/auth/login", response_model=TokenResponse)
def login(body: LoginRequest):
    """Authenticate with admin credentials.

    Returns a short-lived access token + longer-lived refresh token.
    Raises 401 if credentials are invalid or auth is disabled.
    """
    if AUTH_DISABLED:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication is not configured on this server",
        )

    if body.username != ADMIN_USER or body.password != ADMIN_PASS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    access_token = create_access_token(body.username)
    refresh_token = create_refresh_token(body.username)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )


@router.post("/api/auth/refresh", response_model=TokenResponse)
def refresh(body: RefreshRequest):
    """Exchange a valid refresh token for a new access token.

    The refresh token itself is returned unchanged — the client keeps it
    for subsequent refreshes until it expires.
    Raises 401 if the refresh token is missing, expired, or invalid.
    """
    if AUTH_DISABLED:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication is not configured on this server",
        )

    payload = verify_token(body.refresh_token)
    if payload is None or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    username = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token payload",
        )

    new_access_token = create_access_token(username)

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=body.refresh_token,
        token_type="bearer",
    )
