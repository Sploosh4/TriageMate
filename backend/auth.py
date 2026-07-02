"""
Authentication module for TriageMate.

Provides JWT creation/verification, password hashing, and a FastAPI
dependency (get_current_user) that can be injected into route handlers.

Environment variables:
  TRIAGEMATE_JWT_SECRET   — secret key for JWT signing (default: dev-secret-change-me)
  TRIAGEMATE_ADMIN_USER   — admin username. If unset, authentication is DISABLED
                            and get_current_user returns "anonymous" (backward compat).
  TRIAGEMATE_ADMIN_PASS   — admin password (plain-text comparison for now).
"""

import os
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SECRET_KEY = os.getenv("TRIAGEMATE_JWT_SECRET", "dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

ADMIN_USER = os.getenv("TRIAGEMATE_ADMIN_USER")
ADMIN_PASS = os.getenv("TRIAGEMATE_ADMIN_PASS", "")
ADMIN_PASS_HASH = os.getenv("TRIAGEMATE_ADMIN_PASS_HASH", "")

if ADMIN_PASS and not ADMIN_PASS_HASH:
    ADMIN_PASS_HASH = bcrypt.hashpw(
        ADMIN_PASS.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

# When TRIAGEMATE_ADMIN_USER is unset, all routes pass through without auth
AUTH_DISABLED = not ADMIN_USER

security = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Token creation & verification
# ---------------------------------------------------------------------------
def create_access_token(username: str) -> str:
    """Create a short-lived JWT access token (30 min)."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "exp": expire, "type": "access"}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(username: str) -> str:
    """Create a longer-lived JWT refresh token (7 days)."""
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {"sub": username, "exp": expire, "type": "refresh"}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> dict | None:
    """
    Decode and validate a JWT token.

    Returns the decoded payload dict on success, or None if the token is
    expired, malformed, or otherwise invalid.
    """
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None


# ---------------------------------------------------------------------------
# Password hashing (bcrypt)
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """Hash a password with bcrypt and return the encoded hash string."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """Verify a plain-text password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


# ---------------------------------------------------------------------------
# FastAPI dependency — callable via Depends(get_current_user)
# ---------------------------------------------------------------------------
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> str:
    """
    FastAPI dependency that extracts and validates the Bearer token.

    Returns the username (``sub`` claim) on success.

    When *AUTH_DISABLED* is ``True`` (no ``TRIAGEMATE_ADMIN_USER`` env var),
    this function returns ``"anonymous"`` without performing any check,
    providing backward compatibility with deployments that have no auth.

    Raises ``401`` if the token is missing, expired, or invalid.
    """
    if AUTH_DISABLED:
        return "anonymous"

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = verify_token(credentials.credentials)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload.get("sub", "anonymous")
