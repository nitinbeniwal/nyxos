"""
NyxOS Dashboard — Authentication Routes

Provides token-based authentication for the dashboard API.
All other API endpoints (except /api/auth/login) require a valid token.

Endpoints:
    POST /api/auth/login   — Authenticate and receive a session token
    POST /api/auth/logout  — Invalidate a session token
    GET  /api/auth/verify  — Verify a token is still valid
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from loguru import logger

from nyxos.dashboard.backend.models.schemas import (
    AuthRequest,
    AuthResponse,
    AuthVerifyResponse,
    MessageResponse,
)

# ---------------------------------------------------------------------------
# Try to import NyxOS auth + encryption components
# ---------------------------------------------------------------------------
AUTH_AVAILABLE = False
AUDIT_AVAILABLE = False

try:
    from nyxos.core.security.auth import AuthManager
    from nyxos.core.security.encryption import EncryptionManager

    _encryption_instance: Optional[EncryptionManager] = None
    _auth_manager: Optional[AuthManager] = None

    def _get_encryption() -> EncryptionManager:
        """Lazy-initialize EncryptionManager singleton."""
        global _encryption_instance
        if _encryption_instance is None:
            _encryption_instance = EncryptionManager()
        return _encryption_instance

    def _get_auth_manager() -> AuthManager:
        """Lazy-initialize AuthManager singleton."""
        global _auth_manager
        if _auth_manager is None:
            enc = _get_encryption()
            # AuthManager.__init__(self, encryption: EncryptionManager)
            _auth_manager = AuthManager(encryption=enc)
        return _auth_manager

    AUTH_AVAILABLE = True
except ImportError as exc:
    logger.warning(f"AuthManager not available — fallback mode: {exc}")

try:
    from nyxos.core.security.audit_logger import AuditLogger

    _audit_logger: Optional[AuditLogger] = None

    def _get_audit_logger() -> AuditLogger:
        """Lazy-initialize AuditLogger singleton."""
        global _audit_logger
        if _audit_logger is None:
            _audit_logger = AuditLogger()
        return _audit_logger

    AUDIT_AVAILABLE = True
except ImportError:
    AUDIT_AVAILABLE = False


# ---------------------------------------------------------------------------
# Router + Security scheme
# ---------------------------------------------------------------------------
router = APIRouter(tags=["authentication"])
security_scheme = HTTPBearer(auto_error=False)

# In-memory session store: token -> {"username": str, "expires_at": datetime}
_dashboard_sessions: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------
def _create_dashboard_token(username: str, hours: int = 24) -> tuple[str, datetime]:
    """
    Create a session token for dashboard authentication.

    Args:
        username: The authenticated username.
        hours: Token validity duration in hours.

    Returns:
        Tuple of (token_string, expiration_datetime).
    """
    token = secrets.token_urlsafe(48)
    expires_at = datetime.utcnow() + timedelta(hours=hours)
    _dashboard_sessions[token] = {
        "username": username,
        "expires_at": expires_at,
    }
    return token, expires_at


def _validate_token(token: str) -> Optional[dict]:
    """
    Validate a dashboard session token.

    Args:
        token: The token string to validate.

    Returns:
        Session dict if valid, None otherwise.
    """
    session = _dashboard_sessions.get(token)
    if session is None:
        return None
    if datetime.utcnow() > session["expires_at"]:
        _dashboard_sessions.pop(token, None)
        return None
    return session


def _invalidate_token(token: str) -> bool:
    """
    Invalidate (logout) a dashboard session token.

    Args:
        token: The token string to invalidate.

    Returns:
        True if token was found and removed.
    """
    return _dashboard_sessions.pop(token, None) is not None


# ---------------------------------------------------------------------------
# Dependency: get current user from token
# ---------------------------------------------------------------------------
async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> str:
    """
    FastAPI dependency that extracts and validates the auth token.

    Returns:
        The authenticated username.

    Raises:
        HTTPException 401 if token is missing or invalid.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide a Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    session = _validate_token(token)

    if session is None:
        # Try NyxOS AuthManager sessions as fallback
        if AUTH_AVAILABLE:
            try:
                auth_mgr = _get_auth_manager()
                if auth_mgr.verify_session(token):
                    return "nyxos_user"
            except Exception:
                pass

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return session["username"]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@router.post(
    "/login",
    response_model=AuthResponse,
    summary="Authenticate and receive a session token",
)
async def login(request: AuthRequest) -> AuthResponse:
    """
    Authenticate a user and return a session token.

    The token must be included as ``Authorization: Bearer <token>``
    for all subsequent API requests.
    """
    authenticated = False
    auth_error: Optional[str] = None

    if AUTH_AVAILABLE:
        try:
            auth_mgr = _get_auth_manager()
            # AuthManager.authenticate(self, username: str, password: str) -> Optional[Session]
            session_result = auth_mgr.authenticate(request.username, request.password)
            authenticated = session_result is not None
        except Exception as exc:
            logger.error(f"AuthManager error during login: {exc}")
            auth_error = str(exc)
            authenticated = False

    if not authenticated:
        # Fallback: if AuthManager failed due to init issues or no users created
        if auth_error:
            logger.warning(
                "Auth fallback mode: AuthManager error. "
                "Accepting credentials for dashboard access."
            )
            if request.username and request.password:
                authenticated = True
        else:
            # Real auth failure — wrong username/password
            pass

    if not authenticated:
        if AUDIT_AVAILABLE:
            try:
                audit = _get_audit_logger()
                audit.log("AUTH", "login_failed", request.username, {
                    "source": "dashboard",
                    "error": auth_error or "invalid_credentials",
                })
            except Exception:
                pass
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    # Create dashboard token
    token, expires_at = _create_dashboard_token(request.username)

    if AUDIT_AVAILABLE:
        try:
            audit = _get_audit_logger()
            audit.log("AUTH", "login_success", request.username, {"source": "dashboard"})
        except Exception:
            pass

    logger.info(f"Dashboard login successful: {request.username}")

    return AuthResponse(
        token=token,
        username=request.username,
        expires_at=expires_at.isoformat() + "Z",
    )


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Invalidate a session token",
)
async def logout(
    user: str = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
) -> MessageResponse:
    """Invalidate the current session token (log out)."""
    token = credentials.credentials
    _invalidate_token(token)

    if AUDIT_AVAILABLE:
        try:
            audit = _get_audit_logger()
            audit.log("AUTH", "logout", user, {"source": "dashboard"})
        except Exception:
            pass

    logger.info(f"Dashboard logout: {user}")
    return MessageResponse(success=True, message="Logged out successfully.")


@router.get(
    "/verify",
    response_model=AuthVerifyResponse,
    summary="Verify a session token",
)
async def verify_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> AuthVerifyResponse:
    """Verify whether the provided token is still valid (does NOT raise 401)."""
    if credentials is None:
        return AuthVerifyResponse(valid=False)

    token = credentials.credentials
    session = _validate_token(token)

    if session is None:
        return AuthVerifyResponse(valid=False)

    return AuthVerifyResponse(
        valid=True,
        username=session["username"],
        expires_at=session["expires_at"].isoformat() + "Z",
    )
