"""
LOT 3: Authentication & Authorization

Invariants couverts:
- RUN_010-014 (Authentification)
- RUN_020-023 (Permissions)
- INCID_003 (Verrouillage)
"""

from .interfaces import IJWTValidator, ISessionManager, IPermissionChecker, TokenClaims, Session
from .jwt_validator import JWTValidator, JWTValidationError, JWTExpiredError
from .session_manager import SessionManager, SessionManagerError
from .permission_checker import PermissionChecker, PermissionCheckerError

__all__ = [
    # Interfaces
    "IJWTValidator",
    "ISessionManager",
    "IPermissionChecker",
    # Data classes
    "TokenClaims",
    "Session",
    # Implementations
    "JWTValidator",
    "SessionManager",
    "PermissionChecker",
    # Exceptions
    "JWTValidationError",
    "JWTExpiredError",
    "SessionManagerError",
    "PermissionCheckerError",
]
