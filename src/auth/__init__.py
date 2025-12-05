"""
LOT 3: Authentication & Authorization

Invariants couverts:
- RUN_010-014 (Authentification)
- RUN_020-023 (Permissions)
- INCID_003 (Verrouillage)
"""
from .interfaces import IJWTValidator, ISessionManager, IPermissionChecker
from .jwt_validator import JWTValidator, JWTValidationError, JWTExpiredError

__all__ = [
    # Interfaces
    "IJWTValidator", 
    "ISessionManager", 
    "IPermissionChecker",
    # Implementations
    "JWTValidator",
    # Exceptions
    "JWTValidationError",
    "JWTExpiredError",
]