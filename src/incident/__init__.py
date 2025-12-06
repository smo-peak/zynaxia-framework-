"""
LOT 8: Incident & Réponse

Module de gestion des incidents de sécurité avec:
- Détection d'intrusions multi-canal (INCID_001)
- Log et alertes accès non autorisés (INCID_002)
- Verrouillage comptes après échecs auth (INCID_003)
- Détection anomalies base de données (INCID_004)
- Isolation tenant sur breach (INCID_005)
- Notification RSSI < 1h (INCID_006)
- Révocation tokens/sessions (INCID_007)
- Snapshot forensics (INCID_008)

Invariants couverts:
- INCID_001: Détection intrusion = alerte immédiate multi-canal
- INCID_002: Tentative accès non autorisé = log + alerte
- INCID_003: 3 échecs auth = compte verrouillé temporaire (15 min)
- INCID_004: Activité anormale DB = alerte (queries inhabituelles)
- INCID_005: Breach confirmée = isolation automatique du tenant
- INCID_006: Breach = notification RSSI < 1 heure
- INCID_007: Breach = révocation tous tokens/sessions du tenant
- INCID_008: Breach = snapshot données pour forensics
"""

from .interfaces import (
    # Enums
    AlertChannel,
    IncidentSeverity,
    IncidentType,
    # Data classes
    SecurityAlert,
    AuthFailure,
    AccountLockStatus,
    # Interfaces
    IAlertDispatcher,
    IIntrusionDetector,
    IAccountLocker,
)
from .intrusion_detector import IntrusionDetector, IntrusionDetectorError
from .account_locker import AccountLocker, AccountLockerError
from .breach_handler import (
    BreachHandler,
    Breach,
    BreachResponse,
    ITenantIsolator,
    IRssiNotifier,
    IForensicCapture,
    TenantIsolationError,
    RssiNotificationError,
    ForensicCaptureError,
    BreachHandlerError,
)

__all__ = [
    # Enums
    "AlertChannel",
    "IncidentSeverity",
    "IncidentType",
    # Data classes
    "SecurityAlert",
    "AuthFailure",
    "AccountLockStatus",
    "Breach",
    "BreachResponse",
    # Interfaces
    "IAlertDispatcher",
    "IIntrusionDetector",
    "IAccountLocker",
    "ITenantIsolator",
    "IRssiNotifier",
    "IForensicCapture",
    # Implementations
    "IntrusionDetector",
    "AccountLocker",
    "BreachHandler",
    # Exceptions
    "IntrusionDetectorError",
    "AccountLockerError",
    "TenantIsolationError",
    "RssiNotificationError",
    "ForensicCaptureError",
    "BreachHandlerError",
]
