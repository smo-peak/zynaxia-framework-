"""
LOT 8: Incident & Réponse

Module de gestion des incidents de sécurité avec:
- Détection d'intrusions multi-canal (INCID_001)
- Log et alertes accès non autorisés (INCID_002)
- Verrouillage comptes après échecs auth (INCID_003)
- Détection anomalies base de données (INCID_004)

Invariants couverts:
- INCID_001: Détection intrusion = alerte immédiate multi-canal
- INCID_002: Tentative accès non autorisé = log + alerte
- INCID_003: 3 échecs auth = compte verrouillé temporaire (15 min)
- INCID_004: Activité anormale DB = alerte (queries inhabituelles)
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

__all__ = [
    # Enums
    "AlertChannel",
    "IncidentSeverity",
    "IncidentType",
    # Data classes
    "SecurityAlert",
    "AuthFailure",
    "AccountLockStatus",
    # Interfaces
    "IAlertDispatcher",
    "IIntrusionDetector",
    "IAccountLocker",
    # Implementations
    "IntrusionDetector",
    "AccountLocker",
    # Exceptions
    "IntrusionDetectorError",
    "AccountLockerError",
]
