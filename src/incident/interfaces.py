"""
LOT 8: Interfaces Incident & Réponse

Définit les contrats pour le système de détection d'incidents,
alertes et verrouillage de comptes.

Invariants:
    INCID_001: Détection intrusion = alerte immédiate multi-canal
    INCID_002: Tentative accès non autorisé = log + alerte
    INCID_003: 3 échecs auth = compte verrouillé temporaire (15 min)
    INCID_004: Activité anormale DB = alerte (queries inhabituelles)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any


class AlertChannel(Enum):
    """Canaux de notification pour alertes de sécurité."""

    EMAIL = "email"
    SMS = "sms"
    WEBHOOK = "webhook"
    SYSLOG = "syslog"


class IncidentSeverity(Enum):
    """Niveaux de sévérité des incidents."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentType(Enum):
    """Types d'incidents de sécurité."""

    INTRUSION = "intrusion"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    AUTH_FAILURE = "auth_failure"
    DB_ANOMALY = "db_anomaly"
    ACCOUNT_LOCKED = "account_locked"


@dataclass(frozen=True)
class SecurityAlert:
    """
    Alerte de sécurité générée par le système de détection.

    Invariants:
        INCID_001: Intrusion = tous les canaux notifiés
        INCID_002: Accès non autorisé = log + alerte
    """

    alert_id: str
    incident_type: str  # intrusion, unauthorized_access, auth_failure, db_anomaly
    severity: IncidentSeverity
    tenant_id: str
    source_ip: Optional[str]
    user_id: Optional[str]
    description: str
    timestamp: datetime
    channels_notified: List[AlertChannel] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthFailure:
    """
    Enregistrement d'un échec d'authentification.

    Invariant:
        INCID_003: Utilisé pour compter les échecs avant verrouillage
    """

    user_id: str
    tenant_id: str
    source_ip: str
    timestamp: datetime
    reason: str


@dataclass
class AccountLockStatus:
    """
    Statut de verrouillage d'un compte.

    Invariant:
        INCID_003: Locked après 3 échecs, durée 15 min
    """

    user_id: str
    locked: bool
    locked_until: Optional[datetime]
    failure_count: int
    last_failure: Optional[datetime]


class IAlertDispatcher(ABC):
    """
    Interface pour envoi d'alertes multi-canal.

    Responsabilités:
        - Dispatch alertes vers EMAIL, SMS, WEBHOOK, SYSLOG
        - INCID_001: Tous canaux pour intrusion
    """

    @abstractmethod
    async def dispatch(
        self, alert: SecurityAlert, channels: List[AlertChannel]
    ) -> bool:
        """
        Envoie une alerte vers les canaux spécifiés.

        Args:
            alert: Alerte de sécurité à dispatcher
            channels: Liste des canaux de notification

        Returns:
            True si dispatch réussi sur au moins un canal

        Invariant:
            INCID_001: Pour intrusion, tous canaux doivent être notifiés
        """
        pass

    @abstractmethod
    async def dispatch_to_channel(
        self, alert: SecurityAlert, channel: AlertChannel
    ) -> bool:
        """
        Envoie une alerte vers un canal spécifique.

        Args:
            alert: Alerte de sécurité
            channel: Canal de notification

        Returns:
            True si envoi réussi
        """
        pass


class IIntrusionDetector(ABC):
    """
    Interface détection d'intrusions et activités suspectes.

    Responsabilités:
        - Détection intrusion (INCID_001)
        - Log accès non autorisé (INCID_002)
        - Détection anomalies DB (INCID_004)
    """

    @abstractmethod
    async def detect_intrusion(self, event: Dict[str, Any]) -> Optional[SecurityAlert]:
        """
        Détecte une intrusion et génère une alerte immédiate.

        Args:
            event: Événement suspect à analyser

        Returns:
            SecurityAlert si intrusion détectée, None sinon

        Invariant:
            INCID_001: Détection intrusion = alerte immédiate multi-canal
        """
        pass

    @abstractmethod
    async def log_unauthorized_access(
        self, event: Dict[str, Any]
    ) -> SecurityAlert:
        """
        Log et alerte pour tentative d'accès non autorisé.

        Args:
            event: Événement d'accès non autorisé

        Returns:
            SecurityAlert générée

        Invariant:
            INCID_002: Tentative accès non autorisé = log + alerte
        """
        pass

    @abstractmethod
    async def detect_db_anomaly(
        self, query_pattern: str, tenant_id: str
    ) -> Optional[SecurityAlert]:
        """
        Détecte une activité anormale sur la base de données.

        Args:
            query_pattern: Pattern de requête SQL à analyser
            tenant_id: Identifiant du tenant

        Returns:
            SecurityAlert si anomalie détectée, None sinon

        Invariant:
            INCID_004: Activité anormale DB = alerte
        """
        pass


class IAccountLocker(ABC):
    """
    Interface de verrouillage de comptes après échecs d'authentification.

    Responsabilités:
        - Enregistrement échecs auth
        - Verrouillage automatique après 3 échecs (INCID_003)
        - Déverrouillage automatique après 15 min
        - Déverrouillage manuel par admin
    """

    @abstractmethod
    def record_auth_failure(self, failure: AuthFailure) -> AccountLockStatus:
        """
        Enregistre un échec d'authentification et verrouille si nécessaire.

        Args:
            failure: Détails de l'échec d'authentification

        Returns:
            Statut du compte après enregistrement

        Invariant:
            INCID_003: 3 échecs auth = compte verrouillé temporaire (15 min)
        """
        pass

    @abstractmethod
    def is_locked(self, user_id: str) -> bool:
        """
        Vérifie si un compte est actuellement verrouillé.

        Args:
            user_id: Identifiant utilisateur

        Returns:
            True si compte verrouillé
        """
        pass

    @abstractmethod
    def unlock(self, user_id: str) -> bool:
        """
        Déverrouille manuellement un compte (action admin).

        Args:
            user_id: Identifiant utilisateur

        Returns:
            True si déverrouillage réussi
        """
        pass

    @abstractmethod
    def get_status(self, user_id: str) -> AccountLockStatus:
        """
        Récupère le statut détaillé d'un compte.

        Args:
            user_id: Identifiant utilisateur

        Returns:
            Statut complet du compte
        """
        pass

    @abstractmethod
    def reset_failures(self, user_id: str) -> None:
        """
        Réinitialise le compteur d'échecs (après auth réussie).

        Args:
            user_id: Identifiant utilisateur
        """
        pass
