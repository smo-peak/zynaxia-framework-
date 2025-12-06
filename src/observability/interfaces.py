"""
LOT 9: Observability - Interfaces

Définit les interfaces pour la gestion des correlation IDs avec:
- Génération d'identifiants uniques (OBS_001)
- Propagation entre services (OBS_002)
- Inclusion dans les logs (OBS_003)

Invariants:
    OBS_001: Chaque requête DOIT avoir un correlation_id unique (UUID)
    OBS_002: correlation_id propagé dans TOUS les appels
    OBS_003: correlation_id présent dans TOUS les logs liés à la requête
"""

from abc import ABC, abstractmethod
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional


# Context variable pour propagation automatique thread-safe
correlation_id_var: ContextVar[Optional[str]] = ContextVar(
    "correlation_id", default=None
)


@dataclass(frozen=True)
class CorrelationContext:
    """
    Contexte complet de corrélation pour une requête.

    Contient toutes les informations nécessaires pour
    tracer une requête à travers les services.
    """

    correlation_id: str
    parent_id: Optional[str]  # Pour tracing hiérarchique
    tenant_id: Optional[str]
    user_id: Optional[str]
    source: str  # "edge", "cloud", "sync"
    created_at: datetime


class ICorrelationManager(ABC):
    """
    Interface gestion correlation IDs.

    Responsabilités:
        - Génération d'UUID uniques (OBS_001)
        - Gestion du contexte courant
        - Création de contextes enrichis
    """

    @abstractmethod
    def generate(self) -> str:
        """
        Génère un UUID unique pour correlation.

        Returns:
            UUID v4 sous forme de string

        Invariant:
            OBS_001: Chaque requête a un correlation_id unique
        """
        pass

    @abstractmethod
    def get_current(self) -> Optional[str]:
        """
        Retourne le correlation_id courant du contexte.

        Returns:
            correlation_id ou None si non défini
        """
        pass

    @abstractmethod
    def set_current(self, correlation_id: str) -> None:
        """
        Définit le correlation_id dans le contexte.

        Args:
            correlation_id: ID à définir

        Raises:
            ValueError: Si correlation_id invalide
        """
        pass

    @abstractmethod
    def create_context(
        self,
        correlation_id: Optional[str] = None,
        parent_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        user_id: Optional[str] = None,
        source: str = "unknown",
    ) -> CorrelationContext:
        """
        Crée un contexte complet de corrélation.

        Args:
            correlation_id: ID existant ou None pour en générer un
            parent_id: ID parent pour tracing hiérarchique
            tenant_id: Identifiant du tenant
            user_id: Identifiant de l'utilisateur
            source: Source de la requête

        Returns:
            CorrelationContext complet
        """
        pass

    @abstractmethod
    def clear(self) -> None:
        """
        Nettoie le contexte courant (fin de requête).
        """
        pass


class ICorrelationPropagator(ABC):
    """
    Interface propagation correlation ID.

    Responsabilités:
        - Injection dans headers HTTP (OBS_002)
        - Extraction depuis headers (OBS_002)
        - Propagation vers logs (OBS_003)
    """

    @abstractmethod
    def inject_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Injecte correlation_id dans headers HTTP.

        Args:
            headers: Headers existants

        Returns:
            Headers enrichis avec X-Correlation-ID

        Invariant:
            OBS_002: correlation_id propagé dans tous les appels
        """
        pass

    @abstractmethod
    def extract_from_headers(self, headers: Dict[str, str]) -> Optional[str]:
        """
        Extrait correlation_id des headers entrants.

        Args:
            headers: Headers HTTP de la requête

        Returns:
            correlation_id extrait ou None

        Invariant:
            OBS_002: Extraction et définition automatique
        """
        pass

    @abstractmethod
    def propagate_to_log(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ajoute correlation_id aux données de log.

        Args:
            log_data: Données de log existantes

        Returns:
            log_data enrichi avec correlation_id

        Invariant:
            OBS_003: correlation_id présent dans tous les logs
        """
        pass


class ICorrelatedLogger(ABC):
    """
    Interface logger avec correlation automatique.

    Responsabilités:
        - Log avec correlation_id automatique (OBS_003)
        - Méthodes de log par niveau
    """

    @abstractmethod
    def log(self, level: str, message: str, **kwargs: Any) -> None:
        """
        Log avec correlation_id automatique.

        Args:
            level: Niveau de log (INFO, WARNING, ERROR, etc.)
            message: Message à logger
            **kwargs: Données additionnelles

        Invariant:
            OBS_003: correlation_id automatiquement inclus
        """
        pass

    @abstractmethod
    def info(self, message: str, **kwargs: Any) -> None:
        """Log niveau INFO."""
        pass

    @abstractmethod
    def warning(self, message: str, **kwargs: Any) -> None:
        """Log niveau WARNING."""
        pass

    @abstractmethod
    def error(self, message: str, **kwargs: Any) -> None:
        """Log niveau ERROR."""
        pass

    @abstractmethod
    def debug(self, message: str, **kwargs: Any) -> None:
        """Log niveau DEBUG."""
        pass

    @abstractmethod
    def get_logs(self) -> List[Dict[str, Any]]:
        """
        Retourne les logs capturés (pour tests).

        Returns:
            Liste des entrées de log
        """
        pass
