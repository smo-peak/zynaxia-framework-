"""
LOT 10: Network - Interfaces

Interfaces pour la gestion réseau:
- Timeouts (NET_001, NET_002)
- Retry avec backoff (NET_003)

Invariants:
    NET_001: Timeout connexion 10 secondes max
    NET_002: Timeout requête 30 secondes max (configurable par endpoint)
    NET_003: Retry automatique 3 tentatives avec backoff exponentiel
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, TypeVar
from enum import Enum

T = TypeVar("T")


class TimeoutType(Enum):
    """Types de timeout supportés."""

    CONNECTION = "connection"
    REQUEST = "request"
    READ = "read"
    WRITE = "write"


@dataclass
class TimeoutConfig:
    """
    Configuration des timeouts.

    Invariants:
        NET_001: connection_timeout max 10s
        NET_002: request_timeout max 30s (configurable)
    """

    connection_timeout: float = 10.0  # NET_001: max 10s
    request_timeout: float = 30.0  # NET_002: max 30s
    read_timeout: Optional[float] = None
    write_timeout: Optional[float] = None


@dataclass
class EndpointTimeoutConfig:
    """Configuration timeout spécifique à un endpoint."""

    endpoint: str
    timeout_config: TimeoutConfig


@dataclass
class RetryConfig:
    """
    Configuration des retries.

    Invariant:
        NET_003: max 3 tentatives avec backoff exponentiel
    """

    max_attempts: int = 3  # NET_003
    initial_delay: float = 1.0
    max_delay: float = 10.0
    exponential_base: float = 2.0
    retryable_exceptions: tuple = field(
        default_factory=lambda: (ConnectionError, TimeoutError)
    )


@dataclass
class RetryResult:
    """Résultat d'une opération avec retry."""

    success: bool
    result: Optional[Any]
    attempts: int
    total_delay: float
    last_error: Optional[Exception]


class ITimeoutManager(ABC):
    """Interface gestion timeouts."""

    @abstractmethod
    def get_timeout(
        self, timeout_type: TimeoutType, endpoint: Optional[str] = None
    ) -> float:
        """
        Retourne timeout configuré.

        Args:
            timeout_type: Type de timeout
            endpoint: Endpoint optionnel pour config spécifique

        Returns:
            Valeur du timeout en secondes
        """
        pass

    @abstractmethod
    def set_endpoint_timeout(self, endpoint: str, config: TimeoutConfig) -> None:
        """
        NET_002: Configure timeout spécifique par endpoint.

        Args:
            endpoint: URL ou identifiant de l'endpoint
            config: Configuration timeout
        """
        pass

    @abstractmethod
    def validate_timeout(self, timeout_type: TimeoutType, value: float) -> bool:
        """
        Valide que timeout respecte les limites.

        Args:
            timeout_type: Type de timeout
            value: Valeur à valider

        Returns:
            True si valide
        """
        pass


class IRetryHandler(ABC):
    """Interface gestion retries."""

    @abstractmethod
    async def execute_with_retry(
        self,
        func: Callable[..., T],
        *args: Any,
        config: Optional[RetryConfig] = None,
        **kwargs: Any,
    ) -> RetryResult:
        """
        NET_003: Exécute avec retry et backoff exponentiel.

        Args:
            func: Fonction à exécuter
            *args: Arguments positionnels
            config: Configuration retry optionnelle
            **kwargs: Arguments nommés

        Returns:
            RetryResult avec succès/échec et détails
        """
        pass

    @abstractmethod
    def calculate_delay(self, attempt: int, config: RetryConfig) -> float:
        """
        Calcule délai backoff exponentiel.

        Args:
            attempt: Numéro de tentative (0-indexed)
            config: Configuration retry

        Returns:
            Délai en secondes
        """
        pass

    @abstractmethod
    def is_retryable(self, error: Exception, config: RetryConfig) -> bool:
        """
        Vérifie si erreur est retryable.

        Args:
            error: Exception à vérifier
            config: Configuration retry

        Returns:
            True si retryable
        """
        pass
