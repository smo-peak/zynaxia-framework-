"""
LOT 10: Network - Circuit Breaker

Pattern Circuit Breaker pour protection des services.

Invariants:
    NET_004: Circuit breaker ouvert après 5 échecs consécutifs
    NET_005: Circuit breaker half-open après 30 secondes
"""

import functools
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional, TypeVar

T = TypeVar("T")


class CircuitState(Enum):
    """États du circuit breaker."""

    CLOSED = "closed"  # Normal - requêtes passent
    OPEN = "open"  # Échecs - requêtes bloquées
    HALF_OPEN = "half_open"  # Test - une requête passe


@dataclass
class CircuitBreakerConfig:
    """
    Configuration du circuit breaker.

    Invariants:
        NET_004: failure_threshold = 5 par défaut
        NET_005: recovery_timeout = 30s par défaut
    """

    failure_threshold: int = 5  # NET_004: 5 échecs consécutifs
    recovery_timeout: float = 30.0  # NET_005: 30 secondes
    success_threshold: int = 2  # Succès requis en half-open pour fermer


@dataclass
class CircuitBreakerState:
    """État complet du circuit breaker pour monitoring."""

    state: CircuitState
    failure_count: int
    success_count: int
    last_failure_time: Optional[datetime]
    last_state_change: datetime
    total_requests: int
    total_failures: int


class CircuitOpenError(Exception):
    """Circuit ouvert - requête bloquée."""

    def __init__(self, breaker_name: str, retry_after: float) -> None:
        self.breaker_name = breaker_name
        self.retry_after = retry_after
        super().__init__(
            f"Circuit '{breaker_name}' is OPEN. Retry after {retry_after}s"
        )


class CircuitBreaker:
    """
    Circuit breaker pattern pour protection services.

    Protège les services en aval en coupant les requêtes
    après trop d'échecs consécutifs.

    Invariants:
        NET_004: Circuit breaker ouvert après 5 échecs consécutifs
        NET_005: Circuit breaker half-open après 30 secondes
    """

    DEFAULT_FAILURE_THRESHOLD: int = 5  # NET_004
    DEFAULT_RECOVERY_TIMEOUT: float = 30.0  # NET_005
    DEFAULT_SUCCESS_THRESHOLD: int = 2

    def __init__(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None,
    ) -> None:
        """
        Initialise le circuit breaker.

        Args:
            name: Nom identifiant le circuit (pour logs/métriques)
            config: Configuration optionnelle
        """
        if not name or not name.strip():
            raise ValueError("Circuit breaker name cannot be empty")

        self._name = name
        self._config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[datetime] = None
        self._last_state_change = datetime.now(timezone.utc)
        self._total_requests = 0
        self._total_failures = 0

    @property
    def name(self) -> str:
        """Retourne le nom du circuit breaker."""
        return self._name

    @property
    def state(self) -> CircuitState:
        """Retourne l'état actuel du circuit."""
        self._check_recovery()
        return self._state

    def can_execute(self) -> bool:
        """
        Vérifie si une requête peut passer.

        Returns:
            True si la requête peut être exécutée

        Comportement par état:
            - CLOSED: toujours True
            - OPEN: False (sauf si recovery_timeout écoulé → HALF_OPEN)
            - HALF_OPEN: True (permet une requête de test)

        Invariant:
            NET_005: Vérifie si recovery_timeout écoulé
        """
        self._check_recovery()

        if self._state == CircuitState.CLOSED:
            return True
        elif self._state == CircuitState.HALF_OPEN:
            return True
        else:  # OPEN
            return False

    def record_success(self) -> None:
        """
        Enregistre un succès d'exécution.

        En état HALF_OPEN:
            - Incrémente success_count
            - Si success_count >= success_threshold → CLOSED

        En état CLOSED:
            - Reset failure_count à 0
        """
        self._total_requests += 1

        if self._state == CircuitState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self._config.success_threshold:
                self._transition_to(CircuitState.CLOSED)
        elif self._state == CircuitState.CLOSED:
            self._failure_count = 0

    def record_failure(self) -> None:
        """
        Enregistre un échec d'exécution.

        Incrémente failure_count.
        Si failure_count >= failure_threshold → OPEN

        Invariant:
            NET_004: Circuit ouvert après 5 échecs consécutifs
        """
        self._total_requests += 1
        self._total_failures += 1
        self._failure_count += 1
        self._last_failure_time = datetime.now(timezone.utc)

        if self._state == CircuitState.HALF_OPEN:
            # Un échec en half-open → retour à OPEN
            self._transition_to(CircuitState.OPEN)
        elif self._state == CircuitState.CLOSED:
            # NET_004: 5 échecs consécutifs → OPEN
            if self._failure_count >= self._config.failure_threshold:
                self._transition_to(CircuitState.OPEN)

    def _check_recovery(self) -> None:
        """
        Vérifie si le circuit peut passer en HALF_OPEN.

        Si état OPEN et recovery_timeout écoulé → HALF_OPEN

        Invariant:
            NET_005: Circuit breaker half-open après 30 secondes
        """
        if self._state != CircuitState.OPEN:
            return

        if self._last_failure_time is None:
            return

        elapsed = (
            datetime.now(timezone.utc) - self._last_failure_time
        ).total_seconds()

        if elapsed >= self._config.recovery_timeout:
            self._transition_to(CircuitState.HALF_OPEN)

    def _transition_to(self, new_state: CircuitState) -> None:
        """
        Effectue la transition vers un nouvel état.

        Args:
            new_state: Nouvel état cible
        """
        if new_state == self._state:
            return

        self._state = new_state
        self._last_state_change = datetime.now(timezone.utc)

        # Reset des compteurs selon l'état
        if new_state == CircuitState.CLOSED:
            self._failure_count = 0
            self._success_count = 0
        elif new_state == CircuitState.HALF_OPEN:
            self._success_count = 0

    def get_state(self) -> CircuitBreakerState:
        """
        Retourne l'état complet du circuit breaker.

        Returns:
            CircuitBreakerState avec toutes les métriques
        """
        self._check_recovery()

        return CircuitBreakerState(
            state=self._state,
            failure_count=self._failure_count,
            success_count=self._success_count,
            last_failure_time=self._last_failure_time,
            last_state_change=self._last_state_change,
            total_requests=self._total_requests,
            total_failures=self._total_failures,
        )

    def reset(self) -> None:
        """
        Force le reset du circuit à l'état CLOSED.

        Utilisé pour intervention manuelle ou tests.
        """
        self._transition_to(CircuitState.CLOSED)
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time = None

    def get_time_until_recovery(self) -> Optional[float]:
        """
        Retourne le temps restant avant recovery en secondes.

        Returns:
            Temps restant ou None si pas en état OPEN
        """
        if self._state != CircuitState.OPEN:
            return None

        if self._last_failure_time is None:
            return None

        elapsed = (
            datetime.now(timezone.utc) - self._last_failure_time
        ).total_seconds()
        remaining = self._config.recovery_timeout - elapsed

        return max(0.0, remaining)


def with_circuit_breaker(breaker: CircuitBreaker) -> Callable:
    """
    Decorator pour protection avec circuit breaker.

    Usage:
        breaker = CircuitBreaker("api")

        @with_circuit_breaker(breaker)
        async def call_api():
            ...

    Args:
        breaker: Instance de CircuitBreaker à utiliser

    Returns:
        Decorator function

    Raises:
        CircuitOpenError: Si le circuit est ouvert
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            if not breaker.can_execute():
                retry_after = breaker.get_time_until_recovery() or 0.0
                raise CircuitOpenError(breaker.name, retry_after)

            try:
                result = await func(*args, **kwargs)
                breaker.record_success()
                return result
            except Exception:
                breaker.record_failure()
                raise

        return wrapper

    return decorator
