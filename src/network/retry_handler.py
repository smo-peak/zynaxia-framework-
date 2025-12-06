"""
LOT 10: Network - Retry Handler

Gestion des retries avec backoff exponentiel.

Invariant:
    NET_003: Retry automatique 3 tentatives avec backoff exponentiel
"""

import asyncio
import functools
import time
from typing import Any, Callable, Dict, Optional, TypeVar

from .interfaces import IRetryHandler, RetryConfig, RetryResult

T = TypeVar("T")


class MaxRetriesExceededError(Exception):
    """Nombre max de retries atteint."""

    def __init__(self, attempts: int, last_error: Exception) -> None:
        self.attempts = attempts
        self.last_error = last_error
        super().__init__(f"Max retries ({attempts}) exceeded: {last_error}")


class RetryHandler(IRetryHandler):
    """
    Gestion retries avec backoff exponentiel.

    Invariant:
        NET_003: Retry automatique 3 tentatives avec backoff exponentiel
    """

    DEFAULT_MAX_ATTEMPTS: int = 3
    DEFAULT_INITIAL_DELAY: float = 1.0
    DEFAULT_MAX_DELAY: float = 10.0
    DEFAULT_EXPONENTIAL_BASE: float = 2.0

    def __init__(self, default_config: Optional[RetryConfig] = None) -> None:
        """
        Initialise le gestionnaire de retries.

        Args:
            default_config: Configuration par défaut (optionnel)
        """
        self._default_config = default_config or RetryConfig()
        self._retry_stats: Dict[str, int] = {
            "total_retries": 0,
            "successful_retries": 0,
            "failed_retries": 0,
        }

    async def execute_with_retry(
        self,
        func: Callable[..., T],
        *args: Any,
        config: Optional[RetryConfig] = None,
        **kwargs: Any,
    ) -> RetryResult:
        """
        Exécute func avec max 3 tentatives et backoff exponentiel.

        Backoff: delay = min(initial * (base ^ attempt), max_delay)
        - Attempt 0: 1s
        - Attempt 1: 2s
        - Attempt 2: 4s (capped at max_delay)

        Args:
            func: Fonction à exécuter (sync ou async)
            *args: Arguments positionnels
            config: Configuration retry optionnelle
            **kwargs: Arguments nommés

        Returns:
            RetryResult avec succès/échec et détails

        Invariant:
            NET_003: Max 3 tentatives avec backoff exponentiel
        """
        retry_config = config or self._default_config
        last_error: Optional[Exception] = None
        total_delay: float = 0.0

        for attempt in range(retry_config.max_attempts):
            try:
                # Exécuter la fonction
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)

                # Succès
                if attempt > 0:
                    self._retry_stats["successful_retries"] += 1

                return RetryResult(
                    success=True,
                    result=result,
                    attempts=attempt + 1,
                    total_delay=total_delay,
                    last_error=None,
                )

            except Exception as e:
                last_error = e
                self._retry_stats["total_retries"] += 1

                # Vérifier si retryable
                if not self.is_retryable(e, retry_config):
                    # Non retryable, échouer immédiatement
                    return RetryResult(
                        success=False,
                        result=None,
                        attempts=attempt + 1,
                        total_delay=total_delay,
                        last_error=e,
                    )

                # Si pas dernière tentative, attendre avec backoff
                if attempt < retry_config.max_attempts - 1:
                    delay = self.calculate_delay(attempt, retry_config)
                    total_delay += delay
                    await asyncio.sleep(delay)

        # Toutes les tentatives échouées
        self._retry_stats["failed_retries"] += 1

        return RetryResult(
            success=False,
            result=None,
            attempts=retry_config.max_attempts,
            total_delay=total_delay,
            last_error=last_error,
        )

    def calculate_delay(self, attempt: int, config: RetryConfig) -> float:
        """
        Calcule délai backoff exponentiel.

        Formula: min(initial * (base ^ attempt), max_delay)
        - Attempt 0: initial_delay (1s)
        - Attempt 1: initial_delay * base (2s)
        - Attempt 2: initial_delay * base^2 (4s)

        Args:
            attempt: Numéro de tentative (0-indexed)
            config: Configuration retry

        Returns:
            Délai en secondes
        """
        delay = config.initial_delay * (config.exponential_base**attempt)
        return min(delay, config.max_delay)

    def is_retryable(self, error: Exception, config: RetryConfig) -> bool:
        """
        Vérifie si exception est retryable.

        Args:
            error: Exception à vérifier
            config: Configuration retry

        Returns:
            True si l'erreur est dans retryable_exceptions
        """
        return isinstance(error, config.retryable_exceptions)

    def get_retry_stats(self) -> Dict[str, int]:
        """
        Retourne les statistiques de retry.

        Returns:
            Dict avec total_retries, successful_retries, failed_retries
        """
        return dict(self._retry_stats)

    def reset_stats(self) -> None:
        """Remet les statistiques à zéro."""
        self._retry_stats = {
            "total_retries": 0,
            "successful_retries": 0,
            "failed_retries": 0,
        }


def with_retry(
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 10.0,
    exponential_base: float = 2.0,
    retryable_exceptions: tuple = (ConnectionError, TimeoutError),
) -> Callable:
    """
    Decorator pour retry automatique.

    Usage:
        @with_retry(max_attempts=3)
        async def call_api():
            ...

    Args:
        max_attempts: Nombre max de tentatives (défaut: 3)
        initial_delay: Délai initial en secondes (défaut: 1.0)
        max_delay: Délai maximum en secondes (défaut: 10.0)
        exponential_base: Base pour backoff exponentiel (défaut: 2.0)
        retryable_exceptions: Tuple d'exceptions retryables

    Returns:
        Decorator function

    Invariant:
        NET_003: Retry automatique avec backoff exponentiel
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            handler = RetryHandler()
            config = RetryConfig(
                max_attempts=max_attempts,
                initial_delay=initial_delay,
                max_delay=max_delay,
                exponential_base=exponential_base,
                retryable_exceptions=retryable_exceptions,
            )
            result = await handler.execute_with_retry(func, *args, config=config, **kwargs)
            if not result.success:
                raise MaxRetriesExceededError(result.attempts, result.last_error)
            return result.result

        return wrapper

    return decorator


def with_retry_sync(
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 10.0,
    exponential_base: float = 2.0,
    retryable_exceptions: tuple = (ConnectionError, TimeoutError),
) -> Callable:
    """
    Decorator pour retry automatique (version synchrone).

    Usage:
        @with_retry_sync(max_attempts=3)
        def call_api():
            ...

    Args:
        max_attempts: Nombre max de tentatives (défaut: 3)
        initial_delay: Délai initial en secondes (défaut: 1.0)
        max_delay: Délai maximum en secondes (défaut: 10.0)
        exponential_base: Base pour backoff exponentiel (défaut: 2.0)
        retryable_exceptions: Tuple d'exceptions retryables

    Returns:
        Decorator function
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            config = RetryConfig(
                max_attempts=max_attempts,
                initial_delay=initial_delay,
                max_delay=max_delay,
                exponential_base=exponential_base,
                retryable_exceptions=retryable_exceptions,
            )
            last_error: Optional[Exception] = None

            for attempt in range(config.max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_error = e
                    if not isinstance(e, config.retryable_exceptions):
                        raise
                    if attempt < config.max_attempts - 1:
                        delay = config.initial_delay * (config.exponential_base**attempt)
                        delay = min(delay, config.max_delay)
                        time.sleep(delay)

            raise MaxRetriesExceededError(config.max_attempts, last_error)

        return wrapper

    return decorator
