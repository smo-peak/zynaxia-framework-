"""
LOT 10: Network

Module de gestion réseau avec:
- Timeouts connexion/requête (NET_001-002)
- Retry avec backoff exponentiel (NET_003)
- Circuit breaker (NET_004-005)
- Mode dégradé et reconnexion (NET_006-008)

Invariants couverts:
- NET_001: Timeout connexion 10 secondes max
- NET_002: Timeout requête 30 secondes max (configurable par endpoint)
- NET_003: Retry automatique 3 tentatives avec backoff exponentiel
- NET_004: Circuit breaker ouvert après 5 échecs consécutifs
- NET_005: Circuit breaker half-open après 30 secondes
- NET_006: Connexion Cloud perdue = mode dégradé (pas crash)
- NET_007: Reconnexion automatique avec backoff
- NET_008: Keep-alive TCP activé (détection connexion morte)
"""

from .interfaces import (
    # Enums
    TimeoutType,
    # Data classes
    TimeoutConfig,
    EndpointTimeoutConfig,
    RetryConfig,
    RetryResult,
    # Interfaces
    ITimeoutManager,
    IRetryHandler,
)
from .timeout_manager import (
    TimeoutManager,
    TimeoutExceededError,
    InvalidTimeoutError,
)
from .retry_handler import (
    RetryHandler,
    MaxRetriesExceededError,
    with_retry,
    with_retry_sync,
)
from .circuit_breaker import (
    # Enums
    CircuitState,
    # Data classes
    CircuitBreakerConfig,
    CircuitBreakerState,
    # Implementations
    CircuitBreaker,
    # Decorators
    with_circuit_breaker,
    # Exceptions
    CircuitOpenError,
)
from .connection_manager import (
    # Enums
    ConnectionState,
    # Data classes
    KeepAliveConfig,
    ConnectionStatus,
    # Implementations
    ConnectionManager,
    # Exceptions
    ConnectionLostError,
    DegradedModeError,
)

__all__ = [
    # Enums
    "TimeoutType",
    "CircuitState",
    "ConnectionState",
    # Data classes
    "TimeoutConfig",
    "EndpointTimeoutConfig",
    "RetryConfig",
    "RetryResult",
    "CircuitBreakerConfig",
    "CircuitBreakerState",
    "KeepAliveConfig",
    "ConnectionStatus",
    # Interfaces
    "ITimeoutManager",
    "IRetryHandler",
    # Implementations
    "TimeoutManager",
    "RetryHandler",
    "CircuitBreaker",
    "ConnectionManager",
    # Decorators
    "with_retry",
    "with_retry_sync",
    "with_circuit_breaker",
    # Exceptions
    "TimeoutExceededError",
    "InvalidTimeoutError",
    "MaxRetriesExceededError",
    "CircuitOpenError",
    "ConnectionLostError",
    "DegradedModeError",
]
