"""
LOT 10: Network

Module de gestion réseau avec:
- Timeouts connexion/requête (NET_001-002)
- Retry avec backoff exponentiel (NET_003)

Invariants couverts:
- NET_001: Timeout connexion 10 secondes max
- NET_002: Timeout requête 30 secondes max (configurable par endpoint)
- NET_003: Retry automatique 3 tentatives avec backoff exponentiel
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

__all__ = [
    # Enums
    "TimeoutType",
    # Data classes
    "TimeoutConfig",
    "EndpointTimeoutConfig",
    "RetryConfig",
    "RetryResult",
    # Interfaces
    "ITimeoutManager",
    "IRetryHandler",
    # Implementations
    "TimeoutManager",
    "RetryHandler",
    # Decorators
    "with_retry",
    "with_retry_sync",
    # Exceptions
    "TimeoutExceededError",
    "InvalidTimeoutError",
    "MaxRetriesExceededError",
]
