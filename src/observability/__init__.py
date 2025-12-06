"""
LOT 9: Observability

Module d'observabilité avec:
- Correlation IDs pour traçage requêtes (OBS_001-003)

Invariants couverts:
- OBS_001: Chaque requête DOIT avoir un correlation_id unique (UUID)
- OBS_002: correlation_id propagé dans TOUS les appels (Edge→Cloud→DB→Blockchain)
- OBS_003: correlation_id présent dans TOUS les logs liés à la requête
"""

from .interfaces import (
    # Context variable
    correlation_id_var,
    # Data classes
    CorrelationContext,
    # Interfaces
    ICorrelatedLogger,
    ICorrelationManager,
    ICorrelationPropagator,
)
from .correlation import (
    CorrelationManager,
    CorrelationPropagator,
    CorrelatedLogger,
    CorrelationError,
)

__all__ = [
    # Context variable
    "correlation_id_var",
    # Data classes
    "CorrelationContext",
    # Interfaces
    "ICorrelatedLogger",
    "ICorrelationManager",
    "ICorrelationPropagator",
    # Implementations
    "CorrelationManager",
    "CorrelationPropagator",
    "CorrelatedLogger",
    # Exceptions
    "CorrelationError",
]
