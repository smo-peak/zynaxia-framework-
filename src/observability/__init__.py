"""
LOT 9: Observability

Module d'observabilité avec:
- Correlation IDs pour traçage requêtes (OBS_001-003)
- Tracing distribué format OpenTelemetry (OBS_004-007)

Invariants couverts:
- OBS_001: Chaque requête DOIT avoir un correlation_id unique (UUID)
- OBS_002: correlation_id propagé dans TOUS les appels (Edge→Cloud→DB→Blockchain)
- OBS_003: correlation_id présent dans TOUS les logs liés à la requête
- OBS_004: Traces exportées format OpenTelemetry
- OBS_005: Retention traces 30 jours minimum
- OBS_006: Latence chaque span mesurée et stockée
- OBS_007: Erreurs tracées avec stack trace complet
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
from .tracing import (
    # Enums
    SpanStatus,
    # Data classes
    Span,
    SpanEvent,
    OpenTelemetryExport,
    TraceRetentionPolicy,
    # Interfaces
    ISpanExporter,
    ITraceStore,
    # Implementations
    InMemoryTraceStore,
    TracingManager,
    # Context manager
    trace_span,
    # Exceptions
    SpanNotFoundError,
    SpanAlreadyEndedError,
    TracingError,
)

__all__ = [
    # Context variable
    "correlation_id_var",
    # Data classes - Correlation
    "CorrelationContext",
    # Data classes - Tracing
    "SpanStatus",
    "Span",
    "SpanEvent",
    "OpenTelemetryExport",
    "TraceRetentionPolicy",
    # Interfaces - Correlation
    "ICorrelatedLogger",
    "ICorrelationManager",
    "ICorrelationPropagator",
    # Interfaces - Tracing
    "ISpanExporter",
    "ITraceStore",
    # Implementations - Correlation
    "CorrelationManager",
    "CorrelationPropagator",
    "CorrelatedLogger",
    # Implementations - Tracing
    "InMemoryTraceStore",
    "TracingManager",
    # Context manager
    "trace_span",
    # Exceptions
    "CorrelationError",
    "SpanNotFoundError",
    "SpanAlreadyEndedError",
    "TracingError",
]
