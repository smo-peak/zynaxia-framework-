"""
LOT 11: Logging

Module de logging structuré avec:
- Format JSON structuré (LOG_001)
- Champs obligatoires (LOG_002)
- Timestamp ISO 8601 UTC (LOG_003)
- Niveaux standard (LOG_004)
- Masquage données sensibles (LOG_005)

Invariants couverts:
- LOG_001: Format JSON structuré obligatoire
- LOG_002: Champs obligatoires: timestamp, level, correlation_id, tenant_id, message
- LOG_003: Timestamp format ISO 8601 avec timezone UTC
- LOG_004: Niveaux: DEBUG, INFO, WARN, ERROR, CRITICAL
- LOG_005: Données sensibles JAMAIS en clair (masquées)
"""

from .interfaces import (
    # Enums
    LogLevel,
    # Dataclasses
    LogEntry,
    LogConfig,
    # Interfaces
    IStructuredLogger,
    ISensitiveMasker,
)
from .sensitive_masker import (
    SensitiveMasker,
)
from .structured_logger import (
    StructuredLogger,
    ContextualLogger,
    # Exceptions
    MissingRequiredFieldError,
    InvalidLogLevelError,
)

__all__ = [
    # Enums
    "LogLevel",
    # Dataclasses
    "LogEntry",
    "LogConfig",
    # Interfaces
    "IStructuredLogger",
    "ISensitiveMasker",
    # Implementations
    "SensitiveMasker",
    "StructuredLogger",
    "ContextualLogger",
    # Exceptions
    "MissingRequiredFieldError",
    "InvalidLogLevelError",
]
