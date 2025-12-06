"""
LOT 11: Logging - Interfaces

Interfaces pour logging structuré.

Invariants:
    LOG_001: Format JSON structuré obligatoire
    LOG_002: Champs obligatoires: timestamp, level, correlation_id, tenant_id, message
    LOG_003: Timestamp format ISO 8601 avec timezone UTC
    LOG_004: Niveaux: DEBUG, INFO, WARN, ERROR, CRITICAL
    LOG_005: Données sensibles JAMAIS en clair (masquées)
"""

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class LogLevel(Enum):
    """
    LOG_004: Niveaux de log standard.

    Ordre de sévérité: DEBUG < INFO < WARN < ERROR < CRITICAL
    """

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

    @classmethod
    def get_priority(cls, level: "LogLevel") -> int:
        """Retourne la priorité du niveau (plus haut = plus sévère)."""
        priorities = {
            cls.DEBUG: 0,
            cls.INFO: 1,
            cls.WARN: 2,
            cls.ERROR: 3,
            cls.CRITICAL: 4,
        }
        return priorities.get(level, 0)


@dataclass
class LogEntry:
    """
    LOG_002: Structure log avec champs obligatoires.

    Tous les champs sont requis pour conformité audit.
    """

    timestamp: str  # LOG_003: ISO 8601 UTC
    level: LogLevel  # LOG_004
    correlation_id: str  # Obligatoire - traçabilité
    tenant_id: str  # Obligatoire - multi-tenant
    message: str  # Obligatoire - description
    extra: Dict[str, Any] = field(default_factory=dict)
    logger_name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convertit en dictionnaire."""
        result = {
            "timestamp": self.timestamp,
            "level": self.level.value,
            "correlation_id": self.correlation_id,
            "tenant_id": self.tenant_id,
            "message": self.message,
        }
        if self.logger_name:
            result["logger"] = self.logger_name
        if self.extra:
            result["extra"] = self.extra
        return result

    def to_json(self) -> str:
        """LOG_001: Convertit en JSON structuré."""
        return json.dumps(self.to_dict(), ensure_ascii=False)


@dataclass
class LogConfig:
    """Configuration du logger structuré."""

    min_level: LogLevel = LogLevel.INFO
    include_extra: bool = True
    mask_sensitive: bool = True  # LOG_005
    default_tenant_id: Optional[str] = None
    default_correlation_id: Optional[str] = None


class IStructuredLogger(ABC):
    """
    Interface logger structuré.

    Invariants:
        LOG_001: Format JSON structuré obligatoire
        LOG_002: Champs obligatoires présents
        LOG_003: Timestamp ISO 8601 UTC
        LOG_004: Niveaux standard
        LOG_005: Masquage données sensibles
    """

    @abstractmethod
    def log(
        self,
        level: LogLevel,
        message: str,
        correlation_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        **extra: Any,
    ) -> Optional[LogEntry]:
        """
        LOG_001-004: Log structuré JSON.

        Args:
            level: Niveau de log
            message: Message à logger
            correlation_id: ID de corrélation (optionnel si default défini)
            tenant_id: ID tenant (optionnel si default défini)
            **extra: Données supplémentaires

        Returns:
            LogEntry créé ou None si filtré par niveau
        """
        pass

    @abstractmethod
    def debug(self, message: str, **extra: Any) -> Optional[LogEntry]:
        """Log niveau DEBUG."""
        pass

    @abstractmethod
    def info(self, message: str, **extra: Any) -> Optional[LogEntry]:
        """Log niveau INFO."""
        pass

    @abstractmethod
    def warn(self, message: str, **extra: Any) -> Optional[LogEntry]:
        """Log niveau WARN."""
        pass

    @abstractmethod
    def error(self, message: str, **extra: Any) -> Optional[LogEntry]:
        """Log niveau ERROR."""
        pass

    @abstractmethod
    def critical(self, message: str, **extra: Any) -> Optional[LogEntry]:
        """Log niveau CRITICAL."""
        pass

    @abstractmethod
    def get_entries(self) -> List[LogEntry]:
        """Retourne les entrées de log capturées (pour tests)."""
        pass


class ISensitiveMasker(ABC):
    """
    Interface masquage données sensibles.

    Invariant:
        LOG_005: Données sensibles JAMAIS en clair
    """

    SENSITIVE_PATTERNS: List[str] = [
        "password",
        "passwd",
        "pwd",
        "token",
        "access_token",
        "refresh_token",
        "secret",
        "api_key",
        "apikey",
        "key",
        "private_key",
        "credential",
        "auth",
        "authorization",
        "bearer",
        "jwt",
        "session_id",
        "cookie",
        "credit_card",
        "cvv",
        "ssn",
        "pin",
    ]

    MASK_VALUE: str = "***MASKED***"

    @abstractmethod
    def mask(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        LOG_005: Masque données sensibles dans un dictionnaire.

        Args:
            data: Dictionnaire à masquer

        Returns:
            Copie avec données sensibles masquées
        """
        pass

    @abstractmethod
    def mask_string(self, value: str) -> str:
        """
        Masque valeur string sensible.

        Args:
            value: Valeur à masquer

        Returns:
            Valeur masquée
        """
        pass

    @abstractmethod
    def is_sensitive_key(self, key: str) -> bool:
        """
        Vérifie si clé est sensible.

        Args:
            key: Nom de la clé

        Returns:
            True si clé contient pattern sensible
        """
        pass

    @abstractmethod
    def add_pattern(self, pattern: str) -> None:
        """
        Ajoute pattern sensible personnalisé.

        Args:
            pattern: Pattern à ajouter
        """
        pass
