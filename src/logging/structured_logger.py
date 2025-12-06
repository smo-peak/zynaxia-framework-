"""
LOT 11: Logging - Structured Logger

Logger JSON structuré avec champs obligatoires.

Invariants:
    LOG_001: Format JSON structuré obligatoire
    LOG_002: Champs obligatoires: timestamp, level, correlation_id, tenant_id, message
    LOG_003: Timestamp format ISO 8601 avec timezone UTC
    LOG_004: Niveaux: DEBUG, INFO, WARN, ERROR, CRITICAL
    LOG_005: Données sensibles JAMAIS en clair (masquées)
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from .interfaces import (
    IStructuredLogger,
    ISensitiveMasker,
    LogConfig,
    LogEntry,
    LogLevel,
)
from .sensitive_masker import SensitiveMasker


class MissingRequiredFieldError(Exception):
    """Champ obligatoire manquant - LOG_002."""

    def __init__(self, field_name: str) -> None:
        self.field_name = field_name
        super().__init__(f"Required field missing: {field_name} - LOG_002")


class InvalidLogLevelError(Exception):
    """Niveau de log invalide - LOG_004."""

    def __init__(self, level: str) -> None:
        self.level = level
        super().__init__(f"Invalid log level: {level} - LOG_004")


class StructuredLogger(IStructuredLogger):
    """
    Logger JSON structuré avec champs obligatoires.

    Implémente un système de logging conforme aux invariants LOG_001-005
    avec support multi-tenant et corrélation.

    Invariants:
        LOG_001: Format JSON structuré obligatoire
        LOG_002: Champs obligatoires présents
        LOG_003: Timestamp ISO 8601 UTC
        LOG_004: Niveaux standard
        LOG_005: Masquage données sensibles

    Example:
        logger = StructuredLogger("my-service")
        logger.set_default_tenant("tenant-123")
        logger.set_default_correlation("corr-456")
        logger.info("User logged in", user_id="u-789")
    """

    def __init__(
        self,
        name: str,
        config: Optional[LogConfig] = None,
        masker: Optional[ISensitiveMasker] = None,
        output_handler: Optional[Callable[[str], None]] = None,
    ) -> None:
        """
        Initialise le logger structuré.

        Args:
            name: Nom du logger (identifiant service/module)
            config: Configuration optionnelle
            masker: Masker pour données sensibles (LOG_005)
            output_handler: Handler personnalisé pour output (pour tests)

        Raises:
            ValueError: Si name vide
        """
        if not name or not name.strip():
            raise ValueError("Logger name cannot be empty")

        self._name = name.strip()
        self._config = config or LogConfig()
        self._masker = masker or SensitiveMasker()
        self._output_handler = output_handler
        self._entries: List[LogEntry] = []
        self._default_tenant_id: Optional[str] = self._config.default_tenant_id
        self._default_correlation_id: Optional[str] = self._config.default_correlation_id

    @property
    def name(self) -> str:
        """Retourne le nom du logger."""
        return self._name

    @property
    def config(self) -> LogConfig:
        """Retourne la configuration."""
        return self._config

    def set_default_tenant(self, tenant_id: str) -> None:
        """
        Définit tenant_id par défaut.

        Args:
            tenant_id: ID tenant par défaut
        """
        self._default_tenant_id = tenant_id

    def set_default_correlation(self, correlation_id: str) -> None:
        """
        Définit correlation_id par défaut.

        Args:
            correlation_id: ID corrélation par défaut
        """
        self._default_correlation_id = correlation_id

    def clear_defaults(self) -> None:
        """Efface les valeurs par défaut."""
        self._default_tenant_id = None
        self._default_correlation_id = None

    def log(
        self,
        level: LogLevel,
        message: str,
        correlation_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        **extra: Any,
    ) -> Optional[LogEntry]:
        """
        LOG_001-005: Crée log structuré JSON.

        Processus:
            1. Vérifie niveau >= min_level
            2. Génère timestamp ISO 8601 UTC (LOG_003)
            3. Résout correlation_id et tenant_id
            4. Masque données sensibles dans extra (LOG_005)
            5. Crée LogEntry avec champs obligatoires (LOG_002)
            6. Output JSON (LOG_001)

        Args:
            level: Niveau de log (LOG_004)
            message: Message à logger
            correlation_id: ID de corrélation (ou default)
            tenant_id: ID tenant (ou default)
            **extra: Données supplémentaires

        Returns:
            LogEntry créé ou None si filtré

        Raises:
            MissingRequiredFieldError: Si champ obligatoire manquant
        """
        # Vérifier niveau minimum
        if not self._should_log(level):
            return None

        # Résoudre correlation_id (LOG_002)
        resolved_correlation = correlation_id or self._default_correlation_id
        if not resolved_correlation:
            resolved_correlation = self._generate_correlation_id()

        # Résoudre tenant_id (LOG_002)
        resolved_tenant = tenant_id or self._default_tenant_id
        if not resolved_tenant:
            raise MissingRequiredFieldError("tenant_id")

        # Valider message (LOG_002)
        if not message:
            raise MissingRequiredFieldError("message")

        # Masquer données sensibles (LOG_005)
        masked_extra: Dict[str, Any] = {}
        if extra and self._config.include_extra:
            if self._config.mask_sensitive:
                masked_extra = self._masker.mask(dict(extra))
            else:
                masked_extra = dict(extra)

        # Créer entry (LOG_002, LOG_003)
        entry = LogEntry(
            timestamp=self._generate_timestamp(),
            level=level,
            correlation_id=resolved_correlation,
            tenant_id=resolved_tenant,
            message=message,
            extra=masked_extra,
            logger_name=self._name,
        )

        # Stocker pour tests
        self._entries.append(entry)

        # Output JSON (LOG_001)
        json_output = entry.to_json()
        if self._output_handler:
            self._output_handler(json_output)

        return entry

    def _generate_timestamp(self) -> str:
        """
        LOG_003: Génère timestamp ISO 8601 UTC avec millisecondes.

        Format: 2024-12-04T14:30:00.123Z

        Returns:
            Timestamp formaté
        """
        now = datetime.now(timezone.utc)
        # Format ISO 8601 avec millisecondes et Z pour UTC
        return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"

    def _generate_correlation_id(self) -> str:
        """
        Génère un correlation_id unique.

        Returns:
            UUID v4 comme correlation_id
        """
        return str(uuid.uuid4())

    def _should_log(self, level: LogLevel) -> bool:
        """
        Vérifie si niveau >= min_level.

        Args:
            level: Niveau à vérifier

        Returns:
            True si doit être loggé
        """
        return LogLevel.get_priority(level) >= LogLevel.get_priority(
            self._config.min_level
        )

    def debug(self, message: str, **extra: Any) -> Optional[LogEntry]:
        """
        Log niveau DEBUG.

        Args:
            message: Message à logger
            **extra: Données supplémentaires

        Returns:
            LogEntry ou None si filtré
        """
        return self.log(LogLevel.DEBUG, message, **extra)

    def info(self, message: str, **extra: Any) -> Optional[LogEntry]:
        """
        Log niveau INFO.

        Args:
            message: Message à logger
            **extra: Données supplémentaires

        Returns:
            LogEntry ou None si filtré
        """
        return self.log(LogLevel.INFO, message, **extra)

    def warn(self, message: str, **extra: Any) -> Optional[LogEntry]:
        """
        Log niveau WARN.

        Args:
            message: Message à logger
            **extra: Données supplémentaires

        Returns:
            LogEntry ou None si filtré
        """
        return self.log(LogLevel.WARN, message, **extra)

    def error(self, message: str, **extra: Any) -> Optional[LogEntry]:
        """
        Log niveau ERROR.

        Args:
            message: Message à logger
            **extra: Données supplémentaires

        Returns:
            LogEntry ou None si filtré
        """
        return self.log(LogLevel.ERROR, message, **extra)

    def critical(self, message: str, **extra: Any) -> Optional[LogEntry]:
        """
        Log niveau CRITICAL.

        Args:
            message: Message à logger
            **extra: Données supplémentaires

        Returns:
            LogEntry ou None si filtré
        """
        return self.log(LogLevel.CRITICAL, message, **extra)

    def get_entries(self) -> List[LogEntry]:
        """
        Retourne les entrées de log capturées.

        Utile pour tests et débogage.

        Returns:
            Liste des LogEntry
        """
        return list(self._entries)

    def clear_entries(self) -> None:
        """Efface les entrées capturées."""
        self._entries.clear()

    def get_entries_by_level(self, level: LogLevel) -> List[LogEntry]:
        """
        Filtre les entrées par niveau.

        Args:
            level: Niveau à filtrer

        Returns:
            Liste des LogEntry du niveau spécifié
        """
        return [e for e in self._entries if e.level == level]

    def get_entries_by_correlation(self, correlation_id: str) -> List[LogEntry]:
        """
        Filtre les entrées par correlation_id.

        Args:
            correlation_id: ID de corrélation

        Returns:
            Liste des LogEntry avec ce correlation_id
        """
        return [e for e in self._entries if e.correlation_id == correlation_id]

    def with_context(
        self,
        correlation_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> "ContextualLogger":
        """
        Crée un logger avec contexte pré-défini.

        Args:
            correlation_id: ID corrélation pour ce contexte
            tenant_id: ID tenant pour ce contexte

        Returns:
            ContextualLogger avec contexte fixé
        """
        return ContextualLogger(
            self,
            correlation_id=correlation_id or self._default_correlation_id,
            tenant_id=tenant_id or self._default_tenant_id,
        )


class ContextualLogger:
    """
    Logger avec contexte pré-défini.

    Wrapper qui fixe correlation_id et tenant_id pour
    éviter de les répéter à chaque appel.
    """

    def __init__(
        self,
        logger: StructuredLogger,
        correlation_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> None:
        """
        Args:
            logger: Logger parent
            correlation_id: ID corrélation fixé
            tenant_id: ID tenant fixé
        """
        self._logger = logger
        self._correlation_id = correlation_id
        self._tenant_id = tenant_id

    def log(
        self, level: LogLevel, message: str, **extra: Any
    ) -> Optional[LogEntry]:
        """Log avec contexte."""
        return self._logger.log(
            level,
            message,
            correlation_id=self._correlation_id,
            tenant_id=self._tenant_id,
            **extra,
        )

    def debug(self, message: str, **extra: Any) -> Optional[LogEntry]:
        """Log DEBUG."""
        return self.log(LogLevel.DEBUG, message, **extra)

    def info(self, message: str, **extra: Any) -> Optional[LogEntry]:
        """Log INFO."""
        return self.log(LogLevel.INFO, message, **extra)

    def warn(self, message: str, **extra: Any) -> Optional[LogEntry]:
        """Log WARN."""
        return self.log(LogLevel.WARN, message, **extra)

    def error(self, message: str, **extra: Any) -> Optional[LogEntry]:
        """Log ERROR."""
        return self.log(LogLevel.ERROR, message, **extra)

    def critical(self, message: str, **extra: Any) -> Optional[LogEntry]:
        """Log CRITICAL."""
        return self.log(LogLevel.CRITICAL, message, **extra)
