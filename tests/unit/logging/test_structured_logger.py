"""
Tests unitaires pour LOT 11: Logging - Structured Logger

Tests des invariants:
- LOG_001: Format JSON structuré obligatoire
- LOG_002: Champs obligatoires: timestamp, level, correlation_id, tenant_id, message
- LOG_003: Timestamp format ISO 8601 avec timezone UTC
- LOG_004: Niveaux: DEBUG, INFO, WARN, ERROR, CRITICAL
- LOG_005: Données sensibles JAMAIS en clair (masquées)
"""

import json
import re
from datetime import datetime, timezone

import pytest

from src.logging import (
    StructuredLogger,
    ContextualLogger,
    LogConfig,
    LogEntry,
    LogLevel,
    MissingRequiredFieldError,
    InvalidLogLevelError,
    IStructuredLogger,
)


class TestLOG001JsonFormat:
    """Tests LOG_001: Format JSON structuré obligatoire."""

    def test_LOG_001_output_is_valid_json(self) -> None:
        """LOG_001: Output est JSON valide."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Test message")
        assert entry is not None

        json_str = entry.to_json()
        parsed = json.loads(json_str)

        assert isinstance(parsed, dict)

    def test_LOG_001_json_contains_all_fields(self) -> None:
        """LOG_001: JSON contient tous les champs."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Test message")
        assert entry is not None

        parsed = json.loads(entry.to_json())

        assert "timestamp" in parsed
        assert "level" in parsed
        assert "correlation_id" in parsed
        assert "tenant_id" in parsed
        assert "message" in parsed

    def test_LOG_001_json_includes_extra(self) -> None:
        """LOG_001: JSON inclut données extra."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Test", user_id="u-123", action="login")
        assert entry is not None

        parsed = json.loads(entry.to_json())

        assert "extra" in parsed
        assert parsed["extra"]["user_id"] == "u-123"
        assert parsed["extra"]["action"] == "login"

    def test_LOG_001_json_includes_logger_name(self) -> None:
        """LOG_001: JSON inclut nom du logger."""
        logger = StructuredLogger("my-service")
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Test")
        assert entry is not None

        parsed = json.loads(entry.to_json())

        assert parsed["logger"] == "my-service"

    def test_LOG_001_to_dict_method(self) -> None:
        """LOG_001: to_dict retourne dictionnaire."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Test")
        assert entry is not None

        data = entry.to_dict()
        assert isinstance(data, dict)

    def test_LOG_001_json_output_handler(self) -> None:
        """LOG_001: Output handler reçoit JSON."""
        outputs = []

        def handler(json_str: str) -> None:
            outputs.append(json_str)

        logger = StructuredLogger("test", output_handler=handler)
        logger.set_default_tenant("tenant-1")
        logger.info("Test message")

        assert len(outputs) == 1
        parsed = json.loads(outputs[0])
        assert parsed["message"] == "Test message"

    def test_LOG_001_json_unicode_handling(self) -> None:
        """LOG_001: JSON gère unicode correctement."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Message avec accents: éàü")
        assert entry is not None

        json_str = entry.to_json()
        parsed = json.loads(json_str)

        assert "éàü" in parsed["message"]

    def test_LOG_001_empty_extra_not_in_json(self) -> None:
        """LOG_001: Extra vide non inclus dans JSON."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Test")
        assert entry is not None

        parsed = json.loads(entry.to_json())

        # Extra vide ne devrait pas être présent ou être vide
        if "extra" in parsed:
            assert parsed["extra"] == {}


class TestLOG002RequiredFields:
    """Tests LOG_002: Champs obligatoires."""

    def test_LOG_002_timestamp_present(self) -> None:
        """LOG_002: Timestamp présent."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Test")
        assert entry is not None
        assert entry.timestamp is not None
        assert len(entry.timestamp) > 0

    def test_LOG_002_level_present(self) -> None:
        """LOG_002: Level présent."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Test")
        assert entry is not None
        assert entry.level == LogLevel.INFO

    def test_LOG_002_correlation_id_present(self) -> None:
        """LOG_002: Correlation ID présent."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Test")
        assert entry is not None
        assert entry.correlation_id is not None
        assert len(entry.correlation_id) > 0

    def test_LOG_002_tenant_id_required(self) -> None:
        """LOG_002: Tenant ID requis."""
        logger = StructuredLogger("test")

        with pytest.raises(MissingRequiredFieldError) as exc:
            logger.info("Test without tenant")

        assert "tenant_id" in str(exc.value)
        assert "LOG_002" in str(exc.value)

    def test_LOG_002_message_required(self) -> None:
        """LOG_002: Message requis."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        with pytest.raises(MissingRequiredFieldError) as exc:
            logger.info("")

        assert "message" in str(exc.value)

    def test_LOG_002_explicit_correlation_id(self) -> None:
        """LOG_002: Correlation ID explicite utilisé."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.log(
            LogLevel.INFO,
            "Test",
            correlation_id="corr-explicit",
        )
        assert entry is not None
        assert entry.correlation_id == "corr-explicit"

    def test_LOG_002_explicit_tenant_id(self) -> None:
        """LOG_002: Tenant ID explicite utilisé."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("default-tenant")

        entry = logger.log(
            LogLevel.INFO,
            "Test",
            tenant_id="explicit-tenant",
        )
        assert entry is not None
        assert entry.tenant_id == "explicit-tenant"

    def test_LOG_002_default_correlation_id(self) -> None:
        """LOG_002: Correlation ID par défaut utilisé."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")
        logger.set_default_correlation("default-corr")

        entry = logger.info("Test")
        assert entry is not None
        assert entry.correlation_id == "default-corr"

    def test_LOG_002_auto_generated_correlation_id(self) -> None:
        """LOG_002: Correlation ID auto-généré si non fourni."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Test")
        assert entry is not None

        # UUID format
        assert len(entry.correlation_id) == 36
        assert entry.correlation_id.count("-") == 4

    def test_LOG_002_all_fields_in_log_entry(self) -> None:
        """LOG_002: Tous les champs dans LogEntry."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")
        logger.set_default_correlation("corr-1")

        entry = logger.info("Test message")
        assert entry is not None

        assert hasattr(entry, "timestamp")
        assert hasattr(entry, "level")
        assert hasattr(entry, "correlation_id")
        assert hasattr(entry, "tenant_id")
        assert hasattr(entry, "message")

    def test_LOG_002_config_default_tenant(self) -> None:
        """LOG_002: Config avec tenant par défaut."""
        config = LogConfig(default_tenant_id="config-tenant")
        logger = StructuredLogger("test", config=config)

        entry = logger.info("Test")
        assert entry is not None
        assert entry.tenant_id == "config-tenant"


class TestLOG003TimestampFormat:
    """Tests LOG_003: Timestamp format ISO 8601 avec timezone UTC."""

    ISO_8601_PATTERN = re.compile(
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
    )

    def test_LOG_003_timestamp_iso_8601_format(self) -> None:
        """LOG_003: Timestamp format ISO 8601."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Test")
        assert entry is not None

        assert self.ISO_8601_PATTERN.match(entry.timestamp)

    def test_LOG_003_timestamp_ends_with_z(self) -> None:
        """LOG_003: Timestamp termine par Z (UTC)."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Test")
        assert entry is not None
        assert entry.timestamp.endswith("Z")

    def test_LOG_003_timestamp_has_milliseconds(self) -> None:
        """LOG_003: Timestamp inclut millisecondes."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Test")
        assert entry is not None

        # Format: 2024-12-04T14:30:00.123Z
        parts = entry.timestamp.split(".")
        assert len(parts) == 2
        assert len(parts[1]) == 4  # 123Z

    def test_LOG_003_timestamp_year_month_day(self) -> None:
        """LOG_003: Timestamp contient année-mois-jour."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Test")
        assert entry is not None

        now = datetime.now(timezone.utc)
        assert entry.timestamp.startswith(f"{now.year}-")

    def test_LOG_003_timestamp_parseable(self) -> None:
        """LOG_003: Timestamp parseable."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Test")
        assert entry is not None

        # Parse ISO format
        ts = entry.timestamp.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(ts)
        assert parsed.tzinfo is not None

    def test_LOG_003_sequential_timestamps_ordered(self) -> None:
        """LOG_003: Timestamps séquentiels ordonnés."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entries = [logger.info(f"Test {i}") for i in range(5)]

        timestamps = [e.timestamp for e in entries if e is not None]
        assert timestamps == sorted(timestamps)

    def test_LOG_003_timestamp_in_json(self) -> None:
        """LOG_003: Timestamp présent dans JSON."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Test")
        assert entry is not None

        parsed = json.loads(entry.to_json())
        assert self.ISO_8601_PATTERN.match(parsed["timestamp"])


class TestLOG004LogLevels:
    """Tests LOG_004: Niveaux DEBUG, INFO, WARN, ERROR, CRITICAL."""

    def test_LOG_004_debug_level(self) -> None:
        """LOG_004: Niveau DEBUG."""
        config = LogConfig(min_level=LogLevel.DEBUG)
        logger = StructuredLogger("test", config=config)
        logger.set_default_tenant("tenant-1")

        entry = logger.debug("Debug message")
        assert entry is not None
        assert entry.level == LogLevel.DEBUG

    def test_LOG_004_info_level(self) -> None:
        """LOG_004: Niveau INFO."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Info message")
        assert entry is not None
        assert entry.level == LogLevel.INFO

    def test_LOG_004_warn_level(self) -> None:
        """LOG_004: Niveau WARN."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.warn("Warn message")
        assert entry is not None
        assert entry.level == LogLevel.WARN

    def test_LOG_004_error_level(self) -> None:
        """LOG_004: Niveau ERROR."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.error("Error message")
        assert entry is not None
        assert entry.level == LogLevel.ERROR

    def test_LOG_004_critical_level(self) -> None:
        """LOG_004: Niveau CRITICAL."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.critical("Critical message")
        assert entry is not None
        assert entry.level == LogLevel.CRITICAL

    def test_LOG_004_level_filtering(self) -> None:
        """LOG_004: Filtrage par niveau minimum."""
        config = LogConfig(min_level=LogLevel.WARN)
        logger = StructuredLogger("test", config=config)
        logger.set_default_tenant("tenant-1")

        assert logger.debug("Debug") is None
        assert logger.info("Info") is None
        assert logger.warn("Warn") is not None
        assert logger.error("Error") is not None
        assert logger.critical("Critical") is not None

    def test_LOG_004_level_in_json(self) -> None:
        """LOG_004: Level présent dans JSON."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.error("Test")
        assert entry is not None

        parsed = json.loads(entry.to_json())
        assert parsed["level"] == "ERROR"

    def test_LOG_004_all_level_values(self) -> None:
        """LOG_004: Toutes les valeurs de niveau."""
        assert LogLevel.DEBUG.value == "DEBUG"
        assert LogLevel.INFO.value == "INFO"
        assert LogLevel.WARN.value == "WARN"
        assert LogLevel.ERROR.value == "ERROR"
        assert LogLevel.CRITICAL.value == "CRITICAL"

    def test_LOG_004_level_priority(self) -> None:
        """LOG_004: Priorité des niveaux."""
        assert LogLevel.get_priority(LogLevel.DEBUG) < LogLevel.get_priority(LogLevel.INFO)
        assert LogLevel.get_priority(LogLevel.INFO) < LogLevel.get_priority(LogLevel.WARN)
        assert LogLevel.get_priority(LogLevel.WARN) < LogLevel.get_priority(LogLevel.ERROR)
        assert LogLevel.get_priority(LogLevel.ERROR) < LogLevel.get_priority(LogLevel.CRITICAL)


class TestLOG005SensitiveDataInLogger:
    """Tests LOG_005: Masquage données sensibles dans le logger."""

    def test_LOG_005_password_masked_in_extra(self) -> None:
        """LOG_005: Password masqué dans extra."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Login attempt", password="secret123")
        assert entry is not None

        assert entry.extra["password"] == "***MASKED***"

    def test_LOG_005_token_masked_in_extra(self) -> None:
        """LOG_005: Token masqué dans extra."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Auth", access_token="eyJhbGc...")
        assert entry is not None

        assert entry.extra["access_token"] == "***MASKED***"

    def test_LOG_005_masking_in_json(self) -> None:
        """LOG_005: Masquage visible dans JSON."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Config", api_key="sk-123")
        assert entry is not None

        parsed = json.loads(entry.to_json())
        assert parsed["extra"]["api_key"] == "***MASKED***"

    def test_LOG_005_masking_disabled(self) -> None:
        """LOG_005: Masquage désactivable (config)."""
        config = LogConfig(mask_sensitive=False)
        logger = StructuredLogger("test", config=config)
        logger.set_default_tenant("tenant-1")

        entry = logger.info("Test", password="visible")
        assert entry is not None

        # Sans masquage, le password est visible
        assert entry.extra["password"] == "visible"

    def test_LOG_005_nested_sensitive_masked(self) -> None:
        """LOG_005: Données sensibles imbriquées masquées."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        entry = logger.info(
            "User data",
            user={"name": "john", "password": "secret"}
        )
        assert entry is not None

        assert entry.extra["user"]["name"] == "john"
        assert entry.extra["user"]["password"] == "***MASKED***"


class TestStructuredLoggerConfig:
    """Tests configuration StructuredLogger."""

    def test_name_required(self) -> None:
        """Nom du logger requis."""
        with pytest.raises(ValueError) as exc:
            StructuredLogger("")
        assert "empty" in str(exc.value).lower()

    def test_name_whitespace_rejected(self) -> None:
        """Nom whitespace rejeté."""
        with pytest.raises(ValueError):
            StructuredLogger("   ")

    def test_name_property(self) -> None:
        """Propriété name accessible."""
        logger = StructuredLogger("my-logger")
        assert logger.name == "my-logger"

    def test_config_property(self) -> None:
        """Propriété config accessible."""
        config = LogConfig(min_level=LogLevel.WARN)
        logger = StructuredLogger("test", config=config)
        assert logger.config.min_level == LogLevel.WARN

    def test_default_config(self) -> None:
        """Config par défaut."""
        logger = StructuredLogger("test")
        assert logger.config.min_level == LogLevel.INFO
        assert logger.config.mask_sensitive is True

    def test_set_default_tenant(self) -> None:
        """set_default_tenant fonctionne."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("t-123")

        entry = logger.info("Test")
        assert entry is not None
        assert entry.tenant_id == "t-123"

    def test_set_default_correlation(self) -> None:
        """set_default_correlation fonctionne."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")
        logger.set_default_correlation("c-456")

        entry = logger.info("Test")
        assert entry is not None
        assert entry.correlation_id == "c-456"

    def test_clear_defaults(self) -> None:
        """clear_defaults efface les valeurs."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")
        logger.set_default_correlation("corr-1")

        logger.clear_defaults()

        with pytest.raises(MissingRequiredFieldError):
            logger.info("Test")


class TestStructuredLoggerEntries:
    """Tests gestion des entrées."""

    def test_get_entries(self) -> None:
        """get_entries retourne les entrées."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        logger.info("Test 1")
        logger.info("Test 2")

        entries = logger.get_entries()
        assert len(entries) == 2

    def test_clear_entries(self) -> None:
        """clear_entries efface les entrées."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        logger.info("Test 1")
        logger.clear_entries()

        assert len(logger.get_entries()) == 0

    def test_get_entries_by_level(self) -> None:
        """get_entries_by_level filtre par niveau."""
        config = LogConfig(min_level=LogLevel.DEBUG)
        logger = StructuredLogger("test", config=config)
        logger.set_default_tenant("tenant-1")

        logger.debug("Debug")
        logger.info("Info")
        logger.error("Error")

        errors = logger.get_entries_by_level(LogLevel.ERROR)
        assert len(errors) == 1
        assert errors[0].message == "Error"

    def test_get_entries_by_correlation(self) -> None:
        """get_entries_by_correlation filtre par correlation."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        logger.log(LogLevel.INFO, "Test 1", correlation_id="corr-1")
        logger.log(LogLevel.INFO, "Test 2", correlation_id="corr-2")
        logger.log(LogLevel.INFO, "Test 3", correlation_id="corr-1")

        entries = logger.get_entries_by_correlation("corr-1")
        assert len(entries) == 2


class TestContextualLogger:
    """Tests ContextualLogger."""

    def test_with_context_creates_contextual_logger(self) -> None:
        """with_context crée ContextualLogger."""
        logger = StructuredLogger("test")
        logger.set_default_tenant("tenant-1")

        ctx_logger = logger.with_context(
            correlation_id="ctx-corr",
            tenant_id="ctx-tenant"
        )

        assert isinstance(ctx_logger, ContextualLogger)

    def test_contextual_logger_uses_context(self) -> None:
        """ContextualLogger utilise le contexte."""
        logger = StructuredLogger("test")

        ctx_logger = logger.with_context(
            correlation_id="ctx-corr",
            tenant_id="ctx-tenant"
        )

        entry = ctx_logger.info("Test")
        assert entry is not None
        assert entry.correlation_id == "ctx-corr"
        assert entry.tenant_id == "ctx-tenant"

    def test_contextual_logger_all_methods(self) -> None:
        """ContextualLogger a toutes les méthodes."""
        config = LogConfig(min_level=LogLevel.DEBUG)
        logger = StructuredLogger("test", config=config)

        ctx_logger = logger.with_context(
            correlation_id="ctx-corr",
            tenant_id="ctx-tenant"
        )

        assert ctx_logger.debug("Debug") is not None
        assert ctx_logger.info("Info") is not None
        assert ctx_logger.warn("Warn") is not None
        assert ctx_logger.error("Error") is not None
        assert ctx_logger.critical("Critical") is not None


class TestStructuredLoggerInterface:
    """Tests conformité interface."""

    def test_implements_interface(self) -> None:
        """StructuredLogger implémente IStructuredLogger."""
        logger = StructuredLogger("test")
        assert isinstance(logger, IStructuredLogger)


class TestLogEntryDataclass:
    """Tests LogEntry dataclass."""

    def test_log_entry_creation(self) -> None:
        """Création LogEntry."""
        entry = LogEntry(
            timestamp="2024-12-04T14:30:00.123Z",
            level=LogLevel.INFO,
            correlation_id="corr-1",
            tenant_id="tenant-1",
            message="Test message",
        )

        assert entry.timestamp == "2024-12-04T14:30:00.123Z"
        assert entry.level == LogLevel.INFO
        assert entry.message == "Test message"

    def test_log_entry_with_extra(self) -> None:
        """LogEntry avec extra."""
        entry = LogEntry(
            timestamp="2024-12-04T14:30:00.123Z",
            level=LogLevel.INFO,
            correlation_id="corr-1",
            tenant_id="tenant-1",
            message="Test",
            extra={"key": "value"},
        )

        assert entry.extra["key"] == "value"

    def test_log_entry_to_json(self) -> None:
        """LogEntry.to_json() fonctionne."""
        entry = LogEntry(
            timestamp="2024-12-04T14:30:00.123Z",
            level=LogLevel.INFO,
            correlation_id="corr-1",
            tenant_id="tenant-1",
            message="Test",
        )

        json_str = entry.to_json()
        parsed = json.loads(json_str)

        assert parsed["level"] == "INFO"


class TestExceptions:
    """Tests exceptions logging."""

    def test_missing_required_field_error(self) -> None:
        """MissingRequiredFieldError création."""
        error = MissingRequiredFieldError("field_name")
        assert error.field_name == "field_name"
        assert "field_name" in str(error)
        assert "LOG_002" in str(error)

    def test_invalid_log_level_error(self) -> None:
        """InvalidLogLevelError création."""
        error = InvalidLogLevelError("INVALID")
        assert error.level == "INVALID"
        assert "INVALID" in str(error)
        assert "LOG_004" in str(error)
