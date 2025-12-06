"""
Tests unitaires pour Correlation ID (LOT 9 - PARTIE 1).

Vérifie les invariants:
    OBS_001: Chaque requête DOIT avoir un correlation_id unique (UUID)
    OBS_002: correlation_id propagé dans TOUS les appels
    OBS_003: correlation_id présent dans TOUS les logs liés à la requête
"""

import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

import pytest

from src.observability.interfaces import (
    CorrelationContext,
    ICorrelatedLogger,
    ICorrelationManager,
    ICorrelationPropagator,
    correlation_id_var,
)
from src.observability.correlation import (
    CorrelatedLogger,
    CorrelationError,
    CorrelationManager,
    CorrelationPropagator,
)


# UUID v4 regex pattern for validation
UUID_V4_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def manager() -> CorrelationManager:
    """Crée un gestionnaire de correlation."""
    m = CorrelationManager()
    yield m
    # Nettoyer après chaque test
    m.clear_all_contexts()


@pytest.fixture
def propagator(manager: CorrelationManager) -> CorrelationPropagator:
    """Crée un propagateur de correlation."""
    return CorrelationPropagator(manager)


@pytest.fixture
def logger(
    manager: CorrelationManager,
    propagator: CorrelationPropagator,
) -> CorrelatedLogger:
    """Crée un logger corrélé."""
    return CorrelatedLogger(manager, propagator)


# =============================================================================
# TEST OBS_001: UUID UNIQUE ET VALIDE
# =============================================================================


class TestOBS001UniqueUUID:
    """Tests pour OBS_001: Chaque requête DOIT avoir un correlation_id unique."""

    def test_OBS_001_generate_returns_uuid(
        self,
        manager: CorrelationManager,
    ) -> None:
        """OBS_001: generate() retourne un UUID."""
        correlation_id = manager.generate()

        assert correlation_id is not None
        assert isinstance(correlation_id, str)

    def test_OBS_001_generate_uuid_v4_format(
        self,
        manager: CorrelationManager,
    ) -> None:
        """OBS_001: UUID généré est au format v4."""
        correlation_id = manager.generate()

        assert UUID_V4_PATTERN.match(correlation_id) is not None

    def test_OBS_001_generate_unique_ids(
        self,
        manager: CorrelationManager,
    ) -> None:
        """OBS_001: Chaque génération produit un ID unique."""
        ids = [manager.generate() for _ in range(100)]

        # Tous uniques
        assert len(set(ids)) == 100

    def test_OBS_001_is_valid_uuid_true_for_valid(
        self,
        manager: CorrelationManager,
    ) -> None:
        """OBS_001: is_valid_uuid retourne True pour UUID valide."""
        valid_uuid = str(uuid.uuid4())

        assert manager.is_valid_uuid(valid_uuid) is True

    def test_OBS_001_is_valid_uuid_false_for_invalid(
        self,
        manager: CorrelationManager,
    ) -> None:
        """OBS_001: is_valid_uuid retourne False pour format invalide."""
        invalid_values = [
            "not-a-uuid",
            "12345",
            "",
            "00000000-0000-0000-0000-000000000000",  # Pas v4
            "12345678-1234-1234-1234-123456789abc",  # Pas v4 (version incorrecte)
        ]

        for value in invalid_values:
            assert manager.is_valid_uuid(value) is False, f"Should be invalid: {value}"

    def test_OBS_001_is_valid_uuid_case_insensitive(
        self,
        manager: CorrelationManager,
    ) -> None:
        """OBS_001: is_valid_uuid accepte majuscules et minuscules."""
        valid_uuid = manager.generate()

        assert manager.is_valid_uuid(valid_uuid.upper()) is True
        assert manager.is_valid_uuid(valid_uuid.lower()) is True

    def test_OBS_001_set_current_validates_format(
        self,
        manager: CorrelationManager,
    ) -> None:
        """OBS_001: set_current valide le format UUID."""
        with pytest.raises(ValueError):
            manager.set_current("invalid-format")

    def test_OBS_001_set_current_rejects_empty(
        self,
        manager: CorrelationManager,
    ) -> None:
        """OBS_001: set_current rejette chaîne vide."""
        with pytest.raises(ValueError):
            manager.set_current("")

    def test_OBS_001_create_context_generates_if_none(
        self,
        manager: CorrelationManager,
    ) -> None:
        """OBS_001: create_context génère ID si non fourni."""
        context = manager.create_context()

        assert context.correlation_id is not None
        assert UUID_V4_PATTERN.match(context.correlation_id)

    def test_OBS_001_create_context_uses_provided_id(
        self,
        manager: CorrelationManager,
    ) -> None:
        """OBS_001: create_context utilise ID fourni."""
        provided_id = str(uuid.uuid4())

        context = manager.create_context(correlation_id=provided_id)

        assert context.correlation_id == provided_id


# =============================================================================
# TEST OBS_002: PROPAGATION HEADERS
# =============================================================================


class TestOBS002HeaderPropagation:
    """Tests pour OBS_002: correlation_id propagé dans TOUS les appels."""

    def test_OBS_002_header_name_constant(self) -> None:
        """OBS_002: Header name est X-Correlation-ID."""
        assert CorrelationManager.HEADER_NAME == "X-Correlation-ID"

    def test_OBS_002_inject_headers_adds_correlation(
        self,
        manager: CorrelationManager,
        propagator: CorrelationPropagator,
    ) -> None:
        """OBS_002: inject_headers ajoute X-Correlation-ID."""
        correlation_id = manager.generate()
        manager.set_current(correlation_id)

        headers = propagator.inject_headers({})

        assert "X-Correlation-ID" in headers
        assert headers["X-Correlation-ID"] == correlation_id

    def test_OBS_002_inject_headers_preserves_existing(
        self,
        manager: CorrelationManager,
        propagator: CorrelationPropagator,
    ) -> None:
        """OBS_002: inject_headers préserve headers existants."""
        manager.set_current(manager.generate())
        existing = {"Content-Type": "application/json", "Authorization": "Bearer token"}

        result = propagator.inject_headers(existing)

        assert result["Content-Type"] == "application/json"
        assert result["Authorization"] == "Bearer token"
        assert "X-Correlation-ID" in result

    def test_OBS_002_inject_headers_generates_if_none(
        self,
        manager: CorrelationManager,
        propagator: CorrelationPropagator,
    ) -> None:
        """OBS_002: inject_headers génère ID si aucun courant."""
        manager.clear()

        headers = propagator.inject_headers({})

        assert "X-Correlation-ID" in headers
        assert UUID_V4_PATTERN.match(headers["X-Correlation-ID"])

    def test_OBS_002_inject_headers_does_not_modify_original(
        self,
        manager: CorrelationManager,
        propagator: CorrelationPropagator,
    ) -> None:
        """OBS_002: inject_headers ne modifie pas l'original."""
        manager.set_current(manager.generate())
        original = {"Content-Type": "application/json"}

        propagator.inject_headers(original)

        assert "X-Correlation-ID" not in original

    def test_OBS_002_extract_from_headers_finds_id(
        self,
        manager: CorrelationManager,
        propagator: CorrelationPropagator,
    ) -> None:
        """OBS_002: extract_from_headers trouve le correlation_id."""
        expected_id = str(uuid.uuid4())
        headers = {"X-Correlation-ID": expected_id}

        result = propagator.extract_from_headers(headers)

        assert result == expected_id

    def test_OBS_002_extract_from_headers_case_insensitive(
        self,
        manager: CorrelationManager,
        propagator: CorrelationPropagator,
    ) -> None:
        """OBS_002: extract_from_headers est case-insensitive."""
        expected_id = str(uuid.uuid4())

        # Test différentes casses
        headers_variations = [
            {"x-correlation-id": expected_id},
            {"X-CORRELATION-ID": expected_id},
            {"x-Correlation-Id": expected_id},
        ]

        for headers in headers_variations:
            manager.clear()
            result = propagator.extract_from_headers(headers)
            assert result == expected_id

    def test_OBS_002_extract_from_headers_sets_current(
        self,
        manager: CorrelationManager,
        propagator: CorrelationPropagator,
    ) -> None:
        """OBS_002: extract_from_headers définit le contexte courant."""
        expected_id = str(uuid.uuid4())
        headers = {"X-Correlation-ID": expected_id}

        propagator.extract_from_headers(headers)

        assert manager.get_current() == expected_id

    def test_OBS_002_extract_from_headers_returns_none_if_missing(
        self,
        manager: CorrelationManager,
        propagator: CorrelationPropagator,
    ) -> None:
        """OBS_002: extract_from_headers retourne None si absent."""
        headers = {"Content-Type": "application/json"}

        result = propagator.extract_from_headers(headers)

        assert result is None

    def test_OBS_002_extract_from_headers_ignores_invalid(
        self,
        manager: CorrelationManager,
        propagator: CorrelationPropagator,
    ) -> None:
        """OBS_002: extract_from_headers ignore format invalide."""
        headers = {"X-Correlation-ID": "not-a-valid-uuid"}

        result = propagator.extract_from_headers(headers)

        assert result is None

    def test_OBS_002_create_child_correlation(
        self,
        manager: CorrelationManager,
        propagator: CorrelationPropagator,
    ) -> None:
        """OBS_002: create_child_correlation crée enfant avec parent."""
        parent_id = manager.generate()
        manager.set_current(parent_id)

        child_id = propagator.create_child_correlation()

        assert child_id != parent_id
        context = manager.get_context(child_id)
        assert context is not None
        assert context.parent_id == parent_id


# =============================================================================
# TEST OBS_003: CORRELATION DANS LOGS
# =============================================================================


class TestOBS003LogCorrelation:
    """Tests pour OBS_003: correlation_id présent dans TOUS les logs."""

    def test_OBS_003_propagate_to_log_adds_correlation(
        self,
        manager: CorrelationManager,
        propagator: CorrelationPropagator,
    ) -> None:
        """OBS_003: propagate_to_log ajoute correlation_id."""
        correlation_id = manager.generate()
        manager.set_current(correlation_id)

        log_data = {"message": "test log"}
        result = propagator.propagate_to_log(log_data)

        assert "correlation_id" in result
        assert result["correlation_id"] == correlation_id

    def test_OBS_003_propagate_to_log_preserves_data(
        self,
        manager: CorrelationManager,
        propagator: CorrelationPropagator,
    ) -> None:
        """OBS_003: propagate_to_log préserve données existantes."""
        manager.set_current(manager.generate())

        log_data = {"message": "test", "level": "INFO", "extra": "data"}
        result = propagator.propagate_to_log(log_data)

        assert result["message"] == "test"
        assert result["level"] == "INFO"
        assert result["extra"] == "data"

    def test_OBS_003_propagate_to_log_no_correlation_if_none(
        self,
        manager: CorrelationManager,
        propagator: CorrelationPropagator,
    ) -> None:
        """OBS_003: propagate_to_log n'ajoute rien si pas de correlation."""
        manager.clear()

        log_data = {"message": "test"}
        result = propagator.propagate_to_log(log_data)

        assert "correlation_id" not in result

    def test_OBS_003_logger_includes_correlation(
        self,
        manager: CorrelationManager,
        logger: CorrelatedLogger,
    ) -> None:
        """OBS_003: Logger inclut correlation_id automatiquement."""
        correlation_id = manager.generate()
        manager.set_current(correlation_id)

        logger.info("Test message")

        logs = logger.get_logs()
        assert len(logs) == 1
        assert logs[0]["correlation_id"] == correlation_id

    def test_OBS_003_logger_all_levels_include_correlation(
        self,
        manager: CorrelationManager,
        logger: CorrelatedLogger,
    ) -> None:
        """OBS_003: Tous les niveaux de log incluent correlation_id."""
        correlation_id = manager.generate()
        manager.set_current(correlation_id)

        logger.debug("debug message")
        logger.info("info message")
        logger.warning("warning message")
        logger.error("error message")
        logger.critical("critical message")

        logs = logger.get_logs()
        assert len(logs) == 5

        for log in logs:
            assert log["correlation_id"] == correlation_id

    def test_OBS_003_logger_log_format(
        self,
        manager: CorrelationManager,
        logger: CorrelatedLogger,
    ) -> None:
        """OBS_003: Format de log contient champs requis."""
        manager.set_current(manager.generate())

        logger.info("Test message", extra_field="value")

        logs = logger.get_logs()
        log = logs[0]

        assert "timestamp" in log
        assert "level" in log
        assert "message" in log
        assert "logger" in log
        assert "correlation_id" in log
        assert log["level"] == "INFO"
        assert log["message"] == "Test message"
        assert log["extra_field"] == "value"

    def test_OBS_003_logger_filters_by_correlation(
        self,
        manager: CorrelationManager,
        logger: CorrelatedLogger,
    ) -> None:
        """OBS_003: get_logs_by_correlation filtre correctement."""
        id1 = manager.generate()
        id2 = manager.generate()

        manager.set_current(id1)
        logger.info("Message 1")
        logger.info("Message 2")

        manager.set_current(id2)
        logger.info("Message 3")

        logs_id1 = logger.get_logs_by_correlation(id1)
        logs_id2 = logger.get_logs_by_correlation(id2)

        assert len(logs_id1) == 2
        assert len(logs_id2) == 1

    def test_OBS_003_logger_timestamp_is_iso_format(
        self,
        manager: CorrelationManager,
        logger: CorrelatedLogger,
    ) -> None:
        """OBS_003: Timestamp est au format ISO."""
        manager.set_current(manager.generate())

        logger.info("Test")

        logs = logger.get_logs()
        timestamp = logs[0]["timestamp"]

        # Doit être parsable comme ISO
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        assert parsed is not None

    def test_OBS_003_logger_includes_kwargs(
        self,
        manager: CorrelationManager,
        logger: CorrelatedLogger,
    ) -> None:
        """OBS_003: Logger inclut kwargs dans le log."""
        manager.set_current(manager.generate())

        logger.info(
            "User action",
            user_id="user-123",
            action="login",
            ip_address="192.168.1.1",
        )

        logs = logger.get_logs()
        log = logs[0]

        assert log["user_id"] == "user-123"
        assert log["action"] == "login"
        assert log["ip_address"] == "192.168.1.1"

    def test_OBS_003_logger_clear_logs(
        self,
        manager: CorrelationManager,
        logger: CorrelatedLogger,
    ) -> None:
        """OBS_003: clear_logs efface tous les logs."""
        manager.set_current(manager.generate())
        logger.info("Test 1")
        logger.info("Test 2")

        assert len(logger.get_logs()) == 2

        logger.clear_logs()

        assert len(logger.get_logs()) == 0


# =============================================================================
# TEST CONTEXT ET THREADING
# =============================================================================


class TestContextAndThreading:
    """Tests pour ContextVar et comportement multi-thread."""

    def test_context_get_set_current(
        self,
        manager: CorrelationManager,
    ) -> None:
        """get_current/set_current fonctionne correctement."""
        correlation_id = manager.generate()

        manager.set_current(correlation_id)

        assert manager.get_current() == correlation_id

    def test_context_clear(
        self,
        manager: CorrelationManager,
    ) -> None:
        """clear() réinitialise le contexte."""
        manager.set_current(manager.generate())

        manager.clear()

        assert manager.get_current() is None

    def test_context_isolation_between_threads(
        self,
        manager: CorrelationManager,
    ) -> None:
        """ContextVar isole les threads."""
        results: Dict[str, str] = {}

        def thread_func(thread_id: str) -> None:
            # Générer et définir un ID propre à ce thread
            correlation_id = manager.generate()
            manager.set_current(correlation_id)
            # Stocker ce qu'on lit
            results[thread_id] = manager.get_current() or ""

        threads = []
        for i in range(5):
            t = threading.Thread(target=thread_func, args=(f"thread-{i}",))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Chaque thread doit avoir son propre ID
        values = list(results.values())
        assert len(set(values)) == 5  # Tous uniques

    def test_context_create_context_sets_current(
        self,
        manager: CorrelationManager,
    ) -> None:
        """create_context définit le contexte courant."""
        context = manager.create_context(
            tenant_id="tenant-1",
            user_id="user-1",
            source="edge",
        )

        assert manager.get_current() == context.correlation_id

    def test_context_get_context(
        self,
        manager: CorrelationManager,
    ) -> None:
        """get_context retourne le contexte stocké."""
        context = manager.create_context(
            tenant_id="tenant-1",
            user_id="user-1",
            source="cloud",
        )

        retrieved = manager.get_context(context.correlation_id)

        assert retrieved is not None
        assert retrieved.tenant_id == "tenant-1"
        assert retrieved.user_id == "user-1"
        assert retrieved.source == "cloud"

    def test_context_clear_all_contexts(
        self,
        manager: CorrelationManager,
    ) -> None:
        """clear_all_contexts efface tout."""
        context = manager.create_context()

        manager.clear_all_contexts()

        assert manager.get_current() is None
        assert manager.get_context(context.correlation_id) is None


# =============================================================================
# TEST DATACLASSES
# =============================================================================


class TestDataclasses:
    """Tests pour les dataclasses."""

    def test_correlation_context_creation(self) -> None:
        """CorrelationContext création correcte."""
        now = datetime.now(timezone.utc)
        context = CorrelationContext(
            correlation_id="123e4567-e89b-42d3-a456-426614174000",
            parent_id="123e4567-e89b-42d3-a456-426614174001",
            tenant_id="tenant-1",
            user_id="user-1",
            source="edge",
            created_at=now,
        )

        assert context.correlation_id == "123e4567-e89b-42d3-a456-426614174000"
        assert context.parent_id == "123e4567-e89b-42d3-a456-426614174001"
        assert context.tenant_id == "tenant-1"
        assert context.user_id == "user-1"
        assert context.source == "edge"
        assert context.created_at == now

    def test_correlation_context_immutable(self) -> None:
        """CorrelationContext est immutable."""
        context = CorrelationContext(
            correlation_id="123e4567-e89b-42d3-a456-426614174000",
            parent_id=None,
            tenant_id=None,
            user_id=None,
            source="test",
            created_at=datetime.now(timezone.utc),
        )

        with pytest.raises(AttributeError):
            context.correlation_id = "new-id"  # type: ignore

    def test_correlation_context_optional_fields(self) -> None:
        """CorrelationContext avec champs optionnels None."""
        context = CorrelationContext(
            correlation_id="123e4567-e89b-42d3-a456-426614174000",
            parent_id=None,
            tenant_id=None,
            user_id=None,
            source="unknown",
            created_at=datetime.now(timezone.utc),
        )

        assert context.parent_id is None
        assert context.tenant_id is None
        assert context.user_id is None


# =============================================================================
# TEST INTERFACES
# =============================================================================


class TestInterfaces:
    """Tests pour la conformité aux interfaces."""

    def test_manager_implements_interface(
        self,
        manager: CorrelationManager,
    ) -> None:
        """CorrelationManager implémente ICorrelationManager."""
        assert isinstance(manager, ICorrelationManager)

    def test_propagator_implements_interface(
        self,
        propagator: CorrelationPropagator,
    ) -> None:
        """CorrelationPropagator implémente ICorrelationPropagator."""
        assert isinstance(propagator, ICorrelationPropagator)

    def test_logger_implements_interface(
        self,
        logger: CorrelatedLogger,
    ) -> None:
        """CorrelatedLogger implémente ICorrelatedLogger."""
        assert isinstance(logger, ICorrelatedLogger)


# =============================================================================
# TEST EXCEPTIONS
# =============================================================================


class TestExceptions:
    """Tests pour les exceptions."""

    def test_correlation_error(self) -> None:
        """CorrelationError création."""
        error = CorrelationError("Test error")
        assert str(error) == "Test error"

    def test_create_context_invalid_correlation_id(
        self,
        manager: CorrelationManager,
    ) -> None:
        """create_context avec correlation_id invalide lève ValueError."""
        with pytest.raises(ValueError):
            manager.create_context(correlation_id="invalid")

    def test_create_context_invalid_parent_id(
        self,
        manager: CorrelationManager,
    ) -> None:
        """create_context avec parent_id invalide lève ValueError."""
        with pytest.raises(ValueError):
            manager.create_context(parent_id="invalid-parent")
