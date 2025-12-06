"""
Tests unitaires DegradedModeController

Invariants testés:
    RUN_052: Mode dégradé si Cloud offline
        - Lecture données locales: OK
        - Écriture événements locaux: OK
        - Sync vers Cloud: File d'attente
        - Nouvelles configs: Cache local uniquement
    RUN_053: Cache config TTL 7 jours max
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock

from src.ha.interfaces import IDegradedModeController
from src.ha.degraded_mode_controller import (
    DegradedModeController,
    DegradedModeError,
)
from src.audit.interfaces import IAuditEmitter
from src.licensing.interfaces import ILicenseCache


# ══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def mock_audit_emitter():
    """AuditEmitter mocké pour tests."""
    return Mock(spec=IAuditEmitter)


@pytest.fixture
def mock_license_cache():
    """LicenseCache mocké pour tests."""
    cache = Mock(spec=ILicenseCache)
    cache.is_valid.return_value = True
    return cache


@pytest.fixture
def degraded_controller(mock_audit_emitter, mock_license_cache):
    """DegradedModeController instance pour tests."""
    return DegradedModeController(
        audit_emitter=mock_audit_emitter,
        license_cache=mock_license_cache,
    )


@pytest.fixture
def degraded_controller_old_cache(mock_audit_emitter, mock_license_cache):
    """DegradedModeController avec cache ancien (8 jours)."""
    old_timestamp = datetime.now() - timedelta(days=8)
    return DegradedModeController(
        audit_emitter=mock_audit_emitter,
        license_cache=mock_license_cache,
        config_cache_timestamp=old_timestamp,
    )


# ══════════════════════════════════════════════════════════════════════════════
# TESTS INTERFACE
# ══════════════════════════════════════════════════════════════════════════════

class TestDegradedModeControllerInterface:
    """Vérifie conformité interface."""

    def test_implements_interface(self, degraded_controller):
        """DegradedModeController implémente IDegradedModeController."""
        assert isinstance(degraded_controller, IDegradedModeController)

    def test_requires_audit_emitter(self, mock_license_cache):
        """DegradedModeController requiert audit_emitter."""
        with pytest.raises(TypeError):
            DegradedModeController(license_cache=mock_license_cache)

    def test_requires_license_cache(self, mock_audit_emitter):
        """DegradedModeController requiert license_cache."""
        with pytest.raises(TypeError):
            DegradedModeController(audit_emitter=mock_audit_emitter)


# ══════════════════════════════════════════════════════════════════════════════
# TESTS RUN_052: MODE DÉGRADÉ
# ══════════════════════════════════════════════════════════════════════════════

class TestRUN052Compliance:
    """Tests conformité RUN_052: Mode dégradé si Cloud offline."""

    def test_RUN_052_degraded_features_constant(self, degraded_controller):
        """RUN_052: Constante DEGRADED_FEATURES définie."""
        assert hasattr(degraded_controller, "DEGRADED_FEATURES")
        assert "events:read" in degraded_controller.DEGRADED_FEATURES
        assert "events:write:local" in degraded_controller.DEGRADED_FEATURES
        assert "config:read:cached" in degraded_controller.DEGRADED_FEATURES

    def test_RUN_052_disabled_features_constant(self, degraded_controller):
        """RUN_052: Constante DISABLED_FEATURES définie."""
        assert hasattr(degraded_controller, "DISABLED_FEATURES")
        assert "sync:cloud" in degraded_controller.DISABLED_FEATURES
        assert "config:refresh" in degraded_controller.DISABLED_FEATURES

    def test_RUN_052_enter_degraded_mode(self, degraded_controller):
        """RUN_052: Entrée en mode dégradé."""
        assert degraded_controller.is_degraded() is False

        degraded_controller.enter_degraded_mode("Cloud unreachable")

        assert degraded_controller.is_degraded() is True

    def test_RUN_052_exit_degraded_mode(self, degraded_controller):
        """RUN_052: Sortie du mode dégradé."""
        degraded_controller.enter_degraded_mode("Cloud unreachable")
        degraded_controller.exit_degraded_mode()

        assert degraded_controller.is_degraded() is False

    def test_RUN_052_degraded_features_limited(self, degraded_controller):
        """RUN_052: Features limitées en mode dégradé."""
        # Mode normal: toutes features
        normal_features = degraded_controller.get_available_features()

        degraded_controller.enter_degraded_mode("Test")

        # Mode dégradé: features limitées
        degraded_features = degraded_controller.get_available_features()

        # sync:cloud ne doit pas être disponible en dégradé
        assert "sync:cloud" in normal_features
        assert "sync:cloud" not in degraded_features

    def test_RUN_052_local_read_available_in_degraded(self, degraded_controller):
        """RUN_052: Lecture locale disponible en mode dégradé."""
        degraded_controller.enter_degraded_mode("Test")

        features = degraded_controller.get_available_features()

        assert "events:read" in features
        assert "data:read:local" in features

    def test_RUN_052_local_write_available_in_degraded(self, degraded_controller):
        """RUN_052: Écriture locale disponible en mode dégradé."""
        degraded_controller.enter_degraded_mode("Test")

        features = degraded_controller.get_available_features()

        assert "events:write:local" in features
        assert "data:write:local" in features

    def test_RUN_052_cached_config_available_in_degraded(self, degraded_controller):
        """RUN_052: Config cachée disponible en mode dégradé."""
        degraded_controller.enter_degraded_mode("Test")

        features = degraded_controller.get_available_features()

        assert "config:read:cached" in features

    def test_RUN_052_sync_disabled_in_degraded(self, degraded_controller):
        """RUN_052: Sync cloud désactivé en mode dégradé."""
        degraded_controller.enter_degraded_mode("Test")

        features = degraded_controller.get_available_features()
        disabled = degraded_controller.get_disabled_features()

        assert "sync:cloud" not in features
        assert "sync:cloud" in disabled


# ══════════════════════════════════════════════════════════════════════════════
# TESTS RUN_053: CACHE CONFIG TTL 7 JOURS
# ══════════════════════════════════════════════════════════════════════════════

class TestRUN053Compliance:
    """Tests conformité RUN_053: Cache config TTL 7 jours max."""

    def test_RUN_053_ttl_constant(self, degraded_controller):
        """RUN_053: Constante CONFIG_CACHE_MAX_TTL_DAYS = 7."""
        assert degraded_controller.CONFIG_CACHE_MAX_TTL_DAYS == 7

    def test_RUN_053_fresh_cache_valid(self, degraded_controller):
        """RUN_053: Cache récent valide."""
        assert degraded_controller.is_config_cache_valid() is True

    def test_RUN_053_old_cache_invalid(self, degraded_controller_old_cache):
        """RUN_053: Cache > 7 jours invalide."""
        assert degraded_controller_old_cache.is_config_cache_valid() is False

    def test_RUN_053_cache_exactly_7_days_valid(
        self, mock_audit_emitter, mock_license_cache
    ):
        """RUN_053: Cache exactement 7 jours valide."""
        # Utiliser 6 jours 23h 59m pour être sûr d'être sous les 7 jours
        timestamp = datetime.now() - timedelta(days=6, hours=23, minutes=59)
        controller = DegradedModeController(
            audit_emitter=mock_audit_emitter,
            license_cache=mock_license_cache,
            config_cache_timestamp=timestamp,
        )

        assert controller.is_config_cache_valid() is True

    def test_RUN_053_cache_7_days_1_second_invalid(
        self, mock_audit_emitter, mock_license_cache
    ):
        """RUN_053: Cache 7 jours + 1 seconde invalide."""
        timestamp = datetime.now() - timedelta(days=7, seconds=1)
        controller = DegradedModeController(
            audit_emitter=mock_audit_emitter,
            license_cache=mock_license_cache,
            config_cache_timestamp=timestamp,
        )

        assert controller.is_config_cache_valid() is False

    def test_RUN_053_cache_age_days(self, degraded_controller):
        """RUN_053: Calcul âge cache en jours."""
        age = degraded_controller.get_config_cache_age_days()

        # Cache fraîchement créé, âge ~0
        assert 0 <= age < 0.01

    def test_RUN_053_cache_age_old(self, degraded_controller_old_cache):
        """RUN_053: Âge cache ancien."""
        age = degraded_controller_old_cache.get_config_cache_age_days()

        # Cache de 8 jours
        assert 7.9 < age < 8.1

    def test_RUN_053_update_cache_timestamp(self, degraded_controller_old_cache):
        """RUN_053: Mise à jour timestamp cache."""
        assert degraded_controller_old_cache.is_config_cache_valid() is False

        degraded_controller_old_cache.update_config_cache_timestamp()

        assert degraded_controller_old_cache.is_config_cache_valid() is True


# ══════════════════════════════════════════════════════════════════════════════
# TESTS FILE D'ATTENTE ÉVÉNEMENTS
# ══════════════════════════════════════════════════════════════════════════════

class TestEventQueue:
    """Tests file d'attente événements pour sync."""

    def test_queue_event(self, degraded_controller):
        """Mise en file d'événement."""
        event = {"type": "test", "data": "value"}

        result = degraded_controller.queue_event_for_sync(event)

        assert result is True
        assert len(degraded_controller.get_pending_events()) == 1

    def test_queue_adds_timestamp(self, degraded_controller):
        """Queue ajoute timestamp automatiquement."""
        event = {"type": "test"}

        degraded_controller.queue_event_for_sync(event)

        queued = degraded_controller.get_pending_events()[0]
        assert "queued_at" in queued

    def test_queue_max_size_limit(self, degraded_controller):
        """File d'attente limitée en taille."""
        # Remplir la file
        for i in range(degraded_controller.MAX_EVENT_QUEUE_SIZE):
            degraded_controller.queue_event_for_sync({"index": i})

        # Tentative d'ajout supplémentaire
        result = degraded_controller.queue_event_for_sync({"overflow": True})

        assert result is False
        assert degraded_controller.get_pending_events_count() == degraded_controller.MAX_EVENT_QUEUE_SIZE

    def test_get_pending_events_count(self, degraded_controller):
        """Comptage événements en attente."""
        degraded_controller.queue_event_for_sync({"type": "event1"})
        degraded_controller.queue_event_for_sync({"type": "event2"})
        degraded_controller.queue_event_for_sync({"type": "event3"})

        assert degraded_controller.get_pending_events_count() == 3

    def test_clear_pending_events(self, degraded_controller):
        """Vidage file d'attente."""
        degraded_controller.queue_event_for_sync({"type": "event1"})
        degraded_controller.queue_event_for_sync({"type": "event2"})

        cleared = degraded_controller.clear_pending_events()

        assert cleared == 2
        assert degraded_controller.get_pending_events_count() == 0

    def test_pop_pending_events(self, degraded_controller):
        """Récupération et suppression événements."""
        degraded_controller.queue_event_for_sync({"index": 1})
        degraded_controller.queue_event_for_sync({"index": 2})
        degraded_controller.queue_event_for_sync({"index": 3})

        popped = degraded_controller.pop_pending_events(2)

        assert len(popped) == 2
        assert popped[0]["index"] == 1
        assert popped[1]["index"] == 2
        assert degraded_controller.get_pending_events_count() == 1


# ══════════════════════════════════════════════════════════════════════════════
# TESTS ENTRÉE/SORTIE MODE DÉGRADÉ
# ══════════════════════════════════════════════════════════════════════════════

class TestDegradedModeTransitions:
    """Tests transitions mode dégradé."""

    def test_enter_degraded_stores_timestamp(self, degraded_controller):
        """Entrée stocke timestamp."""
        before = datetime.now()
        degraded_controller.enter_degraded_mode("Test reason")
        after = datetime.now()

        degraded_since = degraded_controller.get_degraded_since()

        assert degraded_since is not None
        assert before <= degraded_since <= after

    def test_enter_degraded_stores_reason(self, degraded_controller):
        """Entrée stocke raison."""
        degraded_controller.enter_degraded_mode("Cloud connectivity lost")

        assert degraded_controller.get_degraded_reason() == "Cloud connectivity lost"

    def test_enter_degraded_queues_event(self, degraded_controller):
        """Entrée met événement en file."""
        degraded_controller.enter_degraded_mode("Test")

        events = degraded_controller.get_pending_events()
        assert len(events) >= 1
        assert events[0]["type"] == "degraded_mode_entered"

    def test_exit_degraded_clears_state(self, degraded_controller):
        """Sortie efface état."""
        degraded_controller.enter_degraded_mode("Test")
        degraded_controller.exit_degraded_mode()

        assert degraded_controller.get_degraded_since() is None
        assert degraded_controller.get_degraded_reason() is None

    def test_exit_degraded_queues_event(self, degraded_controller):
        """Sortie met événement en file."""
        degraded_controller.enter_degraded_mode("Test")
        initial_count = degraded_controller.get_pending_events_count()

        degraded_controller.exit_degraded_mode()

        events = degraded_controller.get_pending_events()
        assert len(events) > initial_count
        exit_event = events[-1]
        assert exit_event["type"] == "degraded_mode_exited"

    def test_enter_degraded_idempotent(self, degraded_controller):
        """Entrée répétée ne change pas timestamp."""
        degraded_controller.enter_degraded_mode("First reason")
        first_timestamp = degraded_controller.get_degraded_since()

        import time
        time.sleep(0.01)

        degraded_controller.enter_degraded_mode("Second reason")
        second_timestamp = degraded_controller.get_degraded_since()

        # Timestamp ne doit pas changer
        assert first_timestamp == second_timestamp

    def test_exit_degraded_idempotent(self, degraded_controller):
        """Sortie répétée sans effet."""
        # Pas en mode dégradé
        degraded_controller.exit_degraded_mode()

        assert degraded_controller.is_degraded() is False


# ══════════════════════════════════════════════════════════════════════════════
# TESTS DURÉE MODE DÉGRADÉ
# ══════════════════════════════════════════════════════════════════════════════

class TestDegradedDuration:
    """Tests durée en mode dégradé."""

    def test_duration_zero_when_not_degraded(self, degraded_controller):
        """Durée 0 quand pas dégradé."""
        assert degraded_controller.get_degraded_duration_seconds() == 0.0

    def test_duration_increases_when_degraded(self, degraded_controller):
        """Durée augmente en mode dégradé."""
        degraded_controller.enter_degraded_mode("Test")

        import time
        time.sleep(0.1)

        duration = degraded_controller.get_degraded_duration_seconds()
        assert duration >= 0.1


# ══════════════════════════════════════════════════════════════════════════════
# TESTS VÉRIFICATION FEATURES
# ══════════════════════════════════════════════════════════════════════════════

class TestFeatureAvailability:
    """Tests disponibilité features."""

    def test_is_feature_available_normal_mode(self, degraded_controller):
        """Feature disponible en mode normal."""
        assert degraded_controller.is_feature_available("sync:cloud") is True
        assert degraded_controller.is_feature_available("events:read") is True

    def test_is_feature_available_degraded_mode(self, degraded_controller):
        """Feature non disponible en mode dégradé."""
        degraded_controller.enter_degraded_mode("Test")

        assert degraded_controller.is_feature_available("sync:cloud") is False
        assert degraded_controller.is_feature_available("events:read") is True

    def test_is_feature_available_unknown_feature(self, degraded_controller):
        """Feature inconnue non disponible."""
        assert degraded_controller.is_feature_available("unknown:feature") is False


# ══════════════════════════════════════════════════════════════════════════════
# TESTS STATUS COMPLET
# ══════════════════════════════════════════════════════════════════════════════

class TestStatus:
    """Tests status complet."""

    def test_get_status_normal_mode(self, degraded_controller):
        """Status en mode normal."""
        status = degraded_controller.get_status()

        assert status["is_degraded"] is False
        assert status["degraded_since"] is None
        assert status["reason"] is None
        assert len(status["disabled_features"]) == 0

    def test_get_status_degraded_mode(self, degraded_controller):
        """Status en mode dégradé."""
        degraded_controller.enter_degraded_mode("Test reason")

        status = degraded_controller.get_status()

        assert status["is_degraded"] is True
        assert status["degraded_since"] is not None
        assert status["reason"] == "Test reason"
        assert len(status["disabled_features"]) > 0
        assert status["config_cache_valid"] is True

    def test_get_status_includes_pending_count(self, degraded_controller):
        """Status inclut nombre événements en attente."""
        degraded_controller.queue_event_for_sync({"type": "test"})

        status = degraded_controller.get_status()

        assert status["pending_events_count"] >= 1

    def test_get_status_includes_cache_info(self, degraded_controller_old_cache):
        """Status inclut info cache."""
        status = degraded_controller_old_cache.get_status()

        assert status["config_cache_valid"] is False
        assert status["config_cache_age_days"] > 7
