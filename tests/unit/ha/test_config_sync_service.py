"""
Tests unitaires ConfigSyncService

Invariants testés:
    RUN_053: Cache config TTL 7 jours max
    Sync bidirectionnelle Edge ↔ Cloud
"""
import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock

from src.ha.interfaces import IConfigSyncService, IDegradedModeController, SyncResult
from src.ha.config_sync_service import ConfigSyncService, ConfigSyncError
from src.audit.interfaces import IAuditEmitter


# ══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def mock_audit_emitter():
    """AuditEmitter mocké pour tests."""
    emitter = Mock(spec=IAuditEmitter)
    emitter.emit_event = AsyncMock()
    return emitter


@pytest.fixture
def mock_degraded_controller():
    """DegradedModeController mocké pour tests."""
    controller = Mock(spec=IDegradedModeController)
    controller.is_degraded.return_value = False
    controller.enter_degraded_mode = Mock()
    controller.exit_degraded_mode = Mock()
    controller.update_config_cache_timestamp = Mock()
    controller.queue_event_for_sync = Mock(return_value=True)
    return controller


@pytest.fixture
def mock_cloud_client_success():
    """Client cloud mocké qui réussit."""
    async def client(endpoint: str, data: dict) -> dict:
        if endpoint == "config/sync":
            return {
                "success": True,
                "config": {
                    "feature_flags": {"dark_mode": True},
                    "limits": {"max_users": 100},
                },
            }
        elif endpoint == "events/push":
            return {
                "success": True,
                "synced": len(data.get("events", [])),
                "failed": 0,
            }
        return {"success": True}
    return client


@pytest.fixture
def mock_cloud_client_failure():
    """Client cloud mocké qui échoue."""
    async def client(endpoint: str, data: dict) -> dict:
        raise ConfigSyncError("Connection refused")
    return client


@pytest.fixture
def mock_cloud_client_timeout():
    """Client cloud mocké qui timeout."""
    async def client(endpoint: str, data: dict) -> dict:
        await asyncio.sleep(100)  # Très long
        return {}
    return client


@pytest.fixture
def sync_service(mock_audit_emitter, mock_degraded_controller, mock_cloud_client_success):
    """ConfigSyncService instance avec client cloud qui réussit."""
    return ConfigSyncService(
        node_id="node-test-001",
        audit_emitter=mock_audit_emitter,
        degraded_controller=mock_degraded_controller,
        cloud_client=mock_cloud_client_success,
    )


@pytest.fixture
def sync_service_failing(mock_audit_emitter, mock_degraded_controller, mock_cloud_client_failure):
    """ConfigSyncService instance avec client cloud qui échoue."""
    return ConfigSyncService(
        node_id="node-test-001",
        audit_emitter=mock_audit_emitter,
        degraded_controller=mock_degraded_controller,
        cloud_client=mock_cloud_client_failure,
    )


# ══════════════════════════════════════════════════════════════════════════════
# TESTS INTERFACE
# ══════════════════════════════════════════════════════════════════════════════

class TestConfigSyncServiceInterface:
    """Vérifie conformité interface."""

    def test_implements_interface(self, sync_service):
        """ConfigSyncService implémente IConfigSyncService."""
        assert isinstance(sync_service, IConfigSyncService)

    def test_requires_node_id(self, mock_audit_emitter, mock_degraded_controller):
        """ConfigSyncService requiert node_id."""
        with pytest.raises(TypeError):
            ConfigSyncService(
                audit_emitter=mock_audit_emitter,
                degraded_controller=mock_degraded_controller,
            )

    def test_requires_audit_emitter(self, mock_degraded_controller):
        """ConfigSyncService requiert audit_emitter."""
        with pytest.raises(TypeError):
            ConfigSyncService(
                node_id="node-1",
                degraded_controller=mock_degraded_controller,
            )

    def test_requires_degraded_controller(self, mock_audit_emitter):
        """ConfigSyncService requiert degraded_controller."""
        with pytest.raises(TypeError):
            ConfigSyncService(
                node_id="node-1",
                audit_emitter=mock_audit_emitter,
            )


# ══════════════════════════════════════════════════════════════════════════════
# TESTS RUN_053: CACHE CONFIG TTL 7 JOURS
# ══════════════════════════════════════════════════════════════════════════════

class TestRUN053Compliance:
    """Tests conformité RUN_053: Cache config TTL 7 jours max."""

    def test_RUN_053_max_cache_age_constant(self, sync_service):
        """RUN_053: Constante MAX_CACHE_AGE_DAYS = 7."""
        assert sync_service.MAX_CACHE_AGE_DAYS == 7

    def test_RUN_053_sync_interval_constant(self, sync_service):
        """RUN_053: Constante SYNC_INTERVAL_HOURS = 6."""
        assert sync_service.SYNC_INTERVAL_HOURS == 6

    def test_RUN_053_fresh_cache_not_expired(self, sync_service):
        """RUN_053: Cache récent non expiré."""
        sync_service._config_cache_timestamp = datetime.now()

        assert sync_service.is_cache_expired() is False

    def test_RUN_053_old_cache_expired(self, sync_service):
        """RUN_053: Cache > 7 jours expiré."""
        sync_service._config_cache_timestamp = datetime.now() - timedelta(days=8)

        assert sync_service.is_cache_expired() is True

    def test_RUN_053_no_cache_is_expired(self, sync_service):
        """RUN_053: Pas de cache = expiré."""
        assert sync_service._config_cache_timestamp is None
        assert sync_service.is_cache_expired() is True

    def test_RUN_053_cache_exactly_7_days_not_expired(self, sync_service):
        """RUN_053: Cache exactement 7 jours - 1min non expiré."""
        sync_service._config_cache_timestamp = (
            datetime.now() - timedelta(days=6, hours=23, minutes=59)
        )

        assert sync_service.is_cache_expired() is False

    def test_RUN_053_cache_7_days_1_second_expired(self, sync_service):
        """RUN_053: Cache 7 jours + 1 seconde expiré."""
        sync_service._config_cache_timestamp = (
            datetime.now() - timedelta(days=7, seconds=1)
        )

        assert sync_service.is_cache_expired() is True

    def test_RUN_053_cache_age_hours(self, sync_service):
        """RUN_053: Calcul âge cache en heures."""
        sync_service._config_cache_timestamp = datetime.now() - timedelta(hours=12)

        age = sync_service.get_cache_age_hours()

        assert 11.9 < age < 12.1

    def test_RUN_053_no_cache_age_negative(self, sync_service):
        """RUN_053: Pas de cache = âge -1."""
        assert sync_service.get_cache_age_hours() == -1.0


# ══════════════════════════════════════════════════════════════════════════════
# TESTS SYNC FROM CLOUD
# ══════════════════════════════════════════════════════════════════════════════

class TestSyncFromCloud:
    """Tests synchronisation depuis le Cloud."""

    @pytest.mark.asyncio
    async def test_sync_from_cloud_success(self, sync_service):
        """Sync depuis cloud réussit."""
        result = await sync_service.sync_from_cloud()

        assert result.success is True
        assert result.items_synced > 0
        assert result.error_message is None

    @pytest.mark.asyncio
    async def test_sync_from_cloud_updates_cache(self, sync_service):
        """Sync met à jour le cache."""
        await sync_service.sync_from_cloud()

        config = sync_service.get_all_cached_config()
        assert "feature_flags" in config
        assert config["feature_flags"]["dark_mode"] is True

    @pytest.mark.asyncio
    async def test_sync_from_cloud_updates_timestamp(self, sync_service):
        """Sync met à jour le timestamp."""
        before = datetime.now()
        await sync_service.sync_from_cloud()
        after = datetime.now()

        last_sync = sync_service.get_last_sync()
        assert last_sync is not None
        assert before <= last_sync <= after

    @pytest.mark.asyncio
    async def test_sync_from_cloud_emits_audit(self, sync_service, mock_audit_emitter):
        """Sync émet événement audit."""
        await sync_service.sync_from_cloud()

        mock_audit_emitter.emit_event.assert_called()

    @pytest.mark.asyncio
    async def test_sync_from_cloud_exits_degraded_mode(
        self, sync_service, mock_degraded_controller
    ):
        """Sync réussie sort du mode dégradé."""
        mock_degraded_controller.is_degraded.return_value = True

        await sync_service.sync_from_cloud()

        mock_degraded_controller.exit_degraded_mode.assert_called_once()

    @pytest.mark.asyncio
    async def test_sync_from_cloud_failure_enters_degraded(
        self, sync_service_failing, mock_degraded_controller
    ):
        """Sync échouée entre en mode dégradé."""
        mock_degraded_controller.is_degraded.return_value = False

        result = await sync_service_failing.sync_from_cloud()

        assert result.success is False
        mock_degraded_controller.enter_degraded_mode.assert_called_once()

    @pytest.mark.asyncio
    async def test_sync_from_cloud_failure_returns_error(self, sync_service_failing):
        """Sync échouée retourne erreur."""
        result = await sync_service_failing.sync_from_cloud()

        assert result.success is False
        assert result.error_message is not None
        assert "Connection refused" in result.error_message

    @pytest.mark.asyncio
    async def test_sync_from_cloud_timeout(
        self, mock_audit_emitter, mock_degraded_controller, mock_cloud_client_timeout
    ):
        """Sync timeout retourne erreur."""
        service = ConfigSyncService(
            node_id="node-1",
            audit_emitter=mock_audit_emitter,
            degraded_controller=mock_degraded_controller,
            cloud_client=mock_cloud_client_timeout,
        )
        # Réduire le timeout pour le test
        service.CLOUD_TIMEOUT_SECONDS = 0.1

        result = await service.sync_from_cloud()

        assert result.success is False
        assert "timeout" in result.error_message.lower()


# ══════════════════════════════════════════════════════════════════════════════
# TESTS PUSH EVENTS TO CLOUD
# ══════════════════════════════════════════════════════════════════════════════

class TestPushEventsToCloud:
    """Tests synchronisation événements vers le Cloud."""

    @pytest.mark.asyncio
    async def test_push_events_empty_queue(self, sync_service):
        """Push avec file vide réussit immédiatement."""
        result = await sync_service.push_events_to_cloud()

        assert result.success is True
        assert result.items_synced == 0

    @pytest.mark.asyncio
    async def test_push_events_success(self, sync_service):
        """Push événements réussit."""
        sync_service.queue_event({"type": "test", "data": "value1"})
        sync_service.queue_event({"type": "test", "data": "value2"})

        result = await sync_service.push_events_to_cloud()

        assert result.success is True
        assert result.items_synced == 2

    @pytest.mark.asyncio
    async def test_push_events_clears_queue(self, sync_service):
        """Push réussi vide la file."""
        sync_service.queue_event({"type": "test"})
        assert sync_service.get_pending_events_count() == 1

        await sync_service.push_events_to_cloud()

        assert sync_service.get_pending_events_count() == 0

    @pytest.mark.asyncio
    async def test_push_events_failure_keeps_queue(self, sync_service_failing):
        """Push échoué garde la file."""
        sync_service_failing.queue_event({"type": "test"})

        result = await sync_service_failing.push_events_to_cloud()

        assert result.success is False
        assert sync_service_failing.get_pending_events_count() == 1

    @pytest.mark.asyncio
    async def test_push_events_emits_audit(self, sync_service, mock_audit_emitter):
        """Push événements émet audit."""
        sync_service.queue_event({"type": "test"})

        await sync_service.push_events_to_cloud()

        mock_audit_emitter.emit_event.assert_called()


# ══════════════════════════════════════════════════════════════════════════════
# TESTS SYNC OVERDUE
# ══════════════════════════════════════════════════════════════════════════════

class TestSyncOverdue:
    """Tests détection sync en retard."""

    def test_sync_overdue_no_sync(self, sync_service):
        """Jamais sync = en retard."""
        assert sync_service.is_sync_overdue() is True

    def test_sync_overdue_recent_sync(self, sync_service):
        """Sync récente = pas en retard."""
        sync_service._last_sync = datetime.now()

        assert sync_service.is_sync_overdue() is False

    def test_sync_overdue_old_sync(self, sync_service):
        """Sync ancienne = en retard."""
        sync_service._last_sync = datetime.now() - timedelta(hours=7)

        assert sync_service.is_sync_overdue() is True

    def test_sync_overdue_exactly_6_hours(self, sync_service):
        """Sync exactement 6h = pas en retard."""
        sync_service._last_sync = datetime.now() - timedelta(hours=5, minutes=59)

        assert sync_service.is_sync_overdue() is False

    def test_sync_overdue_6_hours_1_second(self, sync_service):
        """Sync 6h + 1s = en retard."""
        sync_service._last_sync = datetime.now() - timedelta(hours=6, seconds=1)

        assert sync_service.is_sync_overdue() is True


# ══════════════════════════════════════════════════════════════════════════════
# TESTS CACHE CONFIG
# ══════════════════════════════════════════════════════════════════════════════

class TestCacheConfig:
    """Tests cache de configuration."""

    def test_get_cached_config_empty(self, sync_service):
        """Cache vide retourne None."""
        assert sync_service.get_cached_config("unknown") is None

    def test_set_and_get_cached_config(self, sync_service):
        """Set et get config."""
        sync_service.set_cached_config("test_key", "test_value")

        assert sync_service.get_cached_config("test_key") == "test_value"

    def test_set_cached_config_sets_timestamp(self, sync_service):
        """Set config définit timestamp."""
        assert sync_service._config_cache_timestamp is None

        sync_service.set_cached_config("key", "value")

        assert sync_service._config_cache_timestamp is not None

    def test_get_all_cached_config(self, sync_service):
        """Get all config retourne copie."""
        sync_service.set_cached_config("key1", "value1")
        sync_service.set_cached_config("key2", "value2")

        config = sync_service.get_all_cached_config()

        assert config == {"key1": "value1", "key2": "value2"}

    def test_get_all_cached_config_is_copy(self, sync_service):
        """Get all config retourne copie indépendante."""
        sync_service.set_cached_config("key", "value")

        config = sync_service.get_all_cached_config()
        config["new_key"] = "new_value"

        assert sync_service.get_cached_config("new_key") is None


# ══════════════════════════════════════════════════════════════════════════════
# TESTS EVENT QUEUE
# ══════════════════════════════════════════════════════════════════════════════

class TestEventQueue:
    """Tests file d'attente événements."""

    def test_queue_event(self, sync_service):
        """Queue événement."""
        result = sync_service.queue_event({"type": "test"})

        assert result is True
        assert sync_service.get_pending_events_count() == 1

    def test_queue_event_adds_metadata(self, sync_service):
        """Queue ajoute metadata."""
        sync_service.queue_event({"type": "test"})

        event = sync_service.get_pending_events()[0]
        assert "queued_at" in event
        assert "node_id" in event
        assert event["node_id"] == "node-test-001"

    def test_queue_event_max_size(self, sync_service):
        """Queue limitée en taille."""
        for i in range(sync_service.MAX_PENDING_EVENTS):
            sync_service.queue_event({"index": i})

        result = sync_service.queue_event({"overflow": True})

        assert result is False
        assert sync_service.get_pending_events_count() == sync_service.MAX_PENDING_EVENTS

    def test_queue_event_also_queues_in_degraded(
        self, sync_service, mock_degraded_controller
    ):
        """Queue met aussi en file dans degraded controller."""
        sync_service.queue_event({"type": "test"})

        mock_degraded_controller.queue_event_for_sync.assert_called_once()

    def test_get_pending_events(self, sync_service):
        """Get pending events retourne liste."""
        sync_service.queue_event({"type": "event1"})
        sync_service.queue_event({"type": "event2"})

        events = sync_service.get_pending_events()

        assert len(events) == 2

    def test_clear_pending_events(self, sync_service):
        """Clear pending events vide la file."""
        sync_service.queue_event({"type": "event1"})
        sync_service.queue_event({"type": "event2"})

        cleared = sync_service.clear_pending_events()

        assert cleared == 2
        assert sync_service.get_pending_events_count() == 0


# ══════════════════════════════════════════════════════════════════════════════
# TESTS SYNC STATUS
# ══════════════════════════════════════════════════════════════════════════════

class TestSyncStatus:
    """Tests status de synchronisation."""

    def test_get_sync_status_initial(self, sync_service):
        """Status initial."""
        status = sync_service.get_sync_status()

        assert status["node_id"] == "node-test-001"
        assert status["last_sync"] is None
        assert status["last_sync_success"] is False
        assert status["sync_overdue"] is True
        assert status["cache_expired"] is True

    @pytest.mark.asyncio
    async def test_get_sync_status_after_success(self, sync_service):
        """Status après sync réussie."""
        await sync_service.sync_from_cloud()

        status = sync_service.get_sync_status()

        assert status["last_sync"] is not None
        assert status["last_sync_success"] is True
        assert status["sync_overdue"] is False
        assert status["cache_expired"] is False

    @pytest.mark.asyncio
    async def test_get_sync_status_after_failure(self, sync_service_failing):
        """Status après sync échouée."""
        await sync_service_failing.sync_from_cloud()

        status = sync_service_failing.get_sync_status()

        assert status["last_sync_success"] is False
        assert len(status["sync_errors"]) > 0

    def test_get_sync_status_with_pending_events(self, sync_service):
        """Status avec événements en attente."""
        sync_service.queue_event({"type": "test"})

        status = sync_service.get_sync_status()

        assert status["pending_events_count"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# TESTS NEXT SYNC DUE
# ══════════════════════════════════════════════════════════════════════════════

class TestNextSyncDue:
    """Tests calcul prochaine sync."""

    def test_next_sync_due_no_previous(self, sync_service):
        """Pas de sync précédente = maintenant."""
        next_due = sync_service.get_next_sync_due()

        # Devrait être environ maintenant
        diff = abs((next_due - datetime.now()).total_seconds())
        assert diff < 1

    def test_next_sync_due_after_sync(self, sync_service):
        """Prochaine sync = last + interval."""
        sync_service._last_sync = datetime.now()

        next_due = sync_service.get_next_sync_due()

        expected = sync_service._last_sync + timedelta(hours=sync_service.SYNC_INTERVAL_HOURS)
        diff = abs((next_due - expected).total_seconds())
        assert diff < 1


# ══════════════════════════════════════════════════════════════════════════════
# TESTS PROPERTIES
# ══════════════════════════════════════════════════════════════════════════════

class TestProperties:
    """Tests propriétés."""

    def test_node_id_property(self, sync_service):
        """Propriété node_id."""
        assert sync_service.node_id == "node-test-001"

    def test_get_last_sync_attempt(self, sync_service):
        """Get last sync attempt retourne dernière tentative."""
        sync_service._last_sync = datetime.now()
        sync_service._last_sync_success = False

        # get_last_sync retourne None car échec
        assert sync_service.get_last_sync() is None

        # get_last_sync_attempt retourne la tentative
        assert sync_service.get_last_sync_attempt() is not None
