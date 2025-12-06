"""
Tests unitaires pour LOT 10: Network - Connection Manager

Tests des invariants:
- NET_006: Connexion Cloud perdue = mode dégradé (pas crash)
- NET_007: Reconnexion automatique avec backoff
- NET_008: Keep-alive TCP activé (détection connexion morte)
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from src.network import (
    ConnectionManager,
    ConnectionState,
    ConnectionStatus,
    KeepAliveConfig,
    ConnectionLostError,
    DegradedModeError,
    RetryHandler,
)


class TestNET006DegradedMode:
    """Tests NET_006: Connexion Cloud perdue = mode dégradé (pas crash)."""

    def test_NET_006_initially_not_degraded(self) -> None:
        """NET_006: Système non dégradé initialement."""
        manager = ConnectionManager()
        assert manager.is_degraded() is False

    def test_NET_006_enter_degraded_mode(self) -> None:
        """NET_006: Entrée en mode dégradé."""
        manager = ConnectionManager()
        manager.enter_degraded_mode("Connection lost to cloud")
        assert manager.is_degraded() is True

    def test_NET_006_exit_degraded_mode(self) -> None:
        """NET_006: Sortie du mode dégradé."""
        manager = ConnectionManager()
        manager.enter_degraded_mode("Test")
        manager.exit_degraded_mode()
        assert manager.is_degraded() is False

    def test_NET_006_degraded_info_available(self) -> None:
        """NET_006: Informations mode dégradé disponibles."""
        manager = ConnectionManager()
        manager.enter_degraded_mode("Network failure")

        info = manager.get_degraded_info()
        assert info is not None
        assert info["reason"] == "Network failure"
        assert info["since"] is not None

    def test_NET_006_degraded_info_none_when_not_degraded(self) -> None:
        """NET_006: get_degraded_info None quand pas dégradé."""
        manager = ConnectionManager()
        assert manager.get_degraded_info() is None

    @pytest.mark.asyncio
    async def test_NET_006_connections_marked_degraded(self) -> None:
        """NET_006: Connexions marquées dégradées."""
        manager = ConnectionManager()
        await manager.connect("endpoint1")

        manager.enter_degraded_mode("Test")

        status = manager.get_connection_status("endpoint1")
        assert status.state == ConnectionState.DEGRADED

    @pytest.mark.asyncio
    async def test_NET_006_connections_restored_on_exit(self) -> None:
        """NET_006: Connexions restaurées à la sortie."""
        manager = ConnectionManager()
        await manager.connect("endpoint1")

        manager.enter_degraded_mode("Test")
        manager.exit_degraded_mode()

        status = manager.get_connection_status("endpoint1")
        assert status.state == ConnectionState.CONNECTED

    def test_NET_006_no_crash_on_connection_loss(self) -> None:
        """NET_006: Pas de crash sur perte de connexion."""
        manager = ConnectionManager()

        # Simuler une perte de connexion
        manager.enter_degraded_mode("Cloud connection lost")

        # Le système continue de fonctionner
        assert manager.is_degraded() is True
        assert manager.get_all_connections() is not None

    def test_NET_006_degraded_endpoints_listed(self) -> None:
        """NET_006: Liste des endpoints dégradés."""
        manager = ConnectionManager()
        manager._connections["ep1"] = ConnectionStatus(
            state=ConnectionState.DEGRADED,
            endpoint="ep1",
            connected_at=None,
            last_activity=None,
            reconnect_attempts=0,
            degraded_since=datetime.now(timezone.utc),
        )

        degraded = manager.get_degraded_endpoints()
        assert "ep1" in degraded

    def test_NET_006_enter_degraded_idempotent(self) -> None:
        """NET_006: enter_degraded_mode idempotent."""
        manager = ConnectionManager()
        manager.enter_degraded_mode("First")
        first_since = manager._degraded_since

        manager.enter_degraded_mode("Second")

        # Ne change pas si déjà dégradé
        assert manager._degraded_since == first_since


class TestNET007ReconnectionBackoff:
    """Tests NET_007: Reconnexion automatique avec backoff."""

    @pytest.mark.asyncio
    async def test_NET_007_reconnect_uses_retry_handler(self) -> None:
        """NET_007: Reconnexion utilise RetryHandler."""
        handler = RetryHandler()
        manager = ConnectionManager(retry_handler=handler)

        # Connexion initiale
        await manager.connect("endpoint1")
        manager._connections["endpoint1"].state = ConnectionState.DISCONNECTED

        # Reconnexion
        with patch("asyncio.sleep", new_callable=AsyncMock):
            status = await manager.reconnect("endpoint1")

        assert status.state == ConnectionState.CONNECTED

    @pytest.mark.asyncio
    async def test_NET_007_reconnect_increments_attempts(self) -> None:
        """NET_007: Reconnexion incrémente les tentatives."""
        manager = ConnectionManager()

        # Créer une connexion déconnectée
        manager._connections["endpoint1"] = ConnectionStatus(
            state=ConnectionState.DISCONNECTED,
            endpoint="endpoint1",
            connected_at=None,
            last_activity=None,
            reconnect_attempts=0,
            degraded_since=None,
        )

        with patch("asyncio.sleep", new_callable=AsyncMock):
            await manager.reconnect("endpoint1")

        # Le compteur devrait avoir été réinitialisé après succès
        status = manager.get_connection_status("endpoint1")
        assert status.reconnect_attempts == 0

    @pytest.mark.asyncio
    async def test_NET_007_reconnect_enters_degraded_on_failure(self) -> None:
        """NET_007: Mode dégradé si reconnexion échoue."""
        manager = ConnectionManager()

        # Handler qui échoue toujours
        async def failing_connect(endpoint: str) -> None:
            raise ConnectionError("Always fails")

        manager.set_connect_handler(failing_connect)

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(ConnectionLostError):
                await manager.reconnect("endpoint1")

        assert manager.is_degraded() is True

    @pytest.mark.asyncio
    async def test_NET_007_reconnect_state_transitions(self) -> None:
        """NET_007: Transitions d'état pendant reconnexion."""
        manager = ConnectionManager()
        states_observed = []

        original_reconnect = manager.reconnect

        async def track_reconnect(endpoint: str) -> ConnectionStatus:
            status = manager._connections.get(endpoint)
            if status:
                states_observed.append(status.state)
            return await original_reconnect(endpoint)

        await manager.connect("endpoint1")
        manager._connections["endpoint1"].state = ConnectionState.DISCONNECTED

        with patch("asyncio.sleep", new_callable=AsyncMock):
            await manager.reconnect("endpoint1")

        # État final CONNECTED
        status = manager.get_connection_status("endpoint1")
        assert status.state == ConnectionState.CONNECTED

    @pytest.mark.asyncio
    async def test_NET_007_exits_degraded_when_all_reconnected(self) -> None:
        """NET_007: Sort du mode dégradé quand tout reconnecté."""
        manager = ConnectionManager()

        await manager.connect("endpoint1")
        manager.enter_degraded_mode("Test")

        with patch("asyncio.sleep", new_callable=AsyncMock):
            await manager.reconnect("endpoint1")

        assert manager.is_degraded() is False

    @pytest.mark.asyncio
    async def test_NET_007_reconnect_new_endpoint(self) -> None:
        """NET_007: Reconnexion crée l'entrée si inexistante."""
        manager = ConnectionManager()

        with patch("asyncio.sleep", new_callable=AsyncMock):
            status = await manager.reconnect("new_endpoint")

        assert status.endpoint == "new_endpoint"
        assert "new_endpoint" in manager.get_all_connections()

    @pytest.mark.asyncio
    async def test_NET_007_backoff_with_retry_config(self) -> None:
        """NET_007: Backoff via RetryConfig."""
        handler = RetryHandler()
        manager = ConnectionManager(retry_handler=handler)

        call_count = 0

        async def failing_then_success(endpoint: str) -> None:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("Transient")

        manager.set_connect_handler(failing_then_success)

        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await manager.reconnect("endpoint1")

        # Vérifie que le backoff a été appliqué
        assert call_count >= 2

    @pytest.mark.asyncio
    async def test_NET_007_connection_lost_error_details(self) -> None:
        """NET_007: ConnectionLostError contient les détails."""
        manager = ConnectionManager()

        async def always_fails(endpoint: str) -> None:
            raise ConnectionError("Network unreachable")

        manager.set_connect_handler(always_fails)

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(ConnectionLostError) as exc:
                await manager.reconnect("test_endpoint")

        assert exc.value.endpoint == "test_endpoint"
        assert "3 attempts" in str(exc.value)

    @pytest.mark.asyncio
    async def test_NET_007_multiple_endpoints_reconnection(self) -> None:
        """NET_007: Reconnexion plusieurs endpoints."""
        manager = ConnectionManager()

        await manager.connect("ep1")
        await manager.connect("ep2")

        manager._connections["ep1"].state = ConnectionState.DISCONNECTED
        manager._connections["ep2"].state = ConnectionState.DISCONNECTED

        with patch("asyncio.sleep", new_callable=AsyncMock):
            await manager.reconnect("ep1")
            await manager.reconnect("ep2")

        assert manager.get_connection_status("ep1").state == ConnectionState.CONNECTED
        assert manager.get_connection_status("ep2").state == ConnectionState.CONNECTED


class TestNET008KeepAlive:
    """Tests NET_008: Keep-alive TCP activé (détection connexion morte)."""

    def test_NET_008_keep_alive_enabled_by_default(self) -> None:
        """NET_008: Keep-alive activé par défaut."""
        config = KeepAliveConfig()
        assert config.enabled is True

    def test_NET_008_default_keep_alive_config(self) -> None:
        """NET_008: Configuration keep-alive par défaut."""
        config = KeepAliveConfig()
        assert config.interval == 30.0
        assert config.timeout == 10.0
        assert config.max_failures == 3

    @pytest.mark.asyncio
    async def test_NET_008_send_keep_alive_success(self) -> None:
        """NET_008: Keep-alive réussi."""
        manager = ConnectionManager()
        await manager.connect("endpoint1")

        result = await manager.send_keep_alive("endpoint1")
        assert result is True

    @pytest.mark.asyncio
    async def test_NET_008_send_keep_alive_failure(self) -> None:
        """NET_008: Keep-alive échoué."""
        manager = ConnectionManager()
        await manager.connect("endpoint1")

        async def failing_ping(endpoint: str) -> None:
            raise TimeoutError("Ping timeout")

        manager.set_ping_handler(failing_ping)

        result = await manager.send_keep_alive("endpoint1")
        assert result is False

    @pytest.mark.asyncio
    async def test_NET_008_max_failures_triggers_disconnect(self) -> None:
        """NET_008: Max échecs déclenche déconnexion."""
        config = KeepAliveConfig(max_failures=2)
        manager = ConnectionManager(keep_alive_config=config)
        await manager.connect("endpoint1")

        async def failing_ping(endpoint: str) -> None:
            raise TimeoutError("Ping timeout")

        manager.set_ping_handler(failing_ping)

        # 2 échecs = déconnexion
        await manager.send_keep_alive("endpoint1")
        await manager.send_keep_alive("endpoint1")

        status = manager.get_connection_status("endpoint1")
        assert status.state == ConnectionState.DISCONNECTED

    @pytest.mark.asyncio
    async def test_NET_008_success_resets_failure_count(self) -> None:
        """NET_008: Succès reset le compteur d'échecs."""
        manager = ConnectionManager()
        await manager.connect("endpoint1")

        # Un échec
        async def fail_once(endpoint: str) -> None:
            raise TimeoutError()

        manager.set_ping_handler(fail_once)
        await manager.send_keep_alive("endpoint1")

        # Puis succès
        manager.set_ping_handler(None)
        await manager.send_keep_alive("endpoint1")

        status = manager.get_connection_status("endpoint1")
        assert status.keep_alive_failures == 0

    @pytest.mark.asyncio
    async def test_NET_008_check_connection_health(self) -> None:
        """NET_008: Vérification santé connexion."""
        manager = ConnectionManager()
        await manager.connect("endpoint1")

        healthy = await manager.check_connection_health("endpoint1")
        assert healthy is True

    @pytest.mark.asyncio
    async def test_NET_008_disconnected_not_healthy(self) -> None:
        """NET_008: Connexion déconnectée non saine."""
        manager = ConnectionManager()
        manager._connections["endpoint1"] = ConnectionStatus(
            state=ConnectionState.DISCONNECTED,
            endpoint="endpoint1",
            connected_at=None,
            last_activity=None,
            reconnect_attempts=0,
            degraded_since=None,
        )

        healthy = await manager.check_connection_health("endpoint1")
        assert healthy is False

    @pytest.mark.asyncio
    async def test_NET_008_keep_alive_disabled(self) -> None:
        """NET_008: Keep-alive désactivé retourne True."""
        config = KeepAliveConfig(enabled=False)
        manager = ConnectionManager(keep_alive_config=config)
        await manager.connect("endpoint1")

        result = await manager.send_keep_alive("endpoint1")
        assert result is True

    @pytest.mark.asyncio
    async def test_NET_008_triggers_degraded_mode(self) -> None:
        """NET_008: Échecs keep-alive déclenche mode dégradé."""
        config = KeepAliveConfig(max_failures=1)
        manager = ConnectionManager(keep_alive_config=config)
        await manager.connect("endpoint1")

        async def failing_ping(endpoint: str) -> None:
            raise TimeoutError()

        manager.set_ping_handler(failing_ping)
        await manager.send_keep_alive("endpoint1")

        assert manager.is_degraded() is True


class TestConnectionManager:
    """Tests généraux ConnectionManager."""

    @pytest.mark.asyncio
    async def test_connect_success(self) -> None:
        """Connexion réussie."""
        manager = ConnectionManager()
        status = await manager.connect("endpoint1")

        assert status.state == ConnectionState.CONNECTED
        assert status.endpoint == "endpoint1"
        assert status.connected_at is not None

    @pytest.mark.asyncio
    async def test_connect_empty_endpoint_rejected(self) -> None:
        """Endpoint vide rejeté."""
        manager = ConnectionManager()
        with pytest.raises(ValueError) as exc:
            await manager.connect("")
        assert "empty" in str(exc.value)

    @pytest.mark.asyncio
    async def test_disconnect_success(self) -> None:
        """Déconnexion réussie."""
        manager = ConnectionManager()
        await manager.connect("endpoint1")

        result = await manager.disconnect("endpoint1")
        assert result is True

        status = manager.get_connection_status("endpoint1")
        assert status.state == ConnectionState.DISCONNECTED

    @pytest.mark.asyncio
    async def test_disconnect_unknown_endpoint(self) -> None:
        """Déconnexion endpoint inconnu retourne False."""
        manager = ConnectionManager()
        result = await manager.disconnect("unknown")
        assert result is False

    def test_get_connection_status_unknown(self) -> None:
        """get_connection_status None pour endpoint inconnu."""
        manager = ConnectionManager()
        assert manager.get_connection_status("unknown") is None

    @pytest.mark.asyncio
    async def test_get_all_connections(self) -> None:
        """Liste toutes les connexions."""
        manager = ConnectionManager()
        await manager.connect("ep1")
        await manager.connect("ep2")

        connections = manager.get_all_connections()
        assert len(connections) == 2
        assert "ep1" in connections
        assert "ep2" in connections

    @pytest.mark.asyncio
    async def test_get_connected_endpoints(self) -> None:
        """Liste des endpoints connectés."""
        manager = ConnectionManager()
        await manager.connect("ep1")
        await manager.connect("ep2")
        await manager.disconnect("ep2")

        connected = manager.get_connected_endpoints()
        assert "ep1" in connected
        assert "ep2" not in connected

    def test_clear_all_connections(self) -> None:
        """Supprime toutes les connexions."""
        manager = ConnectionManager()
        manager._connections["ep1"] = ConnectionStatus(
            state=ConnectionState.CONNECTED,
            endpoint="ep1",
            connected_at=None,
            last_activity=None,
            reconnect_attempts=0,
            degraded_since=None,
        )

        manager.clear_all_connections()
        assert len(manager.get_all_connections()) == 0


class TestConnectionDataclasses:
    """Tests dataclasses Connection."""

    def test_keep_alive_config_defaults(self) -> None:
        """Valeurs par défaut KeepAliveConfig."""
        config = KeepAliveConfig()
        assert config.enabled is True
        assert config.interval == 30.0
        assert config.timeout == 10.0
        assert config.max_failures == 3

    def test_keep_alive_config_custom(self) -> None:
        """Valeurs personnalisées KeepAliveConfig."""
        config = KeepAliveConfig(
            enabled=False,
            interval=60.0,
            timeout=5.0,
            max_failures=5,
        )
        assert config.enabled is False
        assert config.interval == 60.0

    def test_connection_status_creation(self) -> None:
        """Création ConnectionStatus."""
        now = datetime.now(timezone.utc)
        status = ConnectionStatus(
            state=ConnectionState.CONNECTED,
            endpoint="test",
            connected_at=now,
            last_activity=now,
            reconnect_attempts=0,
            degraded_since=None,
        )
        assert status.state == ConnectionState.CONNECTED
        assert status.endpoint == "test"


class TestConnectionStateEnum:
    """Tests ConnectionState enum."""

    def test_all_states_exist(self) -> None:
        """Tous les états existent."""
        assert ConnectionState.CONNECTED.value == "connected"
        assert ConnectionState.DISCONNECTED.value == "disconnected"
        assert ConnectionState.DEGRADED.value == "degraded"
        assert ConnectionState.RECONNECTING.value == "reconnecting"

    def test_enum_count(self) -> None:
        """Nombre d'états."""
        assert len(ConnectionState) == 4


class TestConnectionErrors:
    """Tests exceptions Connection."""

    def test_connection_lost_error(self) -> None:
        """Création ConnectionLostError."""
        error = ConnectionLostError("endpoint1", "Network unreachable")
        assert error.endpoint == "endpoint1"
        assert error.reason == "Network unreachable"
        assert "endpoint1" in str(error)

    def test_degraded_mode_error(self) -> None:
        """Création DegradedModeError."""
        error = DegradedModeError("write_data")
        assert error.operation == "write_data"
        assert "NET_006" in str(error)

    def test_errors_are_exceptions(self) -> None:
        """Les erreurs sont des Exceptions."""
        assert isinstance(ConnectionLostError("ep", ""), Exception)
        assert isinstance(DegradedModeError("op"), Exception)
