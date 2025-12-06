"""
Tests unitaires FailoverManager

Invariants testés:
    RUN_050: Cluster minimum 2 noeuds
    RUN_051: Failover < 10 secondes
        - Detection timeout: 3s max
        - Promotion timeout: 5s max
"""
import pytest
import asyncio
import time
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch

from src.ha.interfaces import (
    IFailoverManager,
    IHealthMonitor,
    ClusterStatus,
    HealthStatus,
    HealthReport,
    HealthCheck,
)
from src.ha.failover_manager import FailoverManager, FailoverError, NodeInfo
from src.audit.interfaces import IAuditEmitter, AuditEventType


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
def mock_health_monitor():
    """HealthMonitor mocké pour tests."""
    monitor = Mock(spec=IHealthMonitor)
    monitor.check_health = AsyncMock(return_value=HealthReport(
        status=HealthStatus.HEALTHY,
        timestamp=datetime.now(),
        checks=[],
        node_id="node-1",
    ))
    monitor.check_readiness = AsyncMock(return_value=True)
    return monitor


@pytest.fixture
def failover_manager(mock_health_monitor, mock_audit_emitter):
    """FailoverManager instance pour tests."""
    return FailoverManager(
        node_id="node-1",
        health_monitor=mock_health_monitor,
        audit_emitter=mock_audit_emitter,
    )


@pytest.fixture
def cluster_failover_manager(mock_health_monitor, mock_audit_emitter):
    """FailoverManager avec cluster de 3 noeuds."""
    manager = FailoverManager(
        node_id="node-1",
        health_monitor=mock_health_monitor,
        audit_emitter=mock_audit_emitter,
    )
    manager.register_node("node-1", is_primary=True)
    manager.register_node("node-2", is_primary=False)
    manager.register_node("node-3", is_primary=False)
    return manager


# ══════════════════════════════════════════════════════════════════════════════
# TESTS INTERFACE
# ══════════════════════════════════════════════════════════════════════════════

class TestFailoverManagerInterface:
    """Vérifie conformité interface."""

    def test_implements_interface(self, failover_manager):
        """FailoverManager implémente IFailoverManager."""
        assert isinstance(failover_manager, IFailoverManager)

    def test_requires_node_id(self, mock_health_monitor, mock_audit_emitter):
        """FailoverManager requiert node_id."""
        with pytest.raises(TypeError):
            FailoverManager(
                health_monitor=mock_health_monitor,
                audit_emitter=mock_audit_emitter,
            )

    def test_requires_health_monitor(self, mock_audit_emitter):
        """FailoverManager requiert health_monitor."""
        with pytest.raises(TypeError):
            FailoverManager(
                node_id="node-1",
                audit_emitter=mock_audit_emitter,
            )


# ══════════════════════════════════════════════════════════════════════════════
# TESTS RUN_050: CLUSTER MINIMUM 2 NOEUDS
# ══════════════════════════════════════════════════════════════════════════════

class TestRUN050Compliance:
    """Tests conformité RUN_050: Cluster minimum 2 noeuds."""

    def test_RUN_050_min_nodes_constant(self, failover_manager):
        """RUN_050: Constante MIN_NODES = 2."""
        assert failover_manager.MIN_NODES == 2

    def test_RUN_050_single_node_invalid(self, failover_manager):
        """RUN_050: Cluster 1 noeud invalide."""
        failover_manager.register_node("node-1", is_primary=True)

        assert failover_manager.validate_cluster_config() is False

    def test_RUN_050_two_nodes_valid(self, failover_manager):
        """RUN_050: Cluster 2 noeuds valide."""
        failover_manager.register_node("node-1", is_primary=True)
        failover_manager.register_node("node-2", is_primary=False)

        assert failover_manager.validate_cluster_config() is True

    def test_RUN_050_three_nodes_valid(self, cluster_failover_manager):
        """RUN_050: Cluster 3 noeuds valide."""
        assert cluster_failover_manager.validate_cluster_config() is True

    def test_RUN_050_cluster_status_node_count(self, cluster_failover_manager):
        """RUN_050: ClusterStatus reflète nombre de noeuds."""
        status = cluster_failover_manager.get_cluster_status()

        assert status.node_count == 3
        assert status.is_valid_cluster() is True

    def test_RUN_050_cluster_status_single_node_invalid(self, failover_manager):
        """RUN_050: ClusterStatus.is_valid_cluster False pour 1 noeud."""
        failover_manager.register_node("node-1", is_primary=True)

        status = failover_manager.get_cluster_status()

        assert status.node_count == 1
        assert status.is_valid_cluster() is False


# ══════════════════════════════════════════════════════════════════════════════
# TESTS RUN_051: FAILOVER < 10 SECONDES
# ══════════════════════════════════════════════════════════════════════════════

class TestRUN051Compliance:
    """Tests conformité RUN_051: Failover < 10 secondes."""

    def test_RUN_051_timeout_constants(self, failover_manager):
        """RUN_051: Constantes de timeout définies."""
        assert failover_manager.DETECTION_TIMEOUT == 3.0
        assert failover_manager.PROMOTION_TIMEOUT == 5.0
        assert failover_manager.MAX_FAILOVER_TIME == 10.0

    def test_RUN_051_total_timeout_under_max(self, failover_manager):
        """RUN_051: Detection + Promotion < MAX_FAILOVER_TIME."""
        total = failover_manager.DETECTION_TIMEOUT + failover_manager.PROMOTION_TIMEOUT
        assert total < failover_manager.MAX_FAILOVER_TIME

    @pytest.mark.asyncio
    async def test_RUN_051_failover_completes_under_10s(
        self, cluster_failover_manager, mock_audit_emitter
    ):
        """RUN_051: Failover complet < 10 secondes."""
        # Simuler primary défaillant
        cluster_failover_manager._nodes["node-1"].status = HealthStatus.UNHEALTHY
        cluster_failover_manager._nodes["node-1"].last_heartbeat = (
            datetime.now() - timedelta(seconds=10)
        )

        start = time.perf_counter()
        await cluster_failover_manager.trigger_failover("Primary failed")
        elapsed = time.perf_counter() - start

        # Vérifier temps < 10s
        assert elapsed < 10.0

    @pytest.mark.asyncio
    async def test_RUN_051_failover_promotes_standby(
        self, cluster_failover_manager, mock_audit_emitter
    ):
        """RUN_051: Failover promeut un standby."""
        # Simuler primary défaillant
        cluster_failover_manager._nodes["node-1"].status = HealthStatus.UNHEALTHY
        cluster_failover_manager._nodes["node-1"].last_heartbeat = (
            datetime.now() - timedelta(seconds=10)
        )

        old_primary = cluster_failover_manager.get_current_primary()
        await cluster_failover_manager.trigger_failover("Primary failed")
        new_primary = cluster_failover_manager.get_current_primary()

        # Le primary doit avoir changé
        assert new_primary != old_primary
        assert new_primary in ["node-2", "node-3"]

    @pytest.mark.asyncio
    async def test_RUN_051_failover_emits_audit(
        self, cluster_failover_manager, mock_audit_emitter
    ):
        """RUN_051: Failover émet événement audit."""
        cluster_failover_manager._nodes["node-1"].status = HealthStatus.UNHEALTHY
        cluster_failover_manager._nodes["node-1"].last_heartbeat = (
            datetime.now() - timedelta(seconds=10)
        )

        await cluster_failover_manager.trigger_failover("Test failover")

        # Vérifier audit émis
        mock_audit_emitter.emit_event.assert_called()
        calls = mock_audit_emitter.emit_event.call_args_list
        # Au moins un appel pour failover_completed
        assert any(
            call[1].get("action") == "failover_completed"
            for call in calls
        )


# ══════════════════════════════════════════════════════════════════════════════
# TESTS ENREGISTREMENT NOEUDS
# ══════════════════════════════════════════════════════════════════════════════

class TestNodeRegistration:
    """Tests enregistrement/désenregistrement noeuds."""

    def test_register_node_primary(self, failover_manager):
        """Enregistrement noeud primary."""
        failover_manager.register_node("node-1", is_primary=True)

        assert failover_manager.get_current_primary() == "node-1"
        assert failover_manager.is_primary is True

    def test_register_node_standby(self, failover_manager):
        """Enregistrement noeud standby."""
        failover_manager.register_node("node-1", is_primary=True)
        failover_manager.register_node("node-2", is_primary=False)

        status = failover_manager.get_cluster_status()
        assert "node-2" in status.healthy_nodes

    def test_unregister_node(self, cluster_failover_manager):
        """Désenregistrement noeud."""
        cluster_failover_manager.unregister_node("node-3")

        status = cluster_failover_manager.get_cluster_status()
        assert status.node_count == 2
        assert "node-3" not in status.healthy_nodes

    def test_unregister_primary_clears_primary(self, failover_manager):
        """Désenregistrement primary efface le primary."""
        failover_manager.register_node("node-1", is_primary=True)
        failover_manager.unregister_node("node-1")

        assert failover_manager.get_current_primary() == ""

    def test_update_node_heartbeat(self, cluster_failover_manager):
        """Mise à jour heartbeat noeud."""
        old_heartbeat = cluster_failover_manager._nodes["node-2"].last_heartbeat

        # Petite pause pour avoir un timestamp différent
        import time
        time.sleep(0.01)

        cluster_failover_manager.update_node_heartbeat("node-2")
        new_heartbeat = cluster_failover_manager._nodes["node-2"].last_heartbeat

        assert new_heartbeat > old_heartbeat

    def test_update_node_status(self, cluster_failover_manager):
        """Mise à jour status noeud."""
        cluster_failover_manager.update_node_status("node-2", HealthStatus.DEGRADED)

        assert cluster_failover_manager._nodes["node-2"].status == HealthStatus.DEGRADED


# ══════════════════════════════════════════════════════════════════════════════
# TESTS PROMOTION
# ══════════════════════════════════════════════════════════════════════════════

class TestPromotion:
    """Tests promotion noeuds."""

    @pytest.mark.asyncio
    async def test_promote_to_primary_success(
        self, cluster_failover_manager, mock_audit_emitter
    ):
        """Promotion réussie d'un standby."""
        await cluster_failover_manager.promote_to_primary("node-2")

        assert cluster_failover_manager.get_current_primary() == "node-2"
        assert cluster_failover_manager._nodes["node-2"].is_primary is True
        assert cluster_failover_manager._nodes["node-1"].is_primary is False

    @pytest.mark.asyncio
    async def test_promote_unknown_node_fails(
        self, cluster_failover_manager, mock_audit_emitter
    ):
        """Promotion noeud inconnu échoue."""
        with pytest.raises(FailoverError, match="not found"):
            await cluster_failover_manager.promote_to_primary("node-unknown")

    @pytest.mark.asyncio
    async def test_promote_unhealthy_node_fails(
        self, cluster_failover_manager, mock_audit_emitter
    ):
        """Promotion noeud unhealthy échoue."""
        cluster_failover_manager._nodes["node-2"].status = HealthStatus.UNHEALTHY

        with pytest.raises(FailoverError, match="not healthy"):
            await cluster_failover_manager.promote_to_primary("node-2")

    @pytest.mark.asyncio
    async def test_promote_emits_audit(
        self, cluster_failover_manager, mock_audit_emitter
    ):
        """Promotion émet événement audit."""
        await cluster_failover_manager.promote_to_primary("node-2")

        mock_audit_emitter.emit_event.assert_called()
        call_kwargs = mock_audit_emitter.emit_event.call_args[1]
        assert call_kwargs["action"] == "node_promoted_to_primary"


# ══════════════════════════════════════════════════════════════════════════════
# TESTS FAILOVER ERREURS
# ══════════════════════════════════════════════════════════════════════════════

class TestFailoverErrors:
    """Tests erreurs failover."""

    @pytest.mark.asyncio
    async def test_failover_no_standby_fails(
        self, failover_manager, mock_audit_emitter
    ):
        """Failover sans standby échoue."""
        failover_manager.register_node("node-1", is_primary=True)
        failover_manager._nodes["node-1"].status = HealthStatus.UNHEALTHY
        failover_manager._nodes["node-1"].last_heartbeat = (
            datetime.now() - timedelta(seconds=10)
        )

        with pytest.raises(FailoverError, match="No healthy standby"):
            await failover_manager.trigger_failover("No standby available")

    @pytest.mark.asyncio
    async def test_failover_primary_healthy_fails(
        self, cluster_failover_manager, mock_audit_emitter
    ):
        """Failover quand primary healthy échoue."""
        # Primary est healthy par défaut
        with pytest.raises(FailoverError, match="still healthy"):
            await cluster_failover_manager.trigger_failover("Unnecessary failover")

    @pytest.mark.asyncio
    async def test_failover_already_in_progress_fails(
        self, cluster_failover_manager, mock_audit_emitter
    ):
        """Failover concurrent échoue."""
        cluster_failover_manager._failover_in_progress = True

        with pytest.raises(FailoverError, match="already in progress"):
            await cluster_failover_manager.trigger_failover("Concurrent failover")

    @pytest.mark.asyncio
    async def test_failover_all_standbys_unhealthy_fails(
        self, cluster_failover_manager, mock_audit_emitter
    ):
        """Failover quand tous standbys unhealthy échoue."""
        # Primary défaillant
        cluster_failover_manager._nodes["node-1"].status = HealthStatus.UNHEALTHY
        cluster_failover_manager._nodes["node-1"].last_heartbeat = (
            datetime.now() - timedelta(seconds=10)
        )
        # Standbys défaillants
        cluster_failover_manager._nodes["node-2"].status = HealthStatus.UNHEALTHY
        cluster_failover_manager._nodes["node-3"].status = HealthStatus.UNHEALTHY

        with pytest.raises(FailoverError, match="No healthy standby"):
            await cluster_failover_manager.trigger_failover("All nodes failed")


# ══════════════════════════════════════════════════════════════════════════════
# TESTS CLUSTER STATUS
# ══════════════════════════════════════════════════════════════════════════════

class TestClusterStatus:
    """Tests status cluster."""

    def test_cluster_status_healthy_nodes(self, cluster_failover_manager):
        """ClusterStatus liste noeuds healthy."""
        status = cluster_failover_manager.get_cluster_status()

        assert len(status.healthy_nodes) == 3
        assert "node-1" in status.healthy_nodes
        assert "node-2" in status.healthy_nodes
        assert "node-3" in status.healthy_nodes

    def test_cluster_status_unhealthy_nodes(self, cluster_failover_manager):
        """ClusterStatus liste noeuds unhealthy."""
        cluster_failover_manager._nodes["node-2"].status = HealthStatus.UNHEALTHY

        status = cluster_failover_manager.get_cluster_status()

        assert "node-2" in status.unhealthy_nodes
        assert "node-2" not in status.healthy_nodes

    def test_cluster_status_stale_heartbeat_unhealthy(self, cluster_failover_manager):
        """Heartbeat périmé → noeud unhealthy."""
        cluster_failover_manager._nodes["node-3"].last_heartbeat = (
            datetime.now() - timedelta(seconds=60)
        )

        status = cluster_failover_manager.get_cluster_status()

        assert "node-3" in status.unhealthy_nodes

    def test_cluster_status_primary_node(self, cluster_failover_manager):
        """ClusterStatus indique primary."""
        status = cluster_failover_manager.get_cluster_status()

        assert status.primary_node == "node-1"

    def test_empty_cluster_status(self, failover_manager):
        """Status cluster vide."""
        status = failover_manager.get_cluster_status()

        assert status.node_count == 0
        assert status.primary_node == ""
        assert len(status.healthy_nodes) == 0


# ══════════════════════════════════════════════════════════════════════════════
# TESTS DATA CLASSES
# ══════════════════════════════════════════════════════════════════════════════

class TestNodeInfo:
    """Tests NodeInfo dataclass."""

    def test_node_info_creation(self):
        """Création NodeInfo."""
        now = datetime.now()
        info = NodeInfo(
            node_id="test-node",
            is_primary=True,
            last_heartbeat=now,
            status=HealthStatus.HEALTHY,
        )

        assert info.node_id == "test-node"
        assert info.is_primary is True
        assert info.last_heartbeat == now
        assert info.status == HealthStatus.HEALTHY

    def test_node_info_default_status(self):
        """NodeInfo status par défaut."""
        info = NodeInfo(
            node_id="test-node",
            is_primary=False,
            last_heartbeat=datetime.now(),
        )

        assert info.status == HealthStatus.HEALTHY


# ══════════════════════════════════════════════════════════════════════════════
# TESTS PROPRIÉTÉS
# ══════════════════════════════════════════════════════════════════════════════

class TestProperties:
    """Tests propriétés du manager."""

    def test_node_id_property(self, failover_manager):
        """Propriété node_id."""
        assert failover_manager.node_id == "node-1"

    def test_is_primary_property_false(self, failover_manager):
        """Propriété is_primary False initialement."""
        assert failover_manager.is_primary is False

    def test_is_primary_property_true(self, failover_manager):
        """Propriété is_primary True après enregistrement."""
        failover_manager.register_node("node-1", is_primary=True)
        assert failover_manager.is_primary is True

    def test_is_failover_in_progress(self, failover_manager):
        """Propriété is_failover_in_progress."""
        assert failover_manager.is_failover_in_progress() is False

        failover_manager._failover_in_progress = True
        assert failover_manager.is_failover_in_progress() is True
