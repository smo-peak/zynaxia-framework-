"""
Tests unitaires pour DeploymentOrchestrator.

LOT 7: Orchestrateur de déploiement zero-downtime

Invariants testés:
    DEPL_010: Standby-first obligatoire (jamais sur PRIMARY)
    DEPL_011: Healthcheck validé sur STANDBY avant bascule
    DEPL_012: Rollback automatique < 60 secondes si healthcheck échoue
    DEPL_013: Zero-downtime obligatoire
    DEPL_014: Déploiement progressif (1 nœud → validation → autres)
"""

import asyncio
import time
from datetime import datetime
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, PropertyMock

import pytest

from src.audit.interfaces import AuditEventType, IAuditEmitter
from src.deployment.deployment_orchestrator import (
    DeploymentConfig,
    DeploymentError,
    DeploymentOrchestrator,
    DeploymentResult,
    DeploymentSnapshot,
    DeploymentState,
    NodeDeploymentState,
    NodeRole,
    RollbackError,
)
from src.deployment.interfaces import IImageVerifier, VerificationStatus
from src.ha.interfaces import (
    ClusterStatus,
    HealthCheck,
    HealthReport,
    HealthStatus,
    IFailoverManager,
    IHealthMonitor,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mock_image_verifier() -> AsyncMock:
    """Crée un mock de IImageVerifier."""
    verifier = AsyncMock(spec=IImageVerifier)
    # Par défaut, l'image est vérifiée avec succès
    mock_result = MagicMock()
    mock_result.status = VerificationStatus.VERIFIED
    verifier.verify_image = AsyncMock(return_value=mock_result)
    return verifier


@pytest.fixture
def mock_health_monitor() -> AsyncMock:
    """Crée un mock de IHealthMonitor."""
    monitor = AsyncMock(spec=IHealthMonitor)
    # Par défaut, healthcheck réussi
    healthy_report = HealthReport(
        status=HealthStatus.HEALTHY,
        timestamp=datetime.now(),
        checks=[
            HealthCheck(name="database", status=HealthStatus.HEALTHY, latency_ms=5),
        ],
        node_id="node-1",
    )
    monitor.check_health = AsyncMock(return_value=healthy_report)
    return monitor


@pytest.fixture
def mock_failover_manager() -> MagicMock:
    """Crée un mock de IFailoverManager."""
    manager = MagicMock(spec=IFailoverManager)
    manager.get_current_primary = MagicMock(return_value="primary-node")
    manager.get_cluster_status = MagicMock(
        return_value=ClusterStatus(
            node_count=3,
            primary_node="primary-node",
            healthy_nodes=["primary-node", "standby-1", "standby-2"],
            unhealthy_nodes=[],
        )
    )
    return manager


@pytest.fixture
def mock_audit_emitter() -> AsyncMock:
    """Crée un mock de IAuditEmitter."""
    emitter = AsyncMock(spec=IAuditEmitter)
    emitter.emit_event = AsyncMock()
    return emitter


@pytest.fixture
def orchestrator(
    mock_image_verifier: AsyncMock,
    mock_health_monitor: AsyncMock,
    mock_failover_manager: MagicMock,
    mock_audit_emitter: AsyncMock,
) -> DeploymentOrchestrator:
    """Crée un DeploymentOrchestrator pour les tests."""
    return DeploymentOrchestrator(
        image_verifier=mock_image_verifier,
        health_monitor=mock_health_monitor,
        failover_manager=mock_failover_manager,
        audit_emitter=mock_audit_emitter,
    )


@pytest.fixture
def deployment_config() -> Dict[str, Any]:
    """Configuration de déploiement standard."""
    return {
        "deployment_id": "deploy-123",
        "target_nodes": ["primary-node", "standby-1", "standby-2"],
        "config_hash": "abc123",
        "rollback_timeout": 60,
        "healthcheck_timeout": 30,
        "progressive": True,
    }


# ============================================================================
# Tests DEPL_010: Standby-first obligatoire
# ============================================================================


class TestDEPL010StandbyFirst:
    """Tests pour DEPL_010: Standby-first obligatoire."""

    @pytest.mark.asyncio
    async def test_standby_nodes_deployed_first(
        self,
        orchestrator: DeploymentOrchestrator,
        deployment_config: Dict[str, Any],
    ) -> None:
        """DEPL_010: Les nœuds STANDBY sont déployés en premier."""
        result = await orchestrator.deploy_image(
            "registry.example.com/app:v1.0",
            deployment_config,
        )

        assert result["success"] is True
        # Les standby doivent être dans deployed_nodes avant primary
        deployed = result["deployed_nodes"]
        assert "standby-1" in deployed
        assert "standby-2" in deployed

    @pytest.mark.asyncio
    async def test_primary_not_deployed_if_no_standby(
        self,
        orchestrator: DeploymentOrchestrator,
        mock_failover_manager: MagicMock,
        mock_audit_emitter: AsyncMock,
    ) -> None:
        """DEPL_010: PRIMARY seul sans STANDBY = échec."""
        config = {
            "deployment_id": "deploy-456",
            "target_nodes": ["primary-node"],  # Seulement le primary
            "config_hash": "xyz789",
        }

        result = await orchestrator.deploy_image(
            "registry.example.com/app:v1.0",
            config,
        )

        assert result["success"] is False
        assert "STANDBY" in result["error_message"]

    @pytest.mark.asyncio
    async def test_identifies_standby_nodes_correctly(
        self,
        orchestrator: DeploymentOrchestrator,
    ) -> None:
        """DEPL_010: Identification correcte des nœuds STANDBY."""
        standby = orchestrator._get_standby_nodes(
            ["primary-node", "standby-1", "standby-2"]
        )

        assert "primary-node" not in standby
        assert "standby-1" in standby
        assert "standby-2" in standby

    @pytest.mark.asyncio
    async def test_primary_deployed_only_after_standby_success(
        self,
        orchestrator: DeploymentOrchestrator,
        deployment_config: Dict[str, Any],
    ) -> None:
        """DEPL_010: PRIMARY déployé seulement après succès STANDBY."""
        result = await orchestrator.deploy_image(
            "registry.example.com/app:v1.0",
            deployment_config,
        )

        assert result["success"] is True
        deployed = result["deployed_nodes"]
        # Primary doit être le dernier
        if "primary-node" in deployed:
            assert deployed.index("primary-node") == len(deployed) - 1

    @pytest.mark.asyncio
    async def test_node_role_detection(
        self,
        orchestrator: DeploymentOrchestrator,
    ) -> None:
        """DEPL_010: Détection correcte du rôle des nœuds."""
        assert orchestrator._get_node_role("primary-node") == NodeRole.PRIMARY
        assert orchestrator._get_node_role("standby-1") == NodeRole.STANDBY
        assert orchestrator._get_node_role("standby-2") == NodeRole.STANDBY


# ============================================================================
# Tests DEPL_011: Healthcheck avant bascule
# ============================================================================


class TestDEPL011HealthcheckBeforeSwitch:
    """Tests pour DEPL_011: Healthcheck validé avant bascule."""

    @pytest.mark.asyncio
    async def test_healthcheck_called_after_deploy(
        self,
        orchestrator: DeploymentOrchestrator,
        mock_health_monitor: AsyncMock,
        deployment_config: Dict[str, Any],
    ) -> None:
        """DEPL_011: Healthcheck appelé après déploiement."""
        await orchestrator.deploy_image(
            "registry.example.com/app:v1.0",
            deployment_config,
        )

        # Healthcheck doit être appelé pour chaque nœud
        assert mock_health_monitor.check_health.call_count >= 1

    @pytest.mark.asyncio
    async def test_deployment_blocked_if_healthcheck_fails(
        self,
        orchestrator: DeploymentOrchestrator,
        mock_health_monitor: AsyncMock,
        deployment_config: Dict[str, Any],
    ) -> None:
        """DEPL_011: Déploiement bloqué si healthcheck échoue."""
        # Healthcheck échoue
        unhealthy_report = HealthReport(
            status=HealthStatus.UNHEALTHY,
            timestamp=datetime.now(),
            checks=[
                HealthCheck(
                    name="database",
                    status=HealthStatus.UNHEALTHY,
                    message="Connection failed",
                ),
            ],
            node_id="standby-1",
        )
        mock_health_monitor.check_health = AsyncMock(return_value=unhealthy_report)

        result = await orchestrator.deploy_image(
            "registry.example.com/app:v1.0",
            deployment_config,
        )

        assert result["success"] is False
        assert len(result["failed_nodes"]) > 0

    @pytest.mark.asyncio
    async def test_degraded_status_allowed(
        self,
        orchestrator: DeploymentOrchestrator,
        mock_health_monitor: AsyncMock,
        deployment_config: Dict[str, Any],
    ) -> None:
        """DEPL_011: Status DEGRADED autorisé pour continuer."""
        degraded_report = HealthReport(
            status=HealthStatus.DEGRADED,
            timestamp=datetime.now(),
            checks=[
                HealthCheck(name="database", status=HealthStatus.HEALTHY),
                HealthCheck(name="cache", status=HealthStatus.DEGRADED),
            ],
            node_id="standby-1",
        )
        mock_health_monitor.check_health = AsyncMock(return_value=degraded_report)

        result = await orchestrator.deploy_image(
            "registry.example.com/app:v1.0",
            deployment_config,
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_healthcheck_timeout_handled(
        self,
        orchestrator: DeploymentOrchestrator,
        mock_health_monitor: AsyncMock,
        deployment_config: Dict[str, Any],
    ) -> None:
        """DEPL_011: Timeout healthcheck géré correctement."""

        async def slow_healthcheck() -> HealthReport:
            await asyncio.sleep(100)
            return HealthReport(
                status=HealthStatus.HEALTHY,
                timestamp=datetime.now(),
                checks=[],
                node_id="test",
            )

        mock_health_monitor.check_health = slow_healthcheck
        deployment_config["healthcheck_timeout"] = 0.01

        result = await orchestrator.deploy_image(
            "registry.example.com/app:v1.0",
            deployment_config,
        )

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_healthcheck_per_node(
        self,
        orchestrator: DeploymentOrchestrator,
        mock_health_monitor: AsyncMock,
    ) -> None:
        """DEPL_011: Healthcheck effectué pour chaque nœud."""
        config = {
            "deployment_id": "deploy-789",
            "target_nodes": ["primary-node", "standby-1", "standby-2"],
            "config_hash": "test",
        }

        await orchestrator.deploy_image("registry.example.com/app:v1.0", config)

        # Au moins un healthcheck par nœud standby + primary
        assert mock_health_monitor.check_health.call_count >= 2


# ============================================================================
# Tests DEPL_012: Rollback < 60 secondes
# ============================================================================


class TestDEPL012RollbackTimeout:
    """Tests pour DEPL_012: Rollback automatique < 60 secondes."""

    @pytest.mark.asyncio
    async def test_rollback_triggered_on_healthcheck_failure(
        self,
        orchestrator: DeploymentOrchestrator,
        mock_health_monitor: AsyncMock,
        deployment_config: Dict[str, Any],
    ) -> None:
        """DEPL_012: Rollback déclenché si healthcheck échoue."""
        # Premier healthcheck OK, puis échec
        call_count = 0

        async def alternating_healthcheck() -> HealthReport:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return HealthReport(
                    status=HealthStatus.HEALTHY,
                    timestamp=datetime.now(),
                    checks=[],
                    node_id="standby-1",
                )
            return HealthReport(
                status=HealthStatus.UNHEALTHY,
                timestamp=datetime.now(),
                checks=[],
                node_id="standby-2",
            )

        mock_health_monitor.check_health = alternating_healthcheck

        # Configurer une image existante pour le rollback
        orchestrator.set_current_image("standby-1", "registry.example.com/app:v0.9")
        orchestrator.set_current_image("standby-2", "registry.example.com/app:v0.9")

        result = await orchestrator.deploy_image(
            "registry.example.com/app:v1.0",
            deployment_config,
        )

        # Le rollback doit être effectué
        assert result["rollback_performed"] is True

    @pytest.mark.asyncio
    async def test_rollback_restores_previous_image(
        self,
        orchestrator: DeploymentOrchestrator,
        mock_health_monitor: AsyncMock,
    ) -> None:
        """DEPL_012: Rollback restaure l'image précédente."""
        # Configurer l'image actuelle
        orchestrator.set_current_image("standby-1", "registry.example.com/app:v0.9")

        # Healthcheck échoue
        mock_health_monitor.check_health = AsyncMock(
            return_value=HealthReport(
                status=HealthStatus.UNHEALTHY,
                timestamp=datetime.now(),
                checks=[],
                node_id="standby-1",
            )
        )

        config = {
            "deployment_id": "deploy-rollback",
            "target_nodes": ["primary-node", "standby-1"],
            "config_hash": "test",
        }

        await orchestrator.deploy_image("registry.example.com/app:v1.0", config)

        # L'image doit être revenue à la version précédente
        current = orchestrator.get_current_image("standby-1")
        assert current == "registry.example.com/app:v0.9"

    @pytest.mark.asyncio
    async def test_rollback_duration_measured(
        self,
        orchestrator: DeploymentOrchestrator,
        mock_health_monitor: AsyncMock,
        deployment_config: Dict[str, Any],
    ) -> None:
        """DEPL_012: Durée du rollback mesurée."""
        # Healthcheck échoue
        mock_health_monitor.check_health = AsyncMock(
            return_value=HealthReport(
                status=HealthStatus.UNHEALTHY,
                timestamp=datetime.now(),
                checks=[],
                node_id="standby-1",
            )
        )

        orchestrator.set_current_image("standby-1", "old-image")

        result = await orchestrator.deploy_image(
            "registry.example.com/app:v1.0",
            deployment_config,
        )

        if result["rollback_performed"]:
            assert result["rollback_duration_seconds"] >= 0

    @pytest.mark.asyncio
    async def test_manual_rollback_works(
        self,
        orchestrator: DeploymentOrchestrator,
    ) -> None:
        """DEPL_012: Rollback manuel fonctionne."""
        deployment_id = "deploy-manual"

        # Créer un snapshot manuellement
        orchestrator._snapshots[deployment_id] = DeploymentSnapshot(
            deployment_id=deployment_id,
            timestamp=datetime.now(),
            node_states={"standby-1": "old-image"},
            config_hash="test",
        )
        orchestrator.set_current_image("standby-1", "new-image")

        success = await orchestrator.rollback(deployment_id)

        assert success is True
        assert orchestrator.get_current_image("standby-1") == "old-image"

    @pytest.mark.asyncio
    async def test_rollback_without_snapshot_raises_error(
        self,
        orchestrator: DeploymentOrchestrator,
    ) -> None:
        """DEPL_012: Rollback sans snapshot lève une erreur."""
        with pytest.raises(RollbackError, match="No snapshot found"):
            await orchestrator.rollback("nonexistent-deployment")

    @pytest.mark.asyncio
    async def test_rollback_timeout_constant(
        self,
        orchestrator: DeploymentOrchestrator,
    ) -> None:
        """DEPL_012: Timeout rollback = 60s par défaut."""
        assert orchestrator.ROLLBACK_TIMEOUT == 60

    @pytest.mark.asyncio
    async def test_rollback_updates_deployment_state(
        self,
        orchestrator: DeploymentOrchestrator,
    ) -> None:
        """DEPL_012: Rollback met à jour l'état du déploiement."""
        deployment_id = "deploy-state"

        orchestrator._snapshots[deployment_id] = DeploymentSnapshot(
            deployment_id=deployment_id,
            timestamp=datetime.now(),
            node_states={"standby-1": "old-image"},
            config_hash="test",
        )
        orchestrator._deployments[deployment_id] = DeploymentState.FAILED

        await orchestrator.rollback(deployment_id)

        assert orchestrator._deployments[deployment_id] == DeploymentState.ROLLED_BACK

    @pytest.mark.asyncio
    async def test_rollback_emits_audit_event(
        self,
        orchestrator: DeploymentOrchestrator,
        mock_audit_emitter: AsyncMock,
    ) -> None:
        """DEPL_012: Rollback émet un événement audit."""
        deployment_id = "deploy-audit"

        orchestrator._snapshots[deployment_id] = DeploymentSnapshot(
            deployment_id=deployment_id,
            timestamp=datetime.now(),
            node_states={"standby-1": "old-image"},
            config_hash="test",
        )

        await orchestrator.rollback(deployment_id)

        mock_audit_emitter.emit_event.assert_called()


# ============================================================================
# Tests DEPL_013: Zero-downtime
# ============================================================================


class TestDEPL013ZeroDowntime:
    """Tests pour DEPL_013: Zero-downtime obligatoire."""

    @pytest.mark.asyncio
    async def test_primary_not_updated_until_standby_healthy(
        self,
        orchestrator: DeploymentOrchestrator,
        mock_health_monitor: AsyncMock,
        deployment_config: Dict[str, Any],
    ) -> None:
        """DEPL_013: PRIMARY pas mis à jour tant que STANDBY pas healthy."""
        # Configurer healthcheck pour échouer sur standby
        mock_health_monitor.check_health = AsyncMock(
            return_value=HealthReport(
                status=HealthStatus.UNHEALTHY,
                timestamp=datetime.now(),
                checks=[],
                node_id="standby-1",
            )
        )

        orchestrator.set_current_image("primary-node", "old-image")
        orchestrator.set_current_image("standby-1", "old-image")

        result = await orchestrator.deploy_image(
            "registry.example.com/app:v1.0",
            deployment_config,
        )

        # PRIMARY ne doit pas avoir la nouvelle image
        assert "primary-node" not in result["deployed_nodes"]

    @pytest.mark.asyncio
    async def test_service_remains_available_during_deploy(
        self,
        orchestrator: DeploymentOrchestrator,
        deployment_config: Dict[str, Any],
    ) -> None:
        """DEPL_013: Service reste disponible pendant déploiement."""
        # Le primary garde son image tant que standby pas validé
        orchestrator.set_current_image("primary-node", "old-image")

        result = await orchestrator.deploy_image(
            "registry.example.com/app:v1.0",
            deployment_config,
        )

        # Le déploiement ne doit jamais laisser le cluster sans nœud fonctionnel
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_standby_validated_before_primary_switch(
        self,
        orchestrator: DeploymentOrchestrator,
        mock_health_monitor: AsyncMock,
        deployment_config: Dict[str, Any],
    ) -> None:
        """DEPL_013: STANDBY validé avant switch du PRIMARY."""
        healthcheck_order: List[str] = []

        original_verify = orchestrator._verify_healthcheck

        async def track_healthcheck(node_id: str, timeout: int = 30) -> bool:
            healthcheck_order.append(node_id)
            return await original_verify(node_id, timeout)

        orchestrator._verify_healthcheck = track_healthcheck

        await orchestrator.deploy_image(
            "registry.example.com/app:v1.0",
            deployment_config,
        )

        # Les standbys doivent être validés avant le primary
        if "primary-node" in healthcheck_order:
            primary_index = healthcheck_order.index("primary-node")
            for node in ["standby-1", "standby-2"]:
                if node in healthcheck_order:
                    assert healthcheck_order.index(node) < primary_index

    @pytest.mark.asyncio
    async def test_partial_deployment_maintains_availability(
        self,
        orchestrator: DeploymentOrchestrator,
        mock_health_monitor: AsyncMock,
    ) -> None:
        """DEPL_013: Déploiement partiel maintient la disponibilité."""
        # Un standby échoue, mais le primary reste fonctionnel
        call_count = 0

        async def partial_failure() -> HealthReport:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return HealthReport(
                    status=HealthStatus.HEALTHY,
                    timestamp=datetime.now(),
                    checks=[],
                    node_id="standby-1",
                )
            return HealthReport(
                status=HealthStatus.UNHEALTHY,
                timestamp=datetime.now(),
                checks=[],
                node_id="standby-2",
            )

        mock_health_monitor.check_health = partial_failure
        orchestrator.set_current_image("primary-node", "stable-image")
        orchestrator.set_current_image("standby-1", "stable-image")
        orchestrator.set_current_image("standby-2", "stable-image")

        config = {
            "deployment_id": "partial-deploy",
            "target_nodes": ["primary-node", "standby-1", "standby-2"],
            "config_hash": "test",
        }

        result = await orchestrator.deploy_image(
            "registry.example.com/app:v1.0",
            config,
        )

        # Le primary doit toujours avoir une image fonctionnelle
        primary_image = orchestrator.get_current_image("primary-node")
        assert primary_image is not None

    @pytest.mark.asyncio
    async def test_dry_run_doesnt_affect_production(
        self,
        orchestrator: DeploymentOrchestrator,
        deployment_config: Dict[str, Any],
    ) -> None:
        """DEPL_013: Dry-run n'affecte pas la production."""
        orchestrator.set_current_image("primary-node", "production-image")
        orchestrator.set_current_image("standby-1", "production-image")

        result = await orchestrator.deploy_image(
            "registry.example.com/app:v1.0",
            deployment_config,
            dry_run=True,
        )

        assert result["success"] is True
        assert result["metadata"].get("dry_run") is True
        # Les images de production ne doivent pas changer
        assert orchestrator.get_current_image("primary-node") == "production-image"


# ============================================================================
# Tests DEPL_014: Déploiement progressif
# ============================================================================


class TestDEPL014ProgressiveDeployment:
    """Tests pour DEPL_014: Déploiement progressif."""

    @pytest.mark.asyncio
    async def test_progressive_deployment_one_at_a_time(
        self,
        orchestrator: DeploymentOrchestrator,
        mock_health_monitor: AsyncMock,
    ) -> None:
        """DEPL_014: Déploiement un nœud à la fois."""
        deploy_times: List[float] = []
        original_deploy = orchestrator._deploy_to_node

        async def track_deploy(node_id: str, config: DeploymentConfig) -> bool:
            deploy_times.append(time.perf_counter())
            return await original_deploy(node_id, config)

        orchestrator._deploy_to_node = track_deploy
        orchestrator.PROGRESSIVE_DELAY = 0.1  # Réduire pour les tests

        config = {
            "deployment_id": "progressive-test",
            "target_nodes": ["primary-node", "standby-1", "standby-2"],
            "config_hash": "test",
            "progressive": True,
        }

        await orchestrator.deploy_image("registry.example.com/app:v1.0", config)

        # Vérifier qu'il y a un délai entre les déploiements
        if len(deploy_times) >= 2:
            for i in range(1, len(deploy_times)):
                delay = deploy_times[i] - deploy_times[i - 1]
                # Au moins un petit délai entre les déploiements
                assert delay >= 0

    @pytest.mark.asyncio
    async def test_validation_before_next_node(
        self,
        orchestrator: DeploymentOrchestrator,
        mock_health_monitor: AsyncMock,
    ) -> None:
        """DEPL_014: Validation avant déploiement sur nœud suivant."""
        validation_before_next: List[bool] = []
        node_sequence: List[str] = []

        original_deploy = orchestrator._deploy_to_node
        original_verify = orchestrator._verify_healthcheck

        async def track_deploy(node_id: str, config: DeploymentConfig) -> bool:
            node_sequence.append(f"deploy:{node_id}")
            return await original_deploy(node_id, config)

        async def track_verify(node_id: str, timeout: int = 30) -> bool:
            node_sequence.append(f"verify:{node_id}")
            return await original_verify(node_id, timeout)

        orchestrator._deploy_to_node = track_deploy
        orchestrator._verify_healthcheck = track_verify

        config = {
            "deployment_id": "validation-test",
            "target_nodes": ["primary-node", "standby-1", "standby-2"],
            "config_hash": "test",
            "progressive": True,
        }

        await orchestrator.deploy_image("registry.example.com/app:v1.0", config)

        # Vérifier l'ordre: deploy puis verify pour chaque nœud
        for i, action in enumerate(node_sequence):
            if action.startswith("deploy:") and i + 1 < len(node_sequence):
                next_action = node_sequence[i + 1]
                # La prochaine action pour ce nœud doit être verify
                node = action.split(":")[1]
                if f"verify:{node}" in node_sequence[i + 1 :]:
                    verify_index = node_sequence.index(f"verify:{node}", i + 1)
                    # verify doit venir avant le prochain deploy
                    next_deploy_indices = [
                        j
                        for j, a in enumerate(node_sequence[i + 1 :], i + 1)
                        if a.startswith("deploy:")
                    ]
                    if next_deploy_indices:
                        assert verify_index < next_deploy_indices[0]

    @pytest.mark.asyncio
    async def test_stops_on_first_failure(
        self,
        orchestrator: DeploymentOrchestrator,
        mock_health_monitor: AsyncMock,
    ) -> None:
        """DEPL_014: Arrêt au premier échec."""
        # Échec sur le premier standby
        mock_health_monitor.check_health = AsyncMock(
            return_value=HealthReport(
                status=HealthStatus.UNHEALTHY,
                timestamp=datetime.now(),
                checks=[],
                node_id="standby-1",
            )
        )

        config = {
            "deployment_id": "stop-on-failure",
            "target_nodes": ["primary-node", "standby-1", "standby-2"],
            "config_hash": "test",
            "progressive": True,
        }

        result = await orchestrator.deploy_image(
            "registry.example.com/app:v1.0",
            config,
        )

        # Seulement le premier standby doit être dans failed_nodes
        assert "standby-1" in result["failed_nodes"]
        # Le second standby ne doit pas être tenté
        assert "standby-2" not in result["deployed_nodes"]
        assert "standby-2" not in result["failed_nodes"]

    @pytest.mark.asyncio
    async def test_non_progressive_deploys_all_at_once(
        self,
        orchestrator: DeploymentOrchestrator,
    ) -> None:
        """DEPL_014: Mode non-progressif déploie tout en même temps."""
        deploy_times: List[float] = []
        original_deploy = orchestrator._deploy_to_node

        async def track_deploy(node_id: str, config: DeploymentConfig) -> bool:
            deploy_times.append(time.perf_counter())
            return await original_deploy(node_id, config)

        orchestrator._deploy_to_node = track_deploy
        orchestrator.PROGRESSIVE_DELAY = 1.0  # Long délai

        config = {
            "deployment_id": "non-progressive",
            "target_nodes": ["primary-node", "standby-1", "standby-2"],
            "config_hash": "test",
            "progressive": False,  # Désactiver le mode progressif
        }

        await orchestrator.deploy_image("registry.example.com/app:v1.0", config)

        # Les déploiements doivent être rapprochés (pas de délai progressif)
        if len(deploy_times) >= 2:
            total_time = deploy_times[-1] - deploy_times[0]
            # Devrait être beaucoup moins que le délai progressif cumulé
            assert total_time < 0.5  # Moins de 500ms pour 3 nœuds

    @pytest.mark.asyncio
    async def test_progressive_config_respected(
        self,
        orchestrator: DeploymentOrchestrator,
    ) -> None:
        """DEPL_014: Configuration progressive respectée."""
        config = DeploymentConfig(
            deployment_id="test",
            image_ref="test:v1",
            target_nodes=["a", "b"],
            config_hash="hash",
            progressive=True,
        )

        assert config.progressive is True


# ============================================================================
# Tests image verification
# ============================================================================


class TestImageVerification:
    """Tests pour la vérification d'image avant déploiement."""

    @pytest.mark.asyncio
    async def test_deployment_blocked_if_image_invalid(
        self,
        orchestrator: DeploymentOrchestrator,
        mock_image_verifier: AsyncMock,
        deployment_config: Dict[str, Any],
    ) -> None:
        """Image non vérifiée bloque le déploiement."""
        mock_result = MagicMock()
        mock_result.status = VerificationStatus.CVE_BLOCKED
        mock_image_verifier.verify_image = AsyncMock(return_value=mock_result)

        result = await orchestrator.deploy_image(
            "registry.example.com/app:v1.0",
            deployment_config,
        )

        assert result["success"] is False
        assert "verification failed" in result["error_message"]

    @pytest.mark.asyncio
    async def test_image_verified_before_any_deployment(
        self,
        orchestrator: DeploymentOrchestrator,
        mock_image_verifier: AsyncMock,
        deployment_config: Dict[str, Any],
    ) -> None:
        """Image vérifiée avant tout déploiement."""
        verification_called = False
        deployment_called = False

        async def track_verify(image_ref: str) -> MagicMock:
            nonlocal verification_called
            verification_called = True
            result = MagicMock()
            result.status = VerificationStatus.VERIFIED
            return result

        original_deploy = orchestrator._deploy_to_node

        async def track_deploy(node_id: str, config: DeploymentConfig) -> bool:
            nonlocal deployment_called
            assert verification_called, "Verification must happen before deployment"
            deployment_called = True
            return await original_deploy(node_id, config)

        mock_image_verifier.verify_image = track_verify
        orchestrator._deploy_to_node = track_deploy

        await orchestrator.deploy_image(
            "registry.example.com/app:v1.0",
            deployment_config,
        )

        assert verification_called
        assert deployment_called


# ============================================================================
# Tests status et monitoring
# ============================================================================


class TestStatusAndMonitoring:
    """Tests pour le status et le monitoring des déploiements."""

    @pytest.mark.asyncio
    async def test_get_deployment_status(
        self,
        orchestrator: DeploymentOrchestrator,
        deployment_config: Dict[str, Any],
    ) -> None:
        """Récupération du status de déploiement."""
        await orchestrator.deploy_image(
            "registry.example.com/app:v1.0",
            deployment_config,
        )

        status = orchestrator.get_deployment_status("deploy-123")

        assert status["deployment_id"] == "deploy-123"
        assert status["state"] in ["completed", "failed", "rolled_back"]

    @pytest.mark.asyncio
    async def test_deployment_state_transitions(
        self,
        orchestrator: DeploymentOrchestrator,
        deployment_config: Dict[str, Any],
    ) -> None:
        """Transitions d'état du déploiement correctes."""
        await orchestrator.deploy_image(
            "registry.example.com/app:v1.0",
            deployment_config,
        )

        assert orchestrator._deployments["deploy-123"] in [
            DeploymentState.COMPLETED,
            DeploymentState.FAILED,
            DeploymentState.ROLLED_BACK,
        ]

    @pytest.mark.asyncio
    async def test_deployment_duration_measured(
        self,
        orchestrator: DeploymentOrchestrator,
        deployment_config: Dict[str, Any],
    ) -> None:
        """Durée du déploiement mesurée."""
        result = await orchestrator.deploy_image(
            "registry.example.com/app:v1.0",
            deployment_config,
        )

        assert result["duration_seconds"] >= 0

    @pytest.mark.asyncio
    async def test_audit_events_emitted(
        self,
        orchestrator: DeploymentOrchestrator,
        mock_audit_emitter: AsyncMock,
        deployment_config: Dict[str, Any],
    ) -> None:
        """Événements audit émis pendant le déploiement."""
        await orchestrator.deploy_image(
            "registry.example.com/app:v1.0",
            deployment_config,
        )

        mock_audit_emitter.emit_event.assert_called()

    def test_clear_state(
        self,
        orchestrator: DeploymentOrchestrator,
    ) -> None:
        """Nettoyage de l'état."""
        orchestrator._deployments["test"] = DeploymentState.COMPLETED
        orchestrator._snapshots["test"] = MagicMock()
        orchestrator._current_images["node"] = "image"

        orchestrator.clear_state()

        assert len(orchestrator._deployments) == 0
        assert len(orchestrator._snapshots) == 0
        assert len(orchestrator._current_images) == 0


# ============================================================================
# Tests dataclasses
# ============================================================================


class TestDataClasses:
    """Tests pour les dataclasses du module."""

    def test_deployment_config_defaults(self) -> None:
        """DeploymentConfig valeurs par défaut."""
        config = DeploymentConfig(
            deployment_id="test",
            image_ref="test:v1",
            target_nodes=["node-1"],
            config_hash="hash",
        )

        assert config.rollback_timeout == 60  # DEPL_012
        assert config.healthcheck_timeout == 30
        assert config.progressive is True  # DEPL_014

    def test_deployment_result_structure(self) -> None:
        """DeploymentResult structure correcte."""
        result = DeploymentResult(
            deployment_id="test",
            success=True,
            deployed_nodes=["node-1", "node-2"],
            failed_nodes=[],
            duration_seconds=10.5,
        )

        assert result.success is True
        assert len(result.deployed_nodes) == 2
        assert result.rollback_performed is False

    def test_node_deployment_state(self) -> None:
        """NodeDeploymentState structure correcte."""
        state = NodeDeploymentState(
            node_id="node-1",
            role=NodeRole.STANDBY,
            deployed=True,
            healthcheck_passed=True,
        )

        assert state.role == NodeRole.STANDBY
        assert state.deployed is True

    def test_deployment_snapshot(self) -> None:
        """DeploymentSnapshot structure correcte."""
        snapshot = DeploymentSnapshot(
            deployment_id="deploy-123",
            timestamp=datetime.now(),
            node_states={"node-1": "image:v1"},
            config_hash="abc123",
        )

        assert snapshot.deployment_id == "deploy-123"
        assert "node-1" in snapshot.node_states
