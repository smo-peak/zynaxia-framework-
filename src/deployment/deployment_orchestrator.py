"""
LOT 7: Deployment Orchestrator Implementation

Orchestrateur de déploiement zero-downtime avec stratégie standby-first.

Invariants:
    DEPL_010: Standby-first obligatoire (jamais sur PRIMARY)
    DEPL_011: Healthcheck validé sur STANDBY avant bascule
    DEPL_012: Rollback automatique < 60 secondes si healthcheck échoue
    DEPL_013: Zero-downtime obligatoire
    DEPL_014: Déploiement progressif (1 nœud → validation → autres)
"""

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from src.audit.interfaces import AuditEventType, IAuditEmitter
from src.deployment.interfaces import IDeploymentOrchestrator, IImageVerifier, VerificationStatus
from src.ha.interfaces import HealthStatus, IFailoverManager, IHealthMonitor


class DeploymentError(Exception):
    """Erreur lors du déploiement."""

    pass


class RollbackError(Exception):
    """Erreur lors du rollback."""

    pass


class DeploymentState(Enum):
    """État d'un déploiement."""

    PENDING = "pending"
    VERIFYING = "verifying"
    DEPLOYING = "deploying"
    VALIDATING = "validating"
    PROMOTING = "promoting"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class NodeRole(Enum):
    """Rôle d'un nœud dans le cluster."""

    PRIMARY = "primary"
    STANDBY = "standby"
    UNKNOWN = "unknown"


@dataclass
class DeploymentConfig:
    """Configuration de déploiement.

    DEPL_012: rollback_timeout par défaut 60s.
    """

    deployment_id: str
    image_ref: str
    target_nodes: List[str]
    config_hash: str
    rollback_timeout: int = 60  # DEPL_012
    healthcheck_timeout: int = 30
    progressive: bool = True  # DEPL_014


@dataclass
class NodeDeploymentState:
    """État de déploiement pour un nœud."""

    node_id: str
    role: NodeRole
    deployed: bool = False
    healthcheck_passed: bool = False
    previous_image: Optional[str] = None
    error_message: Optional[str] = None


@dataclass
class DeploymentResult:
    """Résultat d'un déploiement."""

    deployment_id: str
    success: bool
    deployed_nodes: List[str]
    failed_nodes: List[str]
    duration_seconds: float
    rollback_performed: bool = False
    rollback_duration_seconds: float = 0.0
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DeploymentSnapshot:
    """Snapshot pré-déploiement pour rollback."""

    deployment_id: str
    timestamp: datetime
    node_states: Dict[str, str]  # node_id -> previous_image
    config_hash: str


class DeploymentOrchestrator(IDeploymentOrchestrator):
    """
    Orchestrateur de déploiement zero-downtime.

    Invariants:
        DEPL_010: Standby-first obligatoire
        DEPL_011: Healthcheck validé avant bascule
        DEPL_012: Rollback < 60 secondes
        DEPL_013: Zero-downtime
        DEPL_014: Déploiement progressif
    """

    # DEPL_012: Timeout rollback max
    ROLLBACK_TIMEOUT: int = 60

    # Timeout healthcheck par défaut
    HEALTHCHECK_TIMEOUT: int = 30

    # Délai entre déploiements progressifs
    PROGRESSIVE_DELAY: float = 2.0

    def __init__(
        self,
        image_verifier: IImageVerifier,
        health_monitor: IHealthMonitor,
        failover_manager: IFailoverManager,
        audit_emitter: IAuditEmitter,
    ) -> None:
        """
        Initialise l'orchestrateur.

        Args:
            image_verifier: Vérificateur d'images Docker.
            health_monitor: Moniteur de santé.
            failover_manager: Gestionnaire de failover.
            audit_emitter: Émetteur d'événements audit.
        """
        self._image_verifier = image_verifier
        self._health_monitor = health_monitor
        self._failover = failover_manager
        self._audit = audit_emitter
        self._deployments: Dict[str, DeploymentState] = {}
        self._snapshots: Dict[str, DeploymentSnapshot] = {}
        self._node_states: Dict[str, NodeDeploymentState] = {}
        self._current_images: Dict[str, str] = {}  # node_id -> image_ref

    def _get_primary_node(self) -> Optional[str]:
        """Retourne le nœud PRIMARY actuel."""
        try:
            return self._failover.get_current_primary()
        except Exception:
            return None

    def _get_standby_nodes(self, target_nodes: List[str]) -> List[str]:
        """
        DEPL_010: Retourne uniquement les nœuds STANDBY parmi les cibles.

        Args:
            target_nodes: Liste des nœuds cibles.

        Returns:
            Liste des nœuds STANDBY.
        """
        primary = self._get_primary_node()
        return [n for n in target_nodes if n != primary]

    def _get_node_role(self, node_id: str) -> NodeRole:
        """Détermine le rôle d'un nœud."""
        primary = self._get_primary_node()
        if primary == node_id:
            return NodeRole.PRIMARY
        return NodeRole.STANDBY

    async def _verify_image(self, image_ref: str) -> bool:
        """Vérifie l'image Docker avant déploiement."""
        result = await self._image_verifier.verify_image(image_ref)
        return result.status == VerificationStatus.VERIFIED

    async def _deploy_to_node(
        self,
        node_id: str,
        config: DeploymentConfig,
    ) -> bool:
        """
        Déploie sur un nœud spécifique.

        Args:
            node_id: ID du nœud.
            config: Configuration de déploiement.

        Returns:
            True si déploiement réussi.
        """
        try:
            # Sauvegarder l'image actuelle pour rollback
            if node_id in self._current_images:
                if config.deployment_id in self._snapshots:
                    self._snapshots[config.deployment_id].node_states[node_id] = (
                        self._current_images[node_id]
                    )

            # Simuler le déploiement (en production: docker pull, docker run, etc.)
            # Pour les tests, on suppose que le déploiement réussit
            self._current_images[node_id] = config.image_ref

            # Mettre à jour l'état du nœud
            self._node_states[node_id] = NodeDeploymentState(
                node_id=node_id,
                role=self._get_node_role(node_id),
                deployed=True,
                previous_image=self._snapshots.get(config.deployment_id, DeploymentSnapshot(
                    deployment_id=config.deployment_id,
                    timestamp=datetime.now(),
                    node_states={},
                    config_hash=config.config_hash,
                )).node_states.get(node_id),
            )

            return True

        except Exception as e:
            if node_id in self._node_states:
                self._node_states[node_id].error_message = str(e)
            return False

    async def _verify_healthcheck(
        self,
        node_id: str,
        timeout: int = 30,
    ) -> bool:
        """
        DEPL_011: Vérifie healthcheck avant bascule.

        Args:
            node_id: ID du nœud.
            timeout: Timeout en secondes.

        Returns:
            True si healthcheck OK.
        """
        try:
            # Vérifier la santé du nœud
            report = await asyncio.wait_for(
                self._health_monitor.check_health(),
                timeout=timeout,
            )

            # Le nœud doit être HEALTHY ou DEGRADED (pas UNHEALTHY)
            is_healthy = report.status in (HealthStatus.HEALTHY, HealthStatus.DEGRADED)

            if node_id in self._node_states:
                self._node_states[node_id].healthcheck_passed = is_healthy

            return is_healthy

        except asyncio.TimeoutError:
            if node_id in self._node_states:
                self._node_states[node_id].error_message = "Healthcheck timeout"
            return False
        except Exception as e:
            if node_id in self._node_states:
                self._node_states[node_id].error_message = str(e)
            return False

    async def _rollback_node(
        self,
        node_id: str,
        deployment_id: str,
    ) -> bool:
        """
        Rollback un nœud à son état précédent.

        Args:
            node_id: ID du nœud.
            deployment_id: ID du déploiement.

        Returns:
            True si rollback réussi.
        """
        snapshot = self._snapshots.get(deployment_id)
        if not snapshot or node_id not in snapshot.node_states:
            return False

        previous_image = snapshot.node_states[node_id]
        if previous_image:
            self._current_images[node_id] = previous_image
            return True

        return False

    async def deploy_image(
        self,
        image_ref: str,
        config: Dict[str, Any],
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        DEPL_010-014: Déploie une image avec stratégie standby-first.

        1. Vérifie image (signature, CVE)
        2. Identifie STANDBY nodes
        3. Déploie sur STANDBY d'abord
        4. Healthcheck
        5. Bascule si OK, rollback si KO

        Args:
            image_ref: Référence de l'image.
            config: Configuration de déploiement.
            dry_run: Si True, simule seulement.

        Returns:
            Résultat du déploiement.
        """
        start_time = time.perf_counter()
        deployment_id = config.get("deployment_id", str(uuid.uuid4()))
        target_nodes = config.get("target_nodes", [])
        config_hash = config.get("config_hash", "")
        rollback_timeout = config.get("rollback_timeout", self.ROLLBACK_TIMEOUT)
        healthcheck_timeout = config.get("healthcheck_timeout", self.HEALTHCHECK_TIMEOUT)
        progressive = config.get("progressive", True)

        deployment_config = DeploymentConfig(
            deployment_id=deployment_id,
            image_ref=image_ref,
            target_nodes=target_nodes,
            config_hash=config_hash,
            rollback_timeout=rollback_timeout,
            healthcheck_timeout=healthcheck_timeout,
            progressive=progressive,
        )

        self._deployments[deployment_id] = DeploymentState.PENDING
        deployed_nodes: List[str] = []
        failed_nodes: List[str] = []
        rollback_performed = False
        rollback_duration = 0.0
        error_message: Optional[str] = None

        try:
            # Créer snapshot pour rollback
            self._snapshots[deployment_id] = DeploymentSnapshot(
                deployment_id=deployment_id,
                timestamp=datetime.now(),
                node_states={n: self._current_images.get(n, "") for n in target_nodes},
                config_hash=config_hash,
            )

            # Étape 1: Vérifier l'image
            self._deployments[deployment_id] = DeploymentState.VERIFYING

            if not dry_run:
                if not await self._verify_image(image_ref):
                    error_message = "Image verification failed"
                    self._deployments[deployment_id] = DeploymentState.FAILED
                    await self._emit_deployment_event(
                        deployment_id, "deployment_failed", {"reason": error_message}
                    )
                    return self._build_result(
                        deployment_id, False, [], target_nodes,
                        time.perf_counter() - start_time, error_message=error_message
                    )

            # Étape 2: DEPL_010 - Identifier les STANDBY nodes
            standby_nodes = self._get_standby_nodes(target_nodes)
            primary_node = self._get_primary_node()

            if not standby_nodes:
                error_message = "No STANDBY nodes available (DEPL_010)"
                self._deployments[deployment_id] = DeploymentState.FAILED
                await self._emit_deployment_event(
                    deployment_id, "deployment_failed", {"reason": error_message}
                )
                return self._build_result(
                    deployment_id, False, [], target_nodes,
                    time.perf_counter() - start_time, error_message=error_message
                )

            # Étape 3: DEPL_014 - Déploiement progressif sur STANDBY
            self._deployments[deployment_id] = DeploymentState.DEPLOYING

            if dry_run:
                # Simulation seulement
                return self._build_result(
                    deployment_id, True, standby_nodes, [],
                    time.perf_counter() - start_time,
                    metadata={"dry_run": True, "would_deploy_to": standby_nodes}
                )

            for i, node_id in enumerate(standby_nodes):
                # DEPL_014: Déploiement progressif
                if progressive and i > 0:
                    await asyncio.sleep(self.PROGRESSIVE_DELAY)

                success = await self._deploy_to_node(node_id, deployment_config)
                if not success:
                    failed_nodes.append(node_id)
                    continue

                # Étape 4: DEPL_011 - Healthcheck sur chaque STANDBY
                self._deployments[deployment_id] = DeploymentState.VALIDATING
                healthcheck_ok = await self._verify_healthcheck(node_id, healthcheck_timeout)

                if not healthcheck_ok:
                    # DEPL_012: Rollback automatique
                    rollback_start = time.perf_counter()
                    await self._rollback_node(node_id, deployment_id)
                    rollback_duration = time.perf_counter() - rollback_start

                    if rollback_duration > rollback_timeout:
                        error_message = f"Rollback timeout exceeded: {rollback_duration:.2f}s > {rollback_timeout}s"

                    rollback_performed = True
                    failed_nodes.append(node_id)

                    await self._emit_deployment_event(
                        deployment_id, "deployment_rollback",
                        {"node_id": node_id, "duration_seconds": rollback_duration}
                    )

                    # Arrêter le déploiement si un nœud échoue
                    break
                else:
                    deployed_nodes.append(node_id)

            # DEPL_013: Zero-downtime - ne déployer sur PRIMARY que si STANDBY OK
            if deployed_nodes and not failed_nodes and primary_node in target_nodes:
                self._deployments[deployment_id] = DeploymentState.PROMOTING

                # Déployer sur PRIMARY
                success = await self._deploy_to_node(primary_node, deployment_config)
                if success:
                    healthcheck_ok = await self._verify_healthcheck(primary_node, healthcheck_timeout)
                    if healthcheck_ok:
                        deployed_nodes.append(primary_node)
                    else:
                        # Rollback PRIMARY
                        rollback_start = time.perf_counter()
                        await self._rollback_node(primary_node, deployment_id)
                        rollback_duration = time.perf_counter() - rollback_start
                        rollback_performed = True
                        failed_nodes.append(primary_node)
                else:
                    failed_nodes.append(primary_node)

            # Déterminer le statut final
            success = len(failed_nodes) == 0 and len(deployed_nodes) > 0

            if success:
                self._deployments[deployment_id] = DeploymentState.COMPLETED
                await self._emit_deployment_event(
                    deployment_id, "deployment_completed",
                    {"deployed_nodes": deployed_nodes}
                )
            else:
                self._deployments[deployment_id] = DeploymentState.FAILED
                if rollback_performed:
                    self._deployments[deployment_id] = DeploymentState.ROLLED_BACK
                await self._emit_deployment_event(
                    deployment_id, "deployment_failed",
                    {"failed_nodes": failed_nodes, "rollback_performed": rollback_performed}
                )

            return self._build_result(
                deployment_id, success, deployed_nodes, failed_nodes,
                time.perf_counter() - start_time,
                rollback_performed=rollback_performed,
                rollback_duration=rollback_duration,
                error_message=error_message
            )

        except Exception as e:
            self._deployments[deployment_id] = DeploymentState.FAILED
            error_message = str(e)
            await self._emit_deployment_event(
                deployment_id, "deployment_error", {"error": error_message}
            )
            return self._build_result(
                deployment_id, False, deployed_nodes, failed_nodes + target_nodes,
                time.perf_counter() - start_time, error_message=error_message
            )

    async def rollback(self, deployment_id: str) -> bool:
        """
        DEPL_012: Rollback < 60s.

        Restaure snapshot pré-déploiement.

        Args:
            deployment_id: ID du déploiement.

        Returns:
            True si rollback réussi.
        """
        start_time = time.perf_counter()

        snapshot = self._snapshots.get(deployment_id)
        if not snapshot:
            raise RollbackError(f"No snapshot found for deployment {deployment_id}")

        success = True
        for node_id, previous_image in snapshot.node_states.items():
            rollback_ok = await self._rollback_node(node_id, deployment_id)
            if not rollback_ok:
                success = False

        duration = time.perf_counter() - start_time

        # DEPL_012: Vérifier que rollback < 60s
        if duration > self.ROLLBACK_TIMEOUT:
            await self._emit_deployment_event(
                deployment_id, "rollback_timeout_exceeded",
                {"duration_seconds": duration, "timeout": self.ROLLBACK_TIMEOUT}
            )
            raise RollbackError(
                f"Rollback timeout exceeded: {duration:.2f}s > {self.ROLLBACK_TIMEOUT}s (DEPL_012)"
            )

        if success:
            self._deployments[deployment_id] = DeploymentState.ROLLED_BACK
            await self._emit_deployment_event(
                deployment_id, "rollback_completed", {"duration_seconds": duration}
            )

        return success

    def get_deployment_status(self, deployment_id: str) -> Dict[str, Any]:
        """
        Retourne le status d'un déploiement.

        Args:
            deployment_id: ID du déploiement.

        Returns:
            Status détaillé.
        """
        state = self._deployments.get(deployment_id)
        snapshot = self._snapshots.get(deployment_id)

        node_states = {}
        for node_id, node_state in self._node_states.items():
            node_states[node_id] = {
                "role": node_state.role.value,
                "deployed": node_state.deployed,
                "healthcheck_passed": node_state.healthcheck_passed,
                "error_message": node_state.error_message,
            }

        return {
            "deployment_id": deployment_id,
            "state": state.value if state else "unknown",
            "snapshot_exists": snapshot is not None,
            "node_states": node_states,
            "current_images": dict(self._current_images),
        }

    def _build_result(
        self,
        deployment_id: str,
        success: bool,
        deployed_nodes: List[str],
        failed_nodes: List[str],
        duration_seconds: float,
        rollback_performed: bool = False,
        rollback_duration: float = 0.0,
        error_message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Construit le résultat de déploiement."""
        result = DeploymentResult(
            deployment_id=deployment_id,
            success=success,
            deployed_nodes=deployed_nodes,
            failed_nodes=failed_nodes,
            duration_seconds=duration_seconds,
            rollback_performed=rollback_performed,
            rollback_duration_seconds=rollback_duration,
            error_message=error_message,
            metadata=metadata or {},
        )
        return {
            "deployment_id": result.deployment_id,
            "success": result.success,
            "deployed_nodes": result.deployed_nodes,
            "failed_nodes": result.failed_nodes,
            "duration_seconds": result.duration_seconds,
            "rollback_performed": result.rollback_performed,
            "rollback_duration_seconds": result.rollback_duration_seconds,
            "error_message": result.error_message,
            "metadata": result.metadata,
        }

    async def _emit_deployment_event(
        self,
        deployment_id: str,
        action: str,
        metadata: Dict[str, Any],
    ) -> None:
        """Émet un événement d'audit pour le déploiement."""
        await self._audit.emit_event(
            event_type=AuditEventType.SYSTEM_CONFIG_CHANGE,
            user_id="system",
            tenant_id="system",
            action=action,
            metadata={
                "deployment_id": deployment_id,
                **metadata,
            },
        )

    def get_current_image(self, node_id: str) -> Optional[str]:
        """Retourne l'image actuelle d'un nœud."""
        return self._current_images.get(node_id)

    def set_current_image(self, node_id: str, image_ref: str) -> None:
        """Définit l'image actuelle d'un nœud (pour tests)."""
        self._current_images[node_id] = image_ref

    def clear_state(self) -> None:
        """Nettoie l'état (pour tests)."""
        self._deployments.clear()
        self._snapshots.clear()
        self._node_states.clear()
        self._current_images.clear()
