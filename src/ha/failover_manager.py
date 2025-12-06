"""
LOT 6: Failover Manager Implementation

Gestion du failover cluster Edge avec détection de pannes
et promotion automatique.

Invariants:
    RUN_050: Cluster minimum 2 noeuds
    RUN_051: Failover < 10 secondes
        - Detection timeout: 3s max
        - Promotion timeout: 5s max
        - Total: 8s < 10s
"""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from src.audit.interfaces import IAuditEmitter, AuditEventType
from src.ha.interfaces import (
    IFailoverManager,
    IHealthMonitor,
    ClusterStatus,
    HealthStatus,
)


class FailoverError(Exception):
    """Erreur lors du failover."""

    pass


@dataclass
class NodeInfo:
    """Information sur un noeud du cluster."""

    node_id: str
    is_primary: bool
    last_heartbeat: datetime
    status: HealthStatus = HealthStatus.HEALTHY


class FailoverManager(IFailoverManager):
    """
    Gestion failover cluster Edge.

    Invariants:
        RUN_050: Cluster minimum 2 noeuds
        RUN_051: Failover < 10 secondes
    """

    # RUN_050: Minimum 2 noeuds
    MIN_NODES: int = 2

    # RUN_051: Timeouts en secondes
    DETECTION_TIMEOUT: float = 3.0
    PROMOTION_TIMEOUT: float = 5.0
    MAX_FAILOVER_TIME: float = 10.0

    # Heartbeat timeout pour considérer un noeud unhealthy
    HEARTBEAT_TIMEOUT_SECONDS: float = 5.0

    def __init__(
        self,
        node_id: str,
        health_monitor: IHealthMonitor,
        audit_emitter: IAuditEmitter,
    ) -> None:
        """
        Initialise le gestionnaire de failover.

        Args:
            node_id: Identifiant unique du noeud courant.
            health_monitor: Moniteur de santé.
            audit_emitter: Émetteur d'événements d'audit.
        """
        self._node_id = node_id
        self._health = health_monitor
        self._audit = audit_emitter
        self._nodes: Dict[str, NodeInfo] = {}
        self._primary_node: Optional[str] = None
        self._is_primary = False
        self._failover_in_progress = False

    def register_node(self, node_id: str, is_primary: bool = False) -> None:
        """
        Enregistre un noeud dans le cluster.

        Args:
            node_id: Identifiant du noeud.
            is_primary: True si ce noeud est le primary.
        """
        self._nodes[node_id] = NodeInfo(
            node_id=node_id,
            is_primary=is_primary,
            last_heartbeat=datetime.now(),
            status=HealthStatus.HEALTHY,
        )
        if is_primary:
            self._primary_node = node_id
            if node_id == self._node_id:
                self._is_primary = True

    def unregister_node(self, node_id: str) -> None:
        """
        Retire un noeud du cluster.

        Args:
            node_id: Identifiant du noeud à retirer.
        """
        if node_id in self._nodes:
            del self._nodes[node_id]
            if self._primary_node == node_id:
                self._primary_node = None

    def update_node_heartbeat(self, node_id: str) -> None:
        """
        Met à jour le heartbeat d'un noeud.

        Args:
            node_id: Identifiant du noeud.
        """
        if node_id in self._nodes:
            self._nodes[node_id].last_heartbeat = datetime.now()
            self._nodes[node_id].status = HealthStatus.HEALTHY

    def update_node_status(self, node_id: str, status: HealthStatus) -> None:
        """
        Met à jour le status d'un noeud.

        Args:
            node_id: Identifiant du noeud.
            status: Nouveau status.
        """
        if node_id in self._nodes:
            self._nodes[node_id].status = status

    def validate_cluster_config(self) -> bool:
        """
        Vérifie la configuration du cluster (RUN_050).

        Returns:
            True si le cluster a >= 2 noeuds.
        """
        return len(self._nodes) >= self.MIN_NODES

    def _get_healthy_standby_nodes(self) -> List[str]:
        """
        Récupère les noeuds standby en bonne santé.

        Returns:
            Liste des node_ids standby healthy.
        """
        now = datetime.now()
        healthy_standbys = []

        for node_id, info in self._nodes.items():
            if info.is_primary:
                continue

            # Vérifier heartbeat récent
            heartbeat_age = (now - info.last_heartbeat).total_seconds()
            if heartbeat_age > self.HEARTBEAT_TIMEOUT_SECONDS:
                continue

            if info.status == HealthStatus.HEALTHY:
                healthy_standbys.append(node_id)

        return healthy_standbys

    async def _detect_primary_failure(self) -> bool:
        """
        Détecte si le primary est en échec (timeout DETECTION_TIMEOUT).

        Returns:
            True si le primary est en échec.
        """
        if not self._primary_node:
            return True

        primary_info = self._nodes.get(self._primary_node)
        if not primary_info:
            return True

        # Vérifier le heartbeat du primary
        now = datetime.now()
        heartbeat_age = (now - primary_info.last_heartbeat).total_seconds()

        return heartbeat_age > self.HEARTBEAT_TIMEOUT_SECONDS or primary_info.status == HealthStatus.UNHEALTHY

    async def trigger_failover(self, reason: str) -> None:
        """
        Déclenche un failover vers un noeud secondaire.

        RUN_051: Le failover complet doit prendre < 10 secondes.

        Args:
            reason: Raison du failover pour audit.

        Raises:
            FailoverError: Si aucun noeud disponible ou timeout dépassé.
        """
        if self._failover_in_progress:
            raise FailoverError("Failover already in progress")

        self._failover_in_progress = True
        start_time = time.perf_counter()

        try:
            # Phase 1: Détection (max DETECTION_TIMEOUT secondes)
            try:
                is_primary_failed = await asyncio.wait_for(
                    self._detect_primary_failure(),
                    timeout=self.DETECTION_TIMEOUT,
                )
            except asyncio.TimeoutError:
                raise FailoverError(f"Detection timeout exceeded ({self.DETECTION_TIMEOUT}s)")

            if not is_primary_failed:
                raise FailoverError("Primary is still healthy, no failover needed")

            # Trouver un standby healthy
            healthy_standbys = self._get_healthy_standby_nodes()
            if not healthy_standbys:
                raise FailoverError("No healthy standby node available for failover")

            # Sélectionner le premier standby disponible
            new_primary = healthy_standbys[0]

            # Phase 2: Promotion (max PROMOTION_TIMEOUT secondes)
            try:
                await asyncio.wait_for(
                    self.promote_to_primary(new_primary),
                    timeout=self.PROMOTION_TIMEOUT,
                )
            except asyncio.TimeoutError:
                raise FailoverError(f"Promotion timeout exceeded ({self.PROMOTION_TIMEOUT}s)")

            # Vérifier temps total (RUN_051)
            elapsed = time.perf_counter() - start_time
            if elapsed > self.MAX_FAILOVER_TIME:
                raise FailoverError(f"Failover took {elapsed:.2f}s, exceeds max {self.MAX_FAILOVER_TIME}s (RUN_051)")

            # Émettre événement audit
            await self._audit.emit_event(
                event_type=AuditEventType.SYSTEM_CONFIG_CHANGE,
                user_id="system",
                tenant_id="system",
                action="failover_completed",
                metadata={
                    "reason": reason,
                    "old_primary": self._primary_node,
                    "new_primary": new_primary,
                    "elapsed_seconds": elapsed,
                },
            )

        finally:
            self._failover_in_progress = False

    async def promote_to_primary(self, node_id: str) -> None:
        """
        Promeut un noeud comme primaire.

        Args:
            node_id: Identifiant du noeud à promouvoir.

        Raises:
            FailoverError: Si le noeud n'existe pas ou n'est pas healthy.
        """
        if node_id not in self._nodes:
            raise FailoverError(f"Node {node_id} not found in cluster")

        node_info = self._nodes[node_id]
        if node_info.status != HealthStatus.HEALTHY:
            raise FailoverError(f"Node {node_id} is not healthy")

        # Dégrader l'ancien primary
        if self._primary_node and self._primary_node in self._nodes:
            self._nodes[self._primary_node].is_primary = False

        # Promouvoir le nouveau primary
        self._nodes[node_id].is_primary = True
        self._primary_node = node_id
        self._is_primary = node_id == self._node_id

        # Émettre événement audit
        await self._audit.emit_event(
            event_type=AuditEventType.SYSTEM_CONFIG_CHANGE,
            user_id="system",
            tenant_id="system",
            action="node_promoted_to_primary",
            metadata={
                "node_id": node_id,
                "timestamp": datetime.now().isoformat(),
            },
        )

    def get_current_primary(self) -> str:
        """
        Récupère l'identifiant du noeud primaire actuel.

        Returns:
            Node ID du primaire, ou chaîne vide si aucun.
        """
        return self._primary_node or ""

    def get_cluster_status(self) -> ClusterStatus:
        """
        Récupère le status complet du cluster.

        RUN_050: Vérifie min 2 noeuds.

        Returns:
            Status du cluster avec tous les noeuds.
        """
        now = datetime.now()
        healthy_nodes = []
        unhealthy_nodes = []

        for node_id, info in self._nodes.items():
            # Vérifier heartbeat récent
            heartbeat_age = (now - info.last_heartbeat).total_seconds()
            is_heartbeat_ok = heartbeat_age <= self.HEARTBEAT_TIMEOUT_SECONDS

            if info.status == HealthStatus.HEALTHY and is_heartbeat_ok:
                healthy_nodes.append(node_id)
            else:
                unhealthy_nodes.append(node_id)

        return ClusterStatus(
            node_count=len(self._nodes),
            primary_node=self._primary_node or "",
            healthy_nodes=healthy_nodes,
            unhealthy_nodes=unhealthy_nodes,
        )

    def is_failover_in_progress(self) -> bool:
        """
        Vérifie si un failover est en cours.

        Returns:
            True si failover en cours.
        """
        return self._failover_in_progress

    @property
    def node_id(self) -> str:
        """Retourne l'ID du noeud courant."""
        return self._node_id

    @property
    def is_primary(self) -> bool:
        """Retourne True si ce noeud est le primary."""
        return self._is_primary
