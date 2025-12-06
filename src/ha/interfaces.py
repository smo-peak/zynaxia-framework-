"""
LOT 6: Interfaces Haute Disponibilité

Définit les contrats pour le système HA avec monitoring de santé,
gestion de cluster, mode dégradé et synchronisation cloud.

Invariants:
    HEALTH_001-008: Health checks et endpoints
    RUN_050-053: Cluster et failover
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable, Awaitable
from enum import Enum


class HealthStatus(Enum):
    """
    Status de santé d'un composant ou du système.

    Invariant HEALTH_006: Status possibles.
    """

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class HealthCheck:
    """
    Résultat d'un check de santé individuel.

    Invariant HEALTH_005: Checks incluent database, vault, keycloak, disk, memory.
    """

    name: str  # database, vault, keycloak, disk, memory
    status: HealthStatus
    latency_ms: Optional[int] = None
    usage_percent: Optional[int] = None
    message: Optional[str] = None


@dataclass
class HealthReport:
    """
    Rapport de santé complet du système.

    Invariant HEALTH_004: Format JSON {status, checks[], timestamp}.
    """

    status: HealthStatus
    timestamp: datetime
    checks: List[HealthCheck]
    node_id: str

    def to_dict(self) -> Dict[str, Any]:
        """Convertit en dict pour sérialisation JSON (HEALTH_004)."""
        return {
            "status": self.status.value,
            "timestamp": self.timestamp.isoformat(),
            "checks": [
                {
                    "name": c.name,
                    "status": c.status.value,
                    "latency_ms": c.latency_ms,
                    "usage_percent": c.usage_percent,
                    "message": c.message,
                }
                for c in self.checks
            ],
            "node_id": self.node_id,
        }


@dataclass
class ClusterStatus:
    """
    Status du cluster HA.

    Invariant RUN_050: Cluster minimum 2 noeuds.
    """

    node_count: int
    primary_node: str
    healthy_nodes: List[str]
    unhealthy_nodes: List[str]

    def is_valid_cluster(self) -> bool:
        """Vérifie RUN_050: minimum 2 noeuds."""
        return self.node_count >= 2


@dataclass
class SyncResult:
    """Résultat d'une synchronisation cloud."""

    success: bool
    synced_at: datetime
    items_synced: int = 0
    items_failed: int = 0
    error_message: Optional[str] = None


# Type alias pour les fonctions checker
HealthChecker = Callable[[], Awaitable[HealthCheck]]


class IHealthMonitor(ABC):
    """
    Interface moniteur de santé.

    Responsabilités:
        - Endpoints health (HEALTH_001-003)
        - Format réponse JSON (HEALTH_004)
        - Checks requis (HEALTH_005)
        - Calcul status (HEALTH_006)
        - Timeout 5s (HEALTH_008)
    """

    @abstractmethod
    async def check_health(self) -> HealthReport:
        """
        Effectue un check de santé complet.

        Returns:
            Rapport de santé avec tous les checks.

        Invariants:
            HEALTH_004: Format JSON {status, checks[], timestamp}
            HEALTH_005: Checks database, vault, keycloak, disk, memory
            HEALTH_008: Timeout 5s par check
        """
        pass

    @abstractmethod
    async def check_liveness(self) -> bool:
        """
        Vérifie si le service répond (liveness probe).

        Returns:
            True si le service est vivant.

        Invariant HEALTH_002: /health/live.
        """
        pass

    @abstractmethod
    async def check_readiness(self) -> bool:
        """
        Vérifie si le service est prêt à recevoir du trafic.

        Returns:
            True si tous les checks sont OK.

        Invariant HEALTH_003: /health/ready.
        """
        pass

    @abstractmethod
    async def send_heartbeat(self) -> None:
        """
        Envoie un heartbeat au cluster.

        Utilisé pour la détection de pannes.
        """
        pass

    @abstractmethod
    def get_health_history(self, minutes: int) -> List[HealthReport]:
        """
        Récupère l'historique des rapports de santé.

        Args:
            minutes: Nombre de minutes d'historique.

        Returns:
            Liste des rapports de santé.
        """
        pass

    @abstractmethod
    def register_check(self, name: str, checker: HealthChecker) -> None:
        """
        Enregistre un checker de santé personnalisé.

        Args:
            name: Nom du check.
            checker: Fonction async retournant un HealthCheck.
        """
        pass


class IFailoverManager(ABC):
    """
    Interface gestionnaire de failover.

    Responsabilités:
        - Déclenchement failover
        - Promotion noeud primaire
        - Gestion cluster (RUN_050)
    """

    @abstractmethod
    async def trigger_failover(self, reason: str) -> None:
        """
        Déclenche un failover vers un noeud secondaire.

        Args:
            reason: Raison du failover pour audit.

        Raises:
            FailoverError: Si aucun noeud disponible.
        """
        pass

    @abstractmethod
    async def promote_to_primary(self, node_id: str) -> None:
        """
        Promeut un noeud comme primaire.

        Args:
            node_id: Identifiant du noeud à promouvoir.

        Raises:
            FailoverError: Si noeud indisponible.
        """
        pass

    @abstractmethod
    def get_current_primary(self) -> str:
        """
        Récupère l'identifiant du noeud primaire actuel.

        Returns:
            Node ID du primaire.
        """
        pass

    @abstractmethod
    def get_cluster_status(self) -> ClusterStatus:
        """
        Récupère le status complet du cluster.

        Returns:
            Status du cluster avec tous les noeuds.

        Invariant RUN_050: Cluster minimum 2 noeuds.
        """
        pass


class IDegradedModeController(ABC):
    """
    Interface contrôleur mode dégradé.

    Responsabilités:
        - Activation/désactivation mode dégradé
        - Gestion des fonctionnalités disponibles
        - Tracking durée mode dégradé
    """

    @abstractmethod
    def enter_degraded_mode(self, reason: str) -> None:
        """
        Active le mode dégradé.

        Args:
            reason: Raison de l'activation pour audit.
        """
        pass

    @abstractmethod
    def exit_degraded_mode(self) -> None:
        """Désactive le mode dégradé."""
        pass

    @abstractmethod
    def is_degraded(self) -> bool:
        """
        Vérifie si le système est en mode dégradé.

        Returns:
            True si mode dégradé actif.
        """
        pass

    @abstractmethod
    def get_available_features(self) -> List[str]:
        """
        Récupère la liste des fonctionnalités disponibles en mode dégradé.

        Returns:
            Liste des features actives.
        """
        pass

    @abstractmethod
    def get_degraded_since(self) -> Optional[datetime]:
        """
        Récupère le timestamp d'entrée en mode dégradé.

        Returns:
            Datetime si dégradé, None sinon.
        """
        pass


class IConfigSyncService(ABC):
    """
    Interface service de synchronisation configuration.

    Responsabilités:
        - Sync config depuis cloud
        - Push événements vers cloud
        - Tracking dernière sync
    """

    @abstractmethod
    async def sync_from_cloud(self) -> SyncResult:
        """
        Synchronise la configuration depuis le cloud.

        Returns:
            Résultat de la synchronisation.
        """
        pass

    @abstractmethod
    async def push_events_to_cloud(self) -> SyncResult:
        """
        Pousse les événements locaux vers le cloud.

        Returns:
            Résultat de la synchronisation.
        """
        pass

    @abstractmethod
    def get_last_sync(self) -> Optional[datetime]:
        """
        Récupère le timestamp de la dernière sync réussie.

        Returns:
            Datetime de la dernière sync, None si jamais sync.
        """
        pass

    @abstractmethod
    def is_sync_overdue(self) -> bool:
        """
        Vérifie si une sync est en retard.

        Returns:
            True si la dernière sync est trop ancienne.
        """
        pass
