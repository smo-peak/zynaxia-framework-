"""
LOT 7: Contraintes de Déploiement

Vérification des contraintes pré-déploiement avec:
- Fenêtre de maintenance (DEPL_030)
- Validation licence (DEPL_031)
- Santé cluster (DEPL_032)
- Notifications Fleet Manager (DEPL_033)

Invariants:
    DEPL_030: Déploiement OTA respecte fenêtre maintenance si définie (WARNING)
    DEPL_031: Déploiement BLOQUÉ si licence invalide
    DEPL_032: Déploiement BLOQUÉ si cluster non-healthy
    DEPL_033: Notification Fleet Manager AVANT et APRÈS déploiement
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from src.licensing.interfaces import ILicenseValidator, License
from src.ha.interfaces import IHealthMonitor, HealthStatus
from src.audit.interfaces import IAuditEmitter, AuditEventType


class DeploymentEventType(Enum):
    """Types d'événements de déploiement pour notifications."""

    DEPLOYMENT_STARTED = "deployment_started"
    DEPLOYMENT_COMPLETED = "deployment_completed"
    DEPLOYMENT_FAILED = "deployment_failed"
    DEPLOYMENT_ROLLED_BACK = "deployment_rolled_back"


class IFleetNotifier(ABC):
    """
    Interface pour notifications Fleet Manager.

    Responsabilités:
        - Notifier le Fleet Manager central des événements de déploiement
        - DEPL_033: Notification AVANT et APRÈS déploiement
    """

    @abstractmethod
    async def notify(self, site_id: str, event: str, data: Dict[str, Any]) -> bool:
        """
        Envoie une notification au Fleet Manager.

        Args:
            site_id: Identifiant du site
            event: Type d'événement ("before" ou "after")
            data: Données additionnelles de l'événement

        Returns:
            True si notification envoyée avec succès

        Invariant:
            DEPL_033: Notification obligatoire AVANT et APRÈS déploiement
        """
        pass


@dataclass
class MaintenanceWindow:
    """
    Fenêtre de maintenance pour déploiements OTA.

    Définit les heures et jours autorisés pour les déploiements.

    Invariant:
        DEPL_030: Déploiement OTA respecte fenêtre si définie
    """

    start_hour: int  # 0-23
    end_hour: int  # 0-23
    days: List[int]  # 0=Monday, 6=Sunday
    timezone: str = "UTC"

    def __post_init__(self) -> None:
        """Valide les paramètres de la fenêtre."""
        if not 0 <= self.start_hour <= 23:
            raise ValueError(f"start_hour must be 0-23, got {self.start_hour}")
        if not 0 <= self.end_hour <= 23:
            raise ValueError(f"end_hour must be 0-23, got {self.end_hour}")
        if not self.days:
            raise ValueError("days list cannot be empty")
        for day in self.days:
            if not 0 <= day <= 6:
                raise ValueError(f"day must be 0-6, got {day}")
        try:
            ZoneInfo(self.timezone)
        except ZoneInfoNotFoundError:
            raise ValueError(f"Unknown timezone: {self.timezone}")


@dataclass
class DeploymentPrecheck:
    """
    Résultat de vérification pré-déploiement.

    Contient les blockers (erreurs bloquantes) et warnings.
    """

    can_deploy: bool
    blockers: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class LicenseInvalidError(Exception):
    """
    Licence invalide - déploiement bloqué.

    Invariant:
        DEPL_031: Déploiement BLOQUÉ si licence invalide
    """

    pass


class ClusterUnhealthyError(Exception):
    """
    Cluster non-healthy - déploiement bloqué.

    Invariant:
        DEPL_032: Déploiement BLOQUÉ si cluster non-healthy
    """

    pass


class FleetNotificationError(Exception):
    """
    Erreur de notification Fleet Manager.

    Invariant:
        DEPL_033: Notification obligatoire
    """

    pass


class DeploymentConstraintsError(Exception):
    """Erreur générale des contraintes de déploiement."""

    pass


class DeploymentConstraints:
    """
    Vérification contraintes pré-déploiement.

    Implémente les invariants DEPL_030-033 pour garantir
    un déploiement sécurisé et contrôlé.

    Invariants:
        DEPL_030: Déploiement OTA respecte fenêtre maintenance si définie (WARNING)
        DEPL_031: Déploiement BLOQUÉ si licence invalide
        DEPL_032: Déploiement BLOQUÉ si cluster non-healthy
        DEPL_033: Notification Fleet Manager AVANT et APRÈS déploiement
    """

    def __init__(
        self,
        license_validator: ILicenseValidator,
        health_monitor: IHealthMonitor,
        fleet_notifier: IFleetNotifier,
        audit_emitter: IAuditEmitter,
    ) -> None:
        """
        Initialise le vérificateur de contraintes.

        Args:
            license_validator: Validateur de licences
            health_monitor: Moniteur de santé cluster
            fleet_notifier: Notifieur Fleet Manager
            audit_emitter: Émetteur d'événements d'audit
        """
        self._license = license_validator
        self._health = health_monitor
        self._fleet = fleet_notifier
        self._audit = audit_emitter
        self._maintenance_windows: Dict[str, MaintenanceWindow] = {}
        self._licenses: Dict[str, License] = {}

    def set_maintenance_window(self, site_id: str, window: MaintenanceWindow) -> None:
        """
        Configure fenêtre maintenance pour un site.

        Args:
            site_id: Identifiant du site
            window: Fenêtre de maintenance

        Invariant:
            DEPL_030: Fenêtre utilisée pour vérification déploiement OTA
        """
        if not site_id:
            raise ValueError("site_id cannot be empty")
        self._maintenance_windows[site_id] = window

    def remove_maintenance_window(self, site_id: str) -> None:
        """
        Supprime la fenêtre de maintenance d'un site.

        Args:
            site_id: Identifiant du site
        """
        self._maintenance_windows.pop(site_id, None)

    def get_maintenance_window(self, site_id: str) -> Optional[MaintenanceWindow]:
        """
        Récupère la fenêtre de maintenance d'un site.

        Args:
            site_id: Identifiant du site

        Returns:
            Fenêtre de maintenance si définie, None sinon
        """
        return self._maintenance_windows.get(site_id)

    def set_license(self, site_id: str, license: License) -> None:
        """
        Enregistre une licence pour un site.

        Args:
            site_id: Identifiant du site
            license: Licence à enregistrer
        """
        if not site_id:
            raise ValueError("site_id cannot be empty")
        self._licenses[site_id] = license

    def is_in_maintenance_window(
        self, site_id: str, check_time: Optional[datetime] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Vérifie si l'heure actuelle est dans la fenêtre de maintenance.

        Args:
            site_id: Identifiant du site
            check_time: Heure à vérifier (défaut: maintenant)

        Returns:
            Tuple (in_window, warning_message):
                - in_window: True si dans la fenêtre ou pas de fenêtre définie
                - warning_message: Message d'avertissement si hors fenêtre

        Invariant:
            DEPL_030: Déploiement OTA respecte fenêtre maintenance si définie (WARNING)
        """
        window = self._maintenance_windows.get(site_id)

        # Pas de fenêtre définie = toujours OK
        if window is None:
            return (True, None)

        # Utiliser l'heure courante si non spécifiée
        if check_time is None:
            check_time = datetime.now(timezone.utc)

        # Convertir vers le timezone de la fenêtre
        tz = ZoneInfo(window.timezone)
        if check_time.tzinfo is None:
            check_time = check_time.replace(tzinfo=timezone.utc)
        local_time = check_time.astimezone(tz)

        current_hour = local_time.hour
        current_day = local_time.weekday()

        # Vérifier le jour
        if current_day not in window.days:
            warning = (
                f"DEPL_030 WARNING: Deployment outside maintenance window. "
                f"Current day {current_day} not in allowed days {window.days}"
            )
            return (False, warning)

        # Vérifier l'heure (gère le cas où la fenêtre traverse minuit)
        if window.start_hour <= window.end_hour:
            # Fenêtre normale (ex: 02:00 - 06:00)
            in_window = window.start_hour <= current_hour < window.end_hour
        else:
            # Fenêtre traversant minuit (ex: 22:00 - 02:00)
            in_window = current_hour >= window.start_hour or current_hour < window.end_hour

        if not in_window:
            warning = (
                f"DEPL_030 WARNING: Deployment outside maintenance window. "
                f"Current hour {current_hour} not in window [{window.start_hour}-{window.end_hour})"
            )
            return (False, warning)

        return (True, None)

    def is_license_valid(self, site_id: str) -> bool:
        """
        Vérifie si la licence du site est valide.

        Args:
            site_id: Identifiant du site

        Returns:
            True si licence valide

        Invariant:
            DEPL_031: Déploiement BLOQUÉ si licence invalide
        """
        license = self._licenses.get(site_id)
        if license is None:
            return False

        # Vérifier signature
        if not self._license.validate_signature(license):
            return False

        # Vérifier structure
        if not self._license.validate_structure(license):
            return False

        # Vérifier durée
        if not self._license.validate_duration(license):
            return False

        # Vérifier non révoquée
        if license.revoked:
            return False

        # Vérifier non expirée
        now = datetime.now(timezone.utc)
        expires_at = license.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if now > expires_at:
            return False

        return True

    async def is_cluster_healthy(self, site_id: str) -> bool:
        """
        Vérifie si le cluster est en bonne santé.

        Args:
            site_id: Identifiant du site

        Returns:
            True si cluster healthy

        Invariant:
            DEPL_032: Déploiement BLOQUÉ si cluster non-healthy
        """
        try:
            health_report = await self._health.check_health()
            return health_report.status == HealthStatus.HEALTHY
        except Exception:
            # En cas d'erreur de health check, considérer comme unhealthy
            return False

    async def notify_fleet_manager(
        self, site_id: str, event: str, deployment_id: str
    ) -> bool:
        """
        Notifie le Fleet Manager d'un événement de déploiement.

        Args:
            site_id: Identifiant du site
            event: Type d'événement ("before" ou "after")
            deployment_id: Identifiant du déploiement

        Returns:
            True si notification réussie

        Raises:
            FleetNotificationError: Si notification échoue

        Invariant:
            DEPL_033: Notification Fleet Manager AVANT et APRÈS déploiement
        """
        if event not in ("before", "after"):
            raise ValueError(f"event must be 'before' or 'after', got '{event}'")

        data = {
            "deployment_id": deployment_id,
            "site_id": site_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event,
        }

        try:
            success = await self._fleet.notify(site_id, event, data)
            if not success:
                raise FleetNotificationError(
                    f"DEPL_033 VIOLATION: Fleet Manager notification failed for {event} event"
                )

            # Audit de la notification
            await self._audit.emit_event(
                event_type=AuditEventType.SYSTEM_CONFIG_CHANGE,
                user_id="system",
                tenant_id=site_id,
                action=f"fleet_notification_{event}",
                resource_id=deployment_id,
                metadata={"event": event, "success": True},
            )

            return True
        except FleetNotificationError:
            raise
        except Exception as e:
            raise FleetNotificationError(
                f"DEPL_033 VIOLATION: Fleet Manager notification error: {e}"
            )

    async def check_all_constraints(self, site_id: str) -> DeploymentPrecheck:
        """
        Vérifie toutes les contraintes de déploiement.

        Args:
            site_id: Identifiant du site

        Returns:
            DeploymentPrecheck avec blockers et warnings

        Invariants:
            DEPL_030: Fenêtre maintenance (WARNING)
            DEPL_031: Licence valide (BLOCKER)
            DEPL_032: Cluster healthy (BLOCKER)
        """
        blockers: List[str] = []
        warnings: List[str] = []

        # DEPL_030: Vérifier fenêtre maintenance (WARNING uniquement)
        in_window, warning_msg = self.is_in_maintenance_window(site_id)
        if not in_window and warning_msg:
            warnings.append(warning_msg)

        # DEPL_031: Vérifier licence valide (BLOCKER)
        if not self.is_license_valid(site_id):
            blockers.append(
                f"DEPL_031 VIOLATION: License invalid or missing for site {site_id}"
            )

        # DEPL_032: Vérifier cluster healthy (BLOCKER)
        cluster_healthy = await self.is_cluster_healthy(site_id)
        if not cluster_healthy:
            blockers.append(
                f"DEPL_032 VIOLATION: Cluster not healthy for site {site_id}"
            )

        can_deploy = len(blockers) == 0

        return DeploymentPrecheck(
            can_deploy=can_deploy,
            blockers=blockers,
            warnings=warnings,
        )

    async def enforce_constraints(self, site_id: str, deployment_id: str) -> None:
        """
        Applique toutes les contraintes et lève des exceptions si non respectées.

        Args:
            site_id: Identifiant du site
            deployment_id: Identifiant du déploiement

        Raises:
            LicenseInvalidError: Si licence invalide (DEPL_031)
            ClusterUnhealthyError: Si cluster non-healthy (DEPL_032)

        Invariants:
            DEPL_031: Déploiement BLOQUÉ si licence invalide
            DEPL_032: Déploiement BLOQUÉ si cluster non-healthy
        """
        # DEPL_031: Licence obligatoire et valide
        if not self.is_license_valid(site_id):
            raise LicenseInvalidError(
                f"DEPL_031 VIOLATION: Cannot deploy - license invalid for site {site_id}"
            )

        # DEPL_032: Cluster doit être healthy
        cluster_healthy = await self.is_cluster_healthy(site_id)
        if not cluster_healthy:
            raise ClusterUnhealthyError(
                f"DEPL_032 VIOLATION: Cannot deploy - cluster not healthy for site {site_id}"
            )

    async def prepare_deployment(self, site_id: str, deployment_id: str) -> DeploymentPrecheck:
        """
        Prépare un déploiement: vérifie contraintes et notifie Fleet Manager.

        Args:
            site_id: Identifiant du site
            deployment_id: Identifiant du déploiement

        Returns:
            DeploymentPrecheck avec résultats des vérifications

        Raises:
            LicenseInvalidError: Si licence invalide
            ClusterUnhealthyError: Si cluster non-healthy
            FleetNotificationError: Si notification échoue

        Invariants:
            DEPL_030-033: Toutes les contraintes appliquées
        """
        # Vérifier toutes les contraintes
        precheck = await self.check_all_constraints(site_id)

        if not precheck.can_deploy:
            # Log et retourne les blockers
            return precheck

        # DEPL_033: Notifier Fleet Manager AVANT déploiement
        await self.notify_fleet_manager(site_id, "before", deployment_id)

        return precheck

    async def complete_deployment(
        self, site_id: str, deployment_id: str, success: bool
    ) -> None:
        """
        Finalise un déploiement: notifie Fleet Manager du résultat.

        Args:
            site_id: Identifiant du site
            deployment_id: Identifiant du déploiement
            success: True si déploiement réussi

        Raises:
            FleetNotificationError: Si notification échoue

        Invariant:
            DEPL_033: Notification Fleet Manager APRÈS déploiement
        """
        # DEPL_033: Notifier Fleet Manager APRÈS déploiement
        await self.notify_fleet_manager(site_id, "after", deployment_id)

        # Audit du résultat
        await self._audit.emit_event(
            event_type=AuditEventType.SYSTEM_CONFIG_CHANGE,
            user_id="system",
            tenant_id=site_id,
            action="deployment_completed" if success else "deployment_failed",
            resource_id=deployment_id,
            metadata={"success": success},
        )
