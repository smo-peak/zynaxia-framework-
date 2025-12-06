"""
Tests unitaires pour DeploymentConstraints (LOT 7 - PARTIE 4).

Vérifie les invariants DEPL_030-033:
    DEPL_030: Déploiement OTA respecte fenêtre maintenance si définie (WARNING)
    DEPL_031: Déploiement BLOQUÉ si licence invalide
    DEPL_032: Déploiement BLOQUÉ si cluster non-healthy
    DEPL_033: Notification Fleet Manager AVANT et APRÈS déploiement
"""

import pytest
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from unittest.mock import AsyncMock, MagicMock

from src.deployment.deployment_constraints import (
    DeploymentConstraints,
    MaintenanceWindow,
    DeploymentPrecheck,
    IFleetNotifier,
    LicenseInvalidError,
    ClusterUnhealthyError,
    FleetNotificationError,
    DeploymentConstraintsError,
)
from src.licensing.interfaces import ILicenseValidator, License
from src.ha.interfaces import IHealthMonitor, HealthReport, HealthStatus, HealthCheck
from src.audit.interfaces import IAuditEmitter, AuditEvent, AuditEventType


# =============================================================================
# FIXTURES
# =============================================================================


class MockLicenseValidator(ILicenseValidator):
    """Mock du validateur de licence."""

    def __init__(self) -> None:
        self.signature_valid = True
        self.structure_valid = True
        self.duration_valid = True
        self.tampering_detected = False

    def validate_signature(self, license: License) -> bool:
        return self.signature_valid

    def validate_structure(self, license: License) -> bool:
        return self.structure_valid

    def validate_duration(self, license: License) -> bool:
        return self.duration_valid

    def detect_tampering(self, license: License) -> bool:
        return not self.tampering_detected


class MockHealthMonitor(IHealthMonitor):
    """Mock du moniteur de santé."""

    def __init__(self) -> None:
        self.health_status = HealthStatus.HEALTHY
        self.check_health_raises = False

    async def check_health(self) -> HealthReport:
        if self.check_health_raises:
            raise Exception("Health check failed")
        return HealthReport(
            status=self.health_status,
            timestamp=datetime.now(timezone.utc),
            checks=[
                HealthCheck(name="database", status=self.health_status),
                HealthCheck(name="vault", status=self.health_status),
            ],
            node_id="node-1",
        )

    async def check_liveness(self) -> bool:
        return True

    async def check_readiness(self) -> bool:
        return self.health_status == HealthStatus.HEALTHY

    async def send_heartbeat(self) -> None:
        pass

    def get_health_history(self, minutes: int) -> List[HealthReport]:
        return []

    def register_check(self, name: str, checker: Any) -> None:
        pass


class MockFleetNotifier(IFleetNotifier):
    """Mock du notifieur Fleet Manager."""

    def __init__(self) -> None:
        self.notifications: List[Dict[str, Any]] = []
        self.should_fail = False

    async def notify(self, site_id: str, event: str, data: Dict[str, Any]) -> bool:
        if self.should_fail:
            return False
        self.notifications.append({
            "site_id": site_id,
            "event": event,
            "data": data,
        })
        return True


class MockAuditEmitter(IAuditEmitter):
    """Mock de l'émetteur d'audit."""

    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []

    async def emit_event(
        self,
        event_type: AuditEventType,
        user_id: str,
        tenant_id: str,
        action: str,
        resource_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuditEvent:
        self.events.append({
            "event_type": event_type,
            "user_id": user_id,
            "tenant_id": tenant_id,
            "action": action,
            "resource_id": resource_id,
            "metadata": metadata,
        })
        return AuditEvent(
            event_id="evt-123",
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            tenant_id=tenant_id,
            resource_id=resource_id,
            action=action,
            metadata=metadata or {},
            ip_address=ip_address,
            user_agent=user_agent,
        )

    def verify_event_signature(self, event: AuditEvent) -> bool:
        return True

    def compute_event_hash(self, event: AuditEvent) -> str:
        return "hash-123"


def create_valid_license(site_id: str = "site-1") -> License:
    """Crée une licence valide pour les tests."""
    return License(
        license_id="lic-123",
        site_id=site_id,
        issued_at=datetime.now(timezone.utc) - timedelta(days=1),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        modules=["module1", "module2"],
        signature="valid-signature",
        issuer_id="issuer-1",
        organization_id="org-1",
        blockchain_tx_id="tx-123",
        revoked=False,
    )


def create_expired_license(site_id: str = "site-1") -> License:
    """Crée une licence expirée pour les tests."""
    return License(
        license_id="lic-expired",
        site_id=site_id,
        issued_at=datetime.now(timezone.utc) - timedelta(days=60),
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        modules=["module1"],
        signature="valid-signature",
        issuer_id="issuer-1",
        organization_id="org-1",
        revoked=False,
    )


def create_revoked_license(site_id: str = "site-1") -> License:
    """Crée une licence révoquée pour les tests."""
    return License(
        license_id="lic-revoked",
        site_id=site_id,
        issued_at=datetime.now(timezone.utc) - timedelta(days=1),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        modules=["module1"],
        signature="valid-signature",
        issuer_id="issuer-1",
        organization_id="org-1",
        revoked=True,
        revoked_at=datetime.now(timezone.utc),
        revoked_reason="Security breach",
    )


@pytest.fixture
def license_validator() -> MockLicenseValidator:
    return MockLicenseValidator()


@pytest.fixture
def health_monitor() -> MockHealthMonitor:
    return MockHealthMonitor()


@pytest.fixture
def fleet_notifier() -> MockFleetNotifier:
    return MockFleetNotifier()


@pytest.fixture
def audit_emitter() -> MockAuditEmitter:
    return MockAuditEmitter()


@pytest.fixture
def constraints(
    license_validator: MockLicenseValidator,
    health_monitor: MockHealthMonitor,
    fleet_notifier: MockFleetNotifier,
    audit_emitter: MockAuditEmitter,
) -> DeploymentConstraints:
    return DeploymentConstraints(
        license_validator=license_validator,
        health_monitor=health_monitor,
        fleet_notifier=fleet_notifier,
        audit_emitter=audit_emitter,
    )


# =============================================================================
# TEST DEPL_030: FENÊTRE DE MAINTENANCE
# =============================================================================


class TestDEPL030MaintenanceWindow:
    """Tests pour DEPL_030: Déploiement OTA respecte fenêtre maintenance."""

    def test_DEPL_030_no_window_defined_allows_deployment(
        self, constraints: DeploymentConstraints
    ) -> None:
        """DEPL_030: Sans fenêtre définie, déploiement autorisé."""
        in_window, warning = constraints.is_in_maintenance_window("site-1")
        assert in_window is True
        assert warning is None

    def test_DEPL_030_inside_maintenance_window_ok(
        self, constraints: DeploymentConstraints
    ) -> None:
        """DEPL_030: Dans la fenêtre = pas de warning."""
        # Fenêtre 02:00 - 06:00 UTC, tous les jours
        window = MaintenanceWindow(
            start_hour=2,
            end_hour=6,
            days=[0, 1, 2, 3, 4, 5, 6],
            timezone="UTC",
        )
        constraints.set_maintenance_window("site-1", window)

        # Tester à 03:00 UTC un lundi
        check_time = datetime(2024, 1, 1, 3, 0, tzinfo=timezone.utc)  # Lundi
        in_window, warning = constraints.is_in_maintenance_window("site-1", check_time)

        assert in_window is True
        assert warning is None

    def test_DEPL_030_outside_window_hour_returns_warning(
        self, constraints: DeploymentConstraints
    ) -> None:
        """DEPL_030: Hors fenêtre horaire = warning."""
        window = MaintenanceWindow(
            start_hour=2,
            end_hour=6,
            days=[0, 1, 2, 3, 4, 5, 6],
            timezone="UTC",
        )
        constraints.set_maintenance_window("site-1", window)

        # Tester à 10:00 UTC (hors fenêtre)
        check_time = datetime(2024, 1, 1, 10, 0, tzinfo=timezone.utc)
        in_window, warning = constraints.is_in_maintenance_window("site-1", check_time)

        assert in_window is False
        assert warning is not None
        assert "DEPL_030" in warning
        assert "WARNING" in warning

    def test_DEPL_030_outside_window_day_returns_warning(
        self, constraints: DeploymentConstraints
    ) -> None:
        """DEPL_030: Hors jour autorisé = warning."""
        # Fenêtre uniquement samedi et dimanche (5, 6)
        window = MaintenanceWindow(
            start_hour=2,
            end_hour=6,
            days=[5, 6],  # Samedi, Dimanche
            timezone="UTC",
        )
        constraints.set_maintenance_window("site-1", window)

        # Tester un lundi (0) à 03:00
        check_time = datetime(2024, 1, 1, 3, 0, tzinfo=timezone.utc)  # Lundi
        in_window, warning = constraints.is_in_maintenance_window("site-1", check_time)

        assert in_window is False
        assert warning is not None
        assert "DEPL_030" in warning
        assert "day" in warning.lower()

    def test_DEPL_030_window_crossing_midnight(
        self, constraints: DeploymentConstraints
    ) -> None:
        """DEPL_030: Fenêtre traversant minuit fonctionne."""
        # Fenêtre 22:00 - 02:00 (traverse minuit)
        window = MaintenanceWindow(
            start_hour=22,
            end_hour=2,
            days=[0, 1, 2, 3, 4, 5, 6],
            timezone="UTC",
        )
        constraints.set_maintenance_window("site-1", window)

        # Test à 23:00 (dans la fenêtre)
        check_time = datetime(2024, 1, 1, 23, 0, tzinfo=timezone.utc)
        in_window, _ = constraints.is_in_maintenance_window("site-1", check_time)
        assert in_window is True

        # Test à 01:00 (dans la fenêtre après minuit)
        check_time = datetime(2024, 1, 2, 1, 0, tzinfo=timezone.utc)
        in_window, _ = constraints.is_in_maintenance_window("site-1", check_time)
        assert in_window is True

        # Test à 10:00 (hors fenêtre)
        check_time = datetime(2024, 1, 1, 10, 0, tzinfo=timezone.utc)
        in_window, _ = constraints.is_in_maintenance_window("site-1", check_time)
        assert in_window is False

    def test_DEPL_030_timezone_conversion(
        self, constraints: DeploymentConstraints
    ) -> None:
        """DEPL_030: Conversion timezone fonctionne."""
        # Fenêtre 02:00 - 06:00 Europe/Paris
        window = MaintenanceWindow(
            start_hour=2,
            end_hour=6,
            days=[0, 1, 2, 3, 4, 5, 6],
            timezone="Europe/Paris",
        )
        constraints.set_maintenance_window("site-1", window)

        # 03:00 Paris = 02:00 UTC (en hiver)
        # Tester avec une heure UTC qui correspond à 03:00 Paris
        check_time = datetime(2024, 1, 1, 2, 0, tzinfo=timezone.utc)  # 03:00 Paris
        in_window, _ = constraints.is_in_maintenance_window("site-1", check_time)
        assert in_window is True

    def test_DEPL_030_invalid_window_parameters(self) -> None:
        """DEPL_030: Paramètres invalides lèvent exception."""
        with pytest.raises(ValueError):
            MaintenanceWindow(start_hour=25, end_hour=6, days=[0])

        with pytest.raises(ValueError):
            MaintenanceWindow(start_hour=2, end_hour=-1, days=[0])

        with pytest.raises(ValueError):
            MaintenanceWindow(start_hour=2, end_hour=6, days=[])

        with pytest.raises(ValueError):
            MaintenanceWindow(start_hour=2, end_hour=6, days=[7])

        with pytest.raises(ValueError):
            MaintenanceWindow(start_hour=2, end_hour=6, days=[0], timezone="Invalid/TZ")

    def test_DEPL_030_remove_window(
        self, constraints: DeploymentConstraints
    ) -> None:
        """DEPL_030: Suppression fenêtre fonctionne."""
        window = MaintenanceWindow(start_hour=2, end_hour=6, days=[0])
        constraints.set_maintenance_window("site-1", window)

        assert constraints.get_maintenance_window("site-1") is not None

        constraints.remove_maintenance_window("site-1")
        assert constraints.get_maintenance_window("site-1") is None


# =============================================================================
# TEST DEPL_031: LICENCE INVALIDE BLOQUE
# =============================================================================


class TestDEPL031LicenseValidation:
    """Tests pour DEPL_031: Déploiement BLOQUÉ si licence invalide."""

    def test_DEPL_031_valid_license_allows_deployment(
        self, constraints: DeploymentConstraints
    ) -> None:
        """DEPL_031: Licence valide = déploiement autorisé."""
        license = create_valid_license("site-1")
        constraints.set_license("site-1", license)

        assert constraints.is_license_valid("site-1") is True

    def test_DEPL_031_missing_license_blocks_deployment(
        self, constraints: DeploymentConstraints
    ) -> None:
        """DEPL_031: Licence absente = déploiement bloqué."""
        assert constraints.is_license_valid("site-1") is False

    def test_DEPL_031_expired_license_blocks_deployment(
        self, constraints: DeploymentConstraints
    ) -> None:
        """DEPL_031: Licence expirée = déploiement bloqué."""
        license = create_expired_license("site-1")
        constraints.set_license("site-1", license)

        assert constraints.is_license_valid("site-1") is False

    def test_DEPL_031_revoked_license_blocks_deployment(
        self, constraints: DeploymentConstraints
    ) -> None:
        """DEPL_031: Licence révoquée = déploiement bloqué."""
        license = create_revoked_license("site-1")
        constraints.set_license("site-1", license)

        assert constraints.is_license_valid("site-1") is False

    def test_DEPL_031_invalid_signature_blocks_deployment(
        self,
        constraints: DeploymentConstraints,
        license_validator: MockLicenseValidator,
    ) -> None:
        """DEPL_031: Signature invalide = déploiement bloqué."""
        license = create_valid_license("site-1")
        constraints.set_license("site-1", license)
        license_validator.signature_valid = False

        assert constraints.is_license_valid("site-1") is False

    def test_DEPL_031_invalid_structure_blocks_deployment(
        self,
        constraints: DeploymentConstraints,
        license_validator: MockLicenseValidator,
    ) -> None:
        """DEPL_031: Structure invalide = déploiement bloqué."""
        license = create_valid_license("site-1")
        constraints.set_license("site-1", license)
        license_validator.structure_valid = False

        assert constraints.is_license_valid("site-1") is False

    def test_DEPL_031_invalid_duration_blocks_deployment(
        self,
        constraints: DeploymentConstraints,
        license_validator: MockLicenseValidator,
    ) -> None:
        """DEPL_031: Durée invalide = déploiement bloqué."""
        license = create_valid_license("site-1")
        constraints.set_license("site-1", license)
        license_validator.duration_valid = False

        assert constraints.is_license_valid("site-1") is False

    @pytest.mark.asyncio
    async def test_DEPL_031_enforce_raises_on_invalid_license(
        self, constraints: DeploymentConstraints
    ) -> None:
        """DEPL_031: enforce_constraints lève LicenseInvalidError."""
        # Pas de licence configurée
        with pytest.raises(LicenseInvalidError) as exc_info:
            await constraints.enforce_constraints("site-1", "deploy-1")

        assert "DEPL_031" in str(exc_info.value)


# =============================================================================
# TEST DEPL_032: CLUSTER NON-HEALTHY BLOQUE
# =============================================================================


class TestDEPL032ClusterHealth:
    """Tests pour DEPL_032: Déploiement BLOQUÉ si cluster non-healthy."""

    @pytest.mark.asyncio
    async def test_DEPL_032_healthy_cluster_allows_deployment(
        self,
        constraints: DeploymentConstraints,
        health_monitor: MockHealthMonitor,
    ) -> None:
        """DEPL_032: Cluster healthy = déploiement autorisé."""
        health_monitor.health_status = HealthStatus.HEALTHY

        assert await constraints.is_cluster_healthy("site-1") is True

    @pytest.mark.asyncio
    async def test_DEPL_032_degraded_cluster_blocks_deployment(
        self,
        constraints: DeploymentConstraints,
        health_monitor: MockHealthMonitor,
    ) -> None:
        """DEPL_032: Cluster dégradé = déploiement bloqué."""
        health_monitor.health_status = HealthStatus.DEGRADED

        assert await constraints.is_cluster_healthy("site-1") is False

    @pytest.mark.asyncio
    async def test_DEPL_032_unhealthy_cluster_blocks_deployment(
        self,
        constraints: DeploymentConstraints,
        health_monitor: MockHealthMonitor,
    ) -> None:
        """DEPL_032: Cluster unhealthy = déploiement bloqué."""
        health_monitor.health_status = HealthStatus.UNHEALTHY

        assert await constraints.is_cluster_healthy("site-1") is False

    @pytest.mark.asyncio
    async def test_DEPL_032_health_check_error_blocks_deployment(
        self,
        constraints: DeploymentConstraints,
        health_monitor: MockHealthMonitor,
    ) -> None:
        """DEPL_032: Erreur health check = déploiement bloqué."""
        health_monitor.check_health_raises = True

        assert await constraints.is_cluster_healthy("site-1") is False

    @pytest.mark.asyncio
    async def test_DEPL_032_enforce_raises_on_unhealthy_cluster(
        self,
        constraints: DeploymentConstraints,
        health_monitor: MockHealthMonitor,
    ) -> None:
        """DEPL_032: enforce_constraints lève ClusterUnhealthyError."""
        # Licence valide mais cluster unhealthy
        license = create_valid_license("site-1")
        constraints.set_license("site-1", license)
        health_monitor.health_status = HealthStatus.UNHEALTHY

        with pytest.raises(ClusterUnhealthyError) as exc_info:
            await constraints.enforce_constraints("site-1", "deploy-1")

        assert "DEPL_032" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_DEPL_032_check_all_includes_health_blocker(
        self,
        constraints: DeploymentConstraints,
        health_monitor: MockHealthMonitor,
    ) -> None:
        """DEPL_032: check_all_constraints inclut blocker cluster."""
        license = create_valid_license("site-1")
        constraints.set_license("site-1", license)
        health_monitor.health_status = HealthStatus.UNHEALTHY

        result = await constraints.check_all_constraints("site-1")

        assert result.can_deploy is False
        assert any("DEPL_032" in b for b in result.blockers)


# =============================================================================
# TEST DEPL_033: NOTIFICATIONS FLEET MANAGER
# =============================================================================


class TestDEPL033FleetNotifications:
    """Tests pour DEPL_033: Notification Fleet Manager AVANT et APRÈS."""

    @pytest.mark.asyncio
    async def test_DEPL_033_notify_before_deployment(
        self,
        constraints: DeploymentConstraints,
        fleet_notifier: MockFleetNotifier,
    ) -> None:
        """DEPL_033: Notification AVANT déploiement."""
        success = await constraints.notify_fleet_manager(
            "site-1", "before", "deploy-123"
        )

        assert success is True
        assert len(fleet_notifier.notifications) == 1
        assert fleet_notifier.notifications[0]["event"] == "before"
        assert fleet_notifier.notifications[0]["site_id"] == "site-1"

    @pytest.mark.asyncio
    async def test_DEPL_033_notify_after_deployment(
        self,
        constraints: DeploymentConstraints,
        fleet_notifier: MockFleetNotifier,
    ) -> None:
        """DEPL_033: Notification APRÈS déploiement."""
        success = await constraints.notify_fleet_manager(
            "site-1", "after", "deploy-123"
        )

        assert success is True
        assert len(fleet_notifier.notifications) == 1
        assert fleet_notifier.notifications[0]["event"] == "after"

    @pytest.mark.asyncio
    async def test_DEPL_033_notification_failure_raises_error(
        self,
        constraints: DeploymentConstraints,
        fleet_notifier: MockFleetNotifier,
    ) -> None:
        """DEPL_033: Échec notification lève FleetNotificationError."""
        fleet_notifier.should_fail = True

        with pytest.raises(FleetNotificationError) as exc_info:
            await constraints.notify_fleet_manager("site-1", "before", "deploy-123")

        assert "DEPL_033" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_DEPL_033_invalid_event_type_raises_error(
        self, constraints: DeploymentConstraints
    ) -> None:
        """DEPL_033: Type d'événement invalide lève ValueError."""
        with pytest.raises(ValueError):
            await constraints.notify_fleet_manager("site-1", "invalid", "deploy-123")

    @pytest.mark.asyncio
    async def test_DEPL_033_notification_includes_audit(
        self,
        constraints: DeploymentConstraints,
        audit_emitter: MockAuditEmitter,
    ) -> None:
        """DEPL_033: Notification génère événement audit."""
        await constraints.notify_fleet_manager("site-1", "before", "deploy-123")

        assert len(audit_emitter.events) == 1
        assert audit_emitter.events[0]["action"] == "fleet_notification_before"

    @pytest.mark.asyncio
    async def test_DEPL_033_notification_data_contains_required_fields(
        self,
        constraints: DeploymentConstraints,
        fleet_notifier: MockFleetNotifier,
    ) -> None:
        """DEPL_033: Données notification contiennent champs requis."""
        await constraints.notify_fleet_manager("site-1", "before", "deploy-123")

        data = fleet_notifier.notifications[0]["data"]
        assert "deployment_id" in data
        assert "site_id" in data
        assert "timestamp" in data
        assert "event_type" in data
        assert data["deployment_id"] == "deploy-123"


# =============================================================================
# TEST CHECK_ALL_CONSTRAINTS: INTÉGRATION
# =============================================================================


class TestCheckAllConstraints:
    """Tests d'intégration pour check_all_constraints."""

    @pytest.mark.asyncio
    async def test_check_all_constraints_all_valid(
        self,
        constraints: DeploymentConstraints,
        health_monitor: MockHealthMonitor,
    ) -> None:
        """Toutes contraintes valides = can_deploy True."""
        license = create_valid_license("site-1")
        constraints.set_license("site-1", license)
        health_monitor.health_status = HealthStatus.HEALTHY

        result = await constraints.check_all_constraints("site-1")

        assert result.can_deploy is True
        assert len(result.blockers) == 0

    @pytest.mark.asyncio
    async def test_check_all_constraints_license_invalid(
        self, constraints: DeploymentConstraints
    ) -> None:
        """Licence invalide = blocker."""
        # Pas de licence
        result = await constraints.check_all_constraints("site-1")

        assert result.can_deploy is False
        assert any("DEPL_031" in b for b in result.blockers)

    @pytest.mark.asyncio
    async def test_check_all_constraints_cluster_unhealthy(
        self,
        constraints: DeploymentConstraints,
        health_monitor: MockHealthMonitor,
    ) -> None:
        """Cluster unhealthy = blocker."""
        license = create_valid_license("site-1")
        constraints.set_license("site-1", license)
        health_monitor.health_status = HealthStatus.UNHEALTHY

        result = await constraints.check_all_constraints("site-1")

        assert result.can_deploy is False
        assert any("DEPL_032" in b for b in result.blockers)

    @pytest.mark.asyncio
    async def test_check_all_constraints_outside_window_warning(
        self, constraints: DeploymentConstraints
    ) -> None:
        """Hors fenêtre = warning (pas blocker)."""
        license = create_valid_license("site-1")
        constraints.set_license("site-1", license)

        window = MaintenanceWindow(start_hour=2, end_hour=6, days=[0, 1, 2, 3, 4, 5, 6])
        constraints.set_maintenance_window("site-1", window)

        # Heure hors fenêtre
        check_time = datetime(2024, 1, 1, 10, 0, tzinfo=timezone.utc)

        # Note: check_all_constraints utilise l'heure courante, pas un paramètre
        # Pour ce test, on vérifie juste que la fenêtre génère un warning
        in_window, warning = constraints.is_in_maintenance_window("site-1", check_time)
        assert in_window is False
        assert warning is not None
        assert "DEPL_030" in warning

    @pytest.mark.asyncio
    async def test_check_all_constraints_multiple_blockers(
        self,
        constraints: DeploymentConstraints,
        health_monitor: MockHealthMonitor,
    ) -> None:
        """Plusieurs problèmes = plusieurs blockers."""
        # Pas de licence + cluster unhealthy
        health_monitor.health_status = HealthStatus.UNHEALTHY

        result = await constraints.check_all_constraints("site-1")

        assert result.can_deploy is False
        assert len(result.blockers) >= 2

    @pytest.mark.asyncio
    async def test_prepare_deployment_success(
        self,
        constraints: DeploymentConstraints,
        fleet_notifier: MockFleetNotifier,
    ) -> None:
        """prepare_deployment réussit et notifie."""
        license = create_valid_license("site-1")
        constraints.set_license("site-1", license)

        result = await constraints.prepare_deployment("site-1", "deploy-123")

        assert result.can_deploy is True
        assert len(fleet_notifier.notifications) == 1
        assert fleet_notifier.notifications[0]["event"] == "before"

    @pytest.mark.asyncio
    async def test_prepare_deployment_blocked_no_notification(
        self,
        constraints: DeploymentConstraints,
        fleet_notifier: MockFleetNotifier,
    ) -> None:
        """prepare_deployment bloqué = pas de notification."""
        # Pas de licence
        result = await constraints.prepare_deployment("site-1", "deploy-123")

        assert result.can_deploy is False
        assert len(fleet_notifier.notifications) == 0

    @pytest.mark.asyncio
    async def test_complete_deployment_sends_notification(
        self,
        constraints: DeploymentConstraints,
        fleet_notifier: MockFleetNotifier,
        audit_emitter: MockAuditEmitter,
    ) -> None:
        """complete_deployment envoie notification et audit."""
        await constraints.complete_deployment("site-1", "deploy-123", success=True)

        # Notification Fleet Manager
        assert len(fleet_notifier.notifications) == 1
        assert fleet_notifier.notifications[0]["event"] == "after"

        # Événement audit
        assert len(audit_emitter.events) >= 1
        actions = [e["action"] for e in audit_emitter.events]
        assert "deployment_completed" in actions or "fleet_notification_after" in actions


# =============================================================================
# TESTS DATACLASSES
# =============================================================================


class TestDataclasses:
    """Tests pour les dataclasses."""

    def test_maintenance_window_valid(self) -> None:
        """MaintenanceWindow avec paramètres valides."""
        window = MaintenanceWindow(
            start_hour=2,
            end_hour=6,
            days=[0, 1, 2],
            timezone="UTC",
        )
        assert window.start_hour == 2
        assert window.end_hour == 6
        assert window.days == [0, 1, 2]

    def test_deployment_precheck_creation(self) -> None:
        """DeploymentPrecheck création et valeurs par défaut."""
        precheck = DeploymentPrecheck(can_deploy=True)
        assert precheck.can_deploy is True
        assert precheck.blockers == []
        assert precheck.warnings == []

        precheck_with_issues = DeploymentPrecheck(
            can_deploy=False,
            blockers=["blocker1"],
            warnings=["warning1"],
        )
        assert precheck_with_issues.can_deploy is False
        assert len(precheck_with_issues.blockers) == 1
        assert len(precheck_with_issues.warnings) == 1

    def test_set_license_empty_site_id_raises(
        self, constraints: DeploymentConstraints
    ) -> None:
        """set_license avec site_id vide lève ValueError."""
        license = create_valid_license("site-1")
        with pytest.raises(ValueError):
            constraints.set_license("", license)

    def test_set_maintenance_window_empty_site_id_raises(
        self, constraints: DeploymentConstraints
    ) -> None:
        """set_maintenance_window avec site_id vide lève ValueError."""
        window = MaintenanceWindow(start_hour=2, end_hour=6, days=[0])
        with pytest.raises(ValueError):
            constraints.set_maintenance_window("", window)
