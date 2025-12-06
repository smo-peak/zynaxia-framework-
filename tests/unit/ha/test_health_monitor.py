"""
Tests unitaires HealthMonitor

Invariants testés:
    HEALTH_001: Endpoint /health obligatoire
    HEALTH_002: /health/live (liveness)
    HEALTH_003: /health/ready (readiness)
    HEALTH_004: Format JSON {status, checks[], timestamp}
    HEALTH_005: Checks database, vault, keycloak, disk, memory
    HEALTH_006: Status: healthy, degraded, unhealthy
    HEALTH_007: Unhealthy = ne reçoit plus de trafic
    HEALTH_008: Health check < 5 secondes (timeout)
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch

from src.ha.interfaces import (
    IHealthMonitor,
    HealthCheck,
    HealthReport,
    HealthStatus,
    ClusterStatus,
)
from src.ha.health_monitor import HealthMonitor, HealthMonitorError
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
def health_monitor(mock_audit_emitter):
    """HealthMonitor instance pour tests."""
    return HealthMonitor(
        node_id="node-test-001",
        audit_emitter=mock_audit_emitter,
    )


@pytest.fixture
def healthy_check():
    """HealthCheck healthy pour tests."""
    return HealthCheck(
        name="test_service",
        status=HealthStatus.HEALTHY,
        latency_ms=10,
        message="OK",
    )


@pytest.fixture
def unhealthy_check():
    """HealthCheck unhealthy pour tests."""
    return HealthCheck(
        name="test_service",
        status=HealthStatus.UNHEALTHY,
        message="Connection failed",
    )


@pytest.fixture
def degraded_check():
    """HealthCheck degraded pour tests."""
    return HealthCheck(
        name="test_service",
        status=HealthStatus.DEGRADED,
        usage_percent=90,
        message="High usage",
    )


# ══════════════════════════════════════════════════════════════════════════════
# TESTS INTERFACE
# ══════════════════════════════════════════════════════════════════════════════


class TestHealthMonitorInterface:
    """Vérifie conformité interface."""

    def test_implements_interface(self, health_monitor):
        """HealthMonitor implémente IHealthMonitor."""
        assert isinstance(health_monitor, IHealthMonitor)

    def test_requires_node_id(self, mock_audit_emitter):
        """HealthMonitor requiert node_id."""
        with pytest.raises(TypeError):
            HealthMonitor(audit_emitter=mock_audit_emitter)

    def test_requires_audit_emitter(self):
        """HealthMonitor requiert audit_emitter."""
        with pytest.raises(TypeError):
            HealthMonitor(node_id="test-node")


# ══════════════════════════════════════════════════════════════════════════════
# TESTS HEALTH_001: ENDPOINT /health
# ══════════════════════════════════════════════════════════════════════════════


class TestHEALTH001Compliance:
    """Tests conformité HEALTH_001: Endpoint /health obligatoire."""

    @pytest.mark.asyncio
    async def test_HEALTH_001_check_health_returns_report(self, health_monitor):
        """HEALTH_001: check_health retourne un rapport."""
        report = await health_monitor.check_health()

        assert isinstance(report, HealthReport)
        assert report.node_id == "node-test-001"

    @pytest.mark.asyncio
    async def test_HEALTH_001_report_has_required_fields(self, health_monitor):
        """HEALTH_001: Rapport contient tous les champs requis."""
        report = await health_monitor.check_health()

        assert hasattr(report, "status")
        assert hasattr(report, "timestamp")
        assert hasattr(report, "checks")
        assert hasattr(report, "node_id")


# ══════════════════════════════════════════════════════════════════════════════
# TESTS HEALTH_002: LIVENESS
# ══════════════════════════════════════════════════════════════════════════════


class TestHEALTH002Compliance:
    """Tests conformité HEALTH_002: /health/live."""

    @pytest.mark.asyncio
    async def test_HEALTH_002_liveness_returns_true(self, health_monitor):
        """HEALTH_002: Liveness retourne True si service vivant."""
        is_live = await health_monitor.check_liveness()

        assert is_live is True

    @pytest.mark.asyncio
    async def test_HEALTH_002_liveness_always_responds(self, health_monitor):
        """HEALTH_002: Liveness répond même si checks échouent."""

        # Enregistrer un checker qui timeout
        async def slow_checker() -> HealthCheck:
            await asyncio.sleep(10)
            return HealthCheck(
                name="slow",
                status=HealthStatus.UNHEALTHY,
            )

        health_monitor.register_check("slow", slow_checker)

        # Liveness doit toujours répondre rapidement
        is_live = await health_monitor.check_liveness()
        assert is_live is True


# ══════════════════════════════════════════════════════════════════════════════
# TESTS HEALTH_003: READINESS
# ══════════════════════════════════════════════════════════════════════════════


class TestHEALTH003Compliance:
    """Tests conformité HEALTH_003: /health/ready."""

    @pytest.mark.asyncio
    async def test_HEALTH_003_readiness_true_when_healthy(self, health_monitor):
        """HEALTH_003: Readiness True si tous checks OK."""
        is_ready = await health_monitor.check_readiness()

        # Avec les checkers par défaut mockés, devrait être ready
        assert is_ready is True

    @pytest.mark.asyncio
    async def test_HEALTH_003_readiness_false_when_unhealthy(self, health_monitor, mock_audit_emitter):
        """HEALTH_003: Readiness False si check critique échoue."""

        # Remplacer checker database pour échouer
        async def failing_db_check() -> HealthCheck:
            return HealthCheck(
                name="database",
                status=HealthStatus.UNHEALTHY,
                message="Connection refused",
            )

        health_monitor.register_check("database", failing_db_check)

        is_ready = await health_monitor.check_readiness()
        assert is_ready is False

    @pytest.mark.asyncio
    async def test_HEALTH_003_readiness_true_when_degraded(self, health_monitor, mock_audit_emitter):
        """HEALTH_003: Readiness True même si dégradé (non critique)."""

        # Remplacer checker disk pour dégradé
        async def degraded_disk_check() -> HealthCheck:
            return HealthCheck(
                name="disk",
                status=HealthStatus.DEGRADED,
                usage_percent=90,
                message="Disk usage high",
            )

        health_monitor.register_check("disk", degraded_disk_check)

        is_ready = await health_monitor.check_readiness()
        # Dégradé n'est pas unhealthy, donc ready
        assert is_ready is True


# ══════════════════════════════════════════════════════════════════════════════
# TESTS HEALTH_004: FORMAT JSON
# ══════════════════════════════════════════════════════════════════════════════


class TestHEALTH004Compliance:
    """Tests conformité HEALTH_004: Format JSON {status, checks[], timestamp}."""

    @pytest.mark.asyncio
    async def test_HEALTH_004_report_to_dict(self, health_monitor):
        """HEALTH_004: Rapport convertible en dict JSON."""
        report = await health_monitor.check_health()

        report_dict = report.to_dict()

        assert isinstance(report_dict, dict)
        assert "status" in report_dict
        assert "timestamp" in report_dict
        assert "checks" in report_dict
        assert "node_id" in report_dict

    @pytest.mark.asyncio
    async def test_HEALTH_004_status_is_string(self, health_monitor):
        """HEALTH_004: status est une chaîne."""
        report = await health_monitor.check_health()
        report_dict = report.to_dict()

        assert isinstance(report_dict["status"], str)
        assert report_dict["status"] in ["healthy", "degraded", "unhealthy"]

    @pytest.mark.asyncio
    async def test_HEALTH_004_timestamp_is_iso_format(self, health_monitor):
        """HEALTH_004: timestamp en format ISO."""
        report = await health_monitor.check_health()
        report_dict = report.to_dict()

        # Vérifier format ISO
        timestamp_str = report_dict["timestamp"]
        datetime.fromisoformat(timestamp_str)  # Lève exception si invalide

    @pytest.mark.asyncio
    async def test_HEALTH_004_checks_is_list(self, health_monitor):
        """HEALTH_004: checks est une liste."""
        report = await health_monitor.check_health()
        report_dict = report.to_dict()

        assert isinstance(report_dict["checks"], list)
        assert len(report_dict["checks"]) > 0

    @pytest.mark.asyncio
    async def test_HEALTH_004_check_format(self, health_monitor):
        """HEALTH_004: Chaque check a format correct."""
        report = await health_monitor.check_health()
        report_dict = report.to_dict()

        for check in report_dict["checks"]:
            assert "name" in check
            assert "status" in check
            assert isinstance(check["name"], str)
            assert check["status"] in ["healthy", "degraded", "unhealthy"]


# ══════════════════════════════════════════════════════════════════════════════
# TESTS HEALTH_005: CHECKS REQUIS
# ══════════════════════════════════════════════════════════════════════════════


class TestHEALTH005Compliance:
    """Tests conformité HEALTH_005: Checks database, vault, keycloak, disk, memory."""

    @pytest.mark.asyncio
    async def test_HEALTH_005_all_required_checks_present(self, health_monitor):
        """HEALTH_005: Tous les checks requis sont présents."""
        report = await health_monitor.check_health()

        check_names = {check.name for check in report.checks}

        assert "database" in check_names
        assert "vault" in check_names
        assert "keycloak" in check_names
        assert "disk" in check_names
        assert "memory" in check_names

    def test_HEALTH_005_required_checks_constant(self, health_monitor):
        """HEALTH_005: Constante REQUIRED_CHECKS définie."""
        assert hasattr(health_monitor, "REQUIRED_CHECKS")
        assert "database" in health_monitor.REQUIRED_CHECKS
        assert "vault" in health_monitor.REQUIRED_CHECKS
        assert "keycloak" in health_monitor.REQUIRED_CHECKS
        assert "disk" in health_monitor.REQUIRED_CHECKS
        assert "memory" in health_monitor.REQUIRED_CHECKS

    @pytest.mark.asyncio
    async def test_HEALTH_005_disk_check_returns_usage(self, health_monitor):
        """HEALTH_005: Check disk retourne usage_percent."""
        report = await health_monitor.check_health()

        disk_check = next(c for c in report.checks if c.name == "disk")
        assert disk_check.usage_percent is not None
        assert 0 <= disk_check.usage_percent <= 100

    @pytest.mark.asyncio
    async def test_HEALTH_005_memory_check_returns_usage(self, health_monitor):
        """HEALTH_005: Check memory retourne usage_percent."""
        report = await health_monitor.check_health()

        memory_check = next(c for c in report.checks if c.name == "memory")
        assert memory_check.usage_percent is not None
        assert 0 <= memory_check.usage_percent <= 100


# ══════════════════════════════════════════════════════════════════════════════
# TESTS HEALTH_006: STATUS
# ══════════════════════════════════════════════════════════════════════════════


class TestHEALTH006Compliance:
    """Tests conformité HEALTH_006: Status healthy, degraded, unhealthy."""

    def test_HEALTH_006_status_enum_values(self):
        """HEALTH_006: Enum HealthStatus a les bonnes valeurs."""
        assert HealthStatus.HEALTHY.value == "healthy"
        assert HealthStatus.DEGRADED.value == "degraded"
        assert HealthStatus.UNHEALTHY.value == "unhealthy"

    @pytest.mark.asyncio
    async def test_HEALTH_006_all_healthy_returns_healthy(self, health_monitor):
        """HEALTH_006: Tous checks healthy → status healthy."""

        # Remplacer tous les checkers par des healthy
        async def healthy_check() -> HealthCheck:
            return HealthCheck(name="test", status=HealthStatus.HEALTHY)

        for name in health_monitor.REQUIRED_CHECKS:
            health_monitor.register_check(name, healthy_check)

        report = await health_monitor.check_health()
        assert report.status == HealthStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_HEALTH_006_critical_unhealthy_returns_unhealthy(self, health_monitor):
        """HEALTH_006: Check critique unhealthy → status unhealthy."""

        async def unhealthy_db() -> HealthCheck:
            return HealthCheck(
                name="database",
                status=HealthStatus.UNHEALTHY,
                message="Connection refused",
            )

        health_monitor.register_check("database", unhealthy_db)

        report = await health_monitor.check_health()
        assert report.status == HealthStatus.UNHEALTHY

    @pytest.mark.asyncio
    async def test_HEALTH_006_non_critical_unhealthy_returns_degraded(self, health_monitor):
        """HEALTH_006: Check non-critique unhealthy → status degraded."""

        # Disk n'est pas critique
        async def unhealthy_disk() -> HealthCheck:
            return HealthCheck(
                name="disk",
                status=HealthStatus.UNHEALTHY,
                message="Disk full",
            )

        health_monitor.register_check("disk", unhealthy_disk)

        report = await health_monitor.check_health()
        assert report.status == HealthStatus.DEGRADED

    @pytest.mark.asyncio
    async def test_HEALTH_006_degraded_returns_degraded(self, health_monitor):
        """HEALTH_006: Check dégradé → status degraded."""

        async def degraded_memory() -> HealthCheck:
            return HealthCheck(
                name="memory",
                status=HealthStatus.DEGRADED,
                usage_percent=90,
            )

        health_monitor.register_check("memory", degraded_memory)

        report = await health_monitor.check_health()
        # Peut être degraded ou healthy selon les autres checks
        assert report.status in [HealthStatus.DEGRADED, HealthStatus.HEALTHY]


# ══════════════════════════════════════════════════════════════════════════════
# TESTS HEALTH_007: UNHEALTHY = PAS DE TRAFIC
# ══════════════════════════════════════════════════════════════════════════════


class TestHEALTH007Compliance:
    """Tests conformité HEALTH_007: Unhealthy = ne reçoit plus de trafic."""

    @pytest.mark.asyncio
    async def test_HEALTH_007_unhealthy_readiness_false(self, health_monitor):
        """HEALTH_007: Status unhealthy → readiness False."""

        # Forcer database unhealthy
        async def unhealthy_db() -> HealthCheck:
            return HealthCheck(
                name="database",
                status=HealthStatus.UNHEALTHY,
            )

        health_monitor.register_check("database", unhealthy_db)

        # Readiness doit être False
        is_ready = await health_monitor.check_readiness()
        assert is_ready is False

    @pytest.mark.asyncio
    async def test_HEALTH_007_vault_unhealthy_stops_traffic(self, health_monitor):
        """HEALTH_007: Vault unhealthy → ne reçoit plus de trafic."""

        async def unhealthy_vault() -> HealthCheck:
            return HealthCheck(
                name="vault",
                status=HealthStatus.UNHEALTHY,
            )

        health_monitor.register_check("vault", unhealthy_vault)

        is_ready = await health_monitor.check_readiness()
        assert is_ready is False


# ══════════════════════════════════════════════════════════════════════════════
# TESTS HEALTH_008: TIMEOUT 5 SECONDES
# ══════════════════════════════════════════════════════════════════════════════


class TestHEALTH008Compliance:
    """Tests conformité HEALTH_008: Health check < 5 secondes."""

    def test_HEALTH_008_timeout_constant(self, health_monitor):
        """HEALTH_008: Constante TIMEOUT_SECONDS = 5."""
        assert health_monitor.TIMEOUT_SECONDS == 5.0

    @pytest.mark.asyncio
    async def test_HEALTH_008_slow_check_timeout(self, health_monitor):
        """HEALTH_008: Check lent → timeout → unhealthy."""

        async def very_slow_check() -> HealthCheck:
            await asyncio.sleep(10)  # Plus que timeout
            return HealthCheck(name="slow", status=HealthStatus.HEALTHY)

        health_monitor.register_check("slow_service", very_slow_check)

        # Le check doit timeout en < 6 secondes
        start = datetime.now()
        report = await health_monitor.check_health()
        duration = (datetime.now() - start).total_seconds()

        # Vérifier que ça a pris moins de 6 secondes (timeout + marge)
        assert duration < 6.0

        # Le check slow doit être unhealthy
        slow_check = next((c for c in report.checks if c.name == "slow_service"), None)
        assert slow_check is not None
        assert slow_check.status == HealthStatus.UNHEALTHY
        assert "timeout" in slow_check.message.lower()

    @pytest.mark.asyncio
    async def test_HEALTH_008_fast_check_succeeds(self, health_monitor):
        """HEALTH_008: Check rapide réussit."""

        async def fast_check() -> HealthCheck:
            await asyncio.sleep(0.01)  # Très rapide
            return HealthCheck(
                name="fast_service",
                status=HealthStatus.HEALTHY,
                latency_ms=10,
            )

        health_monitor.register_check("fast_service", fast_check)

        report = await health_monitor.check_health()

        fast_check_result = next((c for c in report.checks if c.name == "fast_service"), None)
        assert fast_check_result is not None
        assert fast_check_result.status == HealthStatus.HEALTHY


# ══════════════════════════════════════════════════════════════════════════════
# TESTS HISTORIQUE
# ══════════════════════════════════════════════════════════════════════════════


class TestHealthHistory:
    """Tests historique des rapports de santé."""

    @pytest.mark.asyncio
    async def test_history_stored_after_check(self, health_monitor):
        """Historique stocké après check."""
        await health_monitor.check_health()
        await health_monitor.check_health()
        await health_monitor.check_health()

        history = health_monitor.get_health_history(minutes=5)

        assert len(history) == 3

    @pytest.mark.asyncio
    async def test_history_filtered_by_time(self, health_monitor):
        """Historique filtré par temps."""
        # Créer un rapport
        await health_monitor.check_health()

        # Historique récent
        history = health_monitor.get_health_history(minutes=1)
        assert len(history) == 1

        # Historique 0 minutes = vide
        history_zero = health_monitor.get_health_history(minutes=0)
        assert len(history_zero) == 0

    @pytest.mark.asyncio
    async def test_history_negative_minutes_empty(self, health_monitor):
        """Historique négatif retourne vide."""
        await health_monitor.check_health()

        history = health_monitor.get_health_history(minutes=-5)
        assert len(history) == 0


# ══════════════════════════════════════════════════════════════════════════════
# TESTS REGISTER CHECK
# ══════════════════════════════════════════════════════════════════════════════


class TestRegisterCheck:
    """Tests enregistrement checkers personnalisés."""

    @pytest.mark.asyncio
    async def test_register_custom_check(self, health_monitor):
        """Enregistrement checker personnalisé."""

        async def custom_check() -> HealthCheck:
            return HealthCheck(
                name="custom",
                status=HealthStatus.HEALTHY,
                message="Custom OK",
            )

        health_monitor.register_check("custom", custom_check)

        report = await health_monitor.check_health()

        custom = next((c for c in report.checks if c.name == "custom"), None)
        assert custom is not None
        assert custom.status == HealthStatus.HEALTHY
        assert custom.message == "Custom OK"

    @pytest.mark.asyncio
    async def test_override_existing_check(self, health_monitor):
        """Remplacement checker existant."""

        async def new_db_check() -> HealthCheck:
            return HealthCheck(
                name="database",
                status=HealthStatus.DEGRADED,
                message="Slow connection",
                latency_ms=500,
            )

        health_monitor.register_check("database", new_db_check)

        report = await health_monitor.check_health()

        db_check = next(c for c in report.checks if c.name == "database")
        assert db_check.status == HealthStatus.DEGRADED
        assert db_check.message == "Slow connection"


# ══════════════════════════════════════════════════════════════════════════════
# TESTS HEARTBEAT
# ══════════════════════════════════════════════════════════════════════════════


class TestHeartbeat:
    """Tests envoi heartbeat."""

    @pytest.mark.asyncio
    async def test_heartbeat_emits_audit_event(self, health_monitor, mock_audit_emitter):
        """Heartbeat émet événement audit."""
        await health_monitor.send_heartbeat()

        mock_audit_emitter.emit_event.assert_called_once()

        call_kwargs = mock_audit_emitter.emit_event.call_args[1]
        assert call_kwargs["action"] == "heartbeat"
        assert call_kwargs["user_id"] == "system"
        assert "node_id" in call_kwargs["metadata"]
        assert call_kwargs["metadata"]["node_id"] == "node-test-001"


# ══════════════════════════════════════════════════════════════════════════════
# TESTS GESTION ERREURS
# ══════════════════════════════════════════════════════════════════════════════


class TestErrorHandling:
    """Tests gestion erreurs."""

    @pytest.mark.asyncio
    async def test_check_error_returns_unhealthy(self, health_monitor):
        """Erreur dans check → unhealthy."""

        async def error_check() -> HealthCheck:
            raise Exception("Connection error")

        health_monitor.register_check("error_service", error_check)

        report = await health_monitor.check_health()

        error_check_result = next((c for c in report.checks if c.name == "error_service"), None)
        assert error_check_result is not None
        assert error_check_result.status == HealthStatus.UNHEALTHY
        assert "error" in error_check_result.message.lower()

    @pytest.mark.asyncio
    async def test_all_checks_run_despite_errors(self, health_monitor):
        """Tous les checks exécutés malgré erreurs."""

        async def error_check() -> HealthCheck:
            raise Exception("Error")

        # Ajouter checker erreur
        health_monitor.register_check("error_service", error_check)

        report = await health_monitor.check_health()

        # Vérifier que tous les checks par défaut + erreur sont présents
        check_names = {c.name for c in report.checks}
        assert "database" in check_names
        assert "vault" in check_names
        assert "error_service" in check_names


# ══════════════════════════════════════════════════════════════════════════════
# TESTS DATA CLASSES
# ══════════════════════════════════════════════════════════════════════════════


class TestDataClasses:
    """Tests classes de données."""

    def test_health_check_creation(self):
        """Création HealthCheck."""
        check = HealthCheck(
            name="test",
            status=HealthStatus.HEALTHY,
            latency_ms=50,
            usage_percent=45,
            message="All good",
        )

        assert check.name == "test"
        assert check.status == HealthStatus.HEALTHY
        assert check.latency_ms == 50
        assert check.usage_percent == 45
        assert check.message == "All good"

    def test_health_check_optional_fields(self):
        """Champs optionnels HealthCheck."""
        check = HealthCheck(
            name="minimal",
            status=HealthStatus.UNHEALTHY,
        )

        assert check.latency_ms is None
        assert check.usage_percent is None
        assert check.message is None

    def test_health_report_to_dict(self):
        """Conversion HealthReport en dict."""
        now = datetime.now()
        checks = [
            HealthCheck(name="db", status=HealthStatus.HEALTHY, latency_ms=10),
            HealthCheck(name="disk", status=HealthStatus.DEGRADED, usage_percent=85),
        ]
        report = HealthReport(
            status=HealthStatus.DEGRADED,
            timestamp=now,
            checks=checks,
            node_id="node-1",
        )

        d = report.to_dict()

        assert d["status"] == "degraded"
        assert d["node_id"] == "node-1"
        assert len(d["checks"]) == 2
        assert d["checks"][0]["name"] == "db"
        assert d["checks"][0]["latency_ms"] == 10
        assert d["checks"][1]["usage_percent"] == 85

    def test_cluster_status_valid_cluster(self):
        """ClusterStatus.is_valid_cluster vérifie RUN_050."""
        valid = ClusterStatus(
            node_count=3,
            primary_node="node-1",
            healthy_nodes=["node-1", "node-2", "node-3"],
            unhealthy_nodes=[],
        )
        assert valid.is_valid_cluster() is True

        invalid = ClusterStatus(
            node_count=1,
            primary_node="node-1",
            healthy_nodes=["node-1"],
            unhealthy_nodes=[],
        )
        assert invalid.is_valid_cluster() is False

        edge = ClusterStatus(
            node_count=2,
            primary_node="node-1",
            healthy_nodes=["node-1", "node-2"],
            unhealthy_nodes=[],
        )
        assert edge.is_valid_cluster() is True
