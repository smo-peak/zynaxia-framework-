"""
Tests unitaires pour IntrusionDetector (LOT 8 - PARTIE 1).

Vérifie les invariants:
    INCID_001: Détection intrusion = alerte immédiate multi-canal
    INCID_002: Tentative accès non autorisé = log + alerte
    INCID_004: Activité anormale DB = alerte (queries inhabituelles)
"""

import pytest
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from unittest.mock import AsyncMock

from src.incident.intrusion_detector import IntrusionDetector, IntrusionDetectorError
from src.incident.interfaces import (
    IAlertDispatcher,
    SecurityAlert,
    AlertChannel,
    IncidentSeverity,
    IncidentType,
)
from src.audit.interfaces import IAuditEmitter, AuditEvent, AuditEventType


# =============================================================================
# FIXTURES
# =============================================================================


class MockAlertDispatcher(IAlertDispatcher):
    """Mock du dispatcher d'alertes."""

    def __init__(self) -> None:
        self.dispatched_alerts: List[Dict[str, Any]] = []
        self.should_fail = False

    async def dispatch(
        self, alert: SecurityAlert, channels: List[AlertChannel]
    ) -> bool:
        if self.should_fail:
            return False
        self.dispatched_alerts.append({
            "alert": alert,
            "channels": channels,
        })
        return True

    async def dispatch_to_channel(
        self, alert: SecurityAlert, channel: AlertChannel
    ) -> bool:
        if self.should_fail:
            return False
        self.dispatched_alerts.append({
            "alert": alert,
            "channels": [channel],
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
            "ip_address": ip_address,
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


@pytest.fixture
def alert_dispatcher() -> MockAlertDispatcher:
    return MockAlertDispatcher()


@pytest.fixture
def audit_emitter() -> MockAuditEmitter:
    return MockAuditEmitter()


@pytest.fixture
def detector(
    alert_dispatcher: MockAlertDispatcher,
    audit_emitter: MockAuditEmitter,
) -> IntrusionDetector:
    return IntrusionDetector(
        alert_dispatcher=alert_dispatcher,
        audit_emitter=audit_emitter,
    )


# =============================================================================
# TEST INCID_001: DÉTECTION INTRUSION = ALERTE MULTI-CANAL
# =============================================================================


class TestINCID001IntrusionDetection:
    """Tests pour INCID_001: Détection intrusion = alerte immédiate multi-canal."""

    @pytest.mark.asyncio
    async def test_INCID_001_intrusion_detected_sends_all_channels(
        self,
        detector: IntrusionDetector,
        alert_dispatcher: MockAlertDispatcher,
    ) -> None:
        """INCID_001: Intrusion détectée = alerte sur EMAIL, SMS, WEBHOOK, SYSLOG."""
        event = {
            "type": "privilege_escalation",
            "tenant_id": "tenant-1",
            "source_ip": "192.168.1.100",
            "user_id": "user-1",
        }

        alert = await detector.detect_intrusion(event)

        assert alert is not None
        assert len(alert_dispatcher.dispatched_alerts) == 1

        dispatched = alert_dispatcher.dispatched_alerts[0]
        channels = dispatched["channels"]

        # INCID_001: Tous les canaux doivent être notifiés
        assert AlertChannel.EMAIL in channels
        assert AlertChannel.SMS in channels
        assert AlertChannel.WEBHOOK in channels
        assert AlertChannel.SYSLOG in channels

    @pytest.mark.asyncio
    async def test_INCID_001_intrusion_alert_is_critical(
        self,
        detector: IntrusionDetector,
    ) -> None:
        """INCID_001: Alerte intrusion a sévérité CRITICAL."""
        event = {
            "type": "root_access_attempt",
            "tenant_id": "tenant-1",
        }

        alert = await detector.detect_intrusion(event)

        assert alert is not None
        assert alert.severity == IncidentSeverity.CRITICAL

    @pytest.mark.asyncio
    async def test_INCID_001_intrusion_audit_logged(
        self,
        detector: IntrusionDetector,
        audit_emitter: MockAuditEmitter,
    ) -> None:
        """INCID_001: Intrusion génère événement audit SECURITY_BREACH."""
        event = {
            "type": "session_hijacking",
            "tenant_id": "tenant-1",
            "user_id": "attacker",
            "source_ip": "10.0.0.1",
        }

        await detector.detect_intrusion(event)

        assert len(audit_emitter.events) == 1
        assert audit_emitter.events[0]["event_type"] == AuditEventType.SECURITY_BREACH
        assert audit_emitter.events[0]["action"] == "intrusion_detected"

    @pytest.mark.asyncio
    async def test_INCID_001_no_intrusion_returns_none(
        self,
        detector: IntrusionDetector,
        alert_dispatcher: MockAlertDispatcher,
    ) -> None:
        """INCID_001: Événement normal ne génère pas d'alerte intrusion."""
        event = {
            "type": "user_login",
            "tenant_id": "tenant-1",
            "user_id": "user-1",
        }

        alert = await detector.detect_intrusion(event)

        assert alert is None
        assert len(alert_dispatcher.dispatched_alerts) == 0

    @pytest.mark.asyncio
    async def test_INCID_001_explicit_intrusion_flag(
        self,
        detector: IntrusionDetector,
    ) -> None:
        """INCID_001: Flag is_intrusion explicite déclenche alerte."""
        event = {
            "type": "custom_event",
            "tenant_id": "tenant-1",
            "is_intrusion": True,
            "description": "Custom intrusion detected",
        }

        alert = await detector.detect_intrusion(event)

        assert alert is not None
        assert "Custom intrusion detected" in alert.description

    @pytest.mark.asyncio
    async def test_INCID_001_intrusion_contains_source_info(
        self,
        detector: IntrusionDetector,
    ) -> None:
        """INCID_001: Alerte contient informations source."""
        event = {
            "type": "brute_force_detected",
            "tenant_id": "tenant-1",
            "source_ip": "192.168.1.50",
            "user_id": "target-user",
        }

        alert = await detector.detect_intrusion(event)

        assert alert is not None
        assert alert.source_ip == "192.168.1.50"
        assert alert.user_id == "target-user"
        assert alert.tenant_id == "tenant-1"

    @pytest.mark.asyncio
    async def test_INCID_001_multiple_intrusion_types_detected(
        self,
        detector: IntrusionDetector,
    ) -> None:
        """INCID_001: Différents types d'intrusion sont détectés."""
        intrusion_types = [
            "privilege_escalation",
            "root_access_attempt",
            "admin_bypass",
            "authentication_bypass",
            "session_hijacking",
            "token_manipulation",
            "brute_force_detected",
            "credential_stuffing",
        ]

        for intrusion_type in intrusion_types:
            event = {"type": intrusion_type, "tenant_id": "tenant-1"}
            alert = await detector.detect_intrusion(event)
            assert alert is not None, f"Should detect {intrusion_type}"

    @pytest.mark.asyncio
    async def test_INCID_001_intrusion_in_details(
        self,
        detector: IntrusionDetector,
    ) -> None:
        """INCID_001: Intrusion détectée dans les détails de l'événement."""
        event = {
            "type": "security_event",
            "tenant_id": "tenant-1",
            "details": "User attempted privilege_escalation via sudo exploit",
        }

        alert = await detector.detect_intrusion(event)

        assert alert is not None


# =============================================================================
# TEST INCID_002: ACCÈS NON AUTORISÉ = LOG + ALERTE
# =============================================================================


class TestINCID002UnauthorizedAccess:
    """Tests pour INCID_002: Tentative accès non autorisé = log + alerte."""

    @pytest.mark.asyncio
    async def test_INCID_002_unauthorized_access_generates_alert(
        self,
        detector: IntrusionDetector,
        alert_dispatcher: MockAlertDispatcher,
    ) -> None:
        """INCID_002: Accès non autorisé génère une alerte."""
        event = {
            "tenant_id": "tenant-1",
            "user_id": "user-1",
            "resource": "/api/admin/users",
            "source_ip": "10.0.0.5",
            "reason": "Insufficient permissions",
        }

        alert = await detector.log_unauthorized_access(event)

        assert alert is not None
        assert alert.incident_type == IncidentType.UNAUTHORIZED_ACCESS.value
        assert len(alert_dispatcher.dispatched_alerts) == 1

    @pytest.mark.asyncio
    async def test_INCID_002_unauthorized_access_logged(
        self,
        detector: IntrusionDetector,
        audit_emitter: MockAuditEmitter,
    ) -> None:
        """INCID_002: Accès non autorisé est loggé dans l'audit."""
        event = {
            "tenant_id": "tenant-1",
            "user_id": "user-1",
            "resource": "/api/data",
            "source_ip": "10.0.0.5",
            "reason": "Access denied",
        }

        await detector.log_unauthorized_access(event)

        assert len(audit_emitter.events) == 1
        assert audit_emitter.events[0]["action"] == "unauthorized_access_attempt"
        assert audit_emitter.events[0]["event_type"] == AuditEventType.FAILED_AUTH

    @pytest.mark.asyncio
    async def test_INCID_002_admin_resource_high_severity(
        self,
        detector: IntrusionDetector,
    ) -> None:
        """INCID_002: Accès admin = sévérité HIGH."""
        event = {
            "tenant_id": "tenant-1",
            "user_id": "user-1",
            "resource": "/admin/settings",
            "reason": "Not an admin",
        }

        alert = await detector.log_unauthorized_access(event)

        assert alert.severity == IncidentSeverity.HIGH

    @pytest.mark.asyncio
    async def test_INCID_002_root_resource_critical_severity(
        self,
        detector: IntrusionDetector,
    ) -> None:
        """INCID_002: Accès root = sévérité CRITICAL."""
        event = {
            "tenant_id": "tenant-1",
            "user_id": "user-1",
            "resource": "/root/config",
            "reason": "Root access denied",
        }

        alert = await detector.log_unauthorized_access(event)

        assert alert.severity == IncidentSeverity.CRITICAL

    @pytest.mark.asyncio
    async def test_INCID_002_normal_resource_medium_severity(
        self,
        detector: IntrusionDetector,
    ) -> None:
        """INCID_002: Accès ressource normale = sévérité MEDIUM."""
        event = {
            "tenant_id": "tenant-1",
            "user_id": "user-1",
            "resource": "/api/reports",
            "reason": "Permission denied",
        }

        alert = await detector.log_unauthorized_access(event)

        assert alert.severity == IncidentSeverity.MEDIUM

    @pytest.mark.asyncio
    async def test_INCID_002_alert_contains_resource_info(
        self,
        detector: IntrusionDetector,
    ) -> None:
        """INCID_002: Alerte contient infos sur la ressource."""
        event = {
            "tenant_id": "tenant-1",
            "user_id": "user-1",
            "resource": "/api/sensitive",
            "source_ip": "192.168.1.1",
            "reason": "Forbidden",
        }

        alert = await detector.log_unauthorized_access(event)

        assert "sensitive" in alert.description
        assert alert.source_ip == "192.168.1.1"
        assert alert.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_INCID_002_critical_uses_all_channels(
        self,
        detector: IntrusionDetector,
        alert_dispatcher: MockAlertDispatcher,
    ) -> None:
        """INCID_002: Accès CRITICAL utilise tous les canaux."""
        event = {
            "tenant_id": "tenant-1",
            "user_id": "user-1",
            "resource": "/security/keys",
            "reason": "Access denied",
        }

        await detector.log_unauthorized_access(event)

        channels = alert_dispatcher.dispatched_alerts[0]["channels"]
        assert AlertChannel.EMAIL in channels
        assert AlertChannel.SMS in channels

    @pytest.mark.asyncio
    async def test_INCID_002_non_critical_uses_syslog_webhook(
        self,
        detector: IntrusionDetector,
        alert_dispatcher: MockAlertDispatcher,
    ) -> None:
        """INCID_002: Accès non-critical utilise SYSLOG et WEBHOOK."""
        event = {
            "tenant_id": "tenant-1",
            "user_id": "user-1",
            "resource": "/api/data",
            "reason": "Access denied",
        }

        await detector.log_unauthorized_access(event)

        channels = alert_dispatcher.dispatched_alerts[0]["channels"]
        assert AlertChannel.SYSLOG in channels
        assert AlertChannel.WEBHOOK in channels


# =============================================================================
# TEST INCID_004: ACTIVITÉ DB ANORMALE = ALERTE
# =============================================================================


class TestINCID004DBAnomaly:
    """Tests pour INCID_004: Activité anormale DB = alerte."""

    @pytest.mark.asyncio
    async def test_INCID_004_drop_table_detected(
        self,
        detector: IntrusionDetector,
        alert_dispatcher: MockAlertDispatcher,
    ) -> None:
        """INCID_004: DROP TABLE détecté génère alerte CRITICAL."""
        query = "DROP TABLE users"

        alert = await detector.detect_db_anomaly(query, "tenant-1")

        assert alert is not None
        assert alert.severity == IncidentSeverity.CRITICAL
        assert alert.incident_type == IncidentType.DB_ANOMALY.value

    @pytest.mark.asyncio
    async def test_INCID_004_sql_injection_union_detected(
        self,
        detector: IntrusionDetector,
    ) -> None:
        """INCID_004: UNION SELECT (SQL injection) détecté."""
        query = "SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin"

        alert = await detector.detect_db_anomaly(query, "tenant-1")

        assert alert is not None
        assert "UNION" in str(alert.metadata.get("detected_patterns", []))

    @pytest.mark.asyncio
    async def test_INCID_004_delete_without_where_detected(
        self,
        detector: IntrusionDetector,
    ) -> None:
        """INCID_004: DELETE FROM sans WHERE condition spécifique détecté."""
        query = "DELETE FROM users WHERE 1=1"

        alert = await detector.detect_db_anomaly(query, "tenant-1")

        assert alert is not None

    @pytest.mark.asyncio
    async def test_INCID_004_comment_injection_detected(
        self,
        detector: IntrusionDetector,
    ) -> None:
        """INCID_004: Injection via commentaire SQL détectée."""
        query = "SELECT * FROM users WHERE name='admin'; --"

        alert = await detector.detect_db_anomaly(query, "tenant-1")

        assert alert is not None

    @pytest.mark.asyncio
    async def test_INCID_004_or_1_equals_1_detected(
        self,
        detector: IntrusionDetector,
    ) -> None:
        """INCID_004: OR 1=1 (bypass auth) détecté."""
        query = "SELECT * FROM users WHERE user='x' OR 1=1"

        alert = await detector.detect_db_anomaly(query, "tenant-1")

        assert alert is not None

    @pytest.mark.asyncio
    async def test_INCID_004_normal_query_no_alert(
        self,
        detector: IntrusionDetector,
        alert_dispatcher: MockAlertDispatcher,
    ) -> None:
        """INCID_004: Requête normale ne génère pas d'alerte."""
        query = "SELECT id, name FROM users WHERE tenant_id = 'tenant-1'"

        alert = await detector.detect_db_anomaly(query, "tenant-1")

        assert alert is None
        assert len(alert_dispatcher.dispatched_alerts) == 0

    @pytest.mark.asyncio
    async def test_INCID_004_empty_query_no_alert(
        self,
        detector: IntrusionDetector,
    ) -> None:
        """INCID_004: Requête vide ne génère pas d'alerte."""
        alert = await detector.detect_db_anomaly("", "tenant-1")
        assert alert is None

    @pytest.mark.asyncio
    async def test_INCID_004_audit_logged(
        self,
        detector: IntrusionDetector,
        audit_emitter: MockAuditEmitter,
    ) -> None:
        """INCID_004: Anomalie DB génère événement audit."""
        query = "DROP DATABASE production"

        await detector.detect_db_anomaly(query, "tenant-1")

        assert len(audit_emitter.events) == 1
        assert audit_emitter.events[0]["action"] == "db_anomaly_detected"

    @pytest.mark.asyncio
    async def test_INCID_004_truncate_table_detected(
        self,
        detector: IntrusionDetector,
    ) -> None:
        """INCID_004: TRUNCATE TABLE détecté."""
        query = "TRUNCATE TABLE audit_logs"

        alert = await detector.detect_db_anomaly(query, "tenant-1")

        assert alert is not None
        assert alert.severity == IncidentSeverity.CRITICAL

    @pytest.mark.asyncio
    async def test_INCID_004_case_insensitive_detection(
        self,
        detector: IntrusionDetector,
    ) -> None:
        """INCID_004: Détection insensible à la casse."""
        queries = [
            "drop table users",
            "DROP TABLE users",
            "Drop Table users",
            "union select password",
            "UNION SELECT password",
        ]

        for query in queries:
            alert = await detector.detect_db_anomaly(query, "tenant-1")
            assert alert is not None, f"Should detect: {query}"


# =============================================================================
# TESTS UTILITAIRES
# =============================================================================


class TestUtilities:
    """Tests pour les méthodes utilitaires."""

    def test_is_suspicious_query_true(
        self,
        detector: IntrusionDetector,
    ) -> None:
        """is_suspicious_query retourne True pour requêtes suspectes."""
        assert detector.is_suspicious_query("DROP TABLE x") is True
        assert detector.is_suspicious_query("SELECT * UNION SELECT *") is True

    def test_is_suspicious_query_false(
        self,
        detector: IntrusionDetector,
    ) -> None:
        """is_suspicious_query retourne False pour requêtes normales."""
        assert detector.is_suspicious_query("SELECT * FROM users") is False
        assert detector.is_suspicious_query("INSERT INTO logs VALUES (1)") is False

    def test_get_suspicious_patterns(
        self,
        detector: IntrusionDetector,
    ) -> None:
        """get_suspicious_patterns retourne les patterns trouvés."""
        query = "DROP TABLE users; DELETE FROM logs WHERE 1=1"
        patterns = detector.get_suspicious_patterns(query)

        assert len(patterns) >= 2
        assert any("DROP" in p for p in patterns)

    def test_get_suspicious_patterns_empty(
        self,
        detector: IntrusionDetector,
    ) -> None:
        """get_suspicious_patterns retourne liste vide si rien trouvé."""
        patterns = detector.get_suspicious_patterns("SELECT id FROM users")
        assert patterns == []
