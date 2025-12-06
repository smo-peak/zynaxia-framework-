"""
Tests unitaires pour BreachHandler (LOT 8 - PARTIE 2).

Vérifie les invariants:
    INCID_005: Breach confirmée = isolation automatique du tenant
    INCID_006: Breach = notification RSSI < 1 heure
    INCID_007: Breach = révocation tous tokens/sessions du tenant
    INCID_008: Breach = snapshot données pour forensics
"""

import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Tuple
from unittest.mock import AsyncMock, MagicMock

from src.incident.breach_handler import (
    BreachHandler,
    Breach,
    BreachResponse,
    ITenantIsolator,
    IRssiNotifier,
    IForensicCapture,
    TenantIsolationError,
    RssiNotificationError,
    ForensicCaptureError,
    BreachHandlerError,
)
from src.incident.interfaces import IncidentSeverity
from src.auth.interfaces import ISessionManager
from src.audit.interfaces import IAuditEmitter, AuditEvent, AuditEventType


# =============================================================================
# FIXTURES ET MOCKS
# =============================================================================


class MockTenantIsolator(ITenantIsolator):
    """Mock de l'isolateur de tenant."""

    def __init__(self) -> None:
        self.isolated_tenants: Dict[str, str] = {}  # tenant_id -> reason
        self.should_fail: bool = False

    async def isolate(self, tenant_id: str, reason: str) -> bool:
        if self.should_fail:
            raise Exception("Isolation service unavailable")
        self.isolated_tenants[tenant_id] = reason
        return True

    async def is_isolated(self, tenant_id: str) -> bool:
        return tenant_id in self.isolated_tenants

    async def restore(self, tenant_id: str, reason: str) -> bool:
        if tenant_id in self.isolated_tenants:
            del self.isolated_tenants[tenant_id]
            return True
        return False


class MockRssiNotifier(IRssiNotifier):
    """Mock du notifieur RSSI."""

    def __init__(self) -> None:
        self.notifications: List[Breach] = []
        self.should_fail: bool = False
        self.notification_delay: timedelta = timedelta(seconds=0)

    async def notify(self, breach: Breach) -> Tuple[bool, datetime]:
        if self.should_fail:
            raise Exception("RSSI notification service unavailable")
        self.notifications.append(breach)
        notified_at = datetime.now(timezone.utc) + self.notification_delay
        return True, notified_at


class MockForensicCapture(IForensicCapture):
    """Mock de la capture forensics."""

    def __init__(self) -> None:
        self.snapshots: Dict[str, Dict[str, Any]] = {}
        self.should_fail: bool = False
        self._snapshot_counter: int = 0

    async def capture_snapshot(self, tenant_id: str, breach_id: str) -> str:
        if self.should_fail:
            raise Exception("Forensic capture service unavailable")
        self._snapshot_counter += 1
        snapshot_id = f"snapshot-{self._snapshot_counter}"
        self.snapshots[snapshot_id] = {
            "tenant_id": tenant_id,
            "breach_id": breach_id,
            "captured_at": datetime.now(timezone.utc).isoformat(),
        }
        return snapshot_id

    async def get_snapshot(self, snapshot_id: str) -> Optional[Dict[str, Any]]:
        return self.snapshots.get(snapshot_id)


class MockSessionManager(ISessionManager):
    """Mock du gestionnaire de sessions."""

    def __init__(self) -> None:
        self.sessions: Dict[str, List[str]] = {}  # user_id -> session_ids
        self.revoked_sessions: List[str] = []
        self.should_fail: bool = False

    def add_user_sessions(self, user_id: str, session_ids: List[str]) -> None:
        self.sessions[user_id] = session_ids

    async def create_session(
        self,
        user_id: str,
        tenant_id: str,
        token_claims: Any,
    ) -> Any:
        from src.auth.interfaces import Session
        session_id = f"session-{user_id}-{len(self.sessions.get(user_id, []))}"
        if user_id not in self.sessions:
            self.sessions[user_id] = []
        self.sessions[user_id].append(session_id)
        return Session(
            session_id=session_id,
            user_id=user_id,
            tenant_id=tenant_id,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            revoked=False,
        )

    async def get_session(self, session_id: str) -> Optional[Any]:
        from src.auth.interfaces import Session
        for user_id, sessions in self.sessions.items():
            if session_id in sessions:
                return Session(
                    session_id=session_id,
                    user_id=user_id,
                    tenant_id="tenant-1",
                    created_at=datetime.now(timezone.utc),
                    expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                    revoked=False,
                )
        return None

    async def revoke_session(self, session_id: str, reason: str = "") -> bool:
        for user_id, sessions in self.sessions.items():
            if session_id in sessions:
                sessions.remove(session_id)
                self.revoked_sessions.append(session_id)
                return True
        return False

    async def revoke_all_user_sessions(self, user_id: str, reason: str = "") -> int:
        if self.should_fail:
            raise Exception("Session service unavailable")
        sessions = self.sessions.get(user_id, [])
        count = len(sessions)
        self.revoked_sessions.extend(sessions)
        self.sessions[user_id] = []
        return count

    async def is_session_valid(self, session_id: str) -> bool:
        for user_id, sessions in self.sessions.items():
            if session_id in sessions:
                return True
        return False


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


def create_breach(
    breach_id: str = "breach-001",
    tenant_id: str = "tenant-1",
    severity: IncidentSeverity = IncidentSeverity.CRITICAL,
    description: str = "Data exfiltration detected",
    detected_at: Optional[datetime] = None,
) -> Breach:
    """Crée une breach pour les tests."""
    return Breach(
        breach_id=breach_id,
        tenant_id=tenant_id,
        detected_at=detected_at or datetime.now(timezone.utc),
        severity=severity,
        description=description,
        source_indicators=["192.168.1.100", "user-suspicious"],
    )


@pytest.fixture
def isolator() -> MockTenantIsolator:
    return MockTenantIsolator()


@pytest.fixture
def session_manager() -> MockSessionManager:
    return MockSessionManager()


@pytest.fixture
def rssi_notifier() -> MockRssiNotifier:
    return MockRssiNotifier()


@pytest.fixture
def forensic_capture() -> MockForensicCapture:
    return MockForensicCapture()


@pytest.fixture
def audit_emitter() -> MockAuditEmitter:
    return MockAuditEmitter()


@pytest.fixture
def handler(
    isolator: MockTenantIsolator,
    session_manager: MockSessionManager,
    rssi_notifier: MockRssiNotifier,
    forensic_capture: MockForensicCapture,
    audit_emitter: MockAuditEmitter,
) -> BreachHandler:
    return BreachHandler(
        tenant_isolator=isolator,
        session_manager=session_manager,
        rssi_notifier=rssi_notifier,
        forensic_capture=forensic_capture,
        audit_emitter=audit_emitter,
    )


# =============================================================================
# TEST INCID_005: ISOLATION TENANT AUTOMATIQUE
# =============================================================================


class TestINCID005TenantIsolation:
    """Tests pour INCID_005: Breach confirmée = isolation automatique du tenant."""

    @pytest.mark.asyncio
    async def test_INCID_005_breach_triggers_isolation(
        self,
        handler: BreachHandler,
        isolator: MockTenantIsolator,
    ) -> None:
        """INCID_005: Une breach déclenche l'isolation du tenant."""
        breach = create_breach(tenant_id="tenant-compromised")

        response = await handler.handle_breach(breach)

        assert response.tenant_isolated is True
        assert "tenant-compromised" in isolator.isolated_tenants

    @pytest.mark.asyncio
    async def test_INCID_005_isolation_reason_contains_breach(
        self,
        handler: BreachHandler,
        isolator: MockTenantIsolator,
    ) -> None:
        """INCID_005: La raison d'isolation mentionne la breach."""
        breach = create_breach(tenant_id="tenant-1")

        await handler.handle_breach(breach)

        reason = isolator.isolated_tenants.get("tenant-1", "")
        assert "breach" in reason.lower() or "security" in reason.lower()

    @pytest.mark.asyncio
    async def test_INCID_005_isolation_is_immediate(
        self,
        handler: BreachHandler,
        isolator: MockTenantIsolator,
    ) -> None:
        """INCID_005: L'isolation est immédiate (fait partie des actions parallèles)."""
        breach = create_breach()

        response = await handler.handle_breach(breach)

        # L'isolation est faite pendant handle_breach
        assert response.tenant_isolated is True
        assert await isolator.is_isolated(breach.tenant_id) is True

    @pytest.mark.asyncio
    async def test_INCID_005_isolation_failure_recorded(
        self,
        handler: BreachHandler,
        isolator: MockTenantIsolator,
    ) -> None:
        """INCID_005: Échec d'isolation enregistré dans les erreurs."""
        isolator.should_fail = True
        breach = create_breach()

        response = await handler.handle_breach(breach)

        assert response.tenant_isolated is False
        assert any("isolation" in err.lower() for err in response.errors)

    @pytest.mark.asyncio
    async def test_INCID_005_isolation_audit_event(
        self,
        handler: BreachHandler,
        audit_emitter: MockAuditEmitter,
    ) -> None:
        """INCID_005: Isolation génère un événement d'audit."""
        breach = create_breach()

        await handler.handle_breach(breach)

        isolation_events = [
            e for e in audit_emitter.events
            if e["action"] == "tenant_isolated"
        ]
        assert len(isolation_events) >= 1

    @pytest.mark.asyncio
    async def test_INCID_005_multiple_breaches_same_tenant(
        self,
        handler: BreachHandler,
        isolator: MockTenantIsolator,
    ) -> None:
        """INCID_005: Plusieurs breaches sur même tenant = une seule isolation."""
        breach1 = create_breach(breach_id="breach-1", tenant_id="tenant-1")
        breach2 = create_breach(breach_id="breach-2", tenant_id="tenant-1")

        await handler.handle_breach(breach1)
        await handler.handle_breach(breach2)

        assert "tenant-1" in isolator.isolated_tenants
        # Tenant toujours isolé
        assert await isolator.is_isolated("tenant-1") is True

    @pytest.mark.asyncio
    async def test_INCID_005_different_tenants_independent(
        self,
        handler: BreachHandler,
        isolator: MockTenantIsolator,
    ) -> None:
        """INCID_005: Breaches sur différents tenants = isolations indépendantes."""
        breach1 = create_breach(tenant_id="tenant-1")
        breach2 = create_breach(tenant_id="tenant-2")

        await handler.handle_breach(breach1)

        assert await isolator.is_isolated("tenant-1") is True
        assert await isolator.is_isolated("tenant-2") is False

        await handler.handle_breach(breach2)

        assert await isolator.is_isolated("tenant-1") is True
        assert await isolator.is_isolated("tenant-2") is True

    @pytest.mark.asyncio
    async def test_INCID_005_isolation_continues_on_other_failures(
        self,
        handler: BreachHandler,
        isolator: MockTenantIsolator,
        rssi_notifier: MockRssiNotifier,
    ) -> None:
        """INCID_005: Isolation réussie même si autres services échouent."""
        rssi_notifier.should_fail = True
        breach = create_breach()

        response = await handler.handle_breach(breach)

        # Isolation réussie malgré échec RSSI
        assert response.tenant_isolated is True
        assert response.rssi_notified is False


# =============================================================================
# TEST INCID_006: NOTIFICATION RSSI < 1 HEURE
# =============================================================================


class TestINCID006RssiNotification:
    """Tests pour INCID_006: Breach = notification RSSI < 1 heure."""

    @pytest.mark.asyncio
    async def test_INCID_006_breach_notifies_rssi(
        self,
        handler: BreachHandler,
        rssi_notifier: MockRssiNotifier,
    ) -> None:
        """INCID_006: Une breach notifie le RSSI."""
        breach = create_breach()

        response = await handler.handle_breach(breach)

        assert response.rssi_notified is True
        assert len(rssi_notifier.notifications) == 1

    @pytest.mark.asyncio
    async def test_INCID_006_notification_timestamp_recorded(
        self,
        handler: BreachHandler,
    ) -> None:
        """INCID_006: Le timestamp de notification est enregistré."""
        breach = create_breach()

        response = await handler.handle_breach(breach)

        assert response.rssi_notified_at is not None
        assert isinstance(response.rssi_notified_at, datetime)

    @pytest.mark.asyncio
    async def test_INCID_006_notification_within_deadline(
        self,
        handler: BreachHandler,
    ) -> None:
        """INCID_006: Notification dans le délai de 1 heure."""
        detected_at = datetime.now(timezone.utc)
        breach = create_breach(detected_at=detected_at)

        response = await handler.handle_breach(breach)

        assert handler.verify_rssi_deadline_from_breach(breach, response) is True

    @pytest.mark.asyncio
    async def test_INCID_006_notification_failure_recorded(
        self,
        handler: BreachHandler,
        rssi_notifier: MockRssiNotifier,
    ) -> None:
        """INCID_006: Échec de notification enregistré."""
        rssi_notifier.should_fail = True
        breach = create_breach()

        response = await handler.handle_breach(breach)

        assert response.rssi_notified is False
        assert response.rssi_notified_at is None
        assert any("rssi" in err.lower() for err in response.errors)

    @pytest.mark.asyncio
    async def test_INCID_006_notification_audit_event(
        self,
        handler: BreachHandler,
        audit_emitter: MockAuditEmitter,
    ) -> None:
        """INCID_006: Notification génère un événement d'audit."""
        breach = create_breach()

        await handler.handle_breach(breach)

        rssi_events = [
            e for e in audit_emitter.events
            if e["action"] == "rssi_notified"
        ]
        assert len(rssi_events) >= 1

    @pytest.mark.asyncio
    async def test_INCID_006_breach_details_sent_to_rssi(
        self,
        handler: BreachHandler,
        rssi_notifier: MockRssiNotifier,
    ) -> None:
        """INCID_006: Les détails de la breach sont envoyés au RSSI."""
        breach = create_breach(
            breach_id="breach-critical",
            description="Critical data breach",
        )

        await handler.handle_breach(breach)

        notified_breach = rssi_notifier.notifications[0]
        assert notified_breach.breach_id == "breach-critical"
        assert notified_breach.description == "Critical data breach"

    @pytest.mark.asyncio
    async def test_INCID_006_verify_deadline_false_when_not_notified(
        self,
        handler: BreachHandler,
        rssi_notifier: MockRssiNotifier,
    ) -> None:
        """INCID_006: verify_deadline retourne False si non notifié."""
        rssi_notifier.should_fail = True
        breach = create_breach()

        response = await handler.handle_breach(breach)

        assert handler.verify_rssi_notification_deadline(response) is False

    @pytest.mark.asyncio
    async def test_INCID_006_rssi_deadline_constant(
        self,
        handler: BreachHandler,
    ) -> None:
        """INCID_006: La constante de deadline est 1 heure."""
        assert handler.RSSI_NOTIFICATION_DEADLINE == timedelta(hours=1)


# =============================================================================
# TEST INCID_007: REVOCATION TOKENS/SESSIONS
# =============================================================================


class TestINCID007TokenRevocation:
    """Tests pour INCID_007: Breach = révocation tous tokens/sessions du tenant."""

    @pytest.mark.asyncio
    async def test_INCID_007_breach_revokes_sessions(
        self,
        handler: BreachHandler,
        session_manager: MockSessionManager,
    ) -> None:
        """INCID_007: Une breach révoque les sessions du tenant."""
        session_manager.add_user_sessions("user-1", ["sess-1", "sess-2"])
        handler.register_tenant_users("tenant-1", ["user-1"])
        breach = create_breach(tenant_id="tenant-1")

        response = await handler.handle_breach(breach)

        assert response.sessions_revoked == 2

    @pytest.mark.asyncio
    async def test_INCID_007_all_users_revoked(
        self,
        handler: BreachHandler,
        session_manager: MockSessionManager,
    ) -> None:
        """INCID_007: Tous les utilisateurs du tenant sont révoqués."""
        session_manager.add_user_sessions("user-1", ["sess-1"])
        session_manager.add_user_sessions("user-2", ["sess-2", "sess-3"])
        session_manager.add_user_sessions("user-3", ["sess-4"])
        handler.register_tenant_users("tenant-1", ["user-1", "user-2", "user-3"])
        breach = create_breach(tenant_id="tenant-1")

        response = await handler.handle_breach(breach)

        assert response.sessions_revoked == 4

    @pytest.mark.asyncio
    async def test_INCID_007_tokens_equal_sessions(
        self,
        handler: BreachHandler,
        session_manager: MockSessionManager,
    ) -> None:
        """INCID_007: Nombre de tokens = nombre de sessions."""
        session_manager.add_user_sessions("user-1", ["sess-1", "sess-2"])
        handler.register_tenant_users("tenant-1", ["user-1"])
        breach = create_breach(tenant_id="tenant-1")

        response = await handler.handle_breach(breach)

        assert response.tokens_revoked == response.sessions_revoked

    @pytest.mark.asyncio
    async def test_INCID_007_no_users_no_revocation(
        self,
        handler: BreachHandler,
    ) -> None:
        """INCID_007: Pas d'utilisateurs = pas de révocation."""
        # Pas d'enregistrement d'utilisateurs
        breach = create_breach(tenant_id="tenant-empty")

        response = await handler.handle_breach(breach)

        assert response.sessions_revoked == 0
        assert response.tokens_revoked == 0

    @pytest.mark.asyncio
    async def test_INCID_007_revocation_continues_on_failure(
        self,
        handler: BreachHandler,
        session_manager: MockSessionManager,
    ) -> None:
        """INCID_007: Révocation continue même si un utilisateur échoue."""
        session_manager.add_user_sessions("user-1", ["sess-1"])
        session_manager.add_user_sessions("user-2", ["sess-2"])
        handler.register_tenant_users("tenant-1", ["user-1", "user-2"])

        # Simuler un échec pour user-1 seulement
        original_revoke = session_manager.revoke_all_user_sessions
        call_count = 0

        async def partial_fail(user_id: str, reason: str = "") -> int:
            nonlocal call_count
            call_count += 1
            if user_id == "user-1":
                raise Exception("Service error")
            return await original_revoke(user_id, reason)

        session_manager.revoke_all_user_sessions = partial_fail
        breach = create_breach(tenant_id="tenant-1")

        response = await handler.handle_breach(breach)

        # user-2 devrait quand même être révoqué
        assert response.sessions_revoked >= 1

    @pytest.mark.asyncio
    async def test_INCID_007_revocation_audit_event(
        self,
        handler: BreachHandler,
        session_manager: MockSessionManager,
        audit_emitter: MockAuditEmitter,
    ) -> None:
        """INCID_007: Révocation génère un événement d'audit."""
        session_manager.add_user_sessions("user-1", ["sess-1"])
        handler.register_tenant_users("tenant-1", ["user-1"])
        breach = create_breach(tenant_id="tenant-1")

        await handler.handle_breach(breach)

        revoke_events = [
            e for e in audit_emitter.events
            if e["action"] == "all_access_revoked"
        ]
        assert len(revoke_events) >= 1

    @pytest.mark.asyncio
    async def test_INCID_007_revocation_reason_mentions_breach(
        self,
        handler: BreachHandler,
        session_manager: MockSessionManager,
    ) -> None:
        """INCID_007: La raison de révocation mentionne la breach."""
        session_manager.add_user_sessions("user-1", ["sess-1"])
        handler.register_tenant_users("tenant-1", ["user-1"])

        # Capturer la raison
        captured_reason = ""
        original_revoke = session_manager.revoke_all_user_sessions

        async def capture_reason(user_id: str, reason: str = "") -> int:
            nonlocal captured_reason
            captured_reason = reason
            return await original_revoke(user_id, reason)

        session_manager.revoke_all_user_sessions = capture_reason
        breach = create_breach(tenant_id="tenant-1")

        await handler.handle_breach(breach)

        assert "breach" in captured_reason.lower() or "security" in captured_reason.lower()

    @pytest.mark.asyncio
    async def test_INCID_007_other_tenants_unaffected(
        self,
        handler: BreachHandler,
        session_manager: MockSessionManager,
    ) -> None:
        """INCID_007: Les autres tenants ne sont pas affectés."""
        session_manager.add_user_sessions("user-1", ["sess-1"])  # tenant-1
        session_manager.add_user_sessions("user-2", ["sess-2"])  # tenant-2
        handler.register_tenant_users("tenant-1", ["user-1"])
        handler.register_tenant_users("tenant-2", ["user-2"])
        breach = create_breach(tenant_id="tenant-1")

        await handler.handle_breach(breach)

        # user-2 (tenant-2) ne devrait pas être révoqué
        assert "sess-2" in session_manager.sessions.get("user-2", [])

    @pytest.mark.asyncio
    async def test_INCID_007_register_multiple_times(
        self,
        handler: BreachHandler,
        session_manager: MockSessionManager,
    ) -> None:
        """INCID_007: Enregistrement multiple remplace les utilisateurs."""
        handler.register_tenant_users("tenant-1", ["user-1"])
        handler.register_tenant_users("tenant-1", ["user-2", "user-3"])
        session_manager.add_user_sessions("user-1", ["sess-1"])
        session_manager.add_user_sessions("user-2", ["sess-2"])
        session_manager.add_user_sessions("user-3", ["sess-3"])
        breach = create_breach(tenant_id="tenant-1")

        response = await handler.handle_breach(breach)

        # Seuls user-2 et user-3 (dernier enregistrement)
        assert response.sessions_revoked == 2

    @pytest.mark.asyncio
    async def test_INCID_007_empty_user_list(
        self,
        handler: BreachHandler,
    ) -> None:
        """INCID_007: Liste d'utilisateurs vide = pas de révocation."""
        handler.register_tenant_users("tenant-1", [])
        breach = create_breach(tenant_id="tenant-1")

        response = await handler.handle_breach(breach)

        assert response.sessions_revoked == 0


# =============================================================================
# TEST INCID_008: SNAPSHOT FORENSICS
# =============================================================================


class TestINCID008ForensicSnapshot:
    """Tests pour INCID_008: Breach = snapshot données pour forensics."""

    @pytest.mark.asyncio
    async def test_INCID_008_breach_creates_snapshot(
        self,
        handler: BreachHandler,
        forensic_capture: MockForensicCapture,
    ) -> None:
        """INCID_008: Une breach crée un snapshot forensics."""
        breach = create_breach()

        response = await handler.handle_breach(breach)

        assert response.forensic_snapshot_id is not None
        assert response.forensic_snapshot_id in forensic_capture.snapshots

    @pytest.mark.asyncio
    async def test_INCID_008_snapshot_contains_tenant_id(
        self,
        handler: BreachHandler,
        forensic_capture: MockForensicCapture,
    ) -> None:
        """INCID_008: Le snapshot contient le tenant_id."""
        breach = create_breach(tenant_id="tenant-forensic")

        response = await handler.handle_breach(breach)

        snapshot = forensic_capture.snapshots.get(response.forensic_snapshot_id)
        assert snapshot is not None
        assert snapshot["tenant_id"] == "tenant-forensic"

    @pytest.mark.asyncio
    async def test_INCID_008_snapshot_contains_breach_id(
        self,
        handler: BreachHandler,
        forensic_capture: MockForensicCapture,
    ) -> None:
        """INCID_008: Le snapshot contient le breach_id."""
        breach = create_breach(breach_id="breach-forensic")

        response = await handler.handle_breach(breach)

        snapshot = forensic_capture.snapshots.get(response.forensic_snapshot_id)
        assert snapshot is not None
        assert snapshot["breach_id"] == "breach-forensic"

    @pytest.mark.asyncio
    async def test_INCID_008_snapshot_failure_recorded(
        self,
        handler: BreachHandler,
        forensic_capture: MockForensicCapture,
    ) -> None:
        """INCID_008: Échec de snapshot enregistré."""
        forensic_capture.should_fail = True
        breach = create_breach()

        response = await handler.handle_breach(breach)

        assert response.forensic_snapshot_id is None
        assert any("forensic" in err.lower() for err in response.errors)

    @pytest.mark.asyncio
    async def test_INCID_008_snapshot_audit_event(
        self,
        handler: BreachHandler,
        audit_emitter: MockAuditEmitter,
    ) -> None:
        """INCID_008: Snapshot génère un événement d'audit."""
        breach = create_breach()

        await handler.handle_breach(breach)

        snapshot_events = [
            e for e in audit_emitter.events
            if e["action"] == "forensic_snapshot_created"
        ]
        assert len(snapshot_events) >= 1

    @pytest.mark.asyncio
    async def test_INCID_008_snapshot_unique_per_breach(
        self,
        handler: BreachHandler,
        forensic_capture: MockForensicCapture,
    ) -> None:
        """INCID_008: Chaque breach a un snapshot unique."""
        breach1 = create_breach(breach_id="breach-1")
        breach2 = create_breach(breach_id="breach-2")

        response1 = await handler.handle_breach(breach1)
        response2 = await handler.handle_breach(breach2)

        assert response1.forensic_snapshot_id != response2.forensic_snapshot_id

    @pytest.mark.asyncio
    async def test_INCID_008_get_snapshot_retrieves_data(
        self,
        handler: BreachHandler,
        forensic_capture: MockForensicCapture,
    ) -> None:
        """INCID_008: get_snapshot() récupère les données."""
        breach = create_breach()

        response = await handler.handle_breach(breach)

        snapshot = await forensic_capture.get_snapshot(response.forensic_snapshot_id)
        assert snapshot is not None
        assert "captured_at" in snapshot

    @pytest.mark.asyncio
    async def test_INCID_008_snapshot_continues_on_other_failures(
        self,
        handler: BreachHandler,
        forensic_capture: MockForensicCapture,
        rssi_notifier: MockRssiNotifier,
    ) -> None:
        """INCID_008: Snapshot créé même si autres services échouent."""
        rssi_notifier.should_fail = True
        breach = create_breach()

        response = await handler.handle_breach(breach)

        assert response.forensic_snapshot_id is not None


# =============================================================================
# TEST INTEGRATION HANDLE_BREACH
# =============================================================================


class TestHandleBreachIntegration:
    """Tests d'intégration pour handle_breach."""

    @pytest.mark.asyncio
    async def test_handle_breach_all_actions_parallel(
        self,
        handler: BreachHandler,
        session_manager: MockSessionManager,
    ) -> None:
        """handle_breach exécute toutes les actions."""
        session_manager.add_user_sessions("user-1", ["sess-1"])
        handler.register_tenant_users("tenant-1", ["user-1"])
        breach = create_breach()

        response = await handler.handle_breach(breach)

        assert response.tenant_isolated is True
        assert response.rssi_notified is True
        assert response.sessions_revoked >= 0
        assert response.forensic_snapshot_id is not None

    @pytest.mark.asyncio
    async def test_handle_breach_response_time_recorded(
        self,
        handler: BreachHandler,
    ) -> None:
        """handle_breach enregistre le temps de réponse."""
        breach = create_breach()

        response = await handler.handle_breach(breach)

        assert response.response_time_seconds >= 0

    @pytest.mark.asyncio
    async def test_handle_breach_stored_for_retrieval(
        self,
        handler: BreachHandler,
    ) -> None:
        """handle_breach stocke la réponse pour récupération."""
        breach = create_breach(breach_id="breach-stored")

        await handler.handle_breach(breach)

        retrieved = handler.get_breach_response("breach-stored")
        assert retrieved is not None
        assert retrieved.breach_id == "breach-stored"

    @pytest.mark.asyncio
    async def test_handle_breach_final_audit_event(
        self,
        handler: BreachHandler,
        audit_emitter: MockAuditEmitter,
    ) -> None:
        """handle_breach génère un événement d'audit final."""
        breach = create_breach()

        await handler.handle_breach(breach)

        final_events = [
            e for e in audit_emitter.events
            if e["action"] == "breach_response_completed"
        ]
        assert len(final_events) >= 1

    @pytest.mark.asyncio
    async def test_handle_breach_all_failures(
        self,
        handler: BreachHandler,
        isolator: MockTenantIsolator,
        rssi_notifier: MockRssiNotifier,
        forensic_capture: MockForensicCapture,
        session_manager: MockSessionManager,
    ) -> None:
        """handle_breach gère tous les échecs."""
        isolator.should_fail = True
        rssi_notifier.should_fail = True
        forensic_capture.should_fail = True
        session_manager.should_fail = True
        breach = create_breach()

        response = await handler.handle_breach(breach)

        assert response.tenant_isolated is False
        assert response.rssi_notified is False
        assert response.forensic_snapshot_id is None
        assert len(response.errors) >= 2  # Au moins isolation et rssi

    @pytest.mark.asyncio
    async def test_get_breach_response_not_found(
        self,
        handler: BreachHandler,
    ) -> None:
        """get_breach_response retourne None si non trouvée."""
        result = handler.get_breach_response("non-existent")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_all_breach_responses(
        self,
        handler: BreachHandler,
    ) -> None:
        """get_all_breach_responses retourne toutes les réponses."""
        breach1 = create_breach(breach_id="breach-1")
        breach2 = create_breach(breach_id="breach-2")

        await handler.handle_breach(breach1)
        await handler.handle_breach(breach2)

        all_responses = handler.get_all_breach_responses()

        assert len(all_responses) == 2
        assert "breach-1" in all_responses
        assert "breach-2" in all_responses

    @pytest.mark.asyncio
    async def test_clear_state(
        self,
        handler: BreachHandler,
    ) -> None:
        """clear_state efface l'état interne."""
        handler.register_tenant_users("tenant-1", ["user-1"])
        breach = create_breach()
        await handler.handle_breach(breach)

        handler.clear_state()

        assert handler.get_all_breach_responses() == {}


# =============================================================================
# TEST DATACLASSES
# =============================================================================


class TestDataclasses:
    """Tests pour les dataclasses."""

    def test_breach_creation(self) -> None:
        """Breach création correcte."""
        now = datetime.now(timezone.utc)
        breach = Breach(
            breach_id="b-123",
            tenant_id="t-456",
            detected_at=now,
            severity=IncidentSeverity.CRITICAL,
            description="Data leak",
            source_indicators=["ip-1", "user-1"],
            metadata={"key": "value"},
        )

        assert breach.breach_id == "b-123"
        assert breach.tenant_id == "t-456"
        assert breach.detected_at == now
        assert breach.severity == IncidentSeverity.CRITICAL
        assert breach.description == "Data leak"
        assert breach.source_indicators == ["ip-1", "user-1"]
        assert breach.metadata == {"key": "value"}

    def test_breach_default_values(self) -> None:
        """Breach valeurs par défaut."""
        breach = Breach(
            breach_id="b-123",
            tenant_id="t-456",
            detected_at=datetime.now(timezone.utc),
            severity=IncidentSeverity.HIGH,
            description="Test",
        )

        assert breach.source_indicators == []
        assert breach.metadata == {}

    def test_breach_response_creation(self) -> None:
        """BreachResponse création correcte."""
        now = datetime.now(timezone.utc)
        response = BreachResponse(
            breach_id="b-123",
            tenant_isolated=True,
            rssi_notified=True,
            rssi_notified_at=now,
            tokens_revoked=5,
            sessions_revoked=5,
            forensic_snapshot_id="snap-123",
            response_time_seconds=1.5,
            errors=["error1"],
        )

        assert response.breach_id == "b-123"
        assert response.tenant_isolated is True
        assert response.rssi_notified is True
        assert response.rssi_notified_at == now
        assert response.tokens_revoked == 5
        assert response.sessions_revoked == 5
        assert response.forensic_snapshot_id == "snap-123"
        assert response.response_time_seconds == 1.5
        assert response.errors == ["error1"]

    def test_breach_response_default_errors(self) -> None:
        """BreachResponse erreurs par défaut."""
        response = BreachResponse(
            breach_id="b-123",
            tenant_isolated=True,
            rssi_notified=True,
            rssi_notified_at=datetime.now(timezone.utc),
            tokens_revoked=0,
            sessions_revoked=0,
            forensic_snapshot_id=None,
            response_time_seconds=0.5,
        )

        assert response.errors == []


# =============================================================================
# TEST EXCEPTIONS
# =============================================================================


class TestExceptions:
    """Tests pour les exceptions."""

    def test_tenant_isolation_error(self) -> None:
        """TenantIsolationError création."""
        error = TenantIsolationError("Failed to isolate tenant")
        assert str(error) == "Failed to isolate tenant"

    def test_rssi_notification_error(self) -> None:
        """RssiNotificationError création."""
        error = RssiNotificationError("Failed to notify RSSI")
        assert str(error) == "Failed to notify RSSI"

    def test_forensic_capture_error(self) -> None:
        """ForensicCaptureError création."""
        error = ForensicCaptureError("Failed to capture")
        assert str(error) == "Failed to capture"

    def test_breach_handler_error(self) -> None:
        """BreachHandlerError création."""
        error = BreachHandlerError("General error")
        assert str(error) == "General error"
