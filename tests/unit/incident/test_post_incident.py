"""
Tests unitaires pour PostIncidentManager (LOT 8 - PARTIE 3).

Vérifie les invariants:
    INCID_009: Post-incident = rapport obligatoire < 72h (RGPD)
    INCID_010: Incident ancré blockchain (preuve horodatée)
    INCID_011: Procédure incident testée trimestriellement
"""

import pytest
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List

from src.incident.post_incident import (
    PostIncidentManager,
    IncidentReport,
    ComplianceStatus,
    IncidentDrill,
    ReportDeadlineExceededError,
    DrillOverdueError,
    PostIncidentError,
)
from src.audit.interfaces import (
    IAuditEmitter,
    IBlockchainAnchor,
    AuditEvent,
    AuditEventType,
    AnchorReceipt,
)


# =============================================================================
# FIXTURES ET MOCKS
# =============================================================================


class MockBlockchainAnchor(IBlockchainAnchor):
    """Mock de l'ancrage blockchain."""

    def __init__(self) -> None:
        self.anchored_events: Dict[str, AnchorReceipt] = {}
        self.should_fail: bool = False
        self._tx_counter: int = 0

    async def anchor_event(self, event_hash: str) -> AnchorReceipt:
        if self.should_fail:
            raise Exception("Blockchain service unavailable")

        self._tx_counter += 1
        receipt = AnchorReceipt(
            event_hash=event_hash,
            blockchain_tx_id=f"tx-{self._tx_counter:06d}",
            block_height=1000 + self._tx_counter,
            anchor_timestamp=datetime.now(timezone.utc),
            confirmation_count=6,
            anchor_proof=f"proof-{self._tx_counter}",
        )
        self.anchored_events[event_hash] = receipt
        return receipt

    async def verify_anchor(self, receipt: AnchorReceipt) -> bool:
        return receipt.event_hash in self.anchored_events

    async def get_anchor_proof(self, event_hash: str) -> Optional[AnchorReceipt]:
        return self.anchored_events.get(event_hash)

    def requires_anchoring(self, event_type: AuditEventType) -> bool:
        return event_type in [
            AuditEventType.SECURITY_BREACH,
            AuditEventType.SYSTEM_CONFIG_CHANGE,
        ]


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


def create_drill(
    drill_id: str = "drill-001",
    executed_at: Optional[datetime] = None,
    scenario: str = "Data breach simulation",
    participants: Optional[List[str]] = None,
    success: bool = True,
    findings: Optional[List[str]] = None,
) -> IncidentDrill:
    """Crée un exercice pour les tests."""
    return IncidentDrill(
        drill_id=drill_id,
        executed_at=executed_at or datetime.now(timezone.utc),
        scenario=scenario,
        participants=participants or ["admin-1", "security-1"],
        success=success,
        findings=findings or [],
    )


@pytest.fixture
def blockchain() -> MockBlockchainAnchor:
    return MockBlockchainAnchor()


@pytest.fixture
def audit_emitter() -> MockAuditEmitter:
    return MockAuditEmitter()


@pytest.fixture
def manager(
    blockchain: MockBlockchainAnchor,
    audit_emitter: MockAuditEmitter,
) -> PostIncidentManager:
    return PostIncidentManager(
        blockchain_anchor=blockchain,
        audit_emitter=audit_emitter,
    )


# =============================================================================
# TEST INCID_009: RAPPORT < 72H RGPD
# =============================================================================


class TestINCID009ReportDeadline:
    """Tests pour INCID_009: Rapport obligatoire < 72h (RGPD)."""

    def test_INCID_009_report_deadline_constant(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_009: La constante de deadline est 72h."""
        assert manager.REPORT_DEADLINE == timedelta(hours=72)

    def test_INCID_009_create_report_sets_deadline(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_009: Création de rapport définit deadline 72h."""
        before = datetime.now(timezone.utc)
        report = manager.create_report("breach-1", "tenant-1")
        after = datetime.now(timezone.utc)

        expected_min = before + timedelta(hours=72)
        expected_max = after + timedelta(hours=72)

        assert report.deadline >= expected_min
        assert report.deadline <= expected_max

    def test_INCID_009_create_report_not_submitted(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_009: Rapport créé non soumis initialement."""
        report = manager.create_report("breach-1", "tenant-1")

        assert report.submitted is False
        assert report.submitted_at is None

    @pytest.mark.asyncio
    async def test_INCID_009_submit_before_deadline_ok(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_009: Soumission avant deadline réussit."""
        report = manager.create_report("breach-1", "tenant-1")
        content = {"description": "Incident report content"}

        updated = await manager.submit_report(report.report_id, content)

        assert updated.submitted is True
        assert updated.submitted_at is not None
        assert updated.content == content

    @pytest.mark.asyncio
    async def test_INCID_009_submit_after_deadline_raises(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_009: Soumission après deadline lève exception."""
        report = manager.create_report("breach-1", "tenant-1")
        # Modifier la deadline pour qu'elle soit dépassée
        report.deadline = datetime.now(timezone.utc) - timedelta(hours=1)

        with pytest.raises(ReportDeadlineExceededError) as exc_info:
            await manager.submit_report(report.report_id, {"content": "late"})

        assert "INCID_009" in str(exc_info.value)

    def test_INCID_009_is_report_on_time_submitted_before(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_009: is_report_on_time True si soumis avant deadline."""
        report = manager.create_report("breach-1", "tenant-1")
        report.submitted = True
        report.submitted_at = report.created_at + timedelta(hours=24)

        assert manager.is_report_on_time(report) is True

    def test_INCID_009_is_report_on_time_submitted_after(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_009: is_report_on_time False si soumis après deadline."""
        report = manager.create_report("breach-1", "tenant-1")
        report.submitted = True
        report.submitted_at = report.deadline + timedelta(hours=1)

        assert manager.is_report_on_time(report) is False

    def test_INCID_009_is_report_on_time_not_submitted_before_deadline(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_009: Non soumis mais avant deadline = True."""
        report = manager.create_report("breach-1", "tenant-1")
        # Deadline dans le futur

        assert manager.is_report_on_time(report) is True

    def test_INCID_009_is_report_on_time_not_submitted_after_deadline(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_009: Non soumis après deadline = False."""
        report = manager.create_report("breach-1", "tenant-1")
        report.deadline = datetime.now(timezone.utc) - timedelta(hours=1)

        assert manager.is_report_on_time(report) is False

    def test_INCID_009_get_overdue_reports(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_009: get_overdue_reports retourne rapports en retard."""
        # Rapport en retard
        report1 = manager.create_report("breach-1", "tenant-1")
        report1.deadline = datetime.now(timezone.utc) - timedelta(hours=1)

        # Rapport à temps
        report2 = manager.create_report("breach-2", "tenant-1")

        overdue = manager.get_overdue_reports()

        assert len(overdue) == 1
        assert overdue[0].report_id == report1.report_id

    def test_INCID_009_create_report_empty_breach_id_raises(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_009: breach_id vide lève exception."""
        with pytest.raises(ValueError):
            manager.create_report("", "tenant-1")

    def test_INCID_009_create_report_empty_tenant_id_raises(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_009: tenant_id vide lève exception."""
        with pytest.raises(ValueError):
            manager.create_report("breach-1", "")


# =============================================================================
# TEST INCID_010: ANCRAGE BLOCKCHAIN
# =============================================================================


class TestINCID010BlockchainAnchor:
    """Tests pour INCID_010: Incident ancré blockchain (preuve horodatée)."""

    @pytest.mark.asyncio
    async def test_INCID_010_submit_anchors_blockchain(
        self,
        manager: PostIncidentManager,
        blockchain: MockBlockchainAnchor,
    ) -> None:
        """INCID_010: Soumission ancre sur blockchain."""
        report = manager.create_report("breach-1", "tenant-1")

        await manager.submit_report(report.report_id, {"content": "test"})

        assert len(blockchain.anchored_events) >= 1

    @pytest.mark.asyncio
    async def test_INCID_010_report_has_anchor_id(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_010: Rapport soumis a un ID d'ancrage."""
        report = manager.create_report("breach-1", "tenant-1")

        updated = await manager.submit_report(report.report_id, {"content": "test"})

        assert updated.blockchain_anchor is not None
        assert updated.blockchain_anchor.startswith("tx-")

    @pytest.mark.asyncio
    async def test_INCID_010_anchor_incident_returns_tx_id(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_010: anchor_incident retourne transaction ID."""
        tx_id = await manager.anchor_incident(
            "incident-1",
            {"tenant_id": "tenant-1", "data": "test"},
        )

        assert tx_id is not None
        assert tx_id.startswith("tx-")

    @pytest.mark.asyncio
    async def test_INCID_010_anchor_creates_audit_event(
        self,
        manager: PostIncidentManager,
        audit_emitter: MockAuditEmitter,
    ) -> None:
        """INCID_010: Ancrage génère événement d'audit."""
        await manager.anchor_incident(
            "incident-1",
            {"tenant_id": "tenant-1"},
        )

        anchor_events = [
            e for e in audit_emitter.events
            if e["action"] == "incident_anchored_blockchain"
        ]
        assert len(anchor_events) >= 1

    @pytest.mark.asyncio
    async def test_INCID_010_anchor_contains_timestamp(
        self,
        manager: PostIncidentManager,
        audit_emitter: MockAuditEmitter,
    ) -> None:
        """INCID_010: Ancrage contient horodatage."""
        await manager.anchor_incident(
            "incident-1",
            {"tenant_id": "tenant-1"},
        )

        anchor_events = [
            e for e in audit_emitter.events
            if e["action"] == "incident_anchored_blockchain"
        ]
        assert "anchor_timestamp" in anchor_events[0]["metadata"]

    @pytest.mark.asyncio
    async def test_INCID_010_multiple_anchors_unique_tx(
        self,
        manager: PostIncidentManager,
        blockchain: MockBlockchainAnchor,
    ) -> None:
        """INCID_010: Plusieurs ancrages = TX uniques."""
        tx1 = await manager.anchor_incident("incident-1", {"tenant_id": "t1"})
        tx2 = await manager.anchor_incident("incident-2", {"tenant_id": "t2"})

        assert tx1 != tx2
        assert len(blockchain.anchored_events) >= 2

    @pytest.mark.asyncio
    async def test_INCID_010_blockchain_failure_propagates(
        self,
        manager: PostIncidentManager,
        blockchain: MockBlockchainAnchor,
    ) -> None:
        """INCID_010: Échec blockchain propagé."""
        blockchain.should_fail = True
        report = manager.create_report("breach-1", "tenant-1")

        with pytest.raises(Exception) as exc_info:
            await manager.submit_report(report.report_id, {"content": "test"})

        assert "Blockchain" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_INCID_010_compliance_status_anchored(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_010: ComplianceStatus reflète ancrage."""
        report = manager.create_report("breach-1", "tenant-1")
        await manager.submit_report(report.report_id, {"content": "test"})

        status = manager.get_compliance_status(report.report_id)

        assert status.blockchain_anchored is True


# =============================================================================
# TEST INCID_011: EXERCICE TRIMESTRIEL
# =============================================================================


class TestINCID011QuarterlyDrill:
    """Tests pour INCID_011: Procédure incident testée trimestriellement."""

    def test_INCID_011_drill_interval_constant(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_011: La constante d'intervalle est 90 jours."""
        assert manager.DRILL_INTERVAL == timedelta(days=90)

    def test_INCID_011_no_drill_requires_drill(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_011: Aucun exercice = exercice requis."""
        assert manager.is_drill_required() is True

    def test_INCID_011_recent_drill_no_requirement(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_011: Exercice récent = pas d'exercice requis."""
        drill = create_drill(executed_at=datetime.now(timezone.utc))
        manager.record_drill(drill)

        assert manager.is_drill_required() is False

    def test_INCID_011_old_drill_requires_new(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_011: Exercice > 90 jours = exercice requis."""
        old_date = datetime.now(timezone.utc) - timedelta(days=91)
        drill = create_drill(executed_at=old_date)
        manager.record_drill(drill)

        assert manager.is_drill_required() is True

    def test_INCID_011_exactly_90_days_no_requirement(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_011: Exercice exactement 90 jours = pas requis."""
        # Légèrement moins de 90 jours pour s'assurer qu'on est dans la limite
        exact_date = datetime.now(timezone.utc) - timedelta(days=89, hours=23)
        drill = create_drill(executed_at=exact_date)
        manager.record_drill(drill)

        assert manager.is_drill_required() is False

    def test_INCID_011_get_last_drill(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_011: get_last_drill retourne dernier exercice."""
        drill1 = create_drill(
            drill_id="drill-1",
            executed_at=datetime.now(timezone.utc) - timedelta(days=30),
        )
        drill2 = create_drill(
            drill_id="drill-2",
            executed_at=datetime.now(timezone.utc),
        )

        manager.record_drill(drill1)
        manager.record_drill(drill2)

        last = manager.get_last_drill()

        assert last is not None
        assert last.drill_id == "drill-2"

    def test_INCID_011_get_last_drill_none(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_011: get_last_drill retourne None si aucun."""
        assert manager.get_last_drill() is None

    def test_INCID_011_record_drill_validates_id(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_011: record_drill valide drill_id."""
        drill = create_drill(drill_id="")

        with pytest.raises(ValueError):
            manager.record_drill(drill)

    def test_INCID_011_record_drill_validates_scenario(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_011: record_drill valide scenario."""
        drill = create_drill(scenario="")

        with pytest.raises(ValueError):
            manager.record_drill(drill)

    def test_INCID_011_record_drill_validates_participants(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_011: record_drill valide participants."""
        # Créer directement un IncidentDrill avec participants vide
        drill = IncidentDrill(
            drill_id="drill-001",
            executed_at=datetime.now(timezone.utc),
            scenario="Test scenario",
            participants=[],
            success=True,
        )

        with pytest.raises(ValueError):
            manager.record_drill(drill)

    def test_INCID_011_get_days_until_drill(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_011: get_days_until_drill_required calcule jours restants."""
        drill = create_drill(
            executed_at=datetime.now(timezone.utc) - timedelta(days=60),
        )
        manager.record_drill(drill)

        days = manager.get_days_until_drill_required()

        assert days is not None
        assert 29 <= days <= 31  # ~30 jours restants

    def test_INCID_011_get_days_negative_when_overdue(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """INCID_011: Jours négatifs si en retard."""
        drill = create_drill(
            executed_at=datetime.now(timezone.utc) - timedelta(days=100),
        )
        manager.record_drill(drill)

        days = manager.get_days_until_drill_required()

        assert days is not None
        assert days < 0


# =============================================================================
# TEST COMPLIANCE STATUS
# =============================================================================


class TestComplianceStatus:
    """Tests pour le statut de conformité intégré."""

    @pytest.mark.asyncio
    async def test_compliance_status_all_compliant(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """Statut compliance tout conforme."""
        # Rapport soumis à temps
        report = manager.create_report("breach-1", "tenant-1")
        await manager.submit_report(report.report_id, {"content": "test"})

        # Exercice récent
        drill = create_drill()
        manager.record_drill(drill)

        status = manager.get_compliance_status(report.report_id)

        assert status.report_submitted_on_time is True
        assert status.blockchain_anchored is True
        assert status.last_drill_date is not None
        assert status.drill_overdue is False

    def test_compliance_status_report_not_found(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """Statut compliance rapport non trouvé."""
        with pytest.raises(KeyError):
            manager.get_compliance_status("non-existent")

    def test_compliance_status_drill_overdue(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """Statut compliance exercice en retard."""
        report = manager.create_report("breach-1", "tenant-1")

        # Pas d'exercice récent
        status = manager.get_compliance_status(report.report_id)

        assert status.drill_overdue is True

    def test_compliance_status_not_anchored(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """Statut compliance non ancré."""
        report = manager.create_report("breach-1", "tenant-1")
        # Pas de soumission

        status = manager.get_compliance_status(report.report_id)

        assert status.blockchain_anchored is False

    def test_compliance_status_report_late(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """Statut compliance rapport en retard."""
        report = manager.create_report("breach-1", "tenant-1")
        report.deadline = datetime.now(timezone.utc) - timedelta(hours=1)

        status = manager.get_compliance_status(report.report_id)

        assert status.report_submitted_on_time is False


# =============================================================================
# TEST UTILITIES
# =============================================================================


class TestUtilities:
    """Tests pour les utilitaires."""

    def test_get_report(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """get_report retourne le rapport."""
        report = manager.create_report("breach-1", "tenant-1")

        retrieved = manager.get_report(report.report_id)

        assert retrieved is not None
        assert retrieved.report_id == report.report_id

    def test_get_report_not_found(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """get_report retourne None si non trouvé."""
        assert manager.get_report("non-existent") is None

    def test_get_all_reports(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """get_all_reports retourne tous les rapports."""
        manager.create_report("breach-1", "tenant-1")
        manager.create_report("breach-2", "tenant-2")

        all_reports = manager.get_all_reports()

        assert len(all_reports) == 2

    def test_get_pending_reports(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """get_pending_reports retourne rapports en attente."""
        report1 = manager.create_report("breach-1", "tenant-1")
        report2 = manager.create_report("breach-2", "tenant-2")
        # Marquer report2 comme deadline dépassée
        report2.deadline = datetime.now(timezone.utc) - timedelta(hours=1)

        pending = manager.get_pending_reports()

        assert len(pending) == 1
        assert pending[0].report_id == report1.report_id

    def test_get_all_drills(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """get_all_drills retourne tous les exercices."""
        drill1 = create_drill(drill_id="drill-1")
        drill2 = create_drill(drill_id="drill-2")

        manager.record_drill(drill1)
        manager.record_drill(drill2)

        all_drills = manager.get_all_drills()

        assert len(all_drills) == 2

    def test_get_successful_drills(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """get_successful_drills filtre par succès."""
        drill1 = create_drill(drill_id="drill-1", success=True)
        drill2 = create_drill(drill_id="drill-2", success=False)

        manager.record_drill(drill1)
        manager.record_drill(drill2)

        successful = manager.get_successful_drills()

        assert len(successful) == 1
        assert successful[0].drill_id == "drill-1"

    def test_clear_state(
        self,
        manager: PostIncidentManager,
    ) -> None:
        """clear_state efface l'état."""
        manager.create_report("breach-1", "tenant-1")
        manager.record_drill(create_drill())

        manager.clear_state()

        assert manager.get_all_reports() == []
        assert manager.get_all_drills() == []


# =============================================================================
# TEST DATACLASSES
# =============================================================================


class TestDataclasses:
    """Tests pour les dataclasses."""

    def test_incident_report_creation(self) -> None:
        """IncidentReport création correcte."""
        now = datetime.now(timezone.utc)
        report = IncidentReport(
            report_id="rep-123",
            breach_id="breach-456",
            tenant_id="tenant-789",
            created_at=now,
            deadline=now + timedelta(hours=72),
            submitted=True,
            submitted_at=now + timedelta(hours=24),
            content={"description": "test"},
            blockchain_anchor="tx-001",
        )

        assert report.report_id == "rep-123"
        assert report.breach_id == "breach-456"
        assert report.submitted is True
        assert report.blockchain_anchor == "tx-001"

    def test_compliance_status_creation(self) -> None:
        """ComplianceStatus création correcte."""
        now = datetime.now(timezone.utc)
        status = ComplianceStatus(
            report_submitted_on_time=True,
            blockchain_anchored=True,
            last_drill_date=now,
            drill_overdue=False,
        )

        assert status.report_submitted_on_time is True
        assert status.blockchain_anchored is True
        assert status.drill_overdue is False

    def test_incident_drill_creation(self) -> None:
        """IncidentDrill création correcte."""
        now = datetime.now(timezone.utc)
        drill = IncidentDrill(
            drill_id="drill-123",
            executed_at=now,
            scenario="Ransomware attack simulation",
            participants=["admin-1", "security-1", "ops-1"],
            success=True,
            findings=["Need faster response time"],
        )

        assert drill.drill_id == "drill-123"
        assert drill.scenario == "Ransomware attack simulation"
        assert len(drill.participants) == 3
        assert drill.success is True
        assert len(drill.findings) == 1

    def test_incident_drill_default_findings(self) -> None:
        """IncidentDrill findings par défaut."""
        drill = IncidentDrill(
            drill_id="drill-123",
            executed_at=datetime.now(timezone.utc),
            scenario="Test",
            participants=["admin-1"],
            success=True,
        )

        assert drill.findings == []


# =============================================================================
# TEST EXCEPTIONS
# =============================================================================


class TestExceptions:
    """Tests pour les exceptions."""

    def test_report_deadline_exceeded_error(self) -> None:
        """ReportDeadlineExceededError création."""
        error = ReportDeadlineExceededError("Deadline exceeded")
        assert str(error) == "Deadline exceeded"

    def test_drill_overdue_error(self) -> None:
        """DrillOverdueError création."""
        error = DrillOverdueError("Drill overdue")
        assert str(error) == "Drill overdue"

    def test_post_incident_error(self) -> None:
        """PostIncidentError création."""
        error = PostIncidentError("General error")
        assert str(error) == "General error"


# =============================================================================
# TEST AUDIT EVENTS
# =============================================================================


class TestAuditEvents:
    """Tests pour les événements d'audit."""

    @pytest.mark.asyncio
    async def test_submit_report_audit_event(
        self,
        manager: PostIncidentManager,
        audit_emitter: MockAuditEmitter,
    ) -> None:
        """Soumission génère événement d'audit."""
        report = manager.create_report("breach-1", "tenant-1")
        await manager.submit_report(report.report_id, {"content": "test"})

        submit_events = [
            e for e in audit_emitter.events
            if e["action"] == "incident_report_submitted"
        ]
        assert len(submit_events) >= 1

    @pytest.mark.asyncio
    async def test_submit_report_audit_contains_metadata(
        self,
        manager: PostIncidentManager,
        audit_emitter: MockAuditEmitter,
    ) -> None:
        """Événement audit contient métadonnées."""
        report = manager.create_report("breach-1", "tenant-1")
        await manager.submit_report(report.report_id, {"content": "test"})

        submit_events = [
            e for e in audit_emitter.events
            if e["action"] == "incident_report_submitted"
        ]
        metadata = submit_events[0]["metadata"]

        assert "breach_id" in metadata
        assert "submitted_at" in metadata
        assert "blockchain_anchor" in metadata
        assert metadata["on_time"] is True
