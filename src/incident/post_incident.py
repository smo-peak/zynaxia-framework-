"""
LOT 8: Gestion post-incident et compliance

Implémente la gestion post-incident avec:
- Rapport obligatoire < 72h RGPD (INCID_009)
- Ancrage blockchain des incidents (INCID_010)
- Exercices trimestriels (INCID_011)

Invariants:
    INCID_009: Post-incident = rapport obligatoire < 72h (RGPD)
    INCID_010: Incident ancré blockchain (preuve horodatée)
    INCID_011: Procédure incident testée trimestriellement
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any

from src.audit.interfaces import IAuditEmitter, IBlockchainAnchor, AuditEventType


@dataclass
class IncidentReport:
    """
    Rapport d'incident post-breach.

    Contient les informations requises par le RGPD
    pour la notification d'une violation de données.
    """

    report_id: str
    breach_id: str
    tenant_id: str
    created_at: datetime
    deadline: datetime  # created_at + 72h (INCID_009)
    submitted: bool
    submitted_at: Optional[datetime]
    content: Dict[str, Any]  # Rapport structuré
    blockchain_anchor: Optional[str]  # INCID_010


@dataclass
class ComplianceStatus:
    """
    Statut de conformité pour un incident.

    Agrège les vérifications INCID_009, 010, 011.
    """

    report_submitted_on_time: bool  # INCID_009
    blockchain_anchored: bool  # INCID_010
    last_drill_date: Optional[datetime]  # INCID_011
    drill_overdue: bool  # > 90 jours


@dataclass
class IncidentDrill:
    """
    Exercice de procédure d'incident.

    Documente les exercices trimestriels requis
    par INCID_011.
    """

    drill_id: str
    executed_at: datetime
    scenario: str
    participants: List[str]
    success: bool
    findings: List[str] = field(default_factory=list)


class ReportDeadlineExceededError(Exception):
    """
    Deadline 72h RGPD dépassée.

    Invariant:
        INCID_009: Rapport obligatoire < 72h
    """

    pass


class DrillOverdueError(Exception):
    """
    Exercice trimestriel en retard.

    Invariant:
        INCID_011: Procédure testée trimestriellement
    """

    pass


class PostIncidentError(Exception):
    """Erreur générale post-incident."""

    pass


class PostIncidentManager:
    """
    Gestion post-incident et compliance.

    Orchestre:
    1. Création et soumission de rapports (INCID_009)
    2. Ancrage blockchain des incidents (INCID_010)
    3. Gestion des exercices trimestriels (INCID_011)

    Invariants:
        INCID_009: Post-incident = rapport obligatoire < 72h (RGPD)
        INCID_010: Incident ancré blockchain (preuve horodatée)
        INCID_011: Procédure incident testée trimestriellement
    """

    # INCID_009: Délai RGPD pour notification
    REPORT_DEADLINE: timedelta = timedelta(hours=72)

    # INCID_011: Intervalle maximum entre exercices
    DRILL_INTERVAL: timedelta = timedelta(days=90)

    def __init__(
        self,
        blockchain_anchor: IBlockchainAnchor,
        audit_emitter: IAuditEmitter,
    ) -> None:
        """
        Initialise le gestionnaire post-incident.

        Args:
            blockchain_anchor: Service d'ancrage blockchain
            audit_emitter: Émetteur d'événements d'audit
        """
        self._blockchain = blockchain_anchor
        self._audit = audit_emitter
        self._reports: Dict[str, IncidentReport] = {}
        self._drills: List[IncidentDrill] = []

    def create_report(self, breach_id: str, tenant_id: str) -> IncidentReport:
        """
        Crée un rapport d'incident avec deadline 72h.

        Args:
            breach_id: Identifiant de la breach associée
            tenant_id: Identifiant du tenant concerné

        Returns:
            IncidentReport avec deadline calculée

        Invariant:
            INCID_009: Deadline 72h automatiquement définie
        """
        if not breach_id or not breach_id.strip():
            raise ValueError("breach_id cannot be empty")
        if not tenant_id or not tenant_id.strip():
            raise ValueError("tenant_id cannot be empty")

        now = datetime.now(timezone.utc)
        report_id = f"report-{uuid.uuid4().hex[:12]}"

        report = IncidentReport(
            report_id=report_id,
            breach_id=breach_id,
            tenant_id=tenant_id,
            created_at=now,
            deadline=now + self.REPORT_DEADLINE,  # INCID_009
            submitted=False,
            submitted_at=None,
            content={},
            blockchain_anchor=None,
        )

        self._reports[report_id] = report
        return report

    async def submit_report(
        self, report_id: str, content: Dict[str, Any]
    ) -> IncidentReport:
        """
        Soumet un rapport d'incident.

        Args:
            report_id: Identifiant du rapport
            content: Contenu structuré du rapport

        Returns:
            IncidentReport mis à jour avec ancrage blockchain

        Raises:
            ReportDeadlineExceededError: Si deadline 72h dépassée
            KeyError: Si rapport non trouvé

        Invariants:
            INCID_009: Vérifie deadline 72h
            INCID_010: Ancre sur blockchain
        """
        if report_id not in self._reports:
            raise KeyError(f"Report {report_id} not found")

        report = self._reports[report_id]
        now = datetime.now(timezone.utc)

        # INCID_009: Vérifier deadline
        if now > report.deadline:
            raise ReportDeadlineExceededError(
                f"INCID_009 VIOLATION: Report deadline exceeded. "
                f"Deadline was {report.deadline.isoformat()}, "
                f"current time is {now.isoformat()}"
            )

        # Mettre à jour le rapport
        report.content = content
        report.submitted = True
        report.submitted_at = now

        # INCID_010: Ancrer sur blockchain
        anchor_id = await self.anchor_incident(
            report.report_id,
            {
                "report_id": report.report_id,
                "breach_id": report.breach_id,
                "tenant_id": report.tenant_id,
                "submitted_at": now.isoformat(),
                "content_hash": hash(str(content)),
            },
        )
        report.blockchain_anchor = anchor_id

        # Audit de soumission
        await self._audit.emit_event(
            event_type=AuditEventType.SECURITY_BREACH,
            user_id="system",
            tenant_id=report.tenant_id,
            action="incident_report_submitted",
            resource_id=report.report_id,
            metadata={
                "breach_id": report.breach_id,
                "submitted_at": now.isoformat(),
                "blockchain_anchor": anchor_id,
                "on_time": True,
            },
        )

        return report

    def is_report_on_time(self, report: IncidentReport) -> bool:
        """
        Vérifie si un rapport a été soumis dans les 72h.

        Args:
            report: Rapport à vérifier

        Returns:
            True si soumis avant deadline

        Invariant:
            INCID_009: Rapport < 72h
        """
        if not report.submitted or report.submitted_at is None:
            # Non soumis, vérifier si deadline passée
            now = datetime.now(timezone.utc)
            return now <= report.deadline

        return report.submitted_at <= report.deadline

    async def anchor_incident(self, incident_id: str, data: Dict[str, Any]) -> str:
        """
        Ancre un incident sur blockchain.

        Args:
            incident_id: Identifiant de l'incident
            data: Données à ancrer

        Returns:
            Transaction ID blockchain

        Invariant:
            INCID_010: Preuve horodatée blockchain
        """
        # Créer un hash des données
        data_str = str(sorted(data.items()))
        event_hash = f"{incident_id}:{hash(data_str)}"

        # Ancrer sur blockchain
        receipt = await self._blockchain.anchor_event(event_hash)

        # Audit de l'ancrage
        await self._audit.emit_event(
            event_type=AuditEventType.SYSTEM_CONFIG_CHANGE,
            user_id="system",
            tenant_id=data.get("tenant_id", "system"),
            action="incident_anchored_blockchain",
            resource_id=incident_id,
            metadata={
                "blockchain_tx_id": receipt.blockchain_tx_id,
                "block_height": receipt.block_height,
                "anchor_timestamp": receipt.anchor_timestamp.isoformat(),
            },
        )

        return receipt.blockchain_tx_id

    def record_drill(self, drill: IncidentDrill) -> None:
        """
        Enregistre un exercice de procédure d'incident.

        Args:
            drill: Exercice à enregistrer

        Invariant:
            INCID_011: Procédure testée trimestriellement
        """
        if not drill.drill_id or not drill.drill_id.strip():
            raise ValueError("drill_id cannot be empty")
        if not drill.scenario or not drill.scenario.strip():
            raise ValueError("scenario cannot be empty")
        if not drill.participants:
            raise ValueError("participants cannot be empty")

        self._drills.append(drill)
        # Trier par date décroissante
        self._drills.sort(key=lambda d: d.executed_at, reverse=True)

    def is_drill_required(self) -> bool:
        """
        Vérifie si un exercice est requis (> 90 jours).

        Returns:
            True si aucun exercice depuis > 90 jours

        Invariant:
            INCID_011: Exercice trimestriel obligatoire
        """
        if not self._drills:
            return True

        last_drill = self._drills[0]
        now = datetime.now(timezone.utc)
        time_since_last = now - last_drill.executed_at

        return time_since_last > self.DRILL_INTERVAL

    def get_last_drill(self) -> Optional[IncidentDrill]:
        """
        Retourne le dernier exercice effectué.

        Returns:
            Dernier IncidentDrill ou None
        """
        if not self._drills:
            return None
        return self._drills[0]

    def get_days_until_drill_required(self) -> Optional[int]:
        """
        Retourne le nombre de jours avant qu'un exercice soit requis.

        Returns:
            Nombre de jours (négatif si en retard), None si aucun exercice
        """
        if not self._drills:
            return None

        last_drill = self._drills[0]
        now = datetime.now(timezone.utc)
        next_required = last_drill.executed_at + self.DRILL_INTERVAL
        delta = next_required - now

        return delta.days

    def get_compliance_status(self, report_id: str) -> ComplianceStatus:
        """
        Retourne le statut de conformité complet.

        Args:
            report_id: Identifiant du rapport

        Returns:
            ComplianceStatus avec tous les indicateurs

        Raises:
            KeyError: Si rapport non trouvé
        """
        if report_id not in self._reports:
            raise KeyError(f"Report {report_id} not found")

        report = self._reports[report_id]

        return ComplianceStatus(
            report_submitted_on_time=self.is_report_on_time(report),
            blockchain_anchored=report.blockchain_anchor is not None,
            last_drill_date=(
                self._drills[0].executed_at if self._drills else None
            ),
            drill_overdue=self.is_drill_required(),
        )

    def get_overdue_reports(self) -> List[IncidentReport]:
        """
        Retourne les rapports non soumis dont la deadline est dépassée.

        Returns:
            Liste des rapports en retard

        Invariant:
            INCID_009: Identifie les violations de délai
        """
        now = datetime.now(timezone.utc)
        overdue = []

        for report in self._reports.values():
            if not report.submitted and now > report.deadline:
                overdue.append(report)

        return overdue

    def get_pending_reports(self) -> List[IncidentReport]:
        """
        Retourne les rapports non soumis avec deadline pas encore dépassée.

        Returns:
            Liste des rapports en attente
        """
        now = datetime.now(timezone.utc)
        pending = []

        for report in self._reports.values():
            if not report.submitted and now <= report.deadline:
                pending.append(report)

        return pending

    def get_report(self, report_id: str) -> Optional[IncidentReport]:
        """
        Récupère un rapport par ID.

        Args:
            report_id: Identifiant du rapport

        Returns:
            IncidentReport ou None
        """
        return self._reports.get(report_id)

    def get_all_reports(self) -> List[IncidentReport]:
        """
        Retourne tous les rapports.

        Returns:
            Liste de tous les rapports
        """
        return list(self._reports.values())

    def get_all_drills(self) -> List[IncidentDrill]:
        """
        Retourne tous les exercices.

        Returns:
            Liste de tous les exercices (triés par date décroissante)
        """
        return list(self._drills)

    def get_successful_drills(self) -> List[IncidentDrill]:
        """
        Retourne les exercices réussis.

        Returns:
            Liste des exercices avec success=True
        """
        return [d for d in self._drills if d.success]

    def clear_state(self) -> None:
        """Efface l'état interne (pour tests)."""
        self._reports.clear()
        self._drills.clear()
