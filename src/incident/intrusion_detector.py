"""
LOT 8: Détecteur d'intrusions et activités suspectes

Implémente la détection d'intrusions, les logs d'accès non autorisés
et la détection d'anomalies sur la base de données.

Invariants:
    INCID_001: Détection intrusion = alerte immédiate multi-canal
    INCID_002: Tentative accès non autorisé = log + alerte
    INCID_004: Activité anormale DB = alerte (queries inhabituelles)
"""

import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Pattern

from src.incident.interfaces import (
    IIntrusionDetector,
    IAlertDispatcher,
    SecurityAlert,
    AlertChannel,
    IncidentSeverity,
    IncidentType,
)
from src.audit.interfaces import IAuditEmitter, AuditEventType


class IntrusionDetectorError(Exception):
    """Erreur du détecteur d'intrusion."""

    pass


class IntrusionDetector(IIntrusionDetector):
    """
    Détecteur d'intrusions et activités suspectes.

    Analyse les événements de sécurité pour détecter:
    - Intrusions (INCID_001)
    - Accès non autorisés (INCID_002)
    - Anomalies DB (INCID_004)

    Invariants:
        INCID_001: Détection intrusion = alerte immédiate multi-canal
        INCID_002: Tentative accès non autorisé = log + alerte
        INCID_004: Activité anormale DB = alerte
    """

    # Patterns suspects pour détection SQL injection et anomalies DB
    SUSPICIOUS_PATTERNS: List[str] = [
        r"DROP\s+TABLE",
        r"DROP\s+DATABASE",
        r"DELETE\s+FROM\s+\S+\s+WHERE\s+1\s*=\s*1",
        r"DELETE\s+FROM\s+\S+\s*;?\s*$",  # DELETE sans WHERE
        r"TRUNCATE\s+TABLE",
        r"UNION\s+SELECT",
        r"UNION\s+ALL\s+SELECT",
        r"';\s*--",
        r"OR\s+1\s*=\s*1",
        r"OR\s+'1'\s*=\s*'1'",
        r";\s*DROP",
        r";\s*DELETE",
        r"EXEC\s+xp_",
        r"EXECUTE\s+xp_",
        r"INTO\s+OUTFILE",
        r"LOAD_FILE",
    ]

    # Patterns d'intrusion
    INTRUSION_INDICATORS: List[str] = [
        "privilege_escalation",
        "root_access_attempt",
        "admin_bypass",
        "authentication_bypass",
        "session_hijacking",
        "token_manipulation",
        "brute_force_detected",
        "credential_stuffing",
    ]

    # Tous les canaux pour alertes intrusion (INCID_001)
    ALL_CHANNELS: List[AlertChannel] = [
        AlertChannel.EMAIL,
        AlertChannel.SMS,
        AlertChannel.WEBHOOK,
        AlertChannel.SYSLOG,
    ]

    def __init__(
        self,
        alert_dispatcher: IAlertDispatcher,
        audit_emitter: IAuditEmitter,
    ) -> None:
        """
        Initialise le détecteur d'intrusion.

        Args:
            alert_dispatcher: Dispatcher pour envoyer les alertes
            audit_emitter: Émetteur pour les événements d'audit
        """
        self._dispatcher = alert_dispatcher
        self._audit = audit_emitter
        self._compiled_patterns: List[Pattern[str]] = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.SUSPICIOUS_PATTERNS
        ]

    async def detect_intrusion(
        self, event: Dict[str, Any]
    ) -> Optional[SecurityAlert]:
        """
        Détecte une intrusion et génère une alerte immédiate multi-canal.

        Args:
            event: Événement à analyser avec les champs:
                - type: Type d'événement
                - tenant_id: ID du tenant
                - source_ip: IP source (optionnel)
                - user_id: ID utilisateur (optionnel)
                - details: Détails additionnels

        Returns:
            SecurityAlert si intrusion détectée, None sinon

        Invariant:
            INCID_001: Détection intrusion = alerte immédiate multi-canal
            Channels: EMAIL, SMS, WEBHOOK, SYSLOG (tous)
        """
        event_type = event.get("type", "")
        tenant_id = event.get("tenant_id", "unknown")

        # Vérifier si l'événement indique une intrusion
        is_intrusion = False
        description = ""

        for indicator in self.INTRUSION_INDICATORS:
            if indicator in event_type.lower() or indicator in str(event.get("details", "")).lower():
                is_intrusion = True
                description = f"Intrusion detected: {indicator}"
                break

        # Vérifier aussi les flags explicites
        if event.get("is_intrusion", False):
            is_intrusion = True
            description = event.get("description", "Intrusion detected")

        if not is_intrusion:
            return None

        # Créer l'alerte
        alert = SecurityAlert(
            alert_id=str(uuid.uuid4()),
            incident_type=IncidentType.INTRUSION.value,
            severity=IncidentSeverity.CRITICAL,
            tenant_id=tenant_id,
            source_ip=event.get("source_ip"),
            user_id=event.get("user_id"),
            description=description,
            timestamp=datetime.now(timezone.utc),
            channels_notified=list(self.ALL_CHANNELS),
            metadata={"original_event": event},
        )

        # INCID_001: Dispatcher vers TOUS les canaux immédiatement
        await self._dispatcher.dispatch(alert, self.ALL_CHANNELS)

        # Log dans l'audit
        await self._audit.emit_event(
            event_type=AuditEventType.SECURITY_BREACH,
            user_id=event.get("user_id", "unknown"),
            tenant_id=tenant_id,
            action="intrusion_detected",
            resource_id=alert.alert_id,
            metadata={
                "severity": alert.severity.value,
                "channels": [c.value for c in self.ALL_CHANNELS],
                "source_ip": event.get("source_ip"),
            },
            ip_address=event.get("source_ip"),
        )

        return alert

    async def log_unauthorized_access(
        self, event: Dict[str, Any]
    ) -> SecurityAlert:
        """
        Log et génère une alerte pour tentative d'accès non autorisé.

        Args:
            event: Événement d'accès non autorisé avec:
                - tenant_id: ID du tenant
                - user_id: ID utilisateur tentant l'accès
                - resource: Ressource accédée
                - source_ip: IP source
                - reason: Raison du refus

        Returns:
            SecurityAlert générée

        Invariant:
            INCID_002: Tentative accès non autorisé = log + alerte
        """
        tenant_id = event.get("tenant_id", "unknown")
        user_id = event.get("user_id", "unknown")
        resource = event.get("resource", "unknown")
        reason = event.get("reason", "Access denied")

        description = f"Unauthorized access attempt to {resource}: {reason}"

        # Déterminer la sévérité basée sur le type de ressource
        severity = IncidentSeverity.MEDIUM
        if "admin" in resource.lower() or "system" in resource.lower():
            severity = IncidentSeverity.HIGH
        if "root" in resource.lower() or "security" in resource.lower():
            severity = IncidentSeverity.CRITICAL

        # Créer l'alerte
        alert = SecurityAlert(
            alert_id=str(uuid.uuid4()),
            incident_type=IncidentType.UNAUTHORIZED_ACCESS.value,
            severity=severity,
            tenant_id=tenant_id,
            source_ip=event.get("source_ip"),
            user_id=user_id,
            description=description,
            timestamp=datetime.now(timezone.utc),
            channels_notified=[AlertChannel.SYSLOG, AlertChannel.WEBHOOK],
            metadata={
                "resource": resource,
                "reason": reason,
                "original_event": event,
            },
        )

        # INCID_002: Log d'abord
        await self._audit.emit_event(
            event_type=AuditEventType.FAILED_AUTH,
            user_id=user_id,
            tenant_id=tenant_id,
            action="unauthorized_access_attempt",
            resource_id=resource,
            metadata={
                "reason": reason,
                "alert_id": alert.alert_id,
                "severity": severity.value,
            },
            ip_address=event.get("source_ip"),
        )

        # Puis alerte (SYSLOG et WEBHOOK pour accès non autorisé)
        channels = [AlertChannel.SYSLOG, AlertChannel.WEBHOOK]
        if severity == IncidentSeverity.CRITICAL:
            channels = self.ALL_CHANNELS

        await self._dispatcher.dispatch(alert, channels)

        return alert

    async def detect_db_anomaly(
        self, query_pattern: str, tenant_id: str
    ) -> Optional[SecurityAlert]:
        """
        Détecte une activité anormale sur la base de données.

        Args:
            query_pattern: Pattern de requête SQL à analyser
            tenant_id: Identifiant du tenant

        Returns:
            SecurityAlert si anomalie détectée, None sinon

        Invariant:
            INCID_004: Activité anormale DB = alerte
        """
        if not query_pattern:
            return None

        # Vérifier contre les patterns suspects
        detected_patterns: List[str] = []
        for pattern in self._compiled_patterns:
            if pattern.search(query_pattern):
                detected_patterns.append(pattern.pattern)

        if not detected_patterns:
            return None

        # Déterminer la sévérité
        severity = IncidentSeverity.HIGH
        if any("DROP" in p or "TRUNCATE" in p for p in detected_patterns):
            severity = IncidentSeverity.CRITICAL

        description = f"DB anomaly detected: suspicious patterns found ({len(detected_patterns)} matches)"

        # Créer l'alerte
        alert = SecurityAlert(
            alert_id=str(uuid.uuid4()),
            incident_type=IncidentType.DB_ANOMALY.value,
            severity=severity,
            tenant_id=tenant_id,
            source_ip=None,
            user_id=None,
            description=description,
            timestamp=datetime.now(timezone.utc),
            channels_notified=[AlertChannel.SYSLOG, AlertChannel.WEBHOOK, AlertChannel.EMAIL],
            metadata={
                "query_pattern": query_pattern[:500],  # Limiter la taille
                "detected_patterns": detected_patterns,
            },
        )

        # Log dans l'audit
        await self._audit.emit_event(
            event_type=AuditEventType.SECURITY_BREACH,
            user_id="system",
            tenant_id=tenant_id,
            action="db_anomaly_detected",
            resource_id=alert.alert_id,
            metadata={
                "severity": severity.value,
                "detected_patterns": detected_patterns,
            },
        )

        # Dispatcher l'alerte
        channels = [AlertChannel.SYSLOG, AlertChannel.WEBHOOK, AlertChannel.EMAIL]
        if severity == IncidentSeverity.CRITICAL:
            channels = self.ALL_CHANNELS

        await self._dispatcher.dispatch(alert, channels)

        return alert

    def is_suspicious_query(self, query: str) -> bool:
        """
        Vérifie si une requête contient des patterns suspects.

        Args:
            query: Requête SQL à vérifier

        Returns:
            True si la requête contient des patterns suspects
        """
        for pattern in self._compiled_patterns:
            if pattern.search(query):
                return True
        return False

    def get_suspicious_patterns(self, query: str) -> List[str]:
        """
        Retourne la liste des patterns suspects trouvés dans une requête.

        Args:
            query: Requête SQL à analyser

        Returns:
            Liste des patterns suspects détectés
        """
        found: List[str] = []
        for pattern in self._compiled_patterns:
            if pattern.search(query):
                found.append(pattern.pattern)
        return found
