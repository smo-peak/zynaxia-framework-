"""
LOT 5: License Alert Service Implementation

Service alertes expiration licence avec canaux multiples et planning non modifiable.

Invariants:
    LIC_030: Alerte J-60 (email intégrateur + org)
    LIC_031: Alerte J-30 (email + dashboard warning)
    LIC_032: Alerte J-14 (email + SMS)
    LIC_033: Alerte J-7 (email + SMS + dashboard critical)
    LIC_034: Alerte J-1 (tous canaux + webhook)
    LIC_035: Alertes NON désactivables par configuration
"""
from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Set, Optional, Any
from datetime import datetime, timezone, timedelta

from .interfaces import ILicenseCache, License
from ..audit.audit_emitter import AuditEmitter
from ..audit.interfaces import AuditEventType


class AlertLevel(Enum):
    """Niveau d'alerte licence."""
    INFO = "info"
    WARNING = "warning"  
    CRITICAL = "critical"
    URGENT = "urgent"


class AlertChannel(Enum):
    """Canal de diffusion alerte."""
    EMAIL = "email"
    SMS = "sms"
    DASHBOARD = "dashboard"
    WEBHOOK = "webhook"


@dataclass
class AlertConfig:
    """
    Configuration alerte expiration.
    
    Conformité:
        LIC_030-034: Définition planning alertes
        LIC_035: Configuration non modifiable
    """
    days_before: int
    level: AlertLevel
    channels: List[AlertChannel]
    message_template: str
    integrator_notification: bool = True
    organization_notification: bool = True


class LicenseAlertService:
    """
    Service alertes expiration licence avec planning fixe.
    
    Conformité:
        LIC_030: J-60 email intégrateur + organisation
        LIC_031: J-30 email + dashboard warning
        LIC_032: J-14 email + SMS
        LIC_033: J-7 email + SMS + dashboard critical
        LIC_034: J-1 tous canaux + webhook
        LIC_035: Planning non modifiable (hardcodé)
    
    Note:
        Service vérifie automatiquement toutes les licences.
        Évite envois duplicata avec cache alertes envoyées.
    
    Example:
        service = LicenseAlertService(license_cache, audit_emitter)
        alerts = await service.check_and_send_alerts("site-123")
    """
    
    # LIC_035: Planning alertes NON modifiable
    ALERT_SCHEDULE: List[AlertConfig] = [
        # LIC_030: J-60 email intégrateur + org
        AlertConfig(
            days_before=60,
            level=AlertLevel.INFO,
            channels=[AlertChannel.EMAIL],
            message_template="Votre licence ZYNAXIA expire dans 60 jours. Contactez votre intégrateur pour le renouvellement.",
            integrator_notification=True,
            organization_notification=True
        ),
        # LIC_031: J-30 email + dashboard warning  
        AlertConfig(
            days_before=30,
            level=AlertLevel.WARNING,
            channels=[AlertChannel.EMAIL, AlertChannel.DASHBOARD],
            message_template="⚠️ Licence ZYNAXIA expire dans 30 jours. Planifiez le renouvellement rapidement.",
            integrator_notification=True,
            organization_notification=True
        ),
        # LIC_032: J-14 email + SMS
        AlertConfig(
            days_before=14,
            level=AlertLevel.WARNING,
            channels=[AlertChannel.EMAIL, AlertChannel.SMS],
            message_template="⚠️ URGENT: Licence ZYNAXIA expire dans 14 jours. Renouvellement imminent requis.",
            integrator_notification=True,
            organization_notification=True
        ),
        # LIC_033: J-7 email + SMS + dashboard critical
        AlertConfig(
            days_before=7,
            level=AlertLevel.CRITICAL,
            channels=[AlertChannel.EMAIL, AlertChannel.SMS, AlertChannel.DASHBOARD],
            message_template="🚨 CRITIQUE: Licence ZYNAXIA expire dans 7 jours. Services seront suspendus sans renouvellement.",
            integrator_notification=True,
            organization_notification=True
        ),
        # LIC_034: J-1 tous canaux + webhook
        AlertConfig(
            days_before=1,
            level=AlertLevel.URGENT,
            channels=[AlertChannel.EMAIL, AlertChannel.SMS, AlertChannel.DASHBOARD, AlertChannel.WEBHOOK],
            message_template="🔥 DERNIÈRE CHANCE: Licence ZYNAXIA expire DEMAIN. Kill switch activé en cas d'expiration.",
            integrator_notification=True,
            organization_notification=True
        )
    ]
    
    def __init__(
        self,
        license_cache: ILicenseCache,
        audit_emitter: AuditEmitter
    ):
        """
        Args:
            license_cache: Cache licences pour vérifications
            audit_emitter: Émetteur événements audit
        """
        self._cache = license_cache
        self._audit = audit_emitter
        
        # Cache alertes envoyées: site_id -> {days_before}
        self._sent_alerts: Dict[str, Set[int]] = {}
        
        # Contacts pour notifications
        self._integrator_contacts = {
            "email": "support@zynaxia-integrator.com",
            "phone": "+33123456789"
        }
    
    async def check_and_send_alerts(self, site_id: str) -> List[AlertConfig]:
        """
        Vérifie expiration et envoie alertes appropriées.
        
        Args:
            site_id: Site à vérifier
            
        Returns:
            Liste alertes envoyées
            
        Conformité:
            LIC_030-034: Respect planning alertes
            LIC_035: Utilise planning fixe non modifiable
        """
        if not site_id:
            return []
        
        # Récupérer licence
        license = self._cache.get(site_id)
        if not license or license.revoked:
            return []
        
        # Calculer jours avant expiration
        now = datetime.now(timezone.utc)
        days_until_expiry = (license.expires_at - now).days
        
        # Trouver alertes à envoyer
        alerts_to_send = self.get_pending_alerts(site_id, days_until_expiry)
        sent_alerts = []
        
        for alert_config in alerts_to_send:
            try:
                # Envoyer alerte
                await self._send_alert(site_id, license, alert_config, days_until_expiry)
                
                # Marquer comme envoyée
                self._mark_alert_sent(site_id, alert_config.days_before)
                sent_alerts.append(alert_config)
                
                # Audit envoi alerte
                await self._audit_alert_sent(site_id, alert_config, days_until_expiry)
                
            except Exception as e:
                # Audit erreur envoi
                await self._audit_alert_error(site_id, alert_config, str(e))
        
        return sent_alerts
    
    def get_pending_alerts(self, site_id: str, days_until_expiry: int = None) -> List[AlertConfig]:
        """
        Retourne alertes à envoyer pour un site.
        
        Args:
            site_id: Site concerné
            days_until_expiry: Jours avant expiration (calculé si None)
            
        Returns:
            Liste alertes en attente
        """
        if not site_id:
            return []
        
        # Calculer jours avant expiration si pas fourni
        if days_until_expiry is None:
            license = self._cache.get(site_id)
            if not license or license.revoked:
                return []
            
            now = datetime.now(timezone.utc)
            days_until_expiry = (license.expires_at - now).days
        
        # Alertes déjà envoyées pour ce site
        sent_alerts = self._sent_alerts.get(site_id, set())
        
        # Filtrer alertes à envoyer
        pending_alerts = []
        for alert_config in self.ALERT_SCHEDULE:
            # Alerte déclenchée si on atteint le seuil
            should_trigger = days_until_expiry <= alert_config.days_before
            
            # Pas encore envoyée
            not_sent = alert_config.days_before not in sent_alerts
            
            if should_trigger and not_sent:
                pending_alerts.append(alert_config)
        
        # Trier par urgence (jours décroissants)
        pending_alerts.sort(key=lambda a: a.days_before)
        
        return pending_alerts
    
    def is_alert_schedule_modifiable(self) -> bool:
        """
        Vérifie si planning alertes modifiable.
        
        Returns:
            Toujours False (LIC_035)
            
        Conformité:
            LIC_035: Alertes NON désactivables par configuration
        """
        return False
    
    def get_alert_schedule(self) -> List[AlertConfig]:
        """
        Retourne planning alertes (lecture seule).
        
        Returns:
            Configuration alertes système
            
        Conformité:
            LIC_035: Planning fixe non modifiable
        """
        return self.ALERT_SCHEDULE.copy()
    
    async def get_alert_status(self, site_id: str) -> Dict[str, Any]:
        """
        Retourne statut alertes pour un site.
        
        Args:
            site_id: Site concerné
            
        Returns:
            Statut détaillé alertes
        """
        if not site_id:
            return {
                "site_id": site_id,
                "license_found": False,
                "days_until_expiry": None,
                "pending_alerts": 0,
                "sent_alerts": 0,
                "next_alert_in_days": None
            }
        
        license = self._cache.get(site_id)
        if not license or license.revoked:
            return {
                "site_id": site_id,
                "license_found": False,
                "license_revoked": license.revoked if license else False,
                "days_until_expiry": None,
                "pending_alerts": 0,
                "sent_alerts": 0
            }
        
        now = datetime.now(timezone.utc)
        days_until_expiry = (license.expires_at - now).days
        
        pending_alerts = self.get_pending_alerts(site_id, days_until_expiry)
        sent_alerts = self._sent_alerts.get(site_id, set())
        
        # Prochaine alerte
        next_alert_days = None
        for alert_config in self.ALERT_SCHEDULE:
            if (alert_config.days_before >= days_until_expiry and 
                alert_config.days_before not in sent_alerts):
                next_alert_days = alert_config.days_before
                break
        
        return {
            "site_id": site_id,
            "license_found": True,
            "license_id": license.license_id,
            "expires_at": license.expires_at.isoformat(),
            "days_until_expiry": days_until_expiry,
            "pending_alerts": len(pending_alerts),
            "sent_alerts_count": len(sent_alerts),
            "sent_alert_days": sorted(list(sent_alerts)),
            "next_alert_in_days": next_alert_days,
            "alert_schedule_modifiable": False  # LIC_035
        }
    
    def reset_alert_history(self, site_id: str) -> None:
        """
        Remet à zéro historique alertes (ex: après renouvellement).
        
        Args:
            site_id: Site à réinitialiser
            
        Note:
            Utile après renouvellement licence pour reprendre cycle alertes
        """
        if site_id in self._sent_alerts:
            del self._sent_alerts[site_id]
    
    async def _send_alert(
        self,
        site_id: str,
        license: License,
        alert_config: AlertConfig,
        days_until_expiry: int
    ) -> None:
        """
        Envoie alerte sur tous les canaux configurés.
        
        Args:
            site_id: Site concerné
            license: Licence expirante
            alert_config: Configuration alerte
            days_until_expiry: Jours restants
        """
        # Personnaliser message
        message = self._format_alert_message(
            alert_config.message_template,
            site_id,
            license,
            days_until_expiry
        )
        
        # Envoyer sur chaque canal
        for channel in alert_config.channels:
            await self._send_channel_alert(
                channel,
                site_id,
                license,
                message,
                alert_config.level
            )
    
    def _format_alert_message(
        self,
        template: str,
        site_id: str,
        license: License,
        days_until_expiry: int
    ) -> str:
        """Formate message alerte avec variables."""
        return template.format(
            site_id=site_id,
            license_id=license.license_id,
            days=days_until_expiry,
            expires_at=license.expires_at.strftime('%Y-%m-%d %H:%M UTC'),
            organization_id=license.organization_id or "N/A"
        )
    
    async def _send_channel_alert(
        self,
        channel: AlertChannel,
        site_id: str,
        license: License,
        message: str,
        level: AlertLevel
    ) -> None:
        """Envoie alerte sur un canal spécifique."""
        # Simulation envoi (MVP - implémentation réelle selon infrastructure)
        
        if channel == AlertChannel.EMAIL:
            await self._send_email_alert(site_id, license, message, level)
        elif channel == AlertChannel.SMS:
            await self._send_sms_alert(site_id, license, message, level)
        elif channel == AlertChannel.DASHBOARD:
            await self._send_dashboard_alert(site_id, license, message, level)
        elif channel == AlertChannel.WEBHOOK:
            await self._send_webhook_alert(site_id, license, message, level)
    
    async def _send_email_alert(self, site_id: str, license: License, message: str, level: AlertLevel) -> None:
        """Envoie alerte email."""
        # MVP: Log simulé
        # Production: SMTP, SendGrid, etc.
        pass
    
    async def _send_sms_alert(self, site_id: str, license: License, message: str, level: AlertLevel) -> None:
        """Envoie alerte SMS."""  
        # MVP: Log simulé
        # Production: Twilio, AWS SNS, etc.
        pass
    
    async def _send_dashboard_alert(self, site_id: str, license: License, message: str, level: AlertLevel) -> None:
        """Envoie alerte dashboard."""
        # MVP: Log simulé  
        # Production: WebSocket, notification système
        pass
    
    async def _send_webhook_alert(self, site_id: str, license: License, message: str, level: AlertLevel) -> None:
        """Envoie alerte webhook."""
        # MVP: Log simulé
        # Production: HTTP POST vers endpoints configurés
        pass
    
    def _mark_alert_sent(self, site_id: str, days_before: int) -> None:
        """Marque alerte comme envoyée."""
        if site_id not in self._sent_alerts:
            self._sent_alerts[site_id] = set()
        
        self._sent_alerts[site_id].add(days_before)
    
    async def _audit_alert_sent(
        self,
        site_id: str,
        alert_config: AlertConfig,
        days_until_expiry: int
    ) -> None:
        """Audit envoi alerte."""
        await self._audit.emit_event(
            AuditEventType.SYSTEM_CONFIG_CHANGE,
            "license_alert_service",
            site_id,
            "license_expiry_alert_sent",
            resource_id=site_id,
            metadata={
                "alert_days_before": alert_config.days_before,
                "alert_level": alert_config.level.value,
                "alert_channels": [ch.value for ch in alert_config.channels],
                "days_until_expiry": days_until_expiry,
                "severity": alert_config.level.value.upper()
            }
        )
    
    async def _audit_alert_error(
        self,
        site_id: str,
        alert_config: AlertConfig,
        error: str
    ) -> None:
        """Audit erreur envoi alerte."""
        await self._audit.emit_event(
            AuditEventType.SYSTEM_ERROR,
            "license_alert_service",
            site_id,
            "license_alert_send_failed",
            resource_id=site_id,
            metadata={
                "alert_days_before": alert_config.days_before,
                "alert_level": alert_config.level.value,
                "error": error,
                "severity": "ERROR"
            }
        )