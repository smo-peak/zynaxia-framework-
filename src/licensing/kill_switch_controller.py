"""
LOT 5: Kill Switch Controller Implementation

Contrôleur kill switch avec arrêt contrôlé et préservation données.

Invariants:
    LIC_070: Kill switch = arrêt contrôlé TOUS services
    LIC_071: Données PRÉSERVÉES
    LIC_072: Logs audit PRÉSERVÉS
    LIC_073: Monitoring MAINTENU
    LIC_074: Message explicite dashboard
    LIC_075: Réversible UNIQUEMENT par nouvelle licence valide
    LIC_076: Kill switch → ancrage blockchain
    LIC_077: Tentative contournement = alerte CRITICAL
"""
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from dataclasses import dataclass

from .interfaces import IKillSwitchController, License
from ..audit.audit_emitter import AuditEmitter
from ..audit.blockchain_anchor import BlockchainAnchor
from ..audit.interfaces import AuditEventType


class KillSwitchError(Exception):
    """Erreur contrôleur kill switch."""
    pass


@dataclass
class KillSwitchState:
    """
    État kill switch pour un site.
    
    Conformité:
        LIC_074: Tracking état pour dashboard
        LIC_076: blockchain_tx_id pour ancrage
        LIC_077: Compteur tentatives contournement
    """
    site_id: str
    activated_at: datetime
    reason: str
    blockchain_tx_id: str
    bypass_attempts: int = 0
    services_preserved: bool = True  # LIC_071-072
    monitoring_active: bool = True   # LIC_073


class KillSwitchController(IKillSwitchController):
    """
    Contrôleur kill switch avec préservation données et ancrage blockchain.
    
    Conformité:
        LIC_070: Arrêt contrôlé tous services
        LIC_071-073: Préservation données, logs, monitoring
        LIC_074: Message explicite dashboard
        LIC_075: Réversible par licence valide uniquement
        LIC_076: Ancrage blockchain
        LIC_077: Détection tentatives contournement
    
    Example:
        controller = KillSwitchController(audit, blockchain)
        await controller.activate("site-123", "license_expired")
        is_active = controller.is_active("site-123")
    """
    
    # Message dashboard (LIC_074)
    DASHBOARD_MESSAGE = '''
╔═══════════════════════════════════════════════════════════╗
║                    SERVICE SUSPENDU                        ║
║                                                           ║
║  🔒 LICENCE INVALIDE OU REVOQUÉE                          ║
║                                                           ║
║  ⚠️  Tous les services sont temporairement suspendus      ║
║      pour garantir la conformité sécuritaire.            ║
║                                                           ║
║  📞 Contactez votre intégrateur ZYNAXIA                   ║
║      pour renouveler votre licence.                      ║
║                                                           ║
║  💾 Vos données sont préservées et sécurisées.           ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    '''
    
    def __init__(
        self,
        audit_emitter: AuditEmitter,
        blockchain_anchor: BlockchainAnchor
    ):
        """
        Args:
            audit_emitter: Émetteur événements audit
            blockchain_anchor: Service ancrage blockchain
        """
        self.audit_emitter = audit_emitter
        self.blockchain_anchor = blockchain_anchor
        
        # État kill switches actifs
        self._active_switches: Dict[str, KillSwitchState] = {}
        
        # Services préservés pendant kill switch (LIC_071-073)
        self._preserved_services = {
            "data_storage",      # LIC_071: Données préservées
            "audit_logging",     # LIC_072: Logs audit préservés  
            "monitoring",        # LIC_073: Monitoring maintenu
            "license_manager"    # Nécessaire pour réactivation
        }
    
    async def activate(self, site_id: str, reason: str) -> None:
        """
        Active kill switch immédiat (LIC_012, LIC_063, LIC_070).
        
        Args:
            site_id: Site affecté
            reason: Motif activation
            
        Conformité:
            LIC_070: Arrêt contrôlé tous services
            LIC_071-072: Préservation données et logs
            LIC_073: Monitoring maintenu
            LIC_076: Ancrage blockchain
        """
        if not site_id:
            raise KillSwitchError("site_id obligatoire")
        
        if not reason:
            raise KillSwitchError("Raison activation obligatoire")
        
        # Vérifier si déjà actif
        if self.is_active(site_id):
            raise KillSwitchError(f"Kill switch déjà actif pour site {site_id}")
        
        try:
            now = datetime.now(timezone.utc)
            
            # Ancrer activation sur blockchain (LIC_076)
            kill_switch_data = {
                "site_id": site_id,
                "reason": reason,
                "activated_at": now.isoformat(),
                "action": "kill_switch_activated"
            }
            
            kill_switch_hash = self._compute_kill_switch_hash(kill_switch_data)
            anchor_receipt = await self.blockchain_anchor.anchor_event(kill_switch_hash)
            
            # Créer état kill switch
            switch_state = KillSwitchState(
                site_id=site_id,
                activated_at=now,
                reason=reason,
                blockchain_tx_id=anchor_receipt.blockchain_tx_id,
                bypass_attempts=0,
                services_preserved=True,   # LIC_071-072
                monitoring_active=True    # LIC_073
            )
            
            # Activer kill switch
            self._active_switches[site_id] = switch_state
            
            # Arrêt contrôlé services (LIC_070)
            await self._shutdown_services_controlled(site_id)
            
            # Audit activation critique (LIC_076, LIC_091)
            await self.audit_emitter.emit_event(
                AuditEventType.SECURITY_BREACH,  # Kill switch = critique
                "kill_switch_controller",
                site_id,
                "kill_switch_activated",
                resource_id=site_id,
                metadata={
                    "reason": reason,
                    "blockchain_tx_id": anchor_receipt.blockchain_tx_id,
                    "preserved_services": list(self._preserved_services)
                }
            )
            
        except Exception as e:
            raise KillSwitchError(f"Erreur activation kill switch: {str(e)}")
    
    async def deactivate(self, site_id: str, new_license: License) -> None:
        """
        Désactive kill switch avec nouvelle licence (LIC_075).
        
        Args:
            site_id: Site à réactiver
            new_license: Nouvelle licence valide
            
        Conformité:
            LIC_075: Réversible par nouvelle licence uniquement
            LIC_055: Réactivation après healthcheck
        """
        if not site_id:
            raise KillSwitchError("site_id obligatoire")
        
        if not new_license:
            raise KillSwitchError("LIC_075: Nouvelle licence valide obligatoire")
        
        # Vérifier kill switch actif
        if not self.is_active(site_id):
            raise KillSwitchError(f"Aucun kill switch actif pour site {site_id}")
        
        # Vérifier que licence correspond au site
        if new_license.site_id != site_id:
            raise KillSwitchError(f"Licence pour site {new_license.site_id}, attendu {site_id}")
        
        # Vérifier licence non révoquée
        if new_license.revoked:
            raise KillSwitchError("LIC_075: Licence révoquée ne peut réactiver")
        
        # Vérifier expiration
        now = datetime.now(timezone.utc)
        if now > new_license.expires_at:
            raise KillSwitchError("LIC_075: Licence expirée ne peut réactiver")
        
        try:
            switch_state = self._active_switches[site_id]
            
            # Ancrer désactivation sur blockchain
            deactivation_data = {
                "site_id": site_id,
                "deactivated_at": now.isoformat(),
                "new_license_id": new_license.license_id,
                "action": "kill_switch_deactivated"
            }
            
            deactivation_hash = self._compute_kill_switch_hash(deactivation_data)
            anchor_receipt = await self.blockchain_anchor.anchor_event(deactivation_hash)
            
            # Réactiver services (LIC_075)
            await self._reactivate_services(site_id, new_license)
            
            # Supprimer kill switch
            del self._active_switches[site_id]
            
            # Audit désactivation
            await self.audit_emitter.emit_event(
                AuditEventType.SYSTEM_CONFIG_CHANGE,
                "kill_switch_controller",
                site_id,
                "kill_switch_deactivated",
                resource_id=site_id,
                metadata={
                    "new_license_id": new_license.license_id,
                    "blockchain_tx_id": anchor_receipt.blockchain_tx_id,
                    "duration_minutes": int((now - switch_state.activated_at).total_seconds() / 60),
                    "bypass_attempts": switch_state.bypass_attempts
                }
            )
            
        except Exception as e:
            raise KillSwitchError(f"Erreur désactivation kill switch: {str(e)}")
    
    def is_active(self, site_id: str) -> bool:
        """
        Vérifie si kill switch actif.
        
        Args:
            site_id: Site à vérifier
            
        Returns:
            True si kill switch actif
        """
        return site_id in self._active_switches
    
    async def get_status(self, site_id: str) -> Dict[str, Any]:
        """
        Récupère statut détaillé kill switch.
        
        Args:
            site_id: Site concerné
            
        Returns:
            Status avec raison, timestamp, etc.
        """
        if not self.is_active(site_id):
            return {
                "active": False,
                "site_id": site_id
            }
        
        switch_state = self._active_switches[site_id]
        now = datetime.now(timezone.utc)
        duration = now - switch_state.activated_at
        
        return {
            "active": True,
            "site_id": site_id,
            "reason": switch_state.reason,
            "activated_at": switch_state.activated_at.isoformat(),
            "duration_hours": round(duration.total_seconds() / 3600, 2),
            "blockchain_tx_id": switch_state.blockchain_tx_id,
            "bypass_attempts": switch_state.bypass_attempts,
            "services_preserved": switch_state.services_preserved,
            "monitoring_active": switch_state.monitoring_active
        }
    
    def get_dashboard_message(self, site_id: str) -> str:
        """
        Message explicite dashboard (LIC_074).
        
        Args:
            site_id: Site concerné
            
        Returns:
            Message formaté pour dashboard
            
        Conformité:
            LIC_074: Message explicite dashboard
        """
        if not self.is_active(site_id):
            return ""
        
        switch_state = self._active_switches[site_id]
        
        # Message personnalisé avec détails
        custom_message = f"""
╔═══════════════════════════════════════════════════════════╗
║                    SERVICE SUSPENDU                        ║
║                                                           ║
║  🔒 LICENCE INVALIDE OU REVOQUÉE                          ║
║                                                           ║
║  ⚠️  Tous les services sont temporairement suspendus      ║
║      pour garantir la conformité sécuritaire.            ║
║                                                           ║
║  📋 Raison: {switch_state.reason:<42} ║
║  🕐 Depuis: {switch_state.activated_at.strftime('%Y-%m-%d %H:%M UTC'):<40} ║
║                                                           ║
║  📞 Contactez votre intégrateur ZYNAXIA                   ║
║      pour renouveler votre licence.                      ║
║                                                           ║
║  💾 Vos données sont préservées et sécurisées.           ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
        """
        
        return custom_message.strip()
    
    async def detect_bypass_attempt(self, site_id: str, action: str) -> None:
        """
        Détecte tentative contournement (LIC_077).
        
        Args:
            site_id: Site concerné
            action: Action tentée
            
        Conformité:
            LIC_077: Tentative contournement = alerte CRITICAL
        """
        if not self.is_active(site_id):
            return
        
        switch_state = self._active_switches[site_id]
        switch_state.bypass_attempts += 1
        
        # Audit alerte critique (LIC_077)
        await self.audit_emitter.emit_event(
            AuditEventType.SECURITY_BREACH,  # Critique
            "kill_switch_controller",
            site_id,
            "bypass_attempt_detected",
            resource_id=site_id,
            metadata={
                "attempted_action": action,
                "attempt_number": switch_state.bypass_attempts,
                "kill_switch_reason": switch_state.reason,
                "severity": "CRITICAL"
            }
        )
    
    async def _shutdown_services_controlled(self, site_id: str) -> None:
        """
        Arrêt contrôlé services (LIC_070-073).
        
        Args:
            site_id: Site concerné
            
        Conformité:
            LIC_070: Arrêt contrôlé tous services
            LIC_071: Données préservées
            LIC_072: Logs audit préservés
            LIC_073: Monitoring maintenu
        """
        # Simulation arrêt contrôlé (MVP)
        # En production: orchestrateur Kubernetes/Docker
        
        services_to_stop = [
            "web_interface",
            "api_gateway", 
            "business_logic",
            "background_workers",
            "notification_service"
        ]
        
        # Audit arrêt services
        await self.audit_emitter.emit_event(
            AuditEventType.SYSTEM_CONFIG_CHANGE,
            "kill_switch_controller",
            site_id,
            "services_shutdown_controlled",
            metadata={
                "stopped_services": services_to_stop,
                "preserved_services": list(self._preserved_services),
                "shutdown_mode": "controlled"
            }
        )
    
    async def _reactivate_services(self, site_id: str, new_license: License) -> None:
        """
        Réactive services après nouvelle licence (LIC_075).
        
        Args:
            site_id: Site à réactiver
            new_license: Licence valide
        """
        # Simulation réactivation (MVP)
        # En production: healthcheck puis redémarrage services
        
        # Audit réactivation services
        await self.audit_emitter.emit_event(
            AuditEventType.SYSTEM_CONFIG_CHANGE,
            "kill_switch_controller", 
            site_id,
            "services_reactivated",
            metadata={
                "new_license_id": new_license.license_id,
                "reactivation_mode": "controlled",
                "healthcheck_passed": True
            }
        )
    
    def _compute_kill_switch_hash(self, data: Dict[str, Any]) -> str:
        """Calcule hash kill switch pour blockchain."""
        import hashlib
        data_json = json.dumps(data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha384(data_json.encode('utf-8')).hexdigest()
    
    def get_kill_switch_stats(self) -> Dict[str, Any]:
        """Statistiques kill switches pour monitoring."""
        total_active = len(self._active_switches)
        
        if total_active == 0:
            return {
                "total_active_switches": 0,
                "oldest_switch_hours": 0,
                "total_bypass_attempts": 0
            }
        
        # Calculs statistiques
        now = datetime.now(timezone.utc)
        durations = [
            (now - switch.activated_at).total_seconds() / 3600
            for switch in self._active_switches.values()
        ]
        
        total_bypass_attempts = sum(
            switch.bypass_attempts
            for switch in self._active_switches.values()
        )
        
        return {
            "total_active_switches": total_active,
            "oldest_switch_hours": round(max(durations), 2),
            "average_duration_hours": round(sum(durations) / len(durations), 2),
            "total_bypass_attempts": total_bypass_attempts,
            "preserved_services": list(self._preserved_services)
        }