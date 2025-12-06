"""
Tests unitaires KillSwitchController

Invariants testés:
    LIC_070: Kill switch = arrêt contrôlé TOUS services
    LIC_071: Données PRÉSERVÉES
    LIC_072: Logs audit PRÉSERVÉS
    LIC_073: Monitoring MAINTENU
    LIC_074: Message explicite dashboard
    LIC_075: Réversible UNIQUEMENT par nouvelle licence valide
    LIC_076: Kill switch → ancrage blockchain
    LIC_077: Tentative contournement = alerte CRITICAL
"""
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, Mock

from src.licensing.interfaces import IKillSwitchController, License
from src.licensing.kill_switch_controller import (
    KillSwitchController,
    KillSwitchError,
    KillSwitchState
)
from src.audit.audit_emitter import AuditEmitter
from src.audit.blockchain_anchor import BlockchainAnchor, AnchorReceipt
from src.audit.interfaces import AuditEventType


# ══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def audit_emitter():
    """AuditEmitter mocké pour tests."""
    emitter = AsyncMock()
    emitter.emit_event.return_value = Mock()
    return emitter


@pytest.fixture
def blockchain_anchor():
    """BlockchainAnchor mocké pour tests."""
    anchor = AsyncMock()
    mock_receipt = AnchorReceipt(
        event_hash="kill_switch_hash_123",
        blockchain_tx_id="0xdef456",
        block_height=1000001,
        anchor_timestamp=datetime.now(timezone.utc),
        confirmation_count=6,
        anchor_proof="merkle_proof_kill"
    )
    anchor.anchor_event.return_value = mock_receipt
    return anchor


@pytest.fixture
def kill_switch_controller(audit_emitter, blockchain_anchor):
    """KillSwitchController instance pour tests."""
    return KillSwitchController(
        audit_emitter=audit_emitter,
        blockchain_anchor=blockchain_anchor
    )


@pytest.fixture
def sample_license():
    """Licence valide pour réactivation."""
    now = datetime.now(timezone.utc)
    return License(
        license_id="new-license-123",
        site_id="site-test",
        issued_at=now,
        expires_at=now + timedelta(days=180),
        modules=["surveillance", "access_control"],
        signature="valid_reactivation_signature",
        issuer_id="cloud-license-manager",
        organization_id="org-reactivation",
        blockchain_tx_id="0x789abc"
    )


@pytest.fixture
def revoked_license(sample_license):
    """Licence révoquée pour tests."""
    return License(
        license_id="revoked-license-456",
        site_id=sample_license.site_id,
        issued_at=sample_license.issued_at,
        expires_at=sample_license.expires_at,
        modules=sample_license.modules,
        signature="revoked_signature",
        issuer_id=sample_license.issuer_id,
        organization_id=sample_license.organization_id,
        blockchain_tx_id="0xrevoked123",
        revoked=True,
        revoked_at=datetime.now(timezone.utc),
        revoked_reason="security_breach"
    )


@pytest.fixture
def expired_license(sample_license):
    """Licence expirée pour tests."""
    now = datetime.now(timezone.utc)
    return License(
        license_id="expired-license-789",
        site_id=sample_license.site_id,
        issued_at=now - timedelta(days=200),
        expires_at=now - timedelta(days=10),  # Expirée
        modules=sample_license.modules,
        signature="expired_signature",
        issuer_id=sample_license.issuer_id,
        organization_id=sample_license.organization_id,
        blockchain_tx_id="0xexpired456"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TESTS INTERFACE
# ══════════════════════════════════════════════════════════════════════════════

class TestKillSwitchInterface:
    """Vérifie conformité interface."""
    
    def test_implements_interface(self, kill_switch_controller):
        """KillSwitchController implémente IKillSwitchController."""
        assert isinstance(kill_switch_controller, IKillSwitchController)
    
    def test_dashboard_message_constant(self):
        """Message dashboard défini (LIC_074)."""
        assert KillSwitchController.DASHBOARD_MESSAGE is not None
        assert "SERVICE SUSPENDU" in KillSwitchController.DASHBOARD_MESSAGE
        assert "LICENCE INVALIDE" in KillSwitchController.DASHBOARD_MESSAGE
        assert "données sont préservées" in KillSwitchController.DASHBOARD_MESSAGE


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_070: ARRÊT CONTRÔLÉ SERVICES
# ══════════════════════════════════════════════════════════════════════════════

class TestLIC070Compliance:
    """Tests conformité LIC_070: Arrêt contrôlé tous services."""
    
    @pytest.mark.asyncio
    async def test_LIC_070_activate_shuts_down_services(self, kill_switch_controller, audit_emitter):
        """LIC_070: Activation arrête services de façon contrôlée."""
        await kill_switch_controller.activate("site-test", "license_expired")
        
        # Vérifier audit arrêt services
        audit_calls = audit_emitter.emit_event.call_args_list
        shutdown_audit = None
        
        for call in audit_calls:
            if "services_shutdown_controlled" in str(call):
                shutdown_audit = call
                break
        
        assert shutdown_audit is not None
        assert "services_shutdown_controlled" in shutdown_audit[0][3]
    
    @pytest.mark.asyncio
    async def test_LIC_070_preserved_services_maintained(self, kill_switch_controller):
        """LIC_070: Services préservés maintenus."""
        await kill_switch_controller.activate("site-test", "license_expired")
        
        # Vérifier services préservés
        expected_preserved = {
            "data_storage",      # LIC_071
            "audit_logging",     # LIC_072
            "monitoring",        # LIC_073
            "license_manager"    # Réactivation
        }
        
        assert kill_switch_controller._preserved_services == expected_preserved
    
    @pytest.mark.asyncio
    async def test_LIC_070_kill_switch_active_after_activation(self, kill_switch_controller):
        """LIC_070: Kill switch actif après activation."""
        assert not kill_switch_controller.is_active("site-test")
        
        await kill_switch_controller.activate("site-test", "license_expired")
        
        assert kill_switch_controller.is_active("site-test")


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_071-073: PRÉSERVATION DONNÉES, LOGS, MONITORING
# ══════════════════════════════════════════════════════════════════════════════

class TestLIC071to073Compliance:
    """Tests conformité LIC_071-073: Préservation données, logs, monitoring."""
    
    @pytest.mark.asyncio
    async def test_LIC_071_data_preservation(self, kill_switch_controller):
        """LIC_071: Données préservées."""
        await kill_switch_controller.activate("site-test", "license_expired")
        
        status = await kill_switch_controller.get_status("site-test")
        assert status["services_preserved"] is True
        assert "data_storage" in kill_switch_controller._preserved_services
    
    @pytest.mark.asyncio
    async def test_LIC_072_audit_logs_preserved(self, kill_switch_controller):
        """LIC_072: Logs audit préservés."""
        await kill_switch_controller.activate("site-test", "license_expired")
        
        status = await kill_switch_controller.get_status("site-test")
        assert status["services_preserved"] is True
        assert "audit_logging" in kill_switch_controller._preserved_services
    
    @pytest.mark.asyncio
    async def test_LIC_073_monitoring_maintained(self, kill_switch_controller):
        """LIC_073: Monitoring maintenu."""
        await kill_switch_controller.activate("site-test", "license_expired")
        
        status = await kill_switch_controller.get_status("site-test")
        assert status["monitoring_active"] is True
        assert "monitoring" in kill_switch_controller._preserved_services


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_074: MESSAGE EXPLICITE DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

class TestLIC074Compliance:
    """Tests conformité LIC_074: Message explicite dashboard."""
    
    @pytest.mark.asyncio
    async def test_LIC_074_dashboard_message_when_active(self, kill_switch_controller):
        """LIC_074: Message dashboard quand kill switch actif."""
        await kill_switch_controller.activate("site-test", "license_expired")
        
        message = kill_switch_controller.get_dashboard_message("site-test")
        
        assert message != ""
        assert "SERVICE SUSPENDU" in message
        assert "LICENCE INVALIDE" in message
        assert "license_expired" in message  # Raison personnalisée
        assert "données sont préservées" in message
    
    def test_LIC_074_no_message_when_inactive(self, kill_switch_controller):
        """LIC_074: Pas de message quand kill switch inactif."""
        message = kill_switch_controller.get_dashboard_message("site-inactive")
        assert message == ""
    
    @pytest.mark.asyncio
    async def test_LIC_074_message_includes_details(self, kill_switch_controller):
        """LIC_074: Message inclut détails activation."""
        await kill_switch_controller.activate("site-test", "compliance_violation")
        
        message = kill_switch_controller.get_dashboard_message("site-test")
        
        # Vérifier format et contenu
        assert "compliance_violation" in message
        assert "╔" in message and "╚" in message  # Format ASCII box
        assert "UTC" in message  # Timestamp


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_075: RÉVERSIBLE PAR NOUVELLE LICENCE UNIQUEMENT
# ══════════════════════════════════════════════════════════════════════════════

class TestLIC075Compliance:
    """Tests conformité LIC_075: Réversible par nouvelle licence uniquement."""
    
    @pytest.mark.asyncio
    async def test_LIC_075_deactivate_requires_valid_license(self, kill_switch_controller, sample_license):
        """LIC_075: Désactivation requiert nouvelle licence valide."""
        await kill_switch_controller.activate("site-test", "license_expired")
        
        # Ne doit pas lever d'exception
        await kill_switch_controller.deactivate("site-test", sample_license)
        
        assert not kill_switch_controller.is_active("site-test")
    
    @pytest.mark.asyncio
    async def test_LIC_075_deactivate_fails_without_license(self, kill_switch_controller):
        """LIC_075: Désactivation échoue sans licence."""
        await kill_switch_controller.activate("site-test", "license_expired")
        
        with pytest.raises(KillSwitchError, match="LIC_075.*licence valide obligatoire"):
            await kill_switch_controller.deactivate("site-test", None)
    
    @pytest.mark.asyncio
    async def test_LIC_075_deactivate_fails_with_revoked_license(self, kill_switch_controller, revoked_license):
        """LIC_075: Désactivation échoue avec licence révoquée."""
        await kill_switch_controller.activate("site-test", "license_expired")
        
        with pytest.raises(KillSwitchError, match="LIC_075.*révoquée ne peut réactiver"):
            await kill_switch_controller.deactivate("site-test", revoked_license)
    
    @pytest.mark.asyncio
    async def test_LIC_075_deactivate_fails_with_expired_license(self, kill_switch_controller, expired_license):
        """LIC_075: Désactivation échoue avec licence expirée."""
        await kill_switch_controller.activate("site-test", "license_expired")
        
        with pytest.raises(KillSwitchError, match="LIC_075.*expirée ne peut réactiver"):
            await kill_switch_controller.deactivate("site-test", expired_license)
    
    @pytest.mark.asyncio
    async def test_LIC_075_deactivate_fails_wrong_site(self, kill_switch_controller, sample_license):
        """LIC_075: Désactivation échoue si licence pour autre site."""
        await kill_switch_controller.activate("site-test", "license_expired")
        
        # Licence pour autre site
        wrong_site_license = License(
            license_id=sample_license.license_id,
            site_id="other-site",  # Autre site
            issued_at=sample_license.issued_at,
            expires_at=sample_license.expires_at,
            modules=sample_license.modules,
            signature=sample_license.signature,
            issuer_id=sample_license.issuer_id
        )
        
        with pytest.raises(KillSwitchError, match="Licence pour site.*attendu"):
            await kill_switch_controller.deactivate("site-test", wrong_site_license)


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_076: ANCRAGE BLOCKCHAIN
# ══════════════════════════════════════════════════════════════════════════════

class TestLIC076Compliance:
    """Tests conformité LIC_076: Ancrage blockchain."""
    
    @pytest.mark.asyncio
    async def test_LIC_076_activation_anchored_blockchain(self, kill_switch_controller, blockchain_anchor):
        """LIC_076: Activation ancrée blockchain."""
        await kill_switch_controller.activate("site-test", "license_expired")
        
        blockchain_anchor.anchor_event.assert_called()
        
        status = await kill_switch_controller.get_status("site-test")
        assert status["blockchain_tx_id"] is not None
        assert status["blockchain_tx_id"] == "0xdef456"
    
    @pytest.mark.asyncio
    async def test_LIC_076_deactivation_anchored_blockchain(self, kill_switch_controller, sample_license, blockchain_anchor):
        """LIC_076: Désactivation ancrée blockchain."""
        await kill_switch_controller.activate("site-test", "license_expired")
        
        # Reset mock pour compter seulement désactivation
        blockchain_anchor.anchor_event.reset_mock()
        
        await kill_switch_controller.deactivate("site-test", sample_license)
        
        blockchain_anchor.anchor_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_LIC_076_blockchain_tx_id_stored(self, kill_switch_controller):
        """LIC_076: blockchain_tx_id stocké."""
        await kill_switch_controller.activate("site-test", "license_expired")
        
        # Vérifier stockage dans état interne
        switch_state = kill_switch_controller._active_switches["site-test"]
        assert switch_state.blockchain_tx_id == "0xdef456"


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_077: DÉTECTION TENTATIVES CONTOURNEMENT
# ══════════════════════════════════════════════════════════════════════════════

class TestLIC077Compliance:
    """Tests conformité LIC_077: Tentative contournement = alerte CRITICAL."""
    
    @pytest.mark.asyncio
    async def test_LIC_077_bypass_detection_emits_critical_alert(self, kill_switch_controller, audit_emitter):
        """LIC_077: Détection contournement émet alerte CRITICAL."""
        await kill_switch_controller.activate("site-test", "license_expired")
        
        # Reset pour compter seulement détection contournement
        audit_emitter.emit_event.reset_mock()
        
        await kill_switch_controller.detect_bypass_attempt("site-test", "unauthorized_api_call")
        
        # Vérifier audit critique
        audit_emitter.emit_event.assert_called_once()
        call_args = audit_emitter.emit_event.call_args
        
        assert call_args[0][0] == AuditEventType.SECURITY_BREACH  # Critique
        assert call_args[0][3] == "bypass_attempt_detected"
        assert call_args[1]["metadata"]["attempted_action"] == "unauthorized_api_call"
        assert call_args[1]["metadata"]["severity"] == "CRITICAL"
    
    @pytest.mark.asyncio
    async def test_LIC_077_bypass_attempts_counted(self, kill_switch_controller):
        """LIC_077: Tentatives contournement comptées."""
        await kill_switch_controller.activate("site-test", "license_expired")
        
        await kill_switch_controller.detect_bypass_attempt("site-test", "action1")
        await kill_switch_controller.detect_bypass_attempt("site-test", "action2")
        
        switch_state = kill_switch_controller._active_switches["site-test"]
        assert switch_state.bypass_attempts == 2
    
    @pytest.mark.asyncio
    async def test_LIC_077_bypass_detection_inactive_site_ignored(self, kill_switch_controller, audit_emitter):
        """LIC_077: Détection contournement ignorée pour site inactif."""
        # Site pas en kill switch
        await kill_switch_controller.detect_bypass_attempt("site-inactive", "unauthorized_action")
        
        # Aucun audit ne doit être émis
        audit_emitter.emit_event.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_LIC_077_bypass_attempts_in_status(self, kill_switch_controller):
        """LIC_077: Tentatives contournement dans statut."""
        await kill_switch_controller.activate("site-test", "license_expired")
        
        await kill_switch_controller.detect_bypass_attempt("site-test", "bypass_action")
        await kill_switch_controller.detect_bypass_attempt("site-test", "another_bypass")
        
        status = await kill_switch_controller.get_status("site-test")
        assert status["bypass_attempts"] == 2


# ══════════════════════════════════════════════════════════════════════════════
# TESTS FONCTIONS UTILITAIRES
# ══════════════════════════════════════════════════════════════════════════════

class TestUtilities:
    """Tests fonctions utilitaires."""
    
    @pytest.mark.asyncio
    async def test_get_status_inactive_site(self, kill_switch_controller):
        """get_status pour site inactif."""
        status = await kill_switch_controller.get_status("site-inactive")
        
        assert status["active"] is False
        assert status["site_id"] == "site-inactive"
    
    @pytest.mark.asyncio
    async def test_get_status_active_site_complete(self, kill_switch_controller):
        """get_status pour site actif - informations complètes."""
        await kill_switch_controller.activate("site-test", "compliance_issue")
        
        status = await kill_switch_controller.get_status("site-test")
        
        assert status["active"] is True
        assert status["site_id"] == "site-test"
        assert status["reason"] == "compliance_issue"
        assert "activated_at" in status
        assert "duration_hours" in status
        assert status["duration_hours"] >= 0
        assert status["blockchain_tx_id"] is not None
        assert status["bypass_attempts"] == 0
        assert status["services_preserved"] is True
        assert status["monitoring_active"] is True
    
    def test_get_kill_switch_stats_empty(self, kill_switch_controller):
        """Statistiques kill switch - aucun actif."""
        stats = kill_switch_controller.get_kill_switch_stats()
        
        assert stats["total_active_switches"] == 0
        assert stats["oldest_switch_hours"] == 0
        assert stats["total_bypass_attempts"] == 0
    
    @pytest.mark.asyncio
    async def test_get_kill_switch_stats_with_active_switches(self, kill_switch_controller):
        """Statistiques kill switch - avec switches actifs."""
        await kill_switch_controller.activate("site-1", "reason1")
        await kill_switch_controller.activate("site-2", "reason2")
        
        # Ajouter tentatives contournement
        await kill_switch_controller.detect_bypass_attempt("site-1", "action1")
        await kill_switch_controller.detect_bypass_attempt("site-1", "action2")
        await kill_switch_controller.detect_bypass_attempt("site-2", "action3")
        
        stats = kill_switch_controller.get_kill_switch_stats()
        
        assert stats["total_active_switches"] == 2
        assert stats["oldest_switch_hours"] >= 0
        assert stats["average_duration_hours"] >= 0
        assert stats["total_bypass_attempts"] == 3
        assert "data_storage" in stats["preserved_services"]
        assert "audit_logging" in stats["preserved_services"]
        assert "monitoring" in stats["preserved_services"]


# ══════════════════════════════════════════════════════════════════════════════
# TESTS VALIDATION ENTRÉES
# ══════════════════════════════════════════════════════════════════════════════

class TestInputValidation:
    """Tests validation entrées."""
    
    @pytest.mark.asyncio
    async def test_activate_empty_site_id_fails(self, kill_switch_controller):
        """activate() avec site_id vide échoue."""
        with pytest.raises(KillSwitchError, match="site_id obligatoire"):
            await kill_switch_controller.activate("", "reason")
    
    @pytest.mark.asyncio
    async def test_activate_empty_reason_fails(self, kill_switch_controller):
        """activate() avec raison vide échoue."""
        with pytest.raises(KillSwitchError, match="Raison activation obligatoire"):
            await kill_switch_controller.activate("site-test", "")
    
    @pytest.mark.asyncio
    async def test_activate_already_active_fails(self, kill_switch_controller):
        """activate() déjà actif échoue."""
        await kill_switch_controller.activate("site-test", "reason1")
        
        with pytest.raises(KillSwitchError, match="déjà actif"):
            await kill_switch_controller.activate("site-test", "reason2")
    
    @pytest.mark.asyncio
    async def test_deactivate_empty_site_id_fails(self, kill_switch_controller, sample_license):
        """deactivate() avec site_id vide échoue."""
        with pytest.raises(KillSwitchError, match="site_id obligatoire"):
            await kill_switch_controller.deactivate("", sample_license)
    
    @pytest.mark.asyncio
    async def test_deactivate_inactive_site_fails(self, kill_switch_controller, sample_license):
        """deactivate() site inactif échoue."""
        with pytest.raises(KillSwitchError, match="Aucun kill switch actif"):
            await kill_switch_controller.deactivate("site-inactive", sample_license)
    
    def test_is_active_nonexistent_site_returns_false(self, kill_switch_controller):
        """is_active() site inexistant retourne False."""
        assert not kill_switch_controller.is_active("nonexistent-site")


# ══════════════════════════════════════════════════════════════════════════════
# TESTS INTÉGRATION AUDIT
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditIntegration:
    """Tests intégration audit."""
    
    @pytest.mark.asyncio
    async def test_activation_emits_security_breach_audit(self, kill_switch_controller, audit_emitter):
        """Activation émet audit SECURITY_BREACH."""
        await kill_switch_controller.activate("site-test", "license_violation")
        
        # Vérifier audit activation
        calls = audit_emitter.emit_event.call_args_list
        activation_audit = None
        
        for call in calls:
            if call[0][3] == "kill_switch_activated":
                activation_audit = call
                break
        
        assert activation_audit is not None
        assert activation_audit[0][0] == AuditEventType.SECURITY_BREACH
        assert activation_audit[1]["metadata"]["reason"] == "license_violation"
        assert "blockchain_tx_id" in activation_audit[1]["metadata"]
    
    @pytest.mark.asyncio
    async def test_deactivation_emits_config_change_audit(self, kill_switch_controller, sample_license, audit_emitter):
        """Désactivation émet audit SYSTEM_CONFIG_CHANGE."""
        await kill_switch_controller.activate("site-test", "license_expired")
        
        # Reset pour compter seulement désactivation
        audit_emitter.emit_event.reset_mock()
        
        await kill_switch_controller.deactivate("site-test", sample_license)
        
        # Vérifier qu'il y a 2 appels: réactivation services + désactivation kill switch
        assert audit_emitter.emit_event.call_count == 2
        
        calls = audit_emitter.emit_event.call_args_list
        
        # Premier appel: réactivation services
        services_call = calls[0]
        assert services_call[0][0] == AuditEventType.SYSTEM_CONFIG_CHANGE
        assert services_call[0][3] == "services_reactivated"
        
        # Deuxième appel: désactivation kill switch
        deactivation_call = calls[1]
        assert deactivation_call[0][0] == AuditEventType.SYSTEM_CONFIG_CHANGE
        assert deactivation_call[0][3] == "kill_switch_deactivated"
        assert deactivation_call[1]["metadata"]["new_license_id"] == sample_license.license_id