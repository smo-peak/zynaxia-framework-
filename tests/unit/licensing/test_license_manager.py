"""
Tests unitaires LicenseManager

Invariants testés:
    LIC_001: Licence signée ECDSA-P384
    LIC_002: Contenu obligatoire site_id org_id dates modules
    LIC_003: Durée maximale 366 jours
    LIC_004: Émission ancrée blockchain
    LIC_005: Une licence = un site
    LIC_006: Émission par License Manager Cloud uniquement
    LIC_061: Révocation requiert quorum
    LIC_090: Tout événement licence = audit
"""
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, AsyncMock

from src.licensing.interfaces import (
    ILicenseManager,
    LicenseConfig,
    License,
    ValidationResult,
    Signature,
    LicenseStatus,
    GracePeriodStatus
)
from src.licensing.license_manager import LicenseManager, LicenseManagerError
from src.core.crypto_provider import CryptoProvider
from src.audit.audit_emitter import AuditEmitter
from src.audit.blockchain_anchor import BlockchainAnchor, AnchorReceipt


# ══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def crypto_provider():
    """CryptoProvider mocké pour tests."""
    provider = Mock()
    provider.sign.return_value = b"mocked_license_signature"
    provider.verify_signature.return_value = True
    return provider


@pytest.fixture
def audit_emitter():
    """AuditEmitter mocké pour tests."""
    emitter = AsyncMock()
    emitter.emit_event.return_value = Mock()  # AuditEvent mocké
    return emitter


@pytest.fixture
def blockchain_anchor():
    """BlockchainAnchor mocké pour tests."""
    anchor = AsyncMock()
    # Mock receipt ancrage
    mock_receipt = AnchorReceipt(
        event_hash="license_hash_123",
        blockchain_tx_id="0xabc123",
        block_height=1000000,
        anchor_timestamp=datetime.now(timezone.utc),
        confirmation_count=6,
        anchor_proof="merkle_proof_123"
    )
    anchor.anchor_event.return_value = mock_receipt
    anchor.get_anchor_proof.return_value = mock_receipt
    anchor.verify_anchor.return_value = True
    return anchor


@pytest.fixture
def license_manager(crypto_provider, audit_emitter, blockchain_anchor):
    """LicenseManager instance pour tests."""
    return LicenseManager(
        crypto_provider=crypto_provider,
        audit_emitter=audit_emitter,
        blockchain_anchor=blockchain_anchor,
        cloud_mode=True
    )


@pytest.fixture
def valid_license_config():
    """Configuration licence valide."""
    return LicenseConfig(
        site_id="site-123",
        modules=["surveillance", "access_control"],
        duration_days=90,
        issuer_id="cloud-license-manager",
        organization_id="org-456"
    )


@pytest.fixture
def sample_signatures():
    """Signatures quorum pour révocation."""
    import base64
    now = datetime.now(timezone.utc)
    
    # Créer signatures base64 valides
    sig1_bytes = b"valid_signature_admin_1_data_for_tests"
    sig2_bytes = b"valid_signature_admin_2_data_for_tests"
    
    return [
        Signature(
            signer_id="admin-1",
            signature=base64.b64encode(sig1_bytes).decode('utf-8'),
            timestamp=now,
            action="revoke_license"
        ),
        Signature(
            signer_id="admin-2", 
            signature=base64.b64encode(sig2_bytes).decode('utf-8'),
            timestamp=now,
            action="revoke_license"
        )
    ]


# ══════════════════════════════════════════════════════════════════════════════
# TESTS INTERFACE
# ══════════════════════════════════════════════════════════════════════════════

class TestLicenseManagerInterface:
    """Vérifie conformité interface."""
    
    def test_implements_interface(self, license_manager):
        """LicenseManager implémente ILicenseManager."""
        assert isinstance(license_manager, ILicenseManager)
    
    def test_max_duration_constant(self):
        """Durée max licence = 366 jours (LIC_003)."""
        assert LicenseManager.MAX_LICENSE_DURATION_DAYS == 366
    
    def test_available_modules_defined(self):
        """Modules disponibles définis."""
        assert len(LicenseManager.AVAILABLE_MODULES) > 0
        assert "surveillance" in LicenseManager.AVAILABLE_MODULES
        assert "access_control" in LicenseManager.AVAILABLE_MODULES


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_006: ÉMISSION CLOUD UNIQUEMENT
# ══════════════════════════════════════════════════════════════════════════════

class TestLIC006Compliance:
    """Tests conformité LIC_006: Émission Cloud uniquement."""
    
    @pytest.mark.asyncio
    async def test_LIC_006_issue_requires_cloud_mode(self, crypto_provider, audit_emitter, blockchain_anchor, valid_license_config):
        """LIC_006: Émission requiert mode Cloud."""
        # Manager en mode Edge (non-Cloud)
        edge_manager = LicenseManager(
            crypto_provider=crypto_provider,
            audit_emitter=audit_emitter,
            blockchain_anchor=blockchain_anchor,
            cloud_mode=False  # Mode Edge
        )
        
        with pytest.raises(LicenseManagerError, match="LIC_006.*Cloud"):
            await edge_manager.issue(valid_license_config)
    
    @pytest.mark.asyncio
    async def test_LIC_006_renew_requires_cloud_mode(self, crypto_provider, audit_emitter, blockchain_anchor):
        """LIC_006: Renouvellement requiert mode Cloud."""
        edge_manager = LicenseManager(
            crypto_provider=crypto_provider,
            audit_emitter=audit_emitter,
            blockchain_anchor=blockchain_anchor,
            cloud_mode=False
        )
        
        with pytest.raises(LicenseManagerError, match="LIC_006.*Cloud"):
            await edge_manager.renew("site-123", 90)
    
    @pytest.mark.asyncio
    async def test_LIC_006_cloud_mode_allows_issue(self, license_manager, valid_license_config):
        """LIC_006: Mode Cloud permet émission."""
        # Ne doit pas lever d'exception de mode
        license = await license_manager.issue(valid_license_config)
        assert license is not None


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_001-005: STRUCTURE LICENCE
# ══════════════════════════════════════════════════════════════════════════════

class TestLicenseStructure:
    """Tests structure licence LIC_001-005."""
    
    @pytest.mark.asyncio
    async def test_LIC_001_license_has_signature(self, license_manager, valid_license_config, crypto_provider):
        """LIC_001: Licence signée ECDSA-P384."""
        license = await license_manager.issue(valid_license_config)
        
        assert license.signature is not None
        assert len(license.signature) > 0
        crypto_provider.sign.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_LIC_002_license_has_required_fields(self, license_manager, valid_license_config):
        """LIC_002: Contenu obligatoire site_id org_id dates modules."""
        license = await license_manager.issue(valid_license_config)
        
        # Vérifier champs obligatoires
        assert license.license_id is not None
        assert license.site_id == valid_license_config.site_id
        assert license.issued_at is not None
        assert license.expires_at is not None
        assert license.modules == valid_license_config.modules
        assert license.signature is not None
        assert license.issuer_id == valid_license_config.issuer_id
        assert license.organization_id == valid_license_config.organization_id
    
    @pytest.mark.asyncio
    async def test_LIC_003_duration_enforced(self, license_manager):
        """LIC_003: Durée maximale 366 jours."""
        invalid_config = LicenseConfig(
            site_id="site-123",
            modules=["surveillance"],
            duration_days=400,  # > 366 jours
            issuer_id="issuer-123"
        )
        
        with pytest.raises(LicenseManagerError, match="LIC_003"):
            await license_manager.issue(invalid_config)
    
    @pytest.mark.asyncio
    async def test_LIC_004_blockchain_anchor(self, license_manager, valid_license_config, blockchain_anchor):
        """LIC_004: Émission ancrée blockchain."""
        license = await license_manager.issue(valid_license_config)
        
        assert license.blockchain_tx_id is not None
        blockchain_anchor.anchor_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_LIC_005_one_license_per_site(self, license_manager, valid_license_config):
        """LIC_005: Une licence = un site."""
        # Émettre première licence
        await license_manager.issue(valid_license_config)
        
        # Tenter émettre seconde licence même site
        duplicate_config = LicenseConfig(
            site_id=valid_license_config.site_id,  # Même site_id
            modules=["visitor_management"],
            duration_days=60,
            issuer_id="another-issuer"
        )
        
        with pytest.raises(LicenseManagerError, match="LIC_005"):
            await license_manager.issue(duplicate_config)


# ══════════════════════════════════════════════════════════════════════════════
# TESTS VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

class TestLicenseValidation:
    """Tests validation licence."""
    
    @pytest.mark.asyncio
    async def test_validate_valid_license(self, license_manager, valid_license_config):
        """Licence valide passe validation."""
        license = await license_manager.issue(valid_license_config)
        
        result = await license_manager.validate(license)
        
        assert result.valid is True
        assert result.status == LicenseStatus.VALID
        assert result.expires_in_days > 0
        assert result.is_degraded is False
        assert result.blockchain_verified is True
    
    @pytest.mark.asyncio
    async def test_validate_revoked_license(self, license_manager, valid_license_config):
        """Licence révoquée échoue validation."""
        license = await license_manager.issue(valid_license_config)
        
        # Marquer comme révoquée manuellement pour le test
        license_manager._licenses[license.site_id] = License(
            license_id=license.license_id,
            site_id=license.site_id,
            issued_at=license.issued_at,
            expires_at=license.expires_at,
            modules=license.modules,
            signature=license.signature,
            issuer_id=license.issuer_id,
            organization_id=license.organization_id,
            blockchain_tx_id=license.blockchain_tx_id,
            revoked=True,
            revoked_at=datetime.now(timezone.utc),
            revoked_reason="test_revocation"
        )
        
        revoked_license = license_manager._licenses[license.site_id]
        result = await license_manager.validate(revoked_license)
        
        assert result.valid is False
        assert result.status == LicenseStatus.REVOKED
        assert "révoquée" in result.reason.lower()
    
    @pytest.mark.asyncio
    async def test_validate_invalid_signature(self, license_manager, valid_license_config, crypto_provider):
        """Signature invalide échoue validation."""
        license = await license_manager.issue(valid_license_config)
        
        # Simuler signature invalide
        crypto_provider.verify_signature.return_value = False
        
        result = await license_manager.validate(license)
        
        assert result.valid is False
        assert result.status == LicenseStatus.INVALID_SIGNATURE
    
    @pytest.mark.asyncio
    async def test_validate_expired_license_grace_period(self, audit_emitter, blockchain_anchor):
        """Licence expirée en grace period = mode dégradé."""
        # Créer crypto_provider qui retourne True pour validation signature
        from unittest.mock import Mock
        crypto_provider = Mock()
        # verify_signature(data, signature, key_id) - accepte 3 arguments
        crypto_provider.verify_signature.return_value = True
        
        # Créer licence expirée mais dans grace period
        now = datetime.now(timezone.utc)
        
        # Signature base64 valide
        import base64
        valid_sig_bytes = b"test_signature_for_grace_period_license"
        valid_signature_b64 = base64.b64encode(valid_sig_bytes).decode('utf-8')
        
        expired_license = License(
            license_id="expired-123",
            site_id="site-expired",
            issued_at=now - timedelta(days=95),
            expires_at=now - timedelta(days=5),  # Expirée depuis 5 jours < 7j grace period
            modules=["surveillance"],
            signature=valid_signature_b64,  # Base64 valide
            issuer_id="issuer-123",
            blockchain_tx_id="0xabc123"
        )
        
        manager = LicenseManager(crypto_provider, audit_emitter, blockchain_anchor)
        result = await manager.validate(expired_license)
        
        assert result.valid is True  # Techniquement valide mais dégradé
        assert result.status == LicenseStatus.EXPIRED
        assert result.is_degraded is True
        assert result.grace_period_status == GracePeriodStatus.ACTIVE


# ══════════════════════════════════════════════════════════════════════════════
# TESTS RENOUVELLEMENT
# ══════════════════════════════════════════════════════════════════════════════

class TestLicenseRenewal:
    """Tests renouvellement licence."""
    
    @pytest.mark.asyncio
    async def test_LIC_050_renew_creates_new_license(self, license_manager, valid_license_config):
        """LIC_050: Renouvellement = nouvelle licence."""
        # Émettre licence initiale
        original_license = await license_manager.issue(valid_license_config)
        
        # Renouveler
        renewed_license = await license_manager.renew(valid_license_config.site_id, 120)
        
        # Vérifier nouvelle licence
        assert renewed_license.license_id != original_license.license_id
        assert renewed_license.site_id == original_license.site_id
        assert renewed_license.issued_at > original_license.issued_at
        assert (renewed_license.expires_at - renewed_license.issued_at).days == 120
    
    @pytest.mark.asyncio
    async def test_renew_nonexistent_license_fails(self, license_manager):
        """Renouvellement licence inexistante échoue."""
        with pytest.raises(LicenseManagerError, match="Aucune licence trouvée"):
            await license_manager.renew("nonexistent-site", 90)
    
    @pytest.mark.asyncio
    async def test_renew_invalid_duration_fails(self, license_manager, valid_license_config):
        """Renouvellement durée invalide échoue."""
        await license_manager.issue(valid_license_config)
        
        with pytest.raises(LicenseManagerError, match="LIC_003"):
            await license_manager.renew(valid_license_config.site_id, 500)  # > 366 jours


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_061: RÉVOCATION QUORUM
# ══════════════════════════════════════════════════════════════════════════════

class TestLIC061Compliance:
    """Tests conformité LIC_061: Révocation requiert quorum."""
    
    @pytest.mark.asyncio
    async def test_LIC_061_revoke_requires_quorum(self, license_manager, valid_license_config):
        """LIC_061: Révocation requiert minimum 2 signatures."""
        license = await license_manager.issue(valid_license_config)
        
        # Une seule signature = insuffisant
        single_signature = [Signature(
            signer_id="admin-1",
            signature="sig1",
            timestamp=datetime.now(timezone.utc),
            action="revoke"
        )]
        
        with pytest.raises(LicenseManagerError, match="LIC_061.*quorum"):
            await license_manager.revoke(license.site_id, "security_breach", single_signature)
    
    @pytest.mark.asyncio
    async def test_LIC_061_revoke_with_sufficient_quorum(self, license_manager, valid_license_config, sample_signatures, crypto_provider):
        """LIC_061: Révocation avec quorum suffisant."""
        license = await license_manager.issue(valid_license_config)
        
        # Configurer validation signatures
        crypto_provider.verify_signature.return_value = True
        
        # Ne doit pas lever d'exception
        await license_manager.revoke(license.site_id, "security_breach", sample_signatures)
        
        # Vérifier licence révoquée
        revoked_license = await license_manager.get_license(license.site_id)
        assert revoked_license.revoked is True
        assert revoked_license.revoked_reason == "security_breach"
    
    @pytest.mark.asyncio
    async def test_LIC_066_revoke_requires_reason(self, license_manager, valid_license_config, sample_signatures):
        """LIC_066: Raison révocation obligatoire."""
        license = await license_manager.issue(valid_license_config)
        
        with pytest.raises(LicenseManagerError, match="LIC_066.*Raison.*obligatoire"):
            await license_manager.revoke(license.site_id, "", sample_signatures)  # Raison vide


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_090: AUDIT
# ══════════════════════════════════════════════════════════════════════════════

class TestLIC090Compliance:
    """Tests conformité LIC_090: Tout événement licence = audit."""
    
    @pytest.mark.asyncio
    async def test_LIC_090_issue_emits_audit(self, license_manager, valid_license_config, audit_emitter):
        """LIC_090: Émission licence génère audit."""
        await license_manager.issue(valid_license_config)
        
        audit_emitter.emit_event.assert_called_once()
        call_args = audit_emitter.emit_event.call_args
        
        # Vérifier arguments positionnels: emit_event(event_type, user_id, tenant_id, action, resource_id=..., metadata=...)
        assert call_args[0][3] == "license_issued"  # action est le 4ème argument (index 3)
        # Vérifier keyword arguments
        assert call_args[1]['resource_id'] is not None  # license_id
    
    @pytest.mark.asyncio
    async def test_LIC_090_revoke_emits_audit(self, license_manager, valid_license_config, sample_signatures, audit_emitter, crypto_provider):
        """LIC_090: Révocation licence génère audit."""
        license = await license_manager.issue(valid_license_config)
        
        # Reset pour compter seulement audit révocation
        audit_emitter.emit_event.reset_mock()
        crypto_provider.verify_signature.return_value = True
        
        await license_manager.revoke(license.site_id, "security_breach", sample_signatures)
        
        # Vérifier audit révocation
        audit_emitter.emit_event.assert_called_once()
        call_args = audit_emitter.emit_event.call_args
        assert call_args[0][3] == "license_revoked"  # action est le 4ème argument
    
    @pytest.mark.asyncio
    async def test_LIC_090_renew_emits_audit(self, license_manager, valid_license_config, audit_emitter):
        """LIC_090: Renouvellement licence génère audit."""
        await license_manager.issue(valid_license_config)
        
        # Reset pour compter seulement audit renouvellement
        audit_emitter.emit_event.reset_mock()
        
        await license_manager.renew(valid_license_config.site_id, 120)
        
        # Vérifier audit renouvellement (émission + renouvellement = 2 appels)
        assert audit_emitter.emit_event.call_count == 2
        
        # Order: 1) issue() -> "license_issued", 2) renew audit -> "license_renewed" 
        calls = audit_emitter.emit_event.call_args_list
        issue_call = calls[0]  # Premier appel = issue de la nouvelle licence
        renew_call = calls[1]   # Deuxième appel = audit renouvellement
        
        assert issue_call[0][3] == "license_issued"   # Nouvelle licence émise
        assert renew_call[0][3] == "license_renewed"  # Audit renouvellement


# ══════════════════════════════════════════════════════════════════════════════
# TESTS VALIDATION ENTRÉES
# ══════════════════════════════════════════════════════════════════════════════

class TestInputValidation:
    """Tests validation entrées."""
    
    @pytest.mark.asyncio
    async def test_issue_empty_site_id_fails(self, license_manager):
        """site_id vide → Exception."""
        invalid_config = LicenseConfig(
            site_id="",  # Vide
            modules=["surveillance"],
            duration_days=90,
            issuer_id="issuer-123"
        )
        
        with pytest.raises(LicenseManagerError, match="LIC_002.*site_id"):
            await license_manager.issue(invalid_config)
    
    @pytest.mark.asyncio
    async def test_issue_empty_modules_fails(self, license_manager):
        """modules vides → Exception."""
        invalid_config = LicenseConfig(
            site_id="site-123",
            modules=[],  # Vide
            duration_days=90,
            issuer_id="issuer-123"
        )
        
        with pytest.raises(LicenseManagerError, match="LIC_002.*modules"):
            await license_manager.issue(invalid_config)
    
    @pytest.mark.asyncio
    async def test_issue_invalid_modules_fails(self, license_manager):
        """Modules non disponibles → Exception."""
        invalid_config = LicenseConfig(
            site_id="site-123",
            modules=["invalid_module", "another_invalid"],
            duration_days=90,
            issuer_id="issuer-123"
        )
        
        with pytest.raises(LicenseManagerError, match="Modules invalides"):
            await license_manager.issue(invalid_config)
    
    @pytest.mark.asyncio
    async def test_issue_negative_duration_fails(self, license_manager):
        """Durée négative → Exception."""
        invalid_config = LicenseConfig(
            site_id="site-123",
            modules=["surveillance"],
            duration_days=-10,  # Négatif
            issuer_id="issuer-123"
        )
        
        with pytest.raises(LicenseManagerError, match="positive"):
            await license_manager.issue(invalid_config)


# ══════════════════════════════════════════════════════════════════════════════
# TESTS UTILITAIRES
# ══════════════════════════════════════════════════════════════════════════════

class TestUtilities:
    """Tests fonctions utilitaires."""
    
    @pytest.mark.asyncio
    async def test_get_license_returns_existing(self, license_manager, valid_license_config):
        """get_license retourne licence existante."""
        issued_license = await license_manager.issue(valid_license_config)
        
        retrieved_license = await license_manager.get_license(valid_license_config.site_id)
        
        assert retrieved_license is not None
        assert retrieved_license.license_id == issued_license.license_id
    
    @pytest.mark.asyncio
    async def test_get_license_returns_none_for_nonexistent(self, license_manager):
        """get_license retourne None pour licence inexistante."""
        result = await license_manager.get_license("nonexistent-site")
        assert result is None
    
    @pytest.mark.asyncio
    async def test_verify_blockchain_anchor_valid(self, license_manager, valid_license_config):
        """Vérification ancrage blockchain valide."""
        license = await license_manager.issue(valid_license_config)
        
        is_verified = await license_manager.verify_blockchain_anchor(license)
        assert is_verified is True
    
    @pytest.mark.asyncio
    async def test_verify_blockchain_anchor_no_tx_id(self, license_manager):
        """Vérification ancrage sans blockchain_tx_id."""
        license_without_tx = License(
            license_id="test-123",
            site_id="site-123",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=90),
            modules=["surveillance"],
            signature="valid_signature",
            issuer_id="issuer-123",
            blockchain_tx_id=None  # Pas d'ancrage
        )
        
        is_verified = await license_manager.verify_blockchain_anchor(license_without_tx)
        assert is_verified is False
    
    def test_get_license_stats(self, license_manager):
        """Statistiques licences."""
        stats = license_manager.get_license_stats()
        
        assert "total_licenses" in stats
        assert "active_licenses" in stats
        assert "revoked_licenses" in stats
        assert "cloud_mode" in stats
        assert stats["max_duration_days"] == 366
        assert stats["grace_period_days"] == 7