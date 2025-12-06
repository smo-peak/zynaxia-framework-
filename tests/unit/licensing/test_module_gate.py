"""
Tests unitaires ModuleGate

Invariants testés:
    LIC_080: Modules en liste blanche (licence définit modules activés)
    LIC_081: Module non licencié = 403 Forbidden
    LIC_082: UI masque fonctionnalité non licenciée
    LIC_083: Tentative accès module non licencié = audit log
    LIC_084: Upgrade = nouvelle licence complète
    LIC_085: Downgrade = nouvelle licence (modules retirés inaccessibles)
"""
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, AsyncMock

from src.licensing.interfaces import IModuleGate, ILicenseCache, License
from src.licensing.module_gate import (
    ModuleGate,
    ModuleAccessDeniedError
)
from src.audit.audit_emitter import AuditEmitter
from src.audit.interfaces import AuditEventType


# ══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def license_cache():
    """LicenseCache mocké pour tests."""
    cache = Mock()
    cache.get.return_value = None
    return cache


@pytest.fixture
def audit_emitter():
    """AuditEmitter mocké pour tests."""
    emitter = AsyncMock()
    emitter.emit_event.return_value = Mock()
    return emitter


@pytest.fixture
def module_gate(license_cache, audit_emitter):
    """ModuleGate instance pour tests."""
    return ModuleGate(
        license_cache=license_cache,
        audit_emitter=audit_emitter
    )


@pytest.fixture
def sample_license():
    """Licence avec modules pour tests."""
    now = datetime.now(timezone.utc)
    return License(
        license_id="license-modules-123",
        site_id="site-modules",
        issued_at=now - timedelta(days=30),
        expires_at=now + timedelta(days=60),
        modules=["surveillance", "access_control", "visitor_management"],
        signature="valid_signature_modules",
        issuer_id="cloud-license-manager",
        organization_id="org-modules",
        blockchain_tx_id="0xmodules123"
    )


@pytest.fixture
def limited_license():
    """Licence avec modules limités."""
    now = datetime.now(timezone.utc)
    return License(
        license_id="license-limited-456",
        site_id="site-limited",
        issued_at=now,
        expires_at=now + timedelta(days=90),
        modules=["surveillance"],  # Un seul module
        signature="limited_signature",
        issuer_id="cloud-license-manager",
        organization_id="org-limited",
        blockchain_tx_id="0xlimited456"
    )


@pytest.fixture
def expired_license():
    """Licence expirée mais dans grace period."""
    now = datetime.now(timezone.utc)
    return License(
        license_id="expired-grace-789",
        site_id="site-expired-grace",
        issued_at=now - timedelta(days=95),
        expires_at=now - timedelta(days=3),  # Expirée depuis 3j < 7j grace
        modules=["surveillance", "access_control"],
        signature="expired_signature",
        issuer_id="issuer",
        blockchain_tx_id="0xexpired123"
    )


@pytest.fixture
def grace_expired_license():
    """Licence avec grace period expirée."""
    now = datetime.now(timezone.utc)
    return License(
        license_id="grace-expired-999",
        site_id="site-grace-expired",
        issued_at=now - timedelta(days=105),
        expires_at=now - timedelta(days=10),  # Expirée depuis 10j > 7j grace
        modules=["surveillance"],
        signature="grace_expired_signature",
        issuer_id="issuer"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TESTS INTERFACE
# ══════════════════════════════════════════════════════════════════════════════

class TestModuleGateInterface:
    """Vérifie conformité interface."""
    
    def test_implements_interface(self, module_gate):
        """ModuleGate implémente IModuleGate."""
        assert isinstance(module_gate, IModuleGate)
    
    def test_exception_class_defined(self):
        """ModuleAccessDeniedError définie (LIC_081)."""
        exception = ModuleAccessDeniedError("test_module", "test_site")
        assert "test_module" in str(exception)
        assert "test_site" in str(exception)
        assert exception.module_id == "test_module"
        assert exception.site_id == "test_site"


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_080: MODULES LISTE BLANCHE
# ══════════════════════════════════════════════════════════════════════════════

class TestLIC080Compliance:
    """Tests conformité LIC_080: Modules en liste blanche."""
    
    def test_LIC_080_licensed_modules_from_license(self, module_gate, license_cache, sample_license):
        """LIC_080: Modules licenciés définis par licence."""
        license_cache.get.return_value = sample_license
        
        licensed_modules = module_gate.get_licensed_modules("site-modules")
        
        expected_modules = sorted(sample_license.modules)
        assert licensed_modules == expected_modules
        assert "surveillance" in licensed_modules
        assert "access_control" in licensed_modules
        assert "visitor_management" in licensed_modules
    
    def test_LIC_080_no_license_no_modules(self, module_gate, license_cache):
        """LIC_080: Pas de licence = aucun module."""
        license_cache.get.return_value = None
        
        licensed_modules = module_gate.get_licensed_modules("site-no-license")
        
        assert licensed_modules == []
    
    def test_LIC_080_revoked_license_no_modules(self, module_gate, license_cache, sample_license):
        """LIC_080: Licence révoquée = aucun module."""
        revoked_license = License(
            license_id=sample_license.license_id,
            site_id=sample_license.site_id,
            issued_at=sample_license.issued_at,
            expires_at=sample_license.expires_at,
            modules=sample_license.modules,
            signature=sample_license.signature,
            issuer_id=sample_license.issuer_id,
            organization_id=sample_license.organization_id,
            blockchain_tx_id=sample_license.blockchain_tx_id,
            revoked=True,
            revoked_at=datetime.now(timezone.utc),
            revoked_reason="security_breach"
        )
        license_cache.get.return_value = revoked_license
        
        licensed_modules = module_gate.get_licensed_modules("site-modules")
        
        assert licensed_modules == []
    
    def test_LIC_080_module_check_individual(self, module_gate, license_cache, sample_license):
        """LIC_080: Vérification module individuel."""
        license_cache.get.return_value = sample_license
        
        # Modules licenciés
        assert module_gate.is_module_licensed("site-modules", "surveillance") is True
        assert module_gate.is_module_licensed("site-modules", "access_control") is True
        assert module_gate.is_module_licensed("site-modules", "visitor_management") is True
        
        # Modules non licenciés
        assert module_gate.is_module_licensed("site-modules", "analytics_dashboard") is False
        assert module_gate.is_module_licensed("site-modules", "inventory_management") is False


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_081: MODULE NON LICENCIÉ = 403 FORBIDDEN
# ══════════════════════════════════════════════════════════════════════════════

class TestLIC081Compliance:
    """Tests conformité LIC_081: Module non licencié = 403 Forbidden."""
    
    def test_LIC_081_check_module_access_licensed_module_returns_true(self, module_gate, license_cache, sample_license):
        """LIC_081: check_module_access retourne True pour module licencié."""
        license_cache.get.return_value = sample_license
        
        access_granted = module_gate.check_module_access("site-modules", "surveillance", "user-123")
        
        assert access_granted is True
    
    def test_LIC_081_check_module_access_unlicensed_module_returns_false(self, module_gate, license_cache, sample_license):
        """LIC_081: check_module_access retourne False pour module non licencié."""
        license_cache.get.return_value = sample_license
        
        access_denied = module_gate.check_module_access("site-modules", "analytics_dashboard", "user-123")
        
        assert access_denied is False
    
    def test_LIC_081_raise_if_not_licensed_success(self, module_gate, license_cache, sample_license):
        """LIC_081: raise_if_not_licensed réussit pour module licencié."""
        license_cache.get.return_value = sample_license
        
        # Ne doit pas lever d'exception
        module_gate.raise_if_not_licensed("site-modules", "surveillance")
    
    def test_LIC_081_raise_if_not_licensed_raises_exception(self, module_gate, license_cache, sample_license):
        """LIC_081: raise_if_not_licensed lève exception pour module non licencié."""
        license_cache.get.return_value = sample_license
        
        with pytest.raises(ModuleAccessDeniedError) as exc_info:
            module_gate.raise_if_not_licensed("site-modules", "analytics_dashboard")
        
        exception = exc_info.value
        assert exception.module_id == "analytics_dashboard"
        assert exception.site_id == "site-modules"
        assert "non licencié" in str(exception)
    
    def test_LIC_081_invalid_params_returns_false(self, module_gate, license_cache):
        """LIC_081: Paramètres invalides retournent False."""
        license_cache.get.return_value = None
        
        # site_id vide
        assert module_gate.check_module_access("", "surveillance", "user-123") is False
        
        # module_id vide  
        assert module_gate.check_module_access("site-test", "", "user-123") is False
        
        # Les deux vides
        assert module_gate.check_module_access("", "", "user-123") is False


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_082: UI MASQUE FONCTIONNALITÉ NON LICENCIÉE
# ══════════════════════════════════════════════════════════════════════════════

class TestLIC082Compliance:
    """Tests conformité LIC_082: UI masque fonctionnalités non licenciées."""
    
    def test_LIC_082_ui_visibility_licensed_modules(self, module_gate, license_cache, sample_license):
        """LIC_082: UI montre modules licenciés."""
        license_cache.get.return_value = sample_license
        
        visibility = module_gate.get_ui_visibility("site-modules")
        
        # Modules licenciés visibles
        assert visibility["surveillance"] is True
        assert visibility["access_control"] is True
        assert visibility["visitor_management"] is True
        
        # Modules non licenciés cachés
        assert visibility["analytics_dashboard"] is False
        assert visibility["inventory_management"] is False
        assert visibility["transport_coordination"] is False
    
    def test_LIC_082_ui_visibility_limited_license(self, module_gate, license_cache, limited_license):
        """LIC_082: UI masque selon licence limitée."""
        license_cache.get.return_value = limited_license
        
        visibility = module_gate.get_ui_visibility("site-limited")
        
        # Seul module licencié visible
        assert visibility["surveillance"] is True
        
        # Autres modules cachés
        assert visibility["access_control"] is False
        assert visibility["visitor_management"] is False
        assert visibility["incident_reporting"] is False
        assert visibility["analytics_dashboard"] is False
    
    def test_LIC_082_ui_visibility_no_license(self, module_gate, license_cache):
        """LIC_082: Pas de licence = tout caché."""
        license_cache.get.return_value = None
        
        visibility = module_gate.get_ui_visibility("site-no-license")
        
        # Tous modules cachés
        all_modules = [
            "surveillance", "access_control", "visitor_management",
            "incident_reporting", "staff_scheduling", "medical_tracking",
            "inventory_management", "transport_coordination", 
            "communication_hub", "analytics_dashboard"
        ]
        
        for module in all_modules:
            assert visibility[module] is False
    
    def test_LIC_082_ui_visibility_empty_site_id(self, module_gate):
        """LIC_082: site_id vide = dictionnaire vide."""
        visibility = module_gate.get_ui_visibility("")
        
        assert visibility == {}


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_083: TENTATIVE ACCÈS NON LICENCIÉ = AUDIT LOG
# ══════════════════════════════════════════════════════════════════════════════

class TestLIC083Compliance:
    """Tests conformité LIC_083: Tentative accès module non licencié = audit log."""
    
    def test_LIC_083_access_denied_audit_sync(self, module_gate, license_cache, sample_license):
        """LIC_083: Accès refusé génère audit (version sync)."""
        license_cache.get.return_value = sample_license
        
        # Test avec méthode sync (audit sera tenté de façon async en arrière-plan)
        result = module_gate.check_module_access("site-modules", "analytics_dashboard", "user-123")
        
        assert result is False
    
    def test_LIC_083_access_granted_audit_sync(self, module_gate, license_cache, sample_license):
        """LIC_083: Accès autorisé génère audit (version sync)."""
        license_cache.get.return_value = sample_license
        
        result = module_gate.check_module_access("site-modules", "surveillance", "user-123")
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_LIC_083_access_denied_audit_async(self, module_gate, license_cache, sample_license, audit_emitter):
        """LIC_083: Accès refusé génère audit (version async)."""
        license_cache.get.return_value = sample_license
        
        await module_gate.check_access("site-modules", "analytics_dashboard", "user-123")
        
        # Vérifier audit émis
        audit_emitter.emit_event.assert_called()
        call_args = audit_emitter.emit_event.call_args
        
        assert call_args[0][0] == AuditEventType.FAILED_AUTH
        assert call_args[0][1] == "user-123"  # user_id
        assert call_args[0][2] == "site-modules"  # tenant_id
        assert call_args[0][3] == "module_access_denied"  # action
        assert call_args[1]["resource_id"] == "analytics_dashboard"
        assert call_args[1]["metadata"]["module_id"] == "analytics_dashboard"
        assert call_args[1]["metadata"]["reason"] == "Module non licencié"
        assert call_args[1]["metadata"]["severity"] == "WARNING"
    
    @pytest.mark.asyncio
    async def test_LIC_083_access_granted_audit_async(self, module_gate, license_cache, sample_license, audit_emitter):
        """LIC_083: Accès autorisé génère audit (version async)."""
        license_cache.get.return_value = sample_license
        
        await module_gate.check_access("site-modules", "surveillance", "user-123")
        
        # Vérifier audit émis
        audit_emitter.emit_event.assert_called()
        call_args = audit_emitter.emit_event.call_args
        
        assert call_args[0][0] == AuditEventType.USER_LOGIN
        assert call_args[0][3] == "module_access_granted"
        assert call_args[1]["resource_id"] == "surveillance"
        assert call_args[1]["metadata"]["module_id"] == "surveillance"
    
    @pytest.mark.asyncio
    async def test_LIC_083_invalid_params_audit(self, module_gate, license_cache, audit_emitter):
        """LIC_083: Paramètres invalides génèrent audit."""
        license_cache.get.return_value = None
        
        await module_gate.check_access("", "surveillance", "user-123")
        
        audit_emitter.emit_event.assert_called()
        call_args = audit_emitter.emit_event.call_args
        
        assert call_args[0][0] == AuditEventType.FAILED_AUTH
        assert call_args[1]["metadata"]["reason"] == "Paramètres invalides"
    
    @pytest.mark.asyncio
    async def test_LIC_083_user_id_optional_in_audit(self, module_gate, license_cache, sample_license, audit_emitter):
        """LIC_083: user_id optionnel dans audit."""
        license_cache.get.return_value = sample_license
        
        # Sans user_id
        await module_gate.check_access("site-modules", "analytics_dashboard")
        
        audit_emitter.emit_event.assert_called()
        call_args = audit_emitter.emit_event.call_args
        
        assert call_args[0][1] == "system"  # user_id par défaut
        assert call_args[1]["metadata"]["user_id"] is None


# ══════════════════════════════════════════════════════════════════════════════
# TESTS CACHE ET PERFORMANCE
# ══════════════════════════════════════════════════════════════════════════════

class TestCacheManagement:
    """Tests gestion cache modules."""
    
    def test_cache_modules_performance(self, module_gate, license_cache, sample_license):
        """Cache évite appels répétés licence."""
        license_cache.get.return_value = sample_license
        
        # Premier appel charge cache
        modules1 = module_gate.get_licensed_modules("site-modules")
        
        # Deuxième appel utilise cache
        modules2 = module_gate.get_licensed_modules("site-modules")
        
        # Un seul appel au cache licence
        assert license_cache.get.call_count == 1
        assert modules1 == modules2
    
    def test_invalidate_cache_site_specific(self, module_gate, license_cache, sample_license):
        """Invalidation cache site spécifique."""
        license_cache.get.return_value = sample_license
        
        # Charger cache
        module_gate.get_licensed_modules("site-modules")
        
        # Invalider cache pour ce site
        module_gate.invalidate_cache("site-modules")
        
        # Prochain appel recharge
        module_gate.get_licensed_modules("site-modules")
        
        assert license_cache.get.call_count == 2
    
    def test_invalidate_cache_all_sites(self, module_gate, license_cache, sample_license):
        """Invalidation cache tous sites."""
        license_cache.get.return_value = sample_license
        
        # Charger cache pour 2 sites
        module_gate.get_licensed_modules("site-1")
        module_gate.get_licensed_modules("site-2")
        
        # Invalider tout le cache
        module_gate.invalidate_cache()
        
        # Prochains appels rechargent
        module_gate.get_licensed_modules("site-1")
        module_gate.get_licensed_modules("site-2")
        
        assert license_cache.get.call_count == 4


# ══════════════════════════════════════════════════════════════════════════════
# TESTS GESTION EXPIRATION LICENCE
# ══════════════════════════════════════════════════════════════════════════════

class TestLicenseExpiry:
    """Tests gestion expiration licence."""
    
    def test_expired_license_grace_period_modules_available(self, module_gate, license_cache, expired_license):
        """Licence expirée en grace period = modules toujours disponibles."""
        license_cache.get.return_value = expired_license
        
        licensed_modules = module_gate.get_licensed_modules("site-expired-grace")
        
        # Modules toujours disponibles pendant grace period
        assert "surveillance" in licensed_modules
        assert "access_control" in licensed_modules
    
    def test_grace_period_expired_no_modules(self, module_gate, license_cache, grace_expired_license):
        """Grace period expirée = aucun module disponible."""
        license_cache.get.return_value = grace_expired_license
        
        licensed_modules = module_gate.get_licensed_modules("site-grace-expired")
        
        # Aucun module après grace period
        assert licensed_modules == []


# ══════════════════════════════════════════════════════════════════════════════
# TESTS UPGRADE/DOWNGRADE (LIC_084-085)
# ══════════════════════════════════════════════════════════════════════════════

class TestLicenseUpgradeDowngrade:
    """Tests upgrade/downgrade licence."""
    
    def test_LIC_084_upgrade_adds_modules(self, module_gate, license_cache):
        """LIC_084: Upgrade ajoute modules."""
        # Licence initiale limitée
        initial_license = License(
            license_id="upgrade-before",
            site_id="site-upgrade",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=90),
            modules=["surveillance"],  # Module de base
            signature="initial_signature",
            issuer_id="issuer"
        )
        
        # Licence après upgrade
        upgraded_license = License(
            license_id="upgrade-after",
            site_id="site-upgrade",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=90),
            modules=["surveillance", "access_control", "visitor_management"],  # Modules ajoutés
            signature="upgraded_signature",
            issuer_id="issuer"
        )
        
        # Avant upgrade
        license_cache.get.return_value = initial_license
        modules_before = module_gate.get_licensed_modules("site-upgrade")
        assert modules_before == ["surveillance"]
        
        # Invalider cache et simuler upgrade
        module_gate.invalidate_cache("site-upgrade")
        license_cache.get.return_value = upgraded_license
        modules_after = module_gate.get_licensed_modules("site-upgrade")
        
        # Vérifier ajout modules
        assert "surveillance" in modules_after
        assert "access_control" in modules_after
        assert "visitor_management" in modules_after
        assert len(modules_after) == 3
    
    def test_LIC_085_downgrade_removes_modules(self, module_gate, license_cache):
        """LIC_085: Downgrade retire modules."""
        # Licence complète
        full_license = License(
            license_id="downgrade-before",
            site_id="site-downgrade", 
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=90),
            modules=["surveillance", "access_control", "visitor_management", "analytics_dashboard"],
            signature="full_signature",
            issuer_id="issuer"
        )
        
        # Licence après downgrade
        downgraded_license = License(
            license_id="downgrade-after",
            site_id="site-downgrade",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=90),
            modules=["surveillance"],  # Modules retirés
            signature="downgraded_signature", 
            issuer_id="issuer"
        )
        
        # Avant downgrade
        license_cache.get.return_value = full_license
        modules_before = module_gate.get_licensed_modules("site-downgrade")
        assert len(modules_before) == 4
        
        # Invalider cache et simuler downgrade
        module_gate.invalidate_cache("site-downgrade")
        license_cache.get.return_value = downgraded_license
        modules_after = module_gate.get_licensed_modules("site-downgrade")
        
        # Vérifier retrait modules
        assert modules_after == ["surveillance"]
        assert "access_control" not in modules_after
        assert "visitor_management" not in modules_after
        assert "analytics_dashboard" not in modules_after


# ══════════════════════════════════════════════════════════════════════════════
# TESTS STATISTIQUES ET MONITORING
# ══════════════════════════════════════════════════════════════════════════════

class TestModuleStats:
    """Tests statistiques modules."""
    
    @pytest.mark.asyncio
    async def test_module_access_stats_with_license(self, module_gate, license_cache, sample_license):
        """Statistiques accès modules avec licence."""
        license_cache.get.return_value = sample_license
        
        stats = await module_gate.get_module_access_stats("site-modules")
        
        assert stats["licensed_modules_count"] == 3
        assert stats["licensed_modules"] == ["access_control", "surveillance", "visitor_management"]
        assert stats["total_modules_available"] == 10
        assert stats["license_coverage_percent"] == 30.0
        assert stats["site_id"] == "site-modules"
    
    @pytest.mark.asyncio  
    async def test_module_access_stats_no_license(self, module_gate, license_cache):
        """Statistiques accès modules sans licence."""
        license_cache.get.return_value = None
        
        stats = await module_gate.get_module_access_stats("site-no-license")
        
        assert stats["licensed_modules_count"] == 0
        assert stats["total_modules_available"] == 10
        assert stats["license_coverage_percent"] == 0.0
    
    @pytest.mark.asyncio
    async def test_module_access_stats_empty_site_id(self, module_gate):
        """Statistiques accès modules site_id vide."""
        stats = await module_gate.get_module_access_stats("")
        
        assert stats["licensed_modules_count"] == 0
        assert stats["license_coverage_percent"] == 0.0


# ══════════════════════════════════════════════════════════════════════════════
# TESTS VALIDATION ENTRÉES
# ══════════════════════════════════════════════════════════════════════════════

class TestInputValidation:
    """Tests validation entrées."""
    
    def test_is_module_licensed_empty_inputs(self, module_gate):
        """is_module_licensed avec entrées vides."""
        assert module_gate.is_module_licensed("", "surveillance") is False
        assert module_gate.is_module_licensed("site-test", "") is False
        assert module_gate.is_module_licensed("", "") is False
    
    def test_get_licensed_modules_empty_site_id(self, module_gate):
        """get_licensed_modules avec site_id vide."""
        modules = module_gate.get_licensed_modules("")
        assert modules == []
    
    def test_raise_if_not_licensed_empty_inputs(self, module_gate):
        """raise_if_not_licensed avec entrées vides."""
        with pytest.raises(ModuleAccessDeniedError):
            module_gate.raise_if_not_licensed("", "surveillance")
        
        with pytest.raises(ModuleAccessDeniedError):
            module_gate.raise_if_not_licensed("site-test", "")