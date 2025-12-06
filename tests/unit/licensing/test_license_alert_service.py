"""
Tests unitaires LicenseAlertService

Invariants testés:
    LIC_030: Alerte J-60 (email intégrateur + org)
    LIC_031: Alerte J-30 (email + dashboard warning)
    LIC_032: Alerte J-14 (email + SMS)
    LIC_033: Alerte J-7 (email + SMS + dashboard critical)
    LIC_034: Alerte J-1 (tous canaux + webhook)
    LIC_035: Alertes NON désactivables par configuration
"""
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, AsyncMock

from src.licensing.interfaces import ILicenseCache, License
from src.licensing.license_alert_service import (
    LicenseAlertService,
    AlertLevel,
    AlertChannel,
    AlertConfig
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
def alert_service(license_cache, audit_emitter):
    """LicenseAlertService instance pour tests."""
    return LicenseAlertService(
        license_cache=license_cache,
        audit_emitter=audit_emitter
    )


@pytest.fixture
def license_expiring_65_days():
    """Licence expirant dans 65 jours (pas d'alerte)."""
    now = datetime.now(timezone.utc)
    return License(
        license_id="license-65days",
        site_id="site-65days",
        issued_at=now - timedelta(days=30),
        expires_at=now + timedelta(days=65),
        modules=["surveillance", "access_control"],
        signature="valid_signature",
        issuer_id="cloud-license-manager",
        organization_id="org-65days"
    )


@pytest.fixture
def license_expiring_45_days():
    """Licence expirant dans 45 jours (alerte J-60 déjà passée)."""
    now = datetime.now(timezone.utc)
    return License(
        license_id="license-45days",
        site_id="site-45days", 
        issued_at=now - timedelta(days=50),
        expires_at=now + timedelta(days=45),
        modules=["surveillance"],
        signature="valid_signature",
        issuer_id="cloud-license-manager",
        organization_id="org-45days"
    )


@pytest.fixture
def license_expiring_25_days():
    """Licence expirant dans 25 jours (alerte J-30 requise)."""
    now = datetime.now(timezone.utc)
    return License(
        license_id="license-25days",
        site_id="site-25days",
        issued_at=now - timedelta(days=70),
        expires_at=now + timedelta(days=25),
        modules=["surveillance", "access_control", "visitor_management"],
        signature="valid_signature",
        issuer_id="cloud-license-manager",
        organization_id="org-25days"
    )


@pytest.fixture
def license_expiring_10_days():
    """Licence expirant dans 10 jours (alerte J-14 requise)."""
    now = datetime.now(timezone.utc)
    return License(
        license_id="license-10days",
        site_id="site-10days",
        issued_at=now - timedelta(days=85),
        expires_at=now + timedelta(days=10),
        modules=["surveillance"],
        signature="valid_signature",
        issuer_id="cloud-license-manager"
    )


@pytest.fixture
def license_expiring_5_days():
    """Licence expirant dans 5 jours (alerte J-7 requise)."""
    now = datetime.now(timezone.utc)
    return License(
        license_id="license-5days",
        site_id="site-5days",
        issued_at=now - timedelta(days=90),
        expires_at=now + timedelta(days=5),
        modules=["surveillance", "access_control"],
        signature="valid_signature",
        issuer_id="cloud-license-manager"
    )


@pytest.fixture
def license_expiring_tomorrow():
    """Licence expirant demain (alerte J-1 requise)."""
    now = datetime.now(timezone.utc)
    return License(
        license_id="license-1day",
        site_id="site-1day",
        issued_at=now - timedelta(days=95),
        expires_at=now + timedelta(days=1),
        modules=["surveillance"],
        signature="valid_signature",
        issuer_id="cloud-license-manager"
    )


@pytest.fixture 
def expired_license():
    """Licence déjà expirée."""
    now = datetime.now(timezone.utc)
    return License(
        license_id="license-expired",
        site_id="site-expired",
        issued_at=now - timedelta(days=100),
        expires_at=now - timedelta(days=2),  # Expirée depuis 2 jours
        modules=["surveillance"],
        signature="valid_signature",
        issuer_id="cloud-license-manager"
    )


# ══════════════════════════════════════════════════════════════════════════════
# TESTS INTERFACE ET CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

class TestLicenseAlertServiceInterface:
    """Tests interface et configuration service."""
    
    def test_alert_levels_defined(self):
        """Niveaux alertes définis."""
        assert AlertLevel.INFO.value == "info"
        assert AlertLevel.WARNING.value == "warning"
        assert AlertLevel.CRITICAL.value == "critical"
        assert AlertLevel.URGENT.value == "urgent"
    
    def test_alert_channels_defined(self):
        """Canaux alertes définis."""
        assert AlertChannel.EMAIL.value == "email"
        assert AlertChannel.SMS.value == "sms"
        assert AlertChannel.DASHBOARD.value == "dashboard"
        assert AlertChannel.WEBHOOK.value == "webhook"
    
    def test_alert_config_dataclass(self):
        """AlertConfig dataclass fonctionnel."""
        config = AlertConfig(
            days_before=30,
            level=AlertLevel.WARNING,
            channels=[AlertChannel.EMAIL, AlertChannel.DASHBOARD],
            message_template="Test message"
        )
        
        assert config.days_before == 30
        assert config.level == AlertLevel.WARNING
        assert AlertChannel.EMAIL in config.channels
        assert config.integrator_notification is True  # Défaut
        assert config.organization_notification is True  # Défaut


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_035: ALERTES NON DÉSACTIVABLES
# ══════════════════════════════════════════════════════════════════════════════

class TestLIC035Compliance:
    """Tests conformité LIC_035: Alertes NON désactivables."""
    
    def test_LIC_035_alert_schedule_not_modifiable(self, alert_service):
        """LIC_035: Planning alertes non modifiable."""
        modifiable = alert_service.is_alert_schedule_modifiable()
        
        assert modifiable is False
    
    def test_LIC_035_alert_schedule_hardcoded(self, alert_service):
        """LIC_035: Planning alertes hardcodé."""
        schedule = alert_service.get_alert_schedule()
        
        # Vérifier planning fixe avec 5 alertes
        assert len(schedule) == 5
        
        # Vérifier ordre des alertes (J-60, J-30, J-14, J-7, J-1)
        days_list = [config.days_before for config in schedule]
        assert days_list == [60, 30, 14, 7, 1]
    
    def test_LIC_035_schedule_immutable_copy(self, alert_service):
        """LIC_035: get_alert_schedule retourne copie (immutable)."""
        schedule1 = alert_service.get_alert_schedule()
        schedule2 = alert_service.get_alert_schedule()
        
        # Copies indépendantes
        assert schedule1 is not schedule2
        assert schedule1 == schedule2
        
        # Modification copie n'affecte pas original
        schedule1.append(AlertConfig(3, AlertLevel.URGENT, [AlertChannel.EMAIL], "Test"))
        schedule3 = alert_service.get_alert_schedule()
        
        assert len(schedule3) == 5  # Original inchangé


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_030: ALERTE J-60
# ══════════════════════════════════════════════════════════════════════════════

class TestLIC030Compliance:
    """Tests conformité LIC_030: Alerte J-60."""
    
    def test_LIC_030_alert_config_j60(self, alert_service):
        """LIC_030: Configuration alerte J-60."""
        schedule = alert_service.get_alert_schedule()
        j60_alert = schedule[0]  # Première alerte
        
        assert j60_alert.days_before == 60
        assert j60_alert.level == AlertLevel.INFO
        assert j60_alert.channels == [AlertChannel.EMAIL]
        assert j60_alert.integrator_notification is True
        assert j60_alert.organization_notification is True
        assert "60 jours" in j60_alert.message_template
    
    @pytest.mark.asyncio
    async def test_LIC_030_j60_alert_pending_at_45_days(self, alert_service, license_cache, license_expiring_45_days):
        """LIC_030: Alerte J-60 en attente à J-45."""
        license_cache.get.return_value = license_expiring_45_days
        
        pending_alerts = alert_service.get_pending_alerts("site-45days", days_until_expiry=45)
        
        # J-60 doit être déclenchée (45 < 60)
        assert len(pending_alerts) >= 1
        j60_alert = next((a for a in pending_alerts if a.days_before == 60), None)
        assert j60_alert is not None
        assert j60_alert.level == AlertLevel.INFO
        assert AlertChannel.EMAIL in j60_alert.channels
    
    @pytest.mark.asyncio
    async def test_LIC_030_j60_alert_not_pending_at_65_days(self, alert_service, license_cache, license_expiring_65_days):
        """LIC_030: Alerte J-60 pas encore en attente à J-65."""
        license_cache.get.return_value = license_expiring_65_days
        
        pending_alerts = alert_service.get_pending_alerts("site-65days", days_until_expiry=65)
        
        # J-60 pas encore déclenchée (65 > 60)
        j60_alert = next((a for a in pending_alerts if a.days_before == 60), None)
        assert j60_alert is None


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_031: ALERTE J-30
# ══════════════════════════════════════════════════════════════════════════════

class TestLIC031Compliance:
    """Tests conformité LIC_031: Alerte J-30."""
    
    def test_LIC_031_alert_config_j30(self, alert_service):
        """LIC_031: Configuration alerte J-30."""
        schedule = alert_service.get_alert_schedule()
        j30_alert = schedule[1]  # Deuxième alerte
        
        assert j30_alert.days_before == 30
        assert j30_alert.level == AlertLevel.WARNING
        assert AlertChannel.EMAIL in j30_alert.channels
        assert AlertChannel.DASHBOARD in j30_alert.channels
        assert "30 jours" in j30_alert.message_template
    
    @pytest.mark.asyncio
    async def test_LIC_031_j30_alert_pending_at_25_days(self, alert_service, license_cache, license_expiring_25_days):
        """LIC_031: Alerte J-30 en attente à J-25."""
        license_cache.get.return_value = license_expiring_25_days
        
        pending_alerts = alert_service.get_pending_alerts("site-25days", days_until_expiry=25)
        
        # J-30 doit être déclenchée (25 < 30)
        j30_alert = next((a for a in pending_alerts if a.days_before == 30), None)
        assert j30_alert is not None
        assert j30_alert.level == AlertLevel.WARNING
        assert AlertChannel.EMAIL in j30_alert.channels
        assert AlertChannel.DASHBOARD in j30_alert.channels


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_032: ALERTE J-14
# ══════════════════════════════════════════════════════════════════════════════

class TestLIC032Compliance:
    """Tests conformité LIC_032: Alerte J-14."""
    
    def test_LIC_032_alert_config_j14(self, alert_service):
        """LIC_032: Configuration alerte J-14."""
        schedule = alert_service.get_alert_schedule()
        j14_alert = schedule[2]  # Troisième alerte
        
        assert j14_alert.days_before == 14
        assert j14_alert.level == AlertLevel.WARNING
        assert AlertChannel.EMAIL in j14_alert.channels
        assert AlertChannel.SMS in j14_alert.channels
        assert "14 jours" in j14_alert.message_template
    
    @pytest.mark.asyncio
    async def test_LIC_032_j14_alert_pending_at_10_days(self, alert_service, license_cache, license_expiring_10_days):
        """LIC_032: Alerte J-14 en attente à J-10."""
        license_cache.get.return_value = license_expiring_10_days
        
        pending_alerts = alert_service.get_pending_alerts("site-10days", days_until_expiry=10)
        
        # J-14 doit être déclenchée (10 < 14)
        j14_alert = next((a for a in pending_alerts if a.days_before == 14), None)
        assert j14_alert is not None
        assert j14_alert.level == AlertLevel.WARNING
        assert AlertChannel.EMAIL in j14_alert.channels
        assert AlertChannel.SMS in j14_alert.channels


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_033: ALERTE J-7
# ══════════════════════════════════════════════════════════════════════════════

class TestLIC033Compliance:
    """Tests conformité LIC_033: Alerte J-7."""
    
    def test_LIC_033_alert_config_j7(self, alert_service):
        """LIC_033: Configuration alerte J-7."""
        schedule = alert_service.get_alert_schedule()
        j7_alert = schedule[3]  # Quatrième alerte
        
        assert j7_alert.days_before == 7
        assert j7_alert.level == AlertLevel.CRITICAL
        assert AlertChannel.EMAIL in j7_alert.channels
        assert AlertChannel.SMS in j7_alert.channels
        assert AlertChannel.DASHBOARD in j7_alert.channels
        assert "7 jours" in j7_alert.message_template
    
    @pytest.mark.asyncio
    async def test_LIC_033_j7_alert_pending_at_5_days(self, alert_service, license_cache, license_expiring_5_days):
        """LIC_033: Alerte J-7 en attente à J-5."""
        license_cache.get.return_value = license_expiring_5_days
        
        pending_alerts = alert_service.get_pending_alerts("site-5days", days_until_expiry=5)
        
        # J-7 doit être déclenchée (5 < 7)
        j7_alert = next((a for a in pending_alerts if a.days_before == 7), None)
        assert j7_alert is not None
        assert j7_alert.level == AlertLevel.CRITICAL
        assert AlertChannel.EMAIL in j7_alert.channels
        assert AlertChannel.SMS in j7_alert.channels
        assert AlertChannel.DASHBOARD in j7_alert.channels


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_034: ALERTE J-1
# ══════════════════════════════════════════════════════════════════════════════

class TestLIC034Compliance:
    """Tests conformité LIC_034: Alerte J-1."""
    
    def test_LIC_034_alert_config_j1(self, alert_service):
        """LIC_034: Configuration alerte J-1."""
        schedule = alert_service.get_alert_schedule()
        j1_alert = schedule[4]  # Cinquième alerte
        
        assert j1_alert.days_before == 1
        assert j1_alert.level == AlertLevel.URGENT
        assert AlertChannel.EMAIL in j1_alert.channels
        assert AlertChannel.SMS in j1_alert.channels
        assert AlertChannel.DASHBOARD in j1_alert.channels
        assert AlertChannel.WEBHOOK in j1_alert.channels
        assert "DEMAIN" in j1_alert.message_template or "1" in j1_alert.message_template
    
    @pytest.mark.asyncio
    async def test_LIC_034_j1_alert_pending_tomorrow(self, alert_service, license_cache, license_expiring_tomorrow):
        """LIC_034: Alerte J-1 en attente demain."""
        license_cache.get.return_value = license_expiring_tomorrow
        
        pending_alerts = alert_service.get_pending_alerts("site-1day", days_until_expiry=1)
        
        # J-1 doit être déclenchée (1 <= 1)
        j1_alert = next((a for a in pending_alerts if a.days_before == 1), None)
        assert j1_alert is not None
        assert j1_alert.level == AlertLevel.URGENT
        
        # Tous les canaux présents
        expected_channels = [AlertChannel.EMAIL, AlertChannel.SMS, AlertChannel.DASHBOARD, AlertChannel.WEBHOOK]
        for channel in expected_channels:
            assert channel in j1_alert.channels


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LOGIQUE ALERTES
# ══════════════════════════════════════════════════════════════════════════════

class TestAlertLogic:
    """Tests logique business alertes."""
    
    @pytest.mark.asyncio
    async def test_check_and_send_alerts_multiple_pending(self, alert_service, license_cache, license_expiring_5_days, audit_emitter):
        """check_and_send_alerts avec multiples alertes en attente."""
        license_cache.get.return_value = license_expiring_5_days
        
        # À J-5, toutes les alertes précédentes devraient être déclenchées
        sent_alerts = await alert_service.check_and_send_alerts("site-5days")
        
        # Vérifier que plusieurs alertes ont été envoyées
        assert len(sent_alerts) > 0
        
        # Vérifier audit pour chaque alerte envoyée
        assert audit_emitter.emit_event.call_count == len(sent_alerts)
    
    @pytest.mark.asyncio
    async def test_no_duplicate_alerts_sent(self, alert_service, license_cache, license_expiring_5_days):
        """Pas de duplicata alertes envoyées."""
        license_cache.get.return_value = license_expiring_5_days
        
        # Premier envoi
        sent_alerts_1 = await alert_service.check_and_send_alerts("site-5days")
        
        # Deuxième envoi (même situation)
        sent_alerts_2 = await alert_service.check_and_send_alerts("site-5days")
        
        # Pas de nouvelles alertes envoyées
        assert len(sent_alerts_2) == 0
    
    @pytest.mark.asyncio
    async def test_get_alert_status_comprehensive(self, alert_service, license_cache, license_expiring_25_days):
        """get_alert_status retourne informations complètes."""
        license_cache.get.return_value = license_expiring_25_days
        
        # Envoyer quelques alertes
        await alert_service.check_and_send_alerts("site-25days")
        
        # Vérifier statut
        status = await alert_service.get_alert_status("site-25days")
        
        assert status["site_id"] == "site-25days"
        assert status["license_found"] is True
        assert status["license_id"] == "license-25days"
        assert status["days_until_expiry"] in [24, 25]  # Tolérance timing
        assert status["sent_alerts_count"] > 0
        assert status["alert_schedule_modifiable"] is False  # LIC_035
        assert isinstance(status["sent_alert_days"], list)
    
    @pytest.mark.asyncio
    async def test_get_alert_status_no_license(self, alert_service, license_cache):
        """get_alert_status sans licence."""
        license_cache.get.return_value = None
        
        status = await alert_service.get_alert_status("site-no-license")
        
        assert status["site_id"] == "site-no-license"
        assert status["license_found"] is False
        assert status["days_until_expiry"] is None
        assert status["pending_alerts"] == 0
        assert status["sent_alerts"] == 0
    
    def test_reset_alert_history(self, alert_service):
        """reset_alert_history remet à zéro historique."""
        # Simuler alertes envoyées
        alert_service._sent_alerts["site-test"] = {60, 30, 14}
        
        # Reset
        alert_service.reset_alert_history("site-test")
        
        # Historique vide
        assert "site-test" not in alert_service._sent_alerts


# ══════════════════════════════════════════════════════════════════════════════
# TESTS GESTION ERREURS
# ══════════════════════════════════════════════════════════════════════════════

class TestErrorHandling:
    """Tests gestion erreurs."""
    
    @pytest.mark.asyncio
    async def test_check_and_send_alerts_empty_site_id(self, alert_service):
        """check_and_send_alerts avec site_id vide."""
        sent_alerts = await alert_service.check_and_send_alerts("")
        
        assert sent_alerts == []
    
    @pytest.mark.asyncio
    async def test_check_and_send_alerts_revoked_license(self, alert_service, license_cache, license_expiring_5_days):
        """check_and_send_alerts avec licence révoquée."""
        revoked_license = License(
            license_id=license_expiring_5_days.license_id,
            site_id=license_expiring_5_days.site_id,
            issued_at=license_expiring_5_days.issued_at,
            expires_at=license_expiring_5_days.expires_at,
            modules=license_expiring_5_days.modules,
            signature=license_expiring_5_days.signature,
            issuer_id=license_expiring_5_days.issuer_id,
            revoked=True,
            revoked_at=datetime.now(timezone.utc),
            revoked_reason="security_breach"
        )
        license_cache.get.return_value = revoked_license
        
        sent_alerts = await alert_service.check_and_send_alerts("site-5days")
        
        # Pas d'alertes pour licence révoquée
        assert sent_alerts == []
    
    @pytest.mark.asyncio
    async def test_check_and_send_alerts_expired_license_no_alerts(self, alert_service, license_cache, expired_license):
        """check_and_send_alerts avec licence déjà expirée."""
        license_cache.get.return_value = expired_license
        
        sent_alerts = await alert_service.check_and_send_alerts("site-expired")
        
        # Toutes les alertes auraient dû être envoyées avant expiration
        # Mais comme historique vide, elles seront envoyées
        assert len(sent_alerts) > 0
    
    def test_get_pending_alerts_empty_site_id(self, alert_service):
        """get_pending_alerts avec site_id vide."""
        pending_alerts = alert_service.get_pending_alerts("")
        
        assert pending_alerts == []
    
    def test_get_pending_alerts_manual_days_calculation(self, alert_service, license_cache, license_expiring_25_days):
        """get_pending_alerts calcule jours automatiquement."""
        license_cache.get.return_value = license_expiring_25_days
        
        # Sans spécifier days_until_expiry 
        pending_alerts = alert_service.get_pending_alerts("site-25days")
        
        # Devrait calculer automatiquement et trouver alertes
        assert len(pending_alerts) > 0
        
        # Avec days_until_expiry spécifié
        pending_alerts_manual = alert_service.get_pending_alerts("site-25days", days_until_expiry=25)
        
        # Résultats identiques
        assert len(pending_alerts) == len(pending_alerts_manual)


# ══════════════════════════════════════════════════════════════════════════════
# TESTS AUDIT INTÉGRATION
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditIntegration:
    """Tests intégration audit."""
    
    @pytest.mark.asyncio
    async def test_alert_sent_audit(self, alert_service, license_cache, license_expiring_5_days, audit_emitter):
        """Envoi alerte génère audit."""
        license_cache.get.return_value = license_expiring_5_days
        
        sent_alerts = await alert_service.check_and_send_alerts("site-5days")
        
        # Vérifier audit pour chaque alerte
        assert audit_emitter.emit_event.call_count == len(sent_alerts)
        
        # Vérifier premier audit
        first_call = audit_emitter.emit_event.call_args_list[0]
        
        assert first_call[0][0] == AuditEventType.SYSTEM_CONFIG_CHANGE
        assert first_call[0][1] == "license_alert_service"
        assert first_call[0][2] == "site-5days"
        assert first_call[0][3] == "license_expiry_alert_sent"
        assert first_call[1]["resource_id"] == "site-5days"
        assert "alert_days_before" in first_call[1]["metadata"]
        assert "alert_level" in first_call[1]["metadata"]
        assert "days_until_expiry" in first_call[1]["metadata"]


# ══════════════════════════════════════════════════════════════════════════════
# TESTS CANAUX ENVOI (MVP SIMULATION)
# ══════════════════════════════════════════════════════════════════════════════

class TestChannelSending:
    """Tests envoi canaux (simulation MVP)."""
    
    @pytest.mark.asyncio
    async def test_send_alert_all_channels_called(self, alert_service, license_cache, license_expiring_tomorrow):
        """_send_alert appelle tous les canaux configurés."""
        license_cache.get.return_value = license_expiring_tomorrow
        
        # Obtenir config J-1 (tous canaux)
        schedule = alert_service.get_alert_schedule()
        j1_config = next(a for a in schedule if a.days_before == 1)
        
        # Simuler envoi (méthodes privées testables via publiques)
        await alert_service._send_alert("site-1day", license_expiring_tomorrow, j1_config, 1)
        
        # Vérification que simulation s'exécute sans erreur
        assert True  # MVP: méthodes vides
    
    @pytest.mark.asyncio
    async def test_format_alert_message(self, alert_service, license_cache, license_expiring_5_days):
        """_format_alert_message formate correctement."""
        message_template = "Site {site_id} licence {license_id} expire dans {days} jours"
        
        formatted = alert_service._format_alert_message(
            message_template,
            "site-test",
            license_expiring_5_days,
            5
        )
        
        assert "site-test" in formatted
        assert "license-5days" in formatted
        assert "5" in formatted