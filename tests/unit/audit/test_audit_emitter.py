"""
Tests unitaires AuditEmitter

Invariants testés:
    RUN_044: Signature cryptographique événements
    RUN_042: Immutabilité hash SHA-384
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch

from src.audit.interfaces import IAuditEmitter, AuditEvent, AuditEventType
from src.audit.audit_emitter import AuditEmitter, AuditEmitterError
from src.core.crypto_provider import CryptoProvider


# ══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def crypto_provider():
    """CryptoProvider mocké pour tests."""
    from unittest.mock import Mock

    provider = Mock()  # Mock simple (synchrone)
    # Signature mocké en bytes pour correspondre à l'interface
    mock_signature_bytes = b"mocked_signature_data_for_tests_1234567890"
    provider.sign.return_value = mock_signature_bytes
    provider.verify_signature.return_value = True
    return provider


@pytest.fixture
def audit_emitter(crypto_provider):
    """AuditEmitter instance pour tests."""
    return AuditEmitter(crypto_provider)


@pytest.fixture
def sample_metadata():
    """Métadonnées échantillon."""
    return {"session_id": "sess-123", "source_ip": "192.168.1.1", "result": "success", "duration_ms": 234}


# ══════════════════════════════════════════════════════════════════════════════
# TESTS INTERFACE
# ══════════════════════════════════════════════════════════════════════════════


class TestAuditEmitterInterface:
    """Vérifie conformité interface."""

    def test_implements_interface(self, audit_emitter):
        """AuditEmitter implémente IAuditEmitter."""
        assert isinstance(audit_emitter, IAuditEmitter)

    def test_requires_crypto_provider(self):
        """AuditEmitter requiert CryptoProvider."""
        with pytest.raises(TypeError):
            AuditEmitter()  # Manque crypto_provider


# ══════════════════════════════════════════════════════════════════════════════
# TESTS RUN_044: SIGNATURE CRYPTOGRAPHIQUE
# ══════════════════════════════════════════════════════════════════════════════


class TestRUN044Compliance:
    """Tests conformité RUN_044: Signature cryptographique."""

    @pytest.mark.asyncio
    async def test_RUN_044_emit_event_creates_signature(self, audit_emitter, crypto_provider):
        """RUN_044: Événement créé avec signature."""
        event = await audit_emitter.emit_event(AuditEventType.USER_LOGIN, "user-123", "tenant-456", "login_success")

        assert event.signature is not None
        assert len(event.signature) > 0
        crypto_provider.sign.assert_called_once()

    @pytest.mark.asyncio
    async def test_RUN_044_signature_includes_all_event_data(self, audit_emitter, crypto_provider, sample_metadata):
        """RUN_044: Signature inclut toutes les données événement."""
        await audit_emitter.emit_event(
            AuditEventType.SYSTEM_CONFIG_CHANGE,
            "admin-123",
            "platform",
            "config_update",
            resource_id="config-456",
            metadata=sample_metadata,
            ip_address="10.0.0.1",
            user_agent="Mozilla/5.0",
        )

        # Vérifier que sign a été appelé avec données complètes
        call_args = crypto_provider.sign.call_args[0][0]
        call_data = call_args.decode("utf-8")

        # Vérifier présence données clés dans signature
        assert "admin-123" in call_data
        assert "platform" in call_data
        assert "config_update" in call_data
        assert "config-456" in call_data
        assert "10.0.0.1" in call_data
        assert "Mozilla/5.0" in call_data

    @pytest.mark.asyncio
    async def test_RUN_044_verify_valid_signature(self, audit_emitter, crypto_provider):
        """RUN_044: Vérification signature valide."""
        event = await audit_emitter.emit_event(AuditEventType.USER_LOGOUT, "user-789", "tenant-012", "logout")

        # Vérifier signature
        is_valid = audit_emitter.verify_event_signature(event)
        assert is_valid is True
        crypto_provider.verify_signature.assert_called_once()

    @pytest.mark.asyncio
    async def test_RUN_044_verify_invalid_signature_fails(self, audit_emitter, crypto_provider):
        """RUN_044: Signature invalide échoue."""
        # Configurer crypto_provider pour signature invalide
        crypto_provider.verify_signature.return_value = False

        event = await audit_emitter.emit_event(AuditEventType.USER_CREATE, "admin-456", "tenant-789", "create_user")

        is_valid = audit_emitter.verify_event_signature(event)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_RUN_044_verify_missing_signature_fails(self, audit_emitter):
        """RUN_044: Événement sans signature échoue."""
        # Créer événement sans signature
        now = datetime.now(timezone.utc)
        event_no_sig = AuditEvent(
            event_id="test-123",
            event_type=AuditEventType.USER_LOGIN,
            timestamp=now,
            user_id="user-123",
            tenant_id="tenant-456",
            resource_id=None,
            action="login",
            metadata={},
            ip_address=None,
            user_agent=None,
            signature=None,  # Pas de signature
        )

        is_valid = audit_emitter.verify_event_signature(event_no_sig)
        assert is_valid is False


# ══════════════════════════════════════════════════════════════════════════════
# TESTS RUN_042: IMMUTABILITÉ HASH
# ══════════════════════════════════════════════════════════════════════════════


class TestRUN042Compliance:
    """Tests conformité RUN_042: Immutabilité hash SHA-384."""

    @pytest.mark.asyncio
    async def test_RUN_042_emit_event_creates_hash(self, audit_emitter):
        """RUN_042: Événement créé avec hash."""
        event = await audit_emitter.emit_event(
            AuditEventType.SECURITY_BREACH, "security-sys", "platform", "breach_detected"
        )

        assert event.hash_value is not None
        assert len(event.hash_value) == 96  # SHA-384 = 96 caractères hex

    @pytest.mark.asyncio
    async def test_RUN_042_hash_is_sha384(self, audit_emitter):
        """RUN_042: Hash utilise SHA-384."""
        event = await audit_emitter.emit_event(AuditEventType.KEY_ROTATION, "admin-123", "platform", "rotate_keys")

        # Vérifier format SHA-384
        assert len(event.hash_value) == 96
        assert all(c in "0123456789abcdef" for c in event.hash_value.lower())

    @pytest.mark.asyncio
    async def test_RUN_042_hash_deterministic(self, audit_emitter):
        """RUN_042: Hash déterministe pour mêmes données."""
        # Créer événement
        event1 = await audit_emitter.emit_event(
            AuditEventType.TENANT_CREATE,
            "platform-admin",
            "platform",
            "create_tenant",
            metadata={"tenant_name": "test-tenant"},
        )

        # Recalculer hash
        hash2 = audit_emitter.compute_event_hash(event1)

        # Hash doit être identique
        assert event1.hash_value == hash2

    @pytest.mark.asyncio
    async def test_RUN_042_different_events_different_hashes(self, audit_emitter):
        """RUN_042: Événements différents → hash différents."""
        event1 = await audit_emitter.emit_event(AuditEventType.USER_LOGIN, "user-123", "tenant-456", "login")

        event2 = await audit_emitter.emit_event(AuditEventType.USER_LOGOUT, "user-123", "tenant-456", "logout")

        assert event1.hash_value != event2.hash_value


# ══════════════════════════════════════════════════════════════════════════════
# TESTS CRÉATION ÉVÉNEMENTS
# ══════════════════════════════════════════════════════════════════════════════


class TestEventCreation:
    """Tests création événements."""

    @pytest.mark.asyncio
    async def test_emit_valid_event_success(self, audit_emitter):
        """Création événement valide réussit."""
        event = await audit_emitter.emit_event(AuditEventType.USER_LOGIN, "user-123", "tenant-456", "login_success")

        assert isinstance(event, AuditEvent)
        assert event.event_type == AuditEventType.USER_LOGIN
        assert event.user_id == "user-123"
        assert event.tenant_id == "tenant-456"
        assert event.action == "login_success"
        assert event.event_id is not None
        assert len(event.event_id) > 0

    @pytest.mark.asyncio
    async def test_emit_event_with_all_fields(self, audit_emitter, sample_metadata):
        """Création événement avec tous les champs."""
        event = await audit_emitter.emit_event(
            AuditEventType.SYSTEM_CONFIG_CHANGE,
            "admin-789",
            "platform",
            "config_update",
            resource_id="config-123",
            metadata=sample_metadata,
            ip_address="192.168.1.100",
            user_agent="CustomApp/1.0",
        )

        assert event.resource_id == "config-123"
        assert event.metadata == sample_metadata
        assert event.ip_address == "192.168.1.100"
        assert event.user_agent == "CustomApp/1.0"

    @pytest.mark.asyncio
    async def test_emit_event_timestamp_recent(self, audit_emitter):
        """Timestamp événement récent."""
        before = datetime.now(timezone.utc)

        event = await audit_emitter.emit_event(
            AuditEventType.USER_PERMISSION_CHANGE, "admin-456", "tenant-789", "grant_permission"
        )

        after = datetime.now(timezone.utc)

        assert before <= event.timestamp <= after
        assert event.timestamp.tzinfo == timezone.utc

    @pytest.mark.asyncio
    async def test_emit_event_unique_ids(self, audit_emitter):
        """Chaque événement a ID unique."""
        event1 = await audit_emitter.emit_event(AuditEventType.USER_LOGIN, "user-1", "tenant-1", "login")

        event2 = await audit_emitter.emit_event(AuditEventType.USER_LOGIN, "user-1", "tenant-1", "login")

        assert event1.event_id != event2.event_id


# ══════════════════════════════════════════════════════════════════════════════
# TESTS VALIDATION ENTRÉES
# ══════════════════════════════════════════════════════════════════════════════


class TestInputValidation:
    """Tests validation entrées."""

    @pytest.mark.asyncio
    async def test_emit_event_empty_user_id_fails(self, audit_emitter):
        """user_id vide → Exception."""
        with pytest.raises(AuditEmitterError, match="user_id, tenant_id et action sont obligatoires"):
            await audit_emitter.emit_event(
                AuditEventType.USER_LOGIN,
                "",  # user_id vide
                "tenant-456",
                "login",
            )

    @pytest.mark.asyncio
    async def test_emit_event_empty_tenant_id_fails(self, audit_emitter):
        """tenant_id vide → Exception."""
        with pytest.raises(AuditEmitterError, match="user_id, tenant_id et action sont obligatoires"):
            await audit_emitter.emit_event(
                AuditEventType.USER_LOGOUT,
                "user-123",
                "",  # tenant_id vide
                "logout",
            )

    @pytest.mark.asyncio
    async def test_emit_event_empty_action_fails(self, audit_emitter):
        """action vide → Exception."""
        with pytest.raises(AuditEmitterError, match="user_id, tenant_id et action sont obligatoires"):
            await audit_emitter.emit_event(
                AuditEventType.USER_CREATE,
                "admin-123",
                "platform",
                "",  # action vide
            )

    @pytest.mark.asyncio
    async def test_emit_event_invalid_event_type_fails(self, audit_emitter):
        """Type événement invalide → Exception."""
        with pytest.raises(AuditEmitterError, match="Type événement invalide"):
            await audit_emitter.emit_event(
                "invalid_type",  # Type invalide
                "user-123",
                "tenant-456",
                "action",
            )


# ══════════════════════════════════════════════════════════════════════════════
# TESTS SANITISATION MÉTADONNÉES
# ══════════════════════════════════════════════════════════════════════════════


class TestMetadataSanitization:
    """Tests nettoyage métadonnées."""

    @pytest.mark.asyncio
    async def test_sanitize_large_string_metadata(self, audit_emitter):
        """Métadonnées chaîne trop longue tronquée."""
        large_string = "x" * 2000  # > limite 1000

        event = await audit_emitter.emit_event(
            AuditEventType.USER_LOGIN, "user-123", "tenant-456", "login", metadata={"description": large_string}
        )

        # Vérifier troncature
        assert len(event.metadata["description"]) == 1000
        assert event.metadata["description"] == "x" * 1000

    @pytest.mark.asyncio
    async def test_sanitize_nested_dict_metadata(self, audit_emitter):
        """Métadonnées dictionnaire imbriqué nettoyé."""
        nested_metadata = {
            "valid_key": "valid_value",
            "nested": {
                "level1": {
                    "level2": "should_be_removed",  # Trop profond
                    "valid": "kept",
                },
                "simple": "kept",
            },
        }

        event = await audit_emitter.emit_event(
            AuditEventType.USER_CREATE, "admin-123", "tenant-456", "create", metadata=nested_metadata
        )

        # Vérifier nettoyage
        assert "valid_key" in event.metadata
        assert "nested" in event.metadata
        assert "simple" in event.metadata["nested"]

    @pytest.mark.asyncio
    async def test_sanitize_large_list_metadata(self, audit_emitter):
        """Liste métadonnées trop longue tronquée."""
        large_list = list(range(100))  # > limite 50

        event = await audit_emitter.emit_event(
            AuditEventType.AUDIT_LOG_ACCESS, "admin-123", "platform", "access", metadata={"items": large_list}
        )

        # Vérifier troncature liste
        assert len(event.metadata["items"]) == 50
        assert event.metadata["items"] == list(range(50))


# ══════════════════════════════════════════════════════════════════════════════
# TESTS UTILITAIRES
# ══════════════════════════════════════════════════════════════════════════════


class TestUtilities:
    """Tests fonctions utilitaires."""

    @pytest.mark.asyncio
    async def test_get_event_summary(self, audit_emitter):
        """Résumé événement contient infos clés."""
        event = await audit_emitter.emit_event(
            AuditEventType.SECURITY_BREACH, "security-123", "tenant-456", "breach_detected", resource_id="server-789"
        )

        summary = audit_emitter.get_event_summary(event)

        assert summary["event_id"] == event.event_id
        assert summary["type"] == "security_breach"
        assert summary["action"] == "breach_detected"
        assert summary["user"] == "security-123"
        assert summary["tenant"] == "tenant-456"
        assert summary["resource"] == "server-789"
        assert summary["signed"] is True
        assert summary["hash"].endswith("...")

    @pytest.mark.asyncio
    async def test_compute_hash_external_event(self, audit_emitter):
        """Calcul hash événement externe."""
        now = datetime.now(timezone.utc)
        external_event = AuditEvent(
            event_id="external-123",
            event_type=AuditEventType.USER_DELETE,
            timestamp=now,
            user_id="admin-456",
            tenant_id="platform",
            resource_id="user-789",
            action="delete_user",
            metadata={"reason": "inactive"},
            ip_address="10.0.0.1",
            user_agent="AdminTool/2.0",
        )

        event_hash = audit_emitter.compute_event_hash(external_event)

        assert len(event_hash) == 96  # SHA-384
        assert all(c in "0123456789abcdef" for c in event_hash.lower())


# ══════════════════════════════════════════════════════════════════════════════
# TESTS GESTION ERREURS
# ══════════════════════════════════════════════════════════════════════════════


class TestErrorHandling:
    """Tests gestion erreurs."""

    @pytest.mark.asyncio
    async def test_crypto_error_propagated(self, crypto_provider):
        """Erreur crypto propagée."""
        crypto_provider.sign.side_effect = Exception("Crypto error")

        audit_emitter = AuditEmitter(crypto_provider)

        with pytest.raises(AuditEmitterError, match="Erreur création événement audit"):
            await audit_emitter.emit_event(AuditEventType.USER_LOGIN, "user-123", "tenant-456", "login")

    @pytest.mark.asyncio
    async def test_verify_signature_crypto_error_returns_false(self, crypto_provider, audit_emitter):
        """Erreur vérification signature → False."""
        # Créer événement valide
        event = await audit_emitter.emit_event(AuditEventType.USER_LOGOUT, "user-123", "tenant-456", "logout")

        # Simuler erreur vérification
        crypto_provider.verify_signature.side_effect = Exception("Verify error")

        is_valid = audit_emitter.verify_event_signature(event)
        assert is_valid is False
