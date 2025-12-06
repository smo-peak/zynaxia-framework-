"""
Tests unitaires SessionManager

Invariants testés:
    RUN_014: Révocation immédiate à distance
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch

from src.auth.interfaces import ISessionManager, TokenClaims, Session
from src.auth.session_manager import SessionManager, SessionManagerError


# ══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def session_manager():
    """SessionManager instance for tests."""
    return SessionManager()


@pytest.fixture
def sample_token_claims():
    """Sample token claims for testing."""
    now = datetime.now(timezone.utc)
    return TokenClaims(
        user_id="user-123",
        tenant_id="tenant-456",
        level=3,
        roles=["site_operator"],
        permissions=["events:read"],
        exp=now + timedelta(minutes=15),
        iat=now,
        mfa_verified=False,
        session_id="keycloak-session-789",
    )


# ══════════════════════════════════════════════════════════════════════════════
# TESTS INTERFACE
# ══════════════════════════════════════════════════════════════════════════════


class TestSessionManagerInterface:
    """Vérifie conformité à l'interface."""

    def test_implements_interface(self, session_manager):
        """SessionManager implémente ISessionManager."""
        assert isinstance(session_manager, ISessionManager)

    def test_default_session_duration(self):
        """Durée par défaut des sessions = 24h."""
        manager = SessionManager()
        assert manager.default_session_duration_hours == 24

    def test_custom_session_duration(self):
        """Durée personnalisée des sessions."""
        manager = SessionManager(default_session_duration_hours=8)
        assert manager.default_session_duration_hours == 8


# ══════════════════════════════════════════════════════════════════════════════
# TESTS CRÉATION SESSION
# ══════════════════════════════════════════════════════════════════════════════


class TestCreateSession:
    """Tests création de session."""

    @pytest.mark.asyncio
    async def test_create_valid_session(self, session_manager, sample_token_claims):
        """Création session valide."""
        session = await session_manager.create_session("user-123", "tenant-456", sample_token_claims)

        assert isinstance(session, Session)
        assert session.user_id == "user-123"
        assert session.tenant_id == "tenant-456"
        assert session.revoked is False
        assert session.session_id is not None
        assert len(session.session_id) > 0  # UUID généré

    @pytest.mark.asyncio
    async def test_create_session_generates_unique_ids(self, session_manager, sample_token_claims):
        """Chaque session a un ID unique."""
        session1 = await session_manager.create_session("user-1", "tenant-1", sample_token_claims)
        session2 = await session_manager.create_session("user-1", "tenant-1", sample_token_claims)

        assert session1.session_id != session2.session_id

    @pytest.mark.asyncio
    async def test_create_session_uses_token_expiration(self, session_manager):
        """Expiration session basée sur token si plus courte."""
        now = datetime.now(timezone.utc)
        short_claims = TokenClaims(
            user_id="user-123",
            tenant_id="tenant-456",
            level=3,
            roles=[],
            permissions=[],
            exp=now + timedelta(minutes=30),  # 30 min < 24h par défaut
            iat=now,
        )

        session = await session_manager.create_session("user-123", "tenant-456", short_claims)

        # Session doit expirer avec le token (30 min)
        expected_exp = now + timedelta(minutes=30)
        # Tolérance de 1 seconde pour les différences de timing
        assert abs((session.expires_at - expected_exp).total_seconds()) < 1

    @pytest.mark.asyncio
    async def test_create_session_limits_to_max_duration(self, session_manager):
        """Session limitée à durée max même si token plus long."""
        now = datetime.now(timezone.utc)
        long_claims = TokenClaims(
            user_id="user-123",
            tenant_id="tenant-456",
            level=3,
            roles=[],
            permissions=[],
            exp=now + timedelta(days=7),  # 7 jours > 24h par défaut
            iat=now,
        )

        session = await session_manager.create_session("user-123", "tenant-456", long_claims)

        # Session limitée à 24h max
        max_exp = now + timedelta(hours=24)
        assert abs((session.expires_at - max_exp).total_seconds()) < 1

    @pytest.mark.asyncio
    async def test_create_session_empty_user_id_raises(self, session_manager, sample_token_claims):
        """user_id vide → Exception."""
        with pytest.raises(SessionManagerError, match="user_id et tenant_id sont obligatoires"):
            await session_manager.create_session("", "tenant-456", sample_token_claims)

    @pytest.mark.asyncio
    async def test_create_session_empty_tenant_id_raises(self, session_manager, sample_token_claims):
        """tenant_id vide → Exception."""
        with pytest.raises(SessionManagerError, match="user_id et tenant_id sont obligatoires"):
            await session_manager.create_session("user-123", "", sample_token_claims)


# ══════════════════════════════════════════════════════════════════════════════
# TESTS RÉCUPÉRATION SESSION
# ══════════════════════════════════════════════════════════════════════════════


class TestGetSession:
    """Tests récupération session."""

    @pytest.mark.asyncio
    async def test_get_existing_session(self, session_manager, sample_token_claims):
        """Récupération session existante."""
        created_session = await session_manager.create_session("user-123", "tenant-456", sample_token_claims)

        retrieved_session = await session_manager.get_session(created_session.session_id)

        assert retrieved_session is not None
        assert retrieved_session.session_id == created_session.session_id
        assert retrieved_session.user_id == "user-123"

    @pytest.mark.asyncio
    async def test_get_nonexistent_session_returns_none(self, session_manager):
        """Session inexistante → None."""
        result = await session_manager.get_session("nonexistent-session")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_session_empty_id_returns_none(self, session_manager):
        """ID vide → None."""
        result = await session_manager.get_session("")
        assert result is None


# ══════════════════════════════════════════════════════════════════════════════
# TESTS RUN_014: RÉVOCATION IMMÉDIATE
# ══════════════════════════════════════════════════════════════════════════════


class TestRUN014Compliance:
    """Tests conformité RUN_014: Révocation immédiate."""

    @pytest.mark.asyncio
    async def test_RUN_014_revoke_session_immediate(self, session_manager, sample_token_claims):
        """RUN_014: Révocation immédiate d'une session."""
        session = await session_manager.create_session("user-123", "tenant-456", sample_token_claims)

        # Vérifier session valide avant révocation
        assert await session_manager.is_session_valid(session.session_id) is True

        # Révoquer immédiatement
        with patch("src.auth.session_manager.datetime") as mock_datetime:
            revoke_time = datetime.now(timezone.utc)
            mock_datetime.now.return_value = revoke_time

            revoked = await session_manager.revoke_session(session.session_id, "security_breach")

        # Vérifier révocation
        assert revoked is True

        # Vérifier session immédiatement invalide (RUN_014)
        assert await session_manager.is_session_valid(session.session_id) is False

        # Vérifier métadonnées révocation
        revoked_session = await session_manager.get_session(session.session_id)
        assert revoked_session.revoked is True
        assert revoked_session.revoked_reason == "security_breach"
        assert revoked_session.revoked_at is not None

    @pytest.mark.asyncio
    async def test_RUN_014_revoke_nonexistent_session_returns_false(self, session_manager):
        """RUN_014: Révocation session inexistante → False."""
        revoked = await session_manager.revoke_session("nonexistent", "test")
        assert revoked is False

    @pytest.mark.asyncio
    async def test_RUN_014_revoke_all_user_sessions(self, session_manager, sample_token_claims):
        """RUN_014: Révocation en masse des sessions utilisateur."""
        # Créer plusieurs sessions pour le même utilisateur
        session1 = await session_manager.create_session("user-123", "tenant-A", sample_token_claims)
        session2 = await session_manager.create_session("user-123", "tenant-B", sample_token_claims)
        session3 = await session_manager.create_session("user-456", "tenant-C", sample_token_claims)

        # Vérifier toutes valides
        assert await session_manager.is_session_valid(session1.session_id) is True
        assert await session_manager.is_session_valid(session2.session_id) is True
        assert await session_manager.is_session_valid(session3.session_id) is True

        # Révoquer toutes les sessions de user-123
        revoked_count = await session_manager.revoke_all_user_sessions("user-123", "bulk_revoke")

        assert revoked_count == 2

        # Vérifier sessions user-123 révoquées (RUN_014)
        assert await session_manager.is_session_valid(session1.session_id) is False
        assert await session_manager.is_session_valid(session2.session_id) is False

        # Vérifier session user-456 toujours valide
        assert await session_manager.is_session_valid(session3.session_id) is True

    @pytest.mark.asyncio
    async def test_RUN_014_revoke_all_unknown_user_returns_zero(self, session_manager):
        """RUN_014: Révocation utilisateur inexistant → 0."""
        revoked_count = await session_manager.revoke_all_user_sessions("unknown-user", "test")
        assert revoked_count == 0


# ══════════════════════════════════════════════════════════════════════════════
# TESTS VALIDATION SESSION
# ══════════════════════════════════════════════════════════════════════════════


class TestSessionValidation:
    """Tests validation de session."""

    @pytest.mark.asyncio
    async def test_valid_session_returns_true(self, session_manager, sample_token_claims):
        """Session valide → True."""
        session = await session_manager.create_session("user-123", "tenant-456", sample_token_claims)
        assert await session_manager.is_session_valid(session.session_id) is True

    @pytest.mark.asyncio
    async def test_revoked_session_returns_false(self, session_manager, sample_token_claims):
        """Session révoquée → False."""
        session = await session_manager.create_session("user-123", "tenant-456", sample_token_claims)
        await session_manager.revoke_session(session.session_id, "test")

        assert await session_manager.is_session_valid(session.session_id) is False

    @pytest.mark.asyncio
    async def test_expired_session_returns_false(self, session_manager):
        """Session expirée → False."""
        now = datetime.now(timezone.utc)
        expired_claims = TokenClaims(
            user_id="user-123",
            tenant_id="tenant-456",
            level=3,
            roles=[],
            permissions=[],
            exp=now - timedelta(minutes=1),  # Expiré
            iat=now - timedelta(hours=1),
        )

        # Simuler création dans le passé
        with patch("src.auth.session_manager.datetime") as mock_datetime:
            past_time = now - timedelta(hours=2)
            mock_datetime.now.return_value = past_time

            session = await session_manager.create_session("user-123", "tenant-456", expired_claims)

        # Vérifier que session est maintenant expirée
        assert await session_manager.is_session_valid(session.session_id) is False

        # Vérifier auto-révocation
        revoked_session = await session_manager.get_session(session.session_id)
        assert revoked_session.revoked is True
        assert revoked_session.revoked_reason == "expired"

    @pytest.mark.asyncio
    async def test_nonexistent_session_returns_false(self, session_manager):
        """Session inexistante → False."""
        assert await session_manager.is_session_valid("nonexistent") is False


# ══════════════════════════════════════════════════════════════════════════════
# TESTS UTILITAIRES
# ══════════════════════════════════════════════════════════════════════════════


class TestSessionUtilities:
    """Tests fonctions utilitaires."""

    @pytest.mark.asyncio
    async def test_cleanup_expired_sessions(self, session_manager):
        """Nettoyage sessions expirées."""
        now = datetime.now(timezone.utc)

        # Créer session expirée
        expired_claims = TokenClaims(
            user_id="user-123",
            tenant_id="tenant-456",
            level=3,
            roles=[],
            permissions=[],
            exp=now - timedelta(minutes=1),
            iat=now - timedelta(hours=1),
        )

        with patch("src.auth.session_manager.datetime") as mock_datetime:
            past_time = now - timedelta(hours=2)
            mock_datetime.now.return_value = past_time

            expired_session = await session_manager.create_session("user-123", "tenant-456", expired_claims)

        # Créer session valide
        valid_claims = TokenClaims(
            user_id="user-456",
            tenant_id="tenant-789",
            level=3,
            roles=[],
            permissions=[],
            exp=now + timedelta(hours=1),
            iat=now,
        )
        valid_session = await session_manager.create_session("user-456", "tenant-789", valid_claims)

        # Nettoyer
        cleaned_count = await session_manager.cleanup_expired_sessions()

        assert cleaned_count == 1
        assert await session_manager.is_session_valid(expired_session.session_id) is False
        assert await session_manager.is_session_valid(valid_session.session_id) is True

    @pytest.mark.asyncio
    async def test_get_user_sessions(self, session_manager, sample_token_claims):
        """Récupération sessions utilisateur."""
        # Créer plusieurs sessions
        session1 = await session_manager.create_session("user-123", "tenant-A", sample_token_claims)
        session2 = await session_manager.create_session("user-123", "tenant-B", sample_token_claims)
        session3 = await session_manager.create_session("user-456", "tenant-C", sample_token_claims)

        # Révoquer une session
        await session_manager.revoke_session(session1.session_id, "test")

        # Récupérer sessions actives
        active_sessions = await session_manager.get_user_sessions("user-123", include_revoked=False)
        assert len(active_sessions) == 1
        assert active_sessions[0].session_id == session2.session_id

        # Récupérer toutes les sessions
        all_sessions = await session_manager.get_user_sessions("user-123", include_revoked=True)
        assert len(all_sessions) == 2

        # Vérifier utilisateur sans sessions
        no_sessions = await session_manager.get_user_sessions("unknown-user")
        assert len(no_sessions) == 0
