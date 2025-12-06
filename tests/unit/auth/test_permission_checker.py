"""
Tests unitaires PermissionChecker

Invariants testés:
    RUN_013: MFA obligatoire pour permissions élevées
    RUN_020: Niveau N ne peut avoir permissions niveau N-1
    RUN_021: Wildcard (*) interdit sauf Platform (level 0)
    RUN_022: Actions critiques requièrent quorum (2+ signatures)
    RUN_023: Permissions élevées durée limitée
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

from src.auth.interfaces import IPermissionChecker, TokenClaims
from src.auth.permission_checker import PermissionChecker, PermissionCheckerError


# ══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def permission_checker():
    """PermissionChecker instance for tests."""
    return PermissionChecker()


@pytest.fixture
def platform_claims():
    """Platform level claims (level 0) with MFA."""
    now = datetime.now(timezone.utc)
    return TokenClaims(
        user_id="platform-admin",
        tenant_id="platform",
        level=0,
        roles=["platform_admin"],
        permissions=["platform:*"],
        exp=now + timedelta(minutes=15),
        iat=now,
        mfa_verified=True,
        session_id="session-123",
    )


@pytest.fixture
def site_claims():
    """Site level claims (level 3) without MFA."""
    now = datetime.now(timezone.utc)
    return TokenClaims(
        user_id="site-operator",
        tenant_id="site-456",
        level=3,
        roles=["site_operator"],
        permissions=["site:events:read", "site:events:write"],
        exp=now + timedelta(minutes=15),
        iat=now,
        mfa_verified=False,
        session_id="session-456",
    )


@pytest.fixture
def organization_claims():
    """Organization level claims (level 2)."""
    now = datetime.now(timezone.utc)
    return TokenClaims(
        user_id="org-admin",
        tenant_id="org-789",
        level=2,
        roles=["org_admin"],
        permissions=["organization:manage", "site:events:read"],
        exp=now + timedelta(minutes=15),
        iat=now,
        mfa_verified=True,
        session_id="session-789",
    )


# ══════════════════════════════════════════════════════════════════════════════
# TESTS INTERFACE
# ══════════════════════════════════════════════════════════════════════════════


class TestPermissionCheckerInterface:
    """Vérifie conformité à l'interface."""

    def test_implements_interface(self, permission_checker):
        """PermissionChecker implémente IPermissionChecker."""
        assert isinstance(permission_checker, IPermissionChecker)

    def test_elevated_permissions_defined(self, permission_checker):
        """Permissions élevées sont définies."""
        assert len(permission_checker.ELEVATED_PERMISSIONS) > 0
        assert "admin:*" in permission_checker.ELEVATED_PERMISSIONS
        assert "platform:*" in permission_checker.ELEVATED_PERMISSIONS

    def test_critical_actions_defined(self, permission_checker):
        """Actions critiques sont définies."""
        assert len(permission_checker.CRITICAL_ACTIONS) > 0
        assert "platform:shutdown" in permission_checker.CRITICAL_ACTIONS
        assert "users:delete" in permission_checker.CRITICAL_ACTIONS


# ══════════════════════════════════════════════════════════════════════════════
# TESTS RUN_013: MFA OBLIGATOIRE
# ══════════════════════════════════════════════════════════════════════════════


class TestRUN013Compliance:
    """Tests conformité RUN_013: MFA obligatoire pour permissions élevées."""

    def test_RUN_013_requires_mfa_for_elevated_permission(self, permission_checker):
        """RUN_013: Permission élevée requiert MFA."""
        assert permission_checker.requires_mfa("admin:*") is True
        assert permission_checker.requires_mfa("platform:*") is True
        assert permission_checker.requires_mfa("users:create") is True
        assert permission_checker.requires_mfa("security:*") is True

    def test_RUN_013_no_mfa_for_regular_permission(self, permission_checker):
        """RUN_013: Permission normale ne requiert pas MFA."""
        assert permission_checker.requires_mfa("site:events:read") is False
        assert permission_checker.requires_mfa("organization:view") is False
        assert permission_checker.requires_mfa("integrator:reports") is False

    def test_RUN_013_check_blocks_elevated_without_mfa(self, permission_checker):
        """RUN_013: Bloque permission élevée sans MFA."""
        now = datetime.now(timezone.utc)
        claims_no_mfa = TokenClaims(
            user_id="user-123",
            tenant_id="tenant-456",
            level=0,
            roles=["admin"],
            permissions=["admin:*"],
            exp=now + timedelta(minutes=15),
            iat=now,
            mfa_verified=False,  # Pas de MFA
        )

        result = permission_checker.check(claims_no_mfa, "admin:users", "resource-123")
        assert result is False

    def test_RUN_013_check_allows_elevated_with_mfa(self, permission_checker, platform_claims):
        """RUN_013: Autorise permission élevée avec MFA."""
        result = permission_checker.check(platform_claims, "platform:config", "resource-123")
        assert result is True


# ══════════════════════════════════════════════════════════════════════════════
# TESTS RUN_020: ISOLATION HIÉRARCHIQUE
# ══════════════════════════════════════════════════════════════════════════════


class TestRUN020Compliance:
    """Tests conformité RUN_020: Niveau N ne peut avoir permissions niveau N-1."""

    def test_RUN_020_validate_level_permissions_site_cannot_have_org(self, permission_checker):
        """RUN_020: Site (3) ne peut avoir permissions Organization (2)."""
        invalid = permission_checker.validate_level_permissions(
            3,
            [
                "site:events:read",  # OK
                "organization:manage",  # INVALIDE
                "site:alerts:write",  # OK
            ],
        )

        assert "organization:manage" in invalid
        assert "site:events:read" not in invalid
        assert "site:alerts:write" not in invalid

    def test_RUN_020_validate_level_permissions_org_cannot_have_integrator(self, permission_checker):
        """RUN_020: Organization (2) ne peut avoir permissions Integrator (1)."""
        invalid = permission_checker.validate_level_permissions(
            2,
            [
                "organization:view",  # OK
                "integrator:reports",  # INVALIDE
                "site:events:read",  # OK
            ],
        )

        assert "integrator:reports" in invalid
        assert "organization:view" not in invalid
        assert "site:events:read" not in invalid

    def test_RUN_020_validate_level_permissions_platform_can_have_all(self, permission_checker):
        """RUN_020: Platform (0) peut avoir toutes les permissions."""
        invalid = permission_checker.validate_level_permissions(
            0, ["platform:*", "integrator:manage", "organization:create", "site:delete"]
        )

        assert len(invalid) == 0

    def test_RUN_020_check_blocks_higher_level_permissions(self, permission_checker):
        """RUN_020: check() bloque permissions de niveau supérieur."""
        now = datetime.now(timezone.utc)
        site_claims_invalid = TokenClaims(
            user_id="site-user",
            tenant_id="site-123",
            level=3,
            roles=["site_user"],
            permissions=["organization:manage"],  # INVALIDE pour level 3
            exp=now + timedelta(minutes=15),
            iat=now,
            mfa_verified=False,
        )

        result = permission_checker.check(site_claims_invalid, "organization:manage", "resource")
        assert result is False

    def test_RUN_020_invalid_level_returns_all_invalid(self, permission_checker):
        """RUN_020: Niveau invalide → toutes permissions invalides."""
        invalid = permission_checker.validate_level_permissions(5, ["any:permission"])
        assert "any:permission" in invalid


# ══════════════════════════════════════════════════════════════════════════════
# TESTS RUN_021: WILDCARD PLATFORM UNIQUEMENT
# ══════════════════════════════════════════════════════════════════════════════


class TestRUN021Compliance:
    """Tests conformité RUN_021: Wildcard (*) interdit sauf Platform."""

    def test_RUN_021_has_wildcard_detects_wildcard(self, permission_checker):
        """RUN_021: Détecte présence wildcard."""
        assert permission_checker.has_wildcard(["platform:*"]) is True
        assert permission_checker.has_wildcard(["admin:*", "users:read"]) is True
        assert permission_checker.has_wildcard(["site:*:read"]) is True  # Wildcard au milieu

    def test_RUN_021_has_wildcard_no_wildcard(self, permission_checker):
        """RUN_021: Pas de wildcard détecté."""
        assert permission_checker.has_wildcard(["site:events:read"]) is False
        assert permission_checker.has_wildcard(["organization:manage"]) is False
        assert permission_checker.has_wildcard([]) is False

    def test_RUN_021_check_allows_wildcard_for_platform(self, permission_checker, platform_claims):
        """RUN_021: Wildcard autorisé pour Platform (level 0)."""
        result = permission_checker.check(platform_claims, "platform:anything", "resource")
        assert result is True

    def test_RUN_021_check_blocks_wildcard_for_non_platform(self, permission_checker):
        """RUN_021: Wildcard bloqué pour non-Platform."""
        now = datetime.now(timezone.utc)
        site_claims_with_wildcard = TokenClaims(
            user_id="site-admin",
            tenant_id="site-123",
            level=3,
            roles=["site_admin"],
            permissions=["site:*"],  # INVALIDE pour level 3
            exp=now + timedelta(minutes=15),
            iat=now,
            mfa_verified=False,
        )

        result = permission_checker.check(site_claims_with_wildcard, "site:events:read", "resource")
        assert result is False


# ══════════════════════════════════════════════════════════════════════════════
# TESTS RUN_022: QUORUM ACTIONS CRITIQUES
# ══════════════════════════════════════════════════════════════════════════════


class TestRUN022Compliance:
    """Tests conformité RUN_022: Actions critiques requièrent quorum."""

    def test_RUN_022_requires_quorum_for_critical_actions(self, permission_checker):
        """RUN_022: Actions critiques requièrent quorum."""
        assert permission_checker.requires_quorum("platform:shutdown") is True
        assert permission_checker.requires_quorum("users:delete") is True
        assert permission_checker.requires_quorum("audit:purge") is True
        assert permission_checker.requires_quorum("security:key:rotate") is True

    def test_RUN_022_no_quorum_for_regular_actions(self, permission_checker):
        """RUN_022: Actions normales ne requièrent pas quorum."""
        assert permission_checker.requires_quorum("site:events:read") is False
        assert permission_checker.requires_quorum("organization:view") is False
        assert permission_checker.requires_quorum("users:list") is False

    def test_RUN_022_check_quorum_requirement_sufficient(self, permission_checker):
        """RUN_022: Quorum suffisant pour action critique."""
        result = permission_checker.check_quorum_requirement("platform:shutdown", 2)
        assert result is True

        result = permission_checker.check_quorum_requirement("platform:shutdown", 3)
        assert result is True

    def test_RUN_022_check_quorum_requirement_insufficient(self, permission_checker):
        """RUN_022: Quorum insuffisant pour action critique."""
        result = permission_checker.check_quorum_requirement("platform:shutdown", 1)
        assert result is False

        result = permission_checker.check_quorum_requirement("platform:shutdown", 0)
        assert result is False

    def test_RUN_022_check_quorum_requirement_not_critical(self, permission_checker):
        """RUN_022: Action non critique ne requiert pas quorum."""
        result = permission_checker.check_quorum_requirement("site:events:read", 1)
        assert result is True

        result = permission_checker.check_quorum_requirement("site:events:read", 0)
        assert result is True


# ══════════════════════════════════════════════════════════════════════════════
# TESTS RUN_023: TTL PERMISSIONS ÉLEVÉES
# ══════════════════════════════════════════════════════════════════════════════


class TestRUN023Compliance:
    """Tests conformité RUN_023: Permissions élevées durée limitée."""

    def test_RUN_023_check_blocks_expired_elevated_permission(self, permission_checker):
        """RUN_023: Bloque permission élevée expirée."""
        now = datetime.now(timezone.utc)
        old_claims = TokenClaims(
            user_id="admin",
            tenant_id="platform",
            level=0,
            roles=["admin"],
            permissions=["admin:*"],
            exp=now + timedelta(hours=2),
            iat=now - timedelta(hours=2),  # Token émis il y a 2h > 1h limite
            mfa_verified=True,
        )

        result = permission_checker.check(old_claims, "admin:users", "resource")
        assert result is False

    def test_RUN_023_check_allows_recent_elevated_permission(self, permission_checker):
        """RUN_023: Autorise permission élevée récente."""
        now = datetime.now(timezone.utc)
        recent_claims = TokenClaims(
            user_id="admin",
            tenant_id="platform",
            level=0,
            roles=["admin"],
            permissions=["admin:*"],
            exp=now + timedelta(minutes=30),
            iat=now - timedelta(minutes=30),  # Token émis il y a 30min < 1h limite
            mfa_verified=True,
        )

        result = permission_checker.check(recent_claims, "admin:users", "resource")
        assert result is True

    def test_RUN_023_ttl_not_applied_to_regular_permissions(self, permission_checker):
        """RUN_023: TTL ne s'applique pas aux permissions normales."""
        now = datetime.now(timezone.utc)
        old_claims = TokenClaims(
            user_id="user",
            tenant_id="site-123",
            level=3,
            roles=["site_user"],
            permissions=["site:events:read"],
            exp=now + timedelta(hours=2),
            iat=now - timedelta(hours=2),  # Token ancien mais permission normale
            mfa_verified=False,
        )

        result = permission_checker.check(old_claims, "site:events:read", "resource")
        assert result is True


# ══════════════════════════════════════════════════════════════════════════════
# TESTS FONCTIONS CHECK GÉNÉRALES
# ══════════════════════════════════════════════════════════════════════════════


class TestPermissionCheck:
    """Tests généraux de vérification de permissions."""

    def test_check_exact_permission_match(self, permission_checker, site_claims):
        """Permission exacte → autorisé."""
        result = permission_checker.check(site_claims, "site:events:read", "resource")
        assert result is True

    def test_check_no_permission_match(self, permission_checker, site_claims):
        """Pas de permission correspondante → refusé."""
        result = permission_checker.check(site_claims, "site:admin:delete", "resource")
        assert result is False

    def test_check_empty_claims_returns_false(self, permission_checker):
        """Claims vides → False."""
        result = permission_checker.check(None, "any:action", "resource")
        assert result is False

    def test_check_empty_action_returns_false(self, permission_checker, site_claims):
        """Action vide → False."""
        result = permission_checker.check(site_claims, "", "resource")
        assert result is False

    def test_wildcard_pattern_matching(self, permission_checker):
        """Test pattern matching pour wildcards."""
        # Test interne _matches_permission_pattern
        assert permission_checker._matches_permission_pattern("site:*", "site:events:read") is True
        assert permission_checker._matches_permission_pattern("site:events:*", "site:events:read") is True
        assert permission_checker._matches_permission_pattern("site:*:read", "site:events:read") is True
        assert permission_checker._matches_permission_pattern("platform:*", "platform:config") is True
        assert permission_checker._matches_permission_pattern("site:*", "organization:view") is False


# ══════════════════════════════════════════════════════════════════════════════
# TESTS UTILITAIRES
# ══════════════════════════════════════════════════════════════════════════════


class TestPermissionUtilities:
    """Tests fonctions utilitaires."""

    def test_get_allowed_actions_for_platform(self, permission_checker):
        """Actions autorisées pour Platform."""
        actions = permission_checker.get_allowed_actions_for_level(0)
        assert "platform:*" in actions
        assert "integrator:*" in actions
        assert "organization:*" in actions
        assert "site:*" in actions

    def test_get_allowed_actions_for_site(self, permission_checker):
        """Actions autorisées pour Site."""
        actions = permission_checker.get_allowed_actions_for_level(3)
        assert "site:*" in actions
        assert "platform:*" not in actions
        assert "organization:*" not in actions

    def test_get_allowed_actions_invalid_level(self, permission_checker):
        """Niveau invalide → liste vide."""
        actions = permission_checker.get_allowed_actions_for_level(5)
        assert len(actions) == 0

        actions = permission_checker.get_allowed_actions_for_level(-1)
        assert len(actions) == 0
