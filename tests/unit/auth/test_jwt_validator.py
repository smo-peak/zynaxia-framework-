"""
Tests unitaires JWTValidator

Invariants testés:
    RUN_010: Keycloak obligatoire
    RUN_011: Access token ≤ 900s
    RUN_012: Refresh token ≤ 86400s
"""

import pytest
import jwt
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch, MagicMock

from src.auth.interfaces import IJWTValidator, TokenClaims
from src.auth.jwt_validator import JWTValidator, JWTValidationError, JWTExpiredError


# ══════════════════════════════════════════════════════════════════════════════
# TESTS INTERFACE
# ══════════════════════════════════════════════════════════════════════════════


class TestJWTValidatorInterface:
    """Vérifie conformité à l'interface."""

    def test_implements_interface(self):
        """JWTValidator implémente IJWTValidator."""
        validator = JWTValidator("http://localhost:8081", "zynaxia")
        assert isinstance(validator, IJWTValidator)

    def test_RUN_011_max_access_token_constant(self):
        """RUN_011: Constante MAX_ACCESS_TOKEN_SECONDS = 900."""
        assert IJWTValidator.MAX_ACCESS_TOKEN_SECONDS == 900
        assert JWTValidator.MAX_ACCESS_TOKEN_SECONDS == 900

    def test_RUN_012_max_refresh_token_constant(self):
        """RUN_012: Constante MAX_REFRESH_TOKEN_SECONDS = 86400."""
        assert IJWTValidator.MAX_REFRESH_TOKEN_SECONDS == 86400
        assert JWTValidator.MAX_REFRESH_TOKEN_SECONDS == 86400


# ══════════════════════════════════════════════════════════════════════════════
# TESTS CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════


class TestJWTValidatorConfig:
    """Tests configuration Keycloak."""

    def test_jwks_uri_format(self):
        """URI JWKS correctement formatée."""
        validator = JWTValidator("http://localhost:8081", "zynaxia")
        expected = "http://localhost:8081/realms/zynaxia/protocol/openid-connect/certs"
        assert validator.jwks_uri == expected

    def test_issuer_format(self):
        """Issuer correctement formaté."""
        validator = JWTValidator("http://localhost:8081", "zynaxia")
        assert validator.issuer == "http://localhost:8081/realms/zynaxia"

    def test_trailing_slash_removed(self):
        """Trailing slash supprimé de l'URL."""
        validator = JWTValidator("http://localhost:8081/", "zynaxia")
        assert validator.keycloak_url == "http://localhost:8081"
        # Ne doit pas y avoir de double slash après le port
        assert "8081//" not in validator.jwks_uri


# ══════════════════════════════════════════════════════════════════════════════
# TESTS EXPIRATION (RUN_011)
# ══════════════════════════════════════════════════════════════════════════════


class TestJWTExpiration:
    """Tests méthode is_expired."""

    def test_expired_token_returns_true(self):
        """Token expiré → True."""
        validator = JWTValidator("http://localhost:8081", "zynaxia")

        payload = {
            "exp": (datetime.now(timezone.utc) - timedelta(hours=1)).timestamp(),
            "iat": (datetime.now(timezone.utc) - timedelta(hours=2)).timestamp(),
            "sub": "test-user",
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")

        assert validator.is_expired(token) is True

    def test_valid_token_returns_false(self):
        """Token valide → False."""
        validator = JWTValidator("http://localhost:8081", "zynaxia")

        payload = {
            "exp": (datetime.now(timezone.utc) + timedelta(minutes=10)).timestamp(),
            "iat": datetime.now(timezone.utc).timestamp(),
            "sub": "test-user",
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")

        assert validator.is_expired(token) is False

    def test_invalid_token_returns_true(self):
        """Token invalide → True."""
        validator = JWTValidator("http://localhost:8081", "zynaxia")
        assert validator.is_expired("invalid.token") is True

    def test_token_without_exp_returns_true(self):
        """Token sans exp → True."""
        validator = JWTValidator("http://localhost:8081", "zynaxia")

        payload = {"sub": "test-user", "iat": datetime.now(timezone.utc).timestamp()}
        token = jwt.encode(payload, "secret", algorithm="HS256")

        assert validator.is_expired(token) is True


# ══════════════════════════════════════════════════════════════════════════════
# TESTS DECODE SANS VALIDATION
# ══════════════════════════════════════════════════════════════════════════════


class TestJWTDecodeWithoutValidation:
    """Tests decode_without_validation."""

    def test_decodes_payload(self):
        """Décode payload correctement."""
        validator = JWTValidator("http://localhost:8081", "zynaxia")

        payload = {
            "sub": "user-123",
            "tenant_id": "tenant-456",
            "exp": (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp(),
            "iat": datetime.now(timezone.utc).timestamp(),
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")

        decoded = validator.decode_without_validation(token)

        assert decoded["sub"] == "user-123"
        assert decoded["tenant_id"] == "tenant-456"

    def test_decodes_expired_token(self):
        """Décode même token expiré."""
        validator = JWTValidator("http://localhost:8081", "zynaxia")

        payload = {
            "sub": "user-123",
            "exp": (datetime.now(timezone.utc) - timedelta(hours=1)).timestamp(),
            "iat": (datetime.now(timezone.utc) - timedelta(hours=2)).timestamp(),
        }
        token = jwt.encode(payload, "secret", algorithm="HS256")

        decoded = validator.decode_without_validation(token)
        assert decoded["sub"] == "user-123"


# ══════════════════════════════════════════════════════════════════════════════
# TESTS RUN_011: LIFESPAN MAX 15 MINUTES
# ══════════════════════════════════════════════════════════════════════════════


class TestRUN011Compliance:
    """Tests conformité RUN_011: JWT access token ≤ 900s."""

    @patch.object(JWTValidator, "_get_jwks_client")
    def test_RUN_011_reject_lifespan_over_900s(self, mock_jwks):
        """RUN_011: Rejette token avec lifespan > 900s."""
        validator = JWTValidator("http://localhost:8081", "zynaxia")

        # Mock JWKS
        mock_key = MagicMock()
        mock_key.key = "test-key"
        mock_jwks.return_value.get_signing_key_from_jwt.return_value = mock_key

        now = datetime.now(timezone.utc)
        payload = {
            "sub": "user-123",
            "iat": now.timestamp(),
            "exp": (now + timedelta(hours=1)).timestamp(),  # 3600s > 900s
            "iss": validator.issuer,
        }

        with patch("jwt.decode", return_value=payload):
            with pytest.raises(JWTValidationError) as exc_info:
                validator.validate("fake.token.here")

            assert "RUN_011" in str(exc_info.value)
            assert exc_info.value.invariant == "RUN_011"

    @patch.object(JWTValidator, "_get_jwks_client")
    def test_RUN_011_accept_lifespan_900s(self, mock_jwks):
        """RUN_011: Accepte token avec lifespan = 900s."""
        validator = JWTValidator("http://localhost:8081", "zynaxia")

        mock_key = MagicMock()
        mock_key.key = "test-key"
        mock_jwks.return_value.get_signing_key_from_jwt.return_value = mock_key

        now = datetime.now(timezone.utc)
        payload = {
            "sub": "user-123",
            "iat": now.timestamp(),
            "exp": (now + timedelta(seconds=900)).timestamp(),  # Exactement 900s
            "iss": validator.issuer,
        }

        with patch("jwt.decode", return_value=payload):
            claims = validator.validate("fake.token.here")
            assert claims.user_id == "user-123"

    @patch.object(JWTValidator, "_get_jwks_client")
    def test_RUN_011_accept_lifespan_under_900s(self, mock_jwks):
        """RUN_011: Accepte token avec lifespan < 900s."""
        validator = JWTValidator("http://localhost:8081", "zynaxia")

        mock_key = MagicMock()
        mock_key.key = "test-key"
        mock_jwks.return_value.get_signing_key_from_jwt.return_value = mock_key

        now = datetime.now(timezone.utc)
        payload = {
            "sub": "user-123",
            "iat": now.timestamp(),
            "exp": (now + timedelta(minutes=5)).timestamp(),  # 300s < 900s
            "iss": validator.issuer,
        }

        with patch("jwt.decode", return_value=payload):
            claims = validator.validate("fake.token.here")
            assert claims.user_id == "user-123"


# ══════════════════════════════════════════════════════════════════════════════
# TESTS RUN_010: KEYCLOAK OBLIGATOIRE
# ══════════════════════════════════════════════════════════════════════════════


class TestRUN010Compliance:
    """Tests conformité RUN_010: Keycloak obligatoire."""

    @patch.object(JWTValidator, "_get_jwks_client")
    def test_RUN_010_reject_wrong_issuer(self, mock_jwks):
        """RUN_010: Rejette token avec mauvais issuer."""
        validator = JWTValidator("http://localhost:8081", "zynaxia")

        mock_key = MagicMock()
        mock_key.key = "test-key"
        mock_jwks.return_value.get_signing_key_from_jwt.return_value = mock_key

        with patch("jwt.decode", side_effect=jwt.InvalidIssuerError("Wrong issuer")):
            with pytest.raises(JWTValidationError) as exc_info:
                validator.validate("fake.token.here")

            assert "RUN_010" in str(exc_info.value.invariant)


# ══════════════════════════════════════════════════════════════════════════════
# TESTS TOKEN CLAIMS
# ══════════════════════════════════════════════════════════════════════════════


class TestTokenClaims:
    """Tests dataclass TokenClaims."""

    def test_valid_claims(self):
        """Création claims valides."""
        now = datetime.now(timezone.utc)
        claims = TokenClaims(
            user_id="user-123",
            tenant_id="tenant-456",
            level=3,
            roles=["site_operator"],
            permissions=["events:read"],
            exp=now + timedelta(minutes=15),
            iat=now,
            mfa_verified=False,
            session_id="session-789",
        )

        assert claims.user_id == "user-123"
        assert claims.level == 3
        assert claims.mfa_verified is False

    def test_mfa_default_false(self):
        """MFA par défaut = False."""
        now = datetime.now(timezone.utc)
        claims = TokenClaims(
            user_id="u", tenant_id="t", level=3, roles=[], permissions=[], exp=now + timedelta(minutes=1), iat=now
        )
        assert claims.mfa_verified is False

    def test_invalid_level_raises(self):
        """Level invalide → ValueError."""
        now = datetime.now(timezone.utc)
        with pytest.raises(ValueError, match="Level must be 0-3"):
            TokenClaims(
                user_id="u",
                tenant_id="t",
                level=5,  # Invalid
                roles=[],
                permissions=[],
                exp=now + timedelta(minutes=1),
                iat=now,
            )

    def test_exp_before_iat_raises(self):
        """exp <= iat → ValueError."""
        now = datetime.now(timezone.utc)
        with pytest.raises(ValueError, match="exp must be after iat"):
            TokenClaims(
                user_id="u",
                tenant_id="t",
                level=3,
                roles=[],
                permissions=[],
                exp=now - timedelta(minutes=1),  # Before iat
                iat=now,
            )

    def test_frozen_dataclass(self):
        """TokenClaims est immutable."""
        now = datetime.now(timezone.utc)
        claims = TokenClaims(
            user_id="u", tenant_id="t", level=3, roles=[], permissions=[], exp=now + timedelta(minutes=1), iat=now
        )

        with pytest.raises(AttributeError):
            claims.user_id = "modified"


# ══════════════════════════════════════════════════════════════════════════════
# TESTS EXTRACTION CLAIMS
# ══════════════════════════════════════════════════════════════════════════════


class TestClaimsExtraction:
    """Tests extraction claims depuis payload Keycloak."""

    @patch.object(JWTValidator, "_get_jwks_client")
    def test_extract_mfa_from_acr(self, mock_jwks):
        """MFA détecté via acr=aal2."""
        validator = JWTValidator("http://localhost:8081", "zynaxia")

        mock_key = MagicMock()
        mock_key.key = "test-key"
        mock_jwks.return_value.get_signing_key_from_jwt.return_value = mock_key

        now = datetime.now(timezone.utc)
        payload = {
            "sub": "user-123",
            "iat": now.timestamp(),
            "exp": (now + timedelta(minutes=10)).timestamp(),
            "iss": validator.issuer,
            "acr": "aal2",  # MFA indicator
        }

        with patch("jwt.decode", return_value=payload):
            claims = validator.validate("fake.token")
            assert claims.mfa_verified is True

    @patch.object(JWTValidator, "_get_jwks_client")
    def test_extract_mfa_from_amr(self, mock_jwks):
        """MFA détecté via amr contient 'otp'."""
        validator = JWTValidator("http://localhost:8081", "zynaxia")

        mock_key = MagicMock()
        mock_key.key = "test-key"
        mock_jwks.return_value.get_signing_key_from_jwt.return_value = mock_key

        now = datetime.now(timezone.utc)
        payload = {
            "sub": "user-123",
            "iat": now.timestamp(),
            "exp": (now + timedelta(minutes=10)).timestamp(),
            "iss": validator.issuer,
            "amr": ["pwd", "otp"],  # MFA indicator
        }

        with patch("jwt.decode", return_value=payload):
            claims = validator.validate("fake.token")
            assert claims.mfa_verified is True

    @patch.object(JWTValidator, "_get_jwks_client")
    def test_extract_roles_from_realm_access(self, mock_jwks):
        """Rôles extraits depuis realm_access."""
        validator = JWTValidator("http://localhost:8081", "zynaxia")

        mock_key = MagicMock()
        mock_key.key = "test-key"
        mock_jwks.return_value.get_signing_key_from_jwt.return_value = mock_key

        now = datetime.now(timezone.utc)
        payload = {
            "sub": "user-123",
            "iat": now.timestamp(),
            "exp": (now + timedelta(minutes=10)).timestamp(),
            "iss": validator.issuer,
            "realm_access": {"roles": ["site_admin", "operator"]},
        }

        with patch("jwt.decode", return_value=payload):
            claims = validator.validate("fake.token")
            assert "site_admin" in claims.roles
            assert "operator" in claims.roles
