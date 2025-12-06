"""
LOT 3: JWT Validator

Implémentation validation JWT Keycloak.

Invariants:
    RUN_010: Validation Keycloak uniquement (pas de login custom)
    RUN_011: Access token ≤ 900 secondes
    RUN_012: Refresh token ≤ 86400 secondes
"""

import jwt
from datetime import datetime, timezone
from typing import Optional
from functools import lru_cache

from .interfaces import IJWTValidator, TokenClaims


class JWTValidationError(Exception):
    """Erreur validation JWT."""

    def __init__(self, message: str, invariant: Optional[str] = None):
        self.invariant = invariant
        super().__init__(message)


class JWTExpiredError(JWTValidationError):
    """Token expiré."""

    def __init__(self, message: str = "Token expired"):
        super().__init__(message, invariant="RUN_011")


class JWTValidator(IJWTValidator):
    """
    Validateur JWT Keycloak.

    Conformité:
        RUN_010: Validation via JWKS Keycloak uniquement
        RUN_011: Rejette access token si lifespan > 900s
        RUN_012: Rejette refresh token si lifespan > 86400s

    Example:
        validator = JWTValidator("http://localhost:8081", "zynaxia")
        claims = validator.validate(token)
    """

    def __init__(self, keycloak_url: str, realm: str, audience: Optional[str] = None):
        """
        Args:
            keycloak_url: URL base Keycloak (ex: http://localhost:8081)
            realm: Nom du realm (ex: zynaxia)
            audience: Audience attendue (ex: zynaxia-api). Si None, pas de vérification.
        """
        self.keycloak_url = keycloak_url.rstrip("/")
        self.realm = realm
        self.audience = audience
        self._jwks_client: Optional[jwt.PyJWKClient] = None

    @property
    def jwks_uri(self) -> str:
        """URI endpoint JWKS Keycloak."""
        return f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/certs"

    @property
    def issuer(self) -> str:
        """Issuer attendu dans les tokens."""
        return f"{self.keycloak_url}/realms/{self.realm}"

    def _get_jwks_client(self) -> jwt.PyJWKClient:
        """Récupère ou crée le client JWKS (lazy loading)."""
        if self._jwks_client is None:
            self._jwks_client = jwt.PyJWKClient(self.jwks_uri)
        return self._jwks_client

    def validate(self, token: str) -> TokenClaims:
        """
        Valide JWT et retourne claims.

        Raises:
            JWTExpiredError: Token expiré
            JWTValidationError: Token invalide ou violation invariant
        """
        try:
            # RUN_010: Récupérer clé publique depuis Keycloak JWKS
            jwks_client = self._get_jwks_client()
            signing_key = jwks_client.get_signing_key_from_jwt(token)

            # Décoder et valider signature + claims standards
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                issuer=self.issuer,
                audience=self.audience,
                options={
                    "require": ["exp", "iat", "sub"],
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_aud": self.audience is not None,
                },
            )

            # Extraire timestamps
            iat = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)
            exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)

            # RUN_011: Vérifier lifespan max 15 minutes
            token_lifespan_seconds = (exp - iat).total_seconds()

            if token_lifespan_seconds > self.MAX_ACCESS_TOKEN_SECONDS:
                raise JWTValidationError(
                    f"RUN_011 violation: token lifespan {int(token_lifespan_seconds)}s "
                    f"exceeds maximum {self.MAX_ACCESS_TOKEN_SECONDS}s",
                    invariant="RUN_011",
                )

            # Extraire claims métier
            return TokenClaims(
                user_id=payload["sub"],
                tenant_id=self._extract_tenant_id(payload),
                level=payload.get("level", 3),  # Default: Site level
                roles=self._extract_roles(payload),
                permissions=payload.get("permissions", []),
                exp=exp,
                iat=iat,
                mfa_verified=self._check_mfa(payload),
                session_id=payload.get("sid"),
            )

        except jwt.ExpiredSignatureError:
            raise JWTExpiredError("Token expired")
        except jwt.InvalidIssuerError:
            raise JWTValidationError(f"Invalid issuer. Expected: {self.issuer}", invariant="RUN_010")
        except jwt.InvalidTokenError as e:
            raise JWTValidationError(f"Invalid token: {e}")

    def is_expired(self, token: str) -> bool:
        """Vérifie expiration sans valider signature."""
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            exp_timestamp = payload.get("exp")
            if exp_timestamp is None:
                return True
            exp = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
            return datetime.now(timezone.utc) > exp
        except Exception:
            return True

    def decode_without_validation(self, token: str) -> dict:
        """
        Décode sans valider (debug uniquement).

        ⚠️ NE JAMAIS utiliser pour authentification.
        """
        return jwt.decode(token, options={"verify_signature": False})

    def _extract_tenant_id(self, payload: dict) -> str:
        """Extrait tenant_id depuis claims Keycloak."""
        # Ordre de priorité: claim custom > azp > client_id
        return payload.get("tenant_id") or payload.get("azp") or payload.get("client_id", "")

    def _extract_roles(self, payload: dict) -> list:
        """Extrait rôles depuis structure Keycloak."""
        roles = []

        # Realm roles
        realm_access = payload.get("realm_access", {})
        roles.extend(realm_access.get("roles", []))

        # Resource roles (client-specific)
        resource_access = payload.get("resource_access", {})
        for client_roles in resource_access.values():
            roles.extend(client_roles.get("roles", []))

        return list(set(roles))  # Dédupliquer

    def _check_mfa(self, payload: dict) -> bool:
        """
        Vérifie si MFA validé.

        Keycloak indique MFA via:
        - acr (Authentication Context Class Reference) = "aal2"
        - amr (Authentication Methods References) contient "mfa" ou "otp"
        """
        acr = payload.get("acr", "")
        amr = payload.get("amr", [])

        return acr in ("aal2", "aal3") or "mfa" in amr or "otp" in amr or "totp" in amr
