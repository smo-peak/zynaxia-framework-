"""
LOT 3: Interfaces Auth

Définit les contrats pour l'authentification et l'autorisation.
Toute implémentation DOIT respecter ces interfaces.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime


@dataclass(frozen=True)
class TokenClaims:
    """
    Claims extraits et validés du JWT Keycloak.

    Attributes:
        user_id: Identifiant unique utilisateur (sub claim)
        tenant_id: Identifiant tenant (isolation RLS)
        level: Niveau hiérarchique (0=Platform, 1=Integrator, 2=Organization, 3=Site)
        roles: Liste des rôles Keycloak
        permissions: Liste des permissions extraites
        exp: Date expiration token
        iat: Date émission token
        mfa_verified: True si authentification MFA validée
        session_id: Identifiant session Keycloak (sid claim)
    """

    user_id: str
    tenant_id: str
    level: int
    roles: List[str]
    permissions: List[str]
    exp: datetime
    iat: datetime
    mfa_verified: bool = False
    session_id: Optional[str] = None

    def __post_init__(self):
        """Validation des contraintes."""
        if self.level < 0 or self.level > 3:
            raise ValueError(f"Level must be 0-3, got {self.level}")
        if self.exp <= self.iat:
            raise ValueError("exp must be after iat")


@dataclass
class Session:
    """
    Session utilisateur traçable.

    Attributes:
        session_id: Identifiant unique session
        user_id: Utilisateur propriétaire
        tenant_id: Tenant associé
        created_at: Horodatage création
        expires_at: Horodatage expiration
        revoked: True si révoquée (RUN_014)
        revoked_at: Horodatage révocation
        revoked_reason: Motif révocation
    """

    session_id: str
    user_id: str
    tenant_id: str
    created_at: datetime
    expires_at: datetime
    revoked: bool = False
    revoked_at: Optional[datetime] = None
    revoked_reason: Optional[str] = None


class IJWTValidator(ABC):
    """
    Interface validation JWT Keycloak.

    Invariants:
        RUN_010: Validation Keycloak uniquement
        RUN_011: Access token ≤ 900s
        RUN_012: Refresh token ≤ 86400s
    """

    MAX_ACCESS_TOKEN_SECONDS: int = 900  # 15 minutes (RUN_011)
    MAX_REFRESH_TOKEN_SECONDS: int = 86400  # 24 heures (RUN_012)

    @abstractmethod
    def validate(self, token: str) -> TokenClaims:
        """
        Valide JWT Keycloak et retourne claims.

        Args:
            token: JWT brut (sans Bearer)

        Returns:
            TokenClaims validés

        Raises:
            JWTValidationError: Token invalide
            JWTExpiredError: Token expiré
        """
        pass

    @abstractmethod
    def is_expired(self, token: str) -> bool:
        """
        Vérifie si token expiré (sans valider signature).

        Args:
            token: JWT brut

        Returns:
            True si expiré ou invalide
        """
        pass

    @abstractmethod
    def decode_without_validation(self, token: str) -> dict:
        """
        Décode payload sans valider (debug/logs uniquement).

        ⚠️ NE JAMAIS utiliser pour authentification.

        Args:
            token: JWT brut

        Returns:
            Payload décodé
        """
        pass


class ISessionManager(ABC):
    """
    Interface gestion sessions.

    Invariants:
        RUN_014: Révocation immédiate à distance
    """

    @abstractmethod
    async def create_session(self, user_id: str, tenant_id: str, token_claims: TokenClaims) -> Session:
        """Crée une nouvelle session."""
        pass

    @abstractmethod
    async def get_session(self, session_id: str) -> Optional[Session]:
        """Récupère session par ID."""
        pass

    @abstractmethod
    async def revoke_session(self, session_id: str, reason: str = "manual") -> bool:
        """
        Révoque immédiatement une session (RUN_014).

        Args:
            session_id: Session à révoquer
            reason: Motif révocation (audit)

        Returns:
            True si révoquée, False si inexistante
        """
        pass

    @abstractmethod
    async def revoke_all_user_sessions(self, user_id: str, reason: str = "security") -> int:
        """
        Révoque toutes les sessions d'un utilisateur.

        Args:
            user_id: Utilisateur cible
            reason: Motif (audit)

        Returns:
            Nombre de sessions révoquées
        """
        pass

    @abstractmethod
    async def is_session_valid(self, session_id: str) -> bool:
        """Vérifie validité session (non révoquée, non expirée)."""
        pass


class IPermissionChecker(ABC):
    """
    Interface vérification permissions.

    Invariants:
        RUN_013: MFA pour permissions élevées
        RUN_020: Pas de permissions niveau supérieur
        RUN_021: Wildcard Platform uniquement
        RUN_022: Quorum pour actions critiques
        RUN_023: Durée limitée permissions élevées
    """

    @abstractmethod
    def check(self, claims: TokenClaims, action: str, resource: str) -> bool:
        """
        Vérifie permission pour action sur ressource.

        Args:
            claims: Claims JWT validés
            action: Action demandée (ex: "events:write")
            resource: Ressource cible (ex: "tenant-123")

        Returns:
            True si autorisé
        """
        pass

    @abstractmethod
    def requires_mfa(self, action: str) -> bool:
        """
        RUN_013: Vérifie si action requiert MFA.

        Returns:
            True si MFA obligatoire
        """
        pass

    @abstractmethod
    def requires_quorum(self, action: str) -> bool:
        """
        RUN_022: Vérifie si action requiert quorum.

        Returns:
            True si 2+ signatures requises
        """
        pass

    @abstractmethod
    def validate_level_permissions(self, level: int, permissions: List[str]) -> List[str]:
        """
        RUN_020: Valide permissions pour un niveau.

        Args:
            level: Niveau hiérarchique (0-3)
            permissions: Permissions demandées

        Returns:
            Liste des permissions INVALIDES pour ce niveau
        """
        pass

    @abstractmethod
    def has_wildcard(self, permissions: List[str]) -> bool:
        """
        RUN_021: Détecte présence wildcard.

        Returns:
            True si wildcard (*) présent
        """
        pass
