"""
LOT 3: Permission Checker Implementation

Vérification des permissions avec respect des invariants de sécurité.

Invariants:
    RUN_013: MFA obligatoire pour permissions élevées
    RUN_020: Niveau N ne peut avoir permissions niveau N-1
    RUN_021: Wildcard (*) interdit sauf Platform (level 0)
    RUN_022: Actions critiques requièrent quorum (2+ signatures)
    RUN_023: Permissions élevées durée limitée
"""

from datetime import datetime, timezone, timedelta
from typing import List, Dict, Set
import re

from .interfaces import IPermissionChecker, TokenClaims


class PermissionCheckerError(Exception):
    """Erreur de vérification de permissions."""

    pass


class PermissionChecker(IPermissionChecker):
    """
    Vérificateur de permissions avec conformité aux invariants de sécurité.

    Conformité:
        RUN_013: MFA obligatoire pour permissions élevées
        RUN_020: Isolation hiérarchique stricte
        RUN_021: Wildcard Platform uniquement
        RUN_022: Quorum pour actions critiques
        RUN_023: TTL permissions élevées

    Example:
        checker = PermissionChecker()
        allowed = checker.check(claims, "events:write", "tenant-123")
    """

    # Configuration des permissions élevées (RUN_013)
    ELEVATED_PERMISSIONS: Set[str] = {
        "admin:*",
        "platform:*",
        "users:create",
        "users:delete",
        "system:config",
        "audit:access",
        "security:*",
    }

    # Actions critiques nécessitant un quorum (RUN_022)
    CRITICAL_ACTIONS: Set[str] = {
        "platform:shutdown",
        "platform:config:change",
        "users:delete",
        "audit:purge",
        "security:key:rotate",
        "tenant:delete",
        "system:backup:restore",
    }

    # Hiérarchie des niveaux (RUN_020)
    LEVEL_HIERARCHY: Dict[int, Dict[str, str]] = {
        0: {"name": "platform", "prefix": "platform"},
        1: {"name": "integrator", "prefix": "integrator"},
        2: {"name": "organization", "prefix": "organization"},
        3: {"name": "site", "prefix": "site"},
    }

    # TTL max pour permissions élevées en secondes (RUN_023)
    MAX_ELEVATED_PERMISSION_TTL: int = 3600  # 1 heure

    def __init__(self):
        """Initialise le vérificateur de permissions."""
        pass

    def check(self, claims: TokenClaims, action: str, resource: str) -> bool:
        """
        Vérifie permission pour action sur ressource.

        Args:
            claims: Claims JWT validés
            action: Action demandée (ex: "events:write")
            resource: Ressource cible (ex: "tenant-123")

        Returns:
            True si autorisé

        Raises:
            PermissionCheckerError: Erreur de vérification
        """
        if not claims or not action:
            return False

        # RUN_013: Vérifier MFA pour permissions élevées
        if self._is_elevated_permission(action) and not claims.mfa_verified:
            return False

        # RUN_023: Vérifier TTL pour permissions élevées
        if self._is_elevated_permission(action):
            if not self._check_elevated_permission_ttl(claims):
                return False

        # RUN_020: Valider permissions par rapport au niveau hiérarchique
        invalid_permissions = self.validate_level_permissions(claims.level, claims.permissions)
        if invalid_permissions:
            return False

        # RUN_021: Vérifier wildcard autorisé uniquement pour Platform
        if self.has_wildcard(claims.permissions) and claims.level != 0:
            return False

        # Vérifier si l'utilisateur a la permission spécifique ou wildcard
        return self._has_permission(claims.permissions, action, claims.level)

    def requires_mfa(self, action: str) -> bool:
        """
        RUN_013: Vérifie si action requiert MFA.

        Args:
            action: Action à vérifier

        Returns:
            True si MFA obligatoire
        """
        return self._is_elevated_permission(action)

    def requires_quorum(self, action: str) -> bool:
        """
        RUN_022: Vérifie si action requiert quorum.

        Args:
            action: Action à vérifier

        Returns:
            True si 2+ signatures requises
        """
        # Vérification exacte
        if action in self.CRITICAL_ACTIONS:
            return True

        # Vérification par pattern pour actions avec wildcards
        for critical_action in self.CRITICAL_ACTIONS:
            if self._matches_permission_pattern(critical_action, action):
                return True

        return False

    def validate_level_permissions(self, level: int, permissions: List[str]) -> List[str]:
        """
        RUN_020: Valide permissions pour un niveau.

        Args:
            level: Niveau hiérarchique (0-3)
            permissions: Permissions demandées

        Returns:
            Liste des permissions INVALIDES pour ce niveau
        """
        if level < 0 or level > 3:
            return permissions  # Toutes invalides si niveau incorrect

        invalid_permissions = []

        for permission in permissions:
            # Platform (level 0) peut tout faire
            if level == 0:
                continue

            # Vérifier que le niveau n'a pas de permissions de niveaux supérieurs
            for higher_level in range(level):
                higher_level_info = self.LEVEL_HIERARCHY.get(higher_level)
                if higher_level_info:
                    higher_prefix = higher_level_info["prefix"]
                    # Permission commence par préfixe de niveau supérieur = INVALIDE
                    if permission.startswith(f"{higher_prefix}:"):
                        invalid_permissions.append(permission)
                        break

        return invalid_permissions

    def has_wildcard(self, permissions: List[str]) -> bool:
        """
        RUN_021: Détecte présence wildcard.

        Args:
            permissions: Liste des permissions

        Returns:
            True si wildcard (*) présent
        """
        return any("*" in permission for permission in permissions)

    def _is_elevated_permission(self, action: str) -> bool:
        """
        Vérifie si une action est considérée comme permission élevée.

        Args:
            action: Action à vérifier

        Returns:
            True si permission élevée
        """
        # Vérification exacte
        if action in self.ELEVATED_PERMISSIONS:
            return True

        # Vérification par pattern
        for elevated_perm in self.ELEVATED_PERMISSIONS:
            if self._matches_permission_pattern(elevated_perm, action):
                return True

        return False

    def _check_elevated_permission_ttl(self, claims: TokenClaims) -> bool:
        """
        RUN_023: Vérifie TTL des permissions élevées.

        Args:
            claims: Claims JWT

        Returns:
            True si dans les limites de TTL
        """
        now = datetime.now(timezone.utc)
        token_age = (now - claims.iat).total_seconds()

        return token_age <= self.MAX_ELEVATED_PERMISSION_TTL

    def _has_permission(self, permissions: List[str], required_action: str, level: int) -> bool:
        """
        Vérifie si l'utilisateur a la permission requise.

        Args:
            permissions: Permissions de l'utilisateur
            required_action: Action requise
            level: Niveau hiérarchique

        Returns:
            True si autorisé
        """
        for permission in permissions:
            # Permission exacte
            if permission == required_action:
                return True

            # Permission wildcard
            if "*" in permission:
                # RUN_021: Wildcard autorisé uniquement pour Platform (level 0)
                if level != 0:
                    continue

                if self._matches_permission_pattern(permission, required_action):
                    return True

        return False

    def _matches_permission_pattern(self, pattern: str, action: str) -> bool:
        """
        Vérifie si une action correspond à un pattern de permission.

        Args:
            pattern: Pattern de permission (peut contenir *)
            action: Action à vérifier

        Returns:
            True si correspondance
        """
        # Convertir pattern en regex
        # Échapper les caractères spéciaux sauf *
        escaped_pattern = re.escape(pattern)
        # Remplacer \* (échappé) par .* (regex wildcard)
        regex_pattern = escaped_pattern.replace(r"\*", ".*")
        # Ancrer au début et à la fin
        regex_pattern = f"^{regex_pattern}$"

        try:
            return bool(re.match(regex_pattern, action))
        except re.error:
            return False

    def get_allowed_actions_for_level(self, level: int) -> List[str]:
        """
        Retourne les actions autorisées pour un niveau donné.

        Args:
            level: Niveau hiérarchique (0-3)

        Returns:
            Liste des patterns d'actions autorisées
        """
        if level < 0 or level > 3:
            return []

        level_info = self.LEVEL_HIERARCHY.get(level)
        if not level_info:
            return []

        allowed_actions = []

        # Platform peut tout faire
        if level == 0:
            allowed_actions.extend(["platform:*", "integrator:*", "organization:*", "site:*", "admin:*", "system:*"])
        else:
            # Niveau actuel et inférieurs seulement
            for allowed_level in range(level, 4):
                level_info = self.LEVEL_HIERARCHY.get(allowed_level)
                if level_info:
                    allowed_actions.append(f"{level_info['prefix']}:*")

        return allowed_actions

    def check_quorum_requirement(self, action: str, signatures_count: int) -> bool:
        """
        RUN_022: Vérifie si le quorum est atteint pour une action critique.

        Args:
            action: Action à effectuer
            signatures_count: Nombre de signatures fournies

        Returns:
            True si quorum atteint ou action non critique
        """
        if not self.requires_quorum(action):
            return True  # Pas de quorum requis

        return signatures_count >= 2  # Minimum 2 signatures pour actions critiques
