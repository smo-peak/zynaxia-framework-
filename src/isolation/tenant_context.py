"""
ZYNAXIA Framework - Tenant Context Implementation
Injection sécurisée du contexte tenant en session PostgreSQL.
"""

import uuid

from .interfaces import ITenantContext, Connection


class TenantContextError(Exception):
    """Erreur de contexte tenant."""

    pass


class TenantContext(ITenantContext):
    """Implémentation sécurisée de l'injection de contexte tenant."""

    def set_context(self, connection: Connection, tenant_id: str, level: int) -> None:
        """
        Injecte contexte tenant avec validation stricte.

        Args:
            connection: Connexion à la base de données
            tenant_id: Identifiant unique du tenant (UUID)
            level: Niveau hiérarchique du tenant (entier positif)

        Raises:
            TenantContextError: Si tenant_id ou level invalide

        Invariant: RUN_004 - Contexte tenant obligatoire
        """
        # 1. Validation UUID strict (défense injection SQL)
        self._validate_uuid(tenant_id)
        # 2. Validation level positif
        self._validate_level(level)
        # 3. Injection sécurisée des variables session
        connection.execute(f"SET app.tenant_id = '{tenant_id}'")
        connection.execute(f"SET app.tenant_level = {level}")

    def clear_context(self, connection: Connection) -> None:
        """
        Nettoie contexte tenant.

        Args:
            connection: Connexion à la base de données

        Invariant: RUN_004 - Contexte tenant obligatoire
        """
        connection.execute("RESET app.tenant_id")
        connection.execute("RESET app.tenant_level")

    def _validate_uuid(self, tenant_id: str) -> None:
        """
        Validation UUID stricte contre injection SQL.

        Args:
            tenant_id: Identifiant à valider

        Raises:
            TenantContextError: Si format UUID invalide
        """
        try:
            uuid.UUID(tenant_id)  # Lève ValueError si format invalide
        except (ValueError, TypeError):
            raise TenantContextError(f"tenant_id invalide: {tenant_id}")

    def _validate_level(self, level: int) -> None:
        """
        Validation level positif.

        Args:
            level: Niveau hiérarchique à valider

        Raises:
            TenantContextError: Si level invalide
        """
        if not isinstance(level, int) or level < 0:
            raise TenantContextError(f"level invalide: {level}")
