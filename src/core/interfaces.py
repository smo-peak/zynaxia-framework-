"""
ZYNAXIA Framework - LOT 1 Core Interfaces
Contrats à implémenter pour le module Core.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel


# ══════════════════════════════════════════════════════════════════════════════
# TYPES
# ══════════════════════════════════════════════════════════════════════════════


class ValidationSeverity(Enum):
    BLOCKING = "blocking"
    WARNING = "warning"
    INFO = "info"


class ValidationError(BaseModel):
    """Erreur de validation d'un invariant."""

    rule_id: str
    message: str
    location: str
    value: Optional[str] = None
    severity: ValidationSeverity = ValidationSeverity.BLOCKING


class ValidationResult(BaseModel):
    """Résultat de validation d'une configuration."""

    valid: bool
    errors: list[ValidationError] = []
    warnings: list[ValidationError] = []
    checked_at: datetime


# ══════════════════════════════════════════════════════════════════════════════
# INTERFACES
# ══════════════════════════════════════════════════════════════════════════════


class IConfigLoader(ABC):
    """Charge configuration depuis Vault et vérifie intégrité."""

    @abstractmethod
    async def load(self, tenant_id: str) -> dict[str, Any]:
        """
        Charge la config d'un tenant.

        Raises:
            ConfigIntegrityError: Si hash invalide
            ConfigSignatureError: Si signatures invalides
        """
        pass

    @abstractmethod
    async def verify_blockchain_anchor(self, tenant_id: str, config_hash: str) -> bool:
        """Vérifie que la config est ancrée blockchain."""
        pass


class IConfigValidator(ABC):
    """Valide configuration contre les invariants de sécurité."""

    @abstractmethod
    def validate(self, config: dict[str, Any]) -> ValidationResult:
        """
        Valide une config contre TOUS les invariants.
        Retourne TOUTES les erreurs (pas fail-fast).
        """
        pass

    @abstractmethod
    def validate_rule(self, rule_id: str, config: dict[str, Any]) -> Optional[ValidationError]:
        """Valide UNE règle spécifique."""
        pass


class ICryptoProvider(ABC):
    """Opérations cryptographiques conformes RGS 3 étoiles."""

    @abstractmethod
    def sign(self, data: bytes, key_id: str) -> bytes:
        """
        Signe des données avec ECDSA-P384.

        Args:
            data: Données à signer
            key_id: ID de la clé dans Vault

        Returns:
            Signature DER-encoded
        """
        pass

    @abstractmethod
    def verify_signature(self, data: bytes, signature: bytes, key_id: str) -> bool:
        """Vérifie une signature ECDSA-P384."""
        pass

    @abstractmethod
    def hash(self, data: bytes) -> str:
        """
        Calcule hash SHA-384.

        Returns:
            Hash hex string (96 caractères)
        """
        pass


class ISchemaValidator(ABC):
    """Validation JSON Schema."""

    @abstractmethod
    def validate_schema(self, data: dict[str, Any], schema_name: str) -> ValidationResult:
        """Valide des données contre un JSON Schema."""
        pass

    @abstractmethod
    def get_schema(self, schema_name: str) -> dict[str, Any]:
        """Récupère un schema par son nom."""
        pass
