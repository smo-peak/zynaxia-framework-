"""
LOT 5: Interfaces Licensing & Module Control

Définit les contrats pour le système de licensing avec signature cryptographique,
ancrage blockchain et contrôle des modules.

Invariants:
    LIC_001: Licence signée ECDSA-P384
    LIC_002: Contenu obligatoire site_id org_id dates modules
    LIC_003: Durée maximale 366 jours
    LIC_004: Émission ancrée blockchain
    LIC_005: Une licence = un site
    LIC_006: Émission par License Manager Cloud uniquement
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum


class LicenseStatus(Enum):
    """Status d'une licence."""

    VALID = "valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    INVALID_SIGNATURE = "invalid_signature"
    CORRUPTED = "corrupted"


class GracePeriodStatus(Enum):
    """Status de la grace period."""

    ACTIVE = "active"
    EXPIRED = "expired"
    NONE = "none"


@dataclass(frozen=True)
class LicenseConfig:
    """
    Configuration pour émission de licence.

    Conformité:
        LIC_002: Contenu obligatoire
        LIC_003: Durée max 366 jours
        LIC_005: Une licence = un site
    """

    site_id: str
    modules: List[str]
    duration_days: int  # LIC_003: max 366 jours
    issuer_id: str
    organization_id: Optional[str] = None


@dataclass(frozen=True)
class License:
    """
    Licence Edge site avec signature cryptographique.

    Conformité:
        LIC_001: Signature ECDSA-P384
        LIC_002: Champs obligatoires
        LIC_004: Ancrage blockchain
        LIC_005: site_id unique
    """

    license_id: str  # UUID unique
    site_id: str
    issued_at: datetime
    expires_at: datetime
    modules: List[str]
    signature: str  # LIC_001: ECDSA-P384 base64
    issuer_id: str
    organization_id: Optional[str] = None
    blockchain_tx_id: Optional[str] = None  # LIC_004: ancrage blockchain
    revoked: bool = False
    revoked_at: Optional[datetime] = None
    revoked_reason: Optional[str] = None


@dataclass
class ValidationResult:
    """
    Résultat de validation d'une licence.

    Conformité:
        LIC_040-044: Mode dégradé et grace period
    """

    valid: bool
    status: LicenseStatus
    reason: Optional[str] = None
    expires_in_days: int = 0
    is_degraded: bool = False  # LIC_040: mode dégradé si expirée
    grace_period_status: GracePeriodStatus = GracePeriodStatus.NONE
    blockchain_verified: bool = False


@dataclass(frozen=True)
class Signature:
    """
    Signature quorum pour révocation.

    Conformité:
        LIC_061: Révocation requiert quorum
    """

    signer_id: str
    signature: str  # ECDSA-P384 base64
    timestamp: datetime
    action: str  # Type d'action signée


class ILicenseManager(ABC):
    """
    Interface gestionnaire principal de licences.

    Responsabilités:
        - Émission licences (LIC_006: Cloud uniquement)
        - Validation signatures (LIC_001, LIC_010)
        - Renouvellement (LIC_050-055)
        - Révocation avec quorum (LIC_060-066)
        - Ancrage blockchain critique (LIC_004, LIC_091)
    """

    @abstractmethod
    async def issue(self, config: LicenseConfig) -> License:
        """
        Émet nouvelle licence signée (LIC_006: Cloud uniquement).

        Args:
            config: Configuration licence

        Returns:
            Licence signée et ancrée blockchain

        Raises:
            LicenseManagerError: Erreur émission

        Conformité:
            LIC_001: Signature ECDSA-P384
            LIC_002: Contenu obligatoire
            LIC_003: Durée max 366 jours
            LIC_004: Ancrage blockchain
            LIC_005: site_id unique
            LIC_006: Émission Cloud uniquement
        """
        pass

    @abstractmethod
    async def validate(self, license: License) -> ValidationResult:
        """
        Valide licence complètement (LIC_010-015).

        Args:
            license: Licence à valider

        Returns:
            Résultat validation détaillé

        Conformité:
            LIC_010: Validation signature
            LIC_011: Vérification périodique
            LIC_014: Vérification online
            LIC_015: Réponse signée
        """
        pass

    @abstractmethod
    async def renew(self, site_id: str, duration_days: int) -> License:
        """
        Renouvelle licence = nouvelle licence (LIC_050).

        Args:
            site_id: Site à renouveler
            duration_days: Nouvelle durée

        Returns:
            Nouvelle licence

        Raises:
            LicenseManagerError: Erreur renouvellement

        Conformité:
            LIC_050-055: Renouvellement = nouvelle licence
        """
        pass

    @abstractmethod
    async def revoke(self, site_id: str, reason: str, signatures: List[Signature]) -> None:
        """
        Révoque licence avec quorum (LIC_060-066).

        Args:
            site_id: Site à révoquer
            reason: Motif obligatoire (LIC_066)
            signatures: Signatures quorum (LIC_061)

        Raises:
            LicenseManagerError: Quorum insuffisant ou erreur

        Conformité:
            LIC_060-066: Révocation avec quorum et ancrage
        """
        pass

    @abstractmethod
    async def get_license(self, site_id: str) -> Optional[License]:
        """
        Récupère licence active pour site.

        Args:
            site_id: Identifiant site

        Returns:
            Licence si trouvée
        """
        pass

    @abstractmethod
    async def verify_blockchain_anchor(self, license: License) -> bool:
        """
        Vérifie ancrage blockchain (LIC_004).

        Args:
            license: Licence à vérifier

        Returns:
            True si ancrage vérifié
        """
        pass


class ILicenseCache(ABC):
    """
    Interface cache local licences.

    Responsabilités:
        - Cache local obligatoire (LIC_020)
        - TTL max 7 jours (LIC_021)
        - Chiffrement Vault (LIC_022)
        - Vérification hash (LIC_023)
        - Kill switch offline >7j (LIC_024)
    """

    @abstractmethod
    def get(self, site_id: str) -> Optional[License]:
        """
        Récupère licence du cache (LIC_020).

        Args:
            site_id: Site recherché

        Returns:
            Licence cachée si trouvée et valide

        Conformité:
            LIC_023: Hash vérifié chaque lecture
        """
        pass

    @abstractmethod
    def set(self, site_id: str, license: License) -> None:
        """
        Stocke licence en cache chiffré (LIC_022).

        Args:
            site_id: Clé cache
            license: Licence à cacher

        Conformité:
            LIC_021: TTL max 7 jours
            LIC_022: Chiffrement Vault
        """
        pass

    @abstractmethod
    def invalidate(self, site_id: str) -> None:
        """
        Invalide entrée cache.

        Args:
            site_id: Site à invalider
        """
        pass

    @abstractmethod
    def is_valid(self, site_id: str) -> bool:
        """
        Vérifie validité entrée cache.

        Args:
            site_id: Site à vérifier

        Returns:
            True si cache valide et dans TTL

        Conformité:
            LIC_021: TTL max 7 jours
            LIC_024: Offline >7j = kill switch
        """
        pass

    @abstractmethod
    def cleanup_expired(self) -> int:
        """
        Nettoie entrées expirées.

        Returns:
            Nombre d'entrées nettoyées
        """
        pass


class IKillSwitchController(ABC):
    """
    Interface contrôleur kill switch.

    Responsabilités:
        - Arrêt contrôlé services (LIC_070-077)
        - Préservation données/logs (LIC_071-072)
        - Message explicite (LIC_074)
        - Réversible par nouvelle licence (LIC_075)
        - Ancrage blockchain (LIC_076)
    """

    @abstractmethod
    async def activate(self, site_id: str, reason: str) -> None:
        """
        Active kill switch immédiat (LIC_012, LIC_063).

        Args:
            site_id: Site affecté
            reason: Motif activation

        Conformité:
            LIC_070: Arrêt contrôlé tous services
            LIC_071-072: Préservation données et logs
            LIC_074: Message explicite dashboard
            LIC_076: Ancrage blockchain
        """
        pass

    @abstractmethod
    async def deactivate(self, site_id: str, new_license: License) -> None:
        """
        Désactive kill switch avec nouvelle licence (LIC_075).

        Args:
            site_id: Site à réactiver
            new_license: Nouvelle licence valide

        Conformité:
            LIC_075: Réversible par nouvelle licence
            LIC_055: Réactivation après healthcheck
        """
        pass

    @abstractmethod
    def is_active(self, site_id: str) -> bool:
        """
        Vérifie si kill switch actif.

        Args:
            site_id: Site à vérifier

        Returns:
            True si kill switch actif
        """
        pass

    @abstractmethod
    async def get_status(self, site_id: str) -> Dict[str, Any]:
        """
        Récupère statut détaillé kill switch.

        Args:
            site_id: Site concerné

        Returns:
            Status avec raison, timestamp, etc.
        """
        pass


class IModuleGate(ABC):
    """
    Interface contrôle d'accès modules.

    Responsabilités:
        - Modules en liste blanche (LIC_080)
        - Blocage module non licencié (LIC_081)
        - Audit tentatives accès (LIC_083)
        - Upgrade/downgrade = nouvelle licence (LIC_084-085)
    """

    @abstractmethod
    def is_module_licensed(self, site_id: str, module_id: str) -> bool:
        """
        Vérifie licence module (LIC_080-081).

        Args:
            site_id: Site demandeur
            module_id: Module vérifié

        Returns:
            True si module licencié

        Conformité:
            LIC_080: Modules en liste blanche
            LIC_081: Non licencié = 403
            LIC_083: Tentative accès = audit
        """
        pass

    @abstractmethod
    def get_licensed_modules(self, site_id: str) -> List[str]:
        """
        Récupère modules licenciés pour site.

        Args:
            site_id: Site concerné

        Returns:
            Liste modules licenciés
        """
        pass

    @abstractmethod
    def check_module_access(self, site_id: str, module_id: str, user_id: str) -> bool:
        """
        Contrôle accès module avec audit (LIC_083).

        Args:
            site_id: Site demandeur
            module_id: Module accédé
            user_id: Utilisateur demandeur

        Returns:
            True si accès autorisé

        Conformité:
            LIC_081: Module non licencié = 403
            LIC_083: Tentative accès = audit
        """
        pass

    @abstractmethod
    async def update_module_list(self, site_id: str, modules: List[str]) -> None:
        """
        Met à jour liste modules (nouvelle licence).

        Args:
            site_id: Site concerné
            modules: Nouveaux modules licenciés

        Conformité:
            LIC_084-085: Upgrade/downgrade = nouvelle licence
        """
        pass


class ILicenseValidator(ABC):
    """
    Interface validation technique licence.

    Responsabilités:
        - Validation signature (LIC_001, LIC_010)
        - Vérification format (LIC_002)
        - Contrôle durée (LIC_003)
        - Detection altération (LIC_013)
    """

    @abstractmethod
    def validate_signature(self, license: License) -> bool:
        """
        Valide signature ECDSA-P384 (LIC_001, LIC_010).

        Args:
            license: Licence à valider

        Returns:
            True si signature valide
        """
        pass

    @abstractmethod
    def validate_structure(self, license: License) -> bool:
        """
        Valide structure licence (LIC_002).

        Args:
            license: Licence à valider

        Returns:
            True si structure conforme
        """
        pass

    @abstractmethod
    def validate_duration(self, license: License) -> bool:
        """
        Valide durée maximale (LIC_003).

        Args:
            license: Licence à valider

        Returns:
            True si durée conforme (≤ 366 jours)
        """
        pass

    @abstractmethod
    def detect_tampering(self, license: License) -> bool:
        """
        Détecte altération licence (LIC_013).

        Args:
            license: Licence à analyser

        Returns:
            True si licence intègre
        """
        pass
