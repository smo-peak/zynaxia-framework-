"""
LOT 7: Interfaces Deployment

Interfaces pour le déploiement sécurisé.

Invariants:
    DEPL_001: Images Docker signées obligatoirement
    DEPL_002: Vérification signature avant exécution
    DEPL_003: Registry privé uniquement
    DEPL_004: Scan CVE avant déploiement
    DEPL_005: Blocage si CVE critique (CVSS >= 9.0)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class CVESeverity(Enum):
    """Niveau de sévérité CVE selon CVSS."""

    NONE = "none"  # CVSS 0.0
    LOW = "low"  # CVSS 0.1-3.9
    MEDIUM = "medium"  # CVSS 4.0-6.9
    HIGH = "high"  # CVSS 7.0-8.9
    CRITICAL = "critical"  # CVSS 9.0-10.0


class VerificationStatus(Enum):
    """Statut de vérification d'image."""

    PENDING = "pending"
    VERIFIED = "verified"
    SIGNATURE_INVALID = "signature_invalid"
    SIGNATURE_MISSING = "signature_missing"
    CVE_BLOCKED = "cve_blocked"
    REGISTRY_DENIED = "registry_denied"
    ERROR = "error"


@dataclass
class ImageSignature:
    """Signature d'une image Docker.

    DEPL_001: Représente la signature Cosign d'une image.
    """

    image_ref: str  # Ex: registry.example.com/app:v1.0.0
    digest: str  # SHA256 du manifest
    signature: str  # Signature Cosign base64
    signed_at: datetime
    signer_identity: str  # Identité du signataire (email, OIDC subject)
    issuer: Optional[str] = None  # OIDC issuer pour keyless
    certificate: Optional[str] = None  # Certificat x509 si keyless
    annotations: Dict[str, str] = field(default_factory=dict)

    def is_keyless(self) -> bool:
        """Vérifie si la signature est keyless (Fulcio/Rekor)."""
        return self.issuer is not None and self.certificate is not None


@dataclass
class CVEResult:
    """Résultat d'un scan CVE pour une vulnérabilité.

    DEPL_004: Représente une CVE détectée.
    """

    cve_id: str  # Ex: CVE-2021-44228
    severity: CVESeverity
    cvss_score: float  # 0.0-10.0
    package_name: str
    installed_version: str
    fixed_version: Optional[str]  # None si pas de fix
    title: str
    description: str
    published_at: Optional[datetime] = None
    references: List[str] = field(default_factory=list)

    def is_critical(self) -> bool:
        """DEPL_005: Vérifie si CVE critique (CVSS >= 9.0)."""
        return self.cvss_score >= 9.0

    def is_fixable(self) -> bool:
        """Vérifie si une version corrigée existe."""
        return self.fixed_version is not None


@dataclass
class ImageVerificationResult:
    """Résultat complet de vérification d'image.

    Combine signature + scan CVE.
    """

    image_ref: str
    digest: str
    status: VerificationStatus
    verified_at: datetime
    signature: Optional[ImageSignature] = None
    cve_results: List[CVEResult] = field(default_factory=list)
    registry_allowed: bool = True
    error_message: Optional[str] = None
    verification_duration_ms: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_critical_cves(self) -> List[CVEResult]:
        """DEPL_005: Retourne les CVE critiques."""
        return [cve for cve in self.cve_results if cve.is_critical()]

    def get_cve_count_by_severity(self) -> Dict[CVESeverity, int]:
        """Compte les CVE par sévérité."""
        counts: Dict[CVESeverity, int] = {s: 0 for s in CVESeverity}
        for cve in self.cve_results:
            counts[cve.severity] += 1
        return counts

    def is_deployable(self) -> bool:
        """Vérifie si l'image peut être déployée."""
        return self.status == VerificationStatus.VERIFIED


class IImageVerifier(ABC):
    """Interface pour la vérification d'images Docker.

    Invariants:
        DEPL_001: Images signées obligatoirement
        DEPL_002: Vérification avant exécution
        DEPL_003: Registry privé uniquement
        DEPL_004: Scan CVE obligatoire
        DEPL_005: Blocage si CVSS >= 9.0
    """

    @abstractmethod
    async def verify_image(self, image_ref: str) -> ImageVerificationResult:
        """Vérifie une image Docker complètement.

        DEPL_001-005: Vérifie signature + registry + CVE.

        Args:
            image_ref: Référence de l'image (ex: registry/app:tag).

        Returns:
            Résultat complet de vérification.
        """
        pass

    @abstractmethod
    async def verify_signature(self, image_ref: str) -> Optional[ImageSignature]:
        """Vérifie la signature Cosign d'une image.

        DEPL_001: Vérifie que l'image est signée.
        DEPL_002: Valide la signature cryptographiquement.

        Args:
            image_ref: Référence de l'image.

        Returns:
            Signature si valide, None sinon.
        """
        pass

    @abstractmethod
    async def scan_cve(self, image_ref: str) -> List[CVEResult]:
        """Scanne une image pour les CVE.

        DEPL_004: Scan obligatoire avant déploiement.

        Args:
            image_ref: Référence de l'image.

        Returns:
            Liste des CVE détectées.
        """
        pass

    @abstractmethod
    def is_registry_allowed(self, image_ref: str) -> bool:
        """Vérifie si le registry est autorisé.

        DEPL_003: Seuls les registries privés sont autorisés.

        Args:
            image_ref: Référence de l'image.

        Returns:
            True si registry autorisé.
        """
        pass

    @abstractmethod
    def add_allowed_registry(self, registry: str) -> None:
        """Ajoute un registry à la liste blanche.

        Args:
            registry: Hostname du registry (ex: registry.example.com).
        """
        pass

    @abstractmethod
    def remove_allowed_registry(self, registry: str) -> bool:
        """Retire un registry de la liste blanche.

        Args:
            registry: Hostname du registry.

        Returns:
            True si retiré, False si non trouvé.
        """
        pass

    @abstractmethod
    def get_allowed_registries(self) -> List[str]:
        """Retourne la liste des registries autorisés.

        Returns:
            Liste des hostnames autorisés.
        """
        pass

    @abstractmethod
    def set_critical_cvss_threshold(self, threshold: float) -> None:
        """Définit le seuil CVSS critique.

        DEPL_005: Par défaut 9.0.

        Args:
            threshold: Seuil CVSS (0.0-10.0).
        """
        pass

    @abstractmethod
    def get_verification_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques de vérification.

        Returns:
            Statistiques (images vérifiées, bloquées, etc.).
        """
        pass


class IDeploymentOrchestrator(ABC):
    """Interface pour l'orchestration de déploiement.

    Gère le cycle de vie complet d'un déploiement.
    """

    @abstractmethod
    async def deploy_image(
        self,
        image_ref: str,
        config: Dict[str, Any],
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """Déploie une image vérifiée.

        Args:
            image_ref: Référence de l'image.
            config: Configuration de déploiement.
            dry_run: Si True, simule seulement.

        Returns:
            Résultat du déploiement.
        """
        pass

    @abstractmethod
    async def rollback(self, deployment_id: str) -> bool:
        """Annule un déploiement.

        Args:
            deployment_id: ID du déploiement.

        Returns:
            True si rollback réussi.
        """
        pass

    @abstractmethod
    def get_deployment_status(self, deployment_id: str) -> Dict[str, Any]:
        """Retourne le status d'un déploiement.

        Args:
            deployment_id: ID du déploiement.

        Returns:
            Status détaillé.
        """
        pass


class IConfigDeployer(ABC):
    """Interface pour le déploiement de configuration.

    Gère le déploiement de fichiers de configuration.
    """

    @abstractmethod
    async def deploy_config(
        self,
        config_data: Dict[str, Any],
        target_path: str,
        validate: bool = True,
    ) -> bool:
        """Déploie une configuration.

        Args:
            config_data: Données de configuration.
            target_path: Chemin cible.
            validate: Si True, valide avant déploiement.

        Returns:
            True si déployé avec succès.
        """
        pass

    @abstractmethod
    async def validate_config(self, config_data: Dict[str, Any]) -> List[str]:
        """Valide une configuration.

        Args:
            config_data: Données à valider.

        Returns:
            Liste d'erreurs (vide si valide).
        """
        pass

    @abstractmethod
    def backup_config(self, target_path: str) -> Optional[str]:
        """Sauvegarde une configuration existante.

        Args:
            target_path: Chemin de la config.

        Returns:
            Chemin du backup, None si échec.
        """
        pass

    @abstractmethod
    def restore_config(self, backup_path: str, target_path: str) -> bool:
        """Restaure une configuration depuis backup.

        Args:
            backup_path: Chemin du backup.
            target_path: Chemin cible.

        Returns:
            True si restauré.
        """
        pass
