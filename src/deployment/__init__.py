"""
LOT 7: Déploiement et Distribution

Module de déploiement sécurisé avec:
- Vérification d'images Docker signées (DEPL_001-002)
- Gestion du registry privé (DEPL_003)
- Scan CVE obligatoire (DEPL_004-005)
- Orchestration zero-downtime (DEPL_010-014)
- Déploiement de configuration sécurisé (DEPL_020-024)
- Contraintes de déploiement (DEPL_030-033)

Invariants couverts:
- DEPL_001: Images Docker signées obligatoirement
- DEPL_002: Vérification signature avant exécution
- DEPL_003: Registry privé uniquement (pas DockerHub public)
- DEPL_004: Scan CVE avant déploiement
- DEPL_005: Blocage si CVE critique (CVSS >= 9.0)
- DEPL_010: Standby-first obligatoire (jamais sur PRIMARY)
- DEPL_011: Healthcheck validé sur STANDBY avant bascule
- DEPL_012: Rollback automatique < 60 secondes
- DEPL_013: Zero-downtime obligatoire
- DEPL_014: Déploiement progressif (1 nœud → validation → autres)
- DEPL_020: Config validée par ConfigValidator AVANT déploiement
- DEPL_021: Config signée (quorum atteint) AVANT déploiement
- DEPL_022: Config ancrée blockchain AVANT déploiement
- DEPL_023: Hash config vérifié sur chaque nœud après réception
- DEPL_024: Ancienne config archivée (JAMAIS supprimée)
- DEPL_030: Déploiement OTA respecte fenêtre maintenance (WARNING)
- DEPL_031: Déploiement BLOQUÉ si licence invalide
- DEPL_032: Déploiement BLOQUÉ si cluster non-healthy
- DEPL_033: Notification Fleet Manager AVANT et APRÈS déploiement
"""

from .interfaces import (
    # Enums
    CVESeverity,
    VerificationStatus,
    # Data classes
    ImageSignature,
    CVEResult,
    ImageVerificationResult,
    # Interfaces
    IImageVerifier,
    IDeploymentOrchestrator,
    IConfigDeployer,
)
from .image_verifier import ImageVerifier, ImageVerifierError
from .deployment_orchestrator import (
    DeploymentOrchestrator,
    DeploymentError,
    RollbackError,
    DeploymentConfig,
    DeploymentResult,
    DeploymentState,
    NodeRole,
)
from .config_deployer import (
    ConfigDeployer,
    ConfigDeployerError,
    ConfigNotValidError,
    QuorumNotReachedError,
    BlockchainAnchorError,
    ConfigHashMismatchError,
    ConfigVersion,
)
from .deployment_constraints import (
    DeploymentConstraints,
    DeploymentConstraintsError,
    LicenseInvalidError,
    ClusterUnhealthyError,
    FleetNotificationError,
    MaintenanceWindow,
    DeploymentPrecheck,
    IFleetNotifier,
    DeploymentEventType,
)

__all__ = [
    # Enums
    "CVESeverity",
    "VerificationStatus",
    "DeploymentState",
    "NodeRole",
    "DeploymentEventType",
    # Data classes
    "ImageSignature",
    "CVEResult",
    "ImageVerificationResult",
    "DeploymentConfig",
    "DeploymentResult",
    "ConfigVersion",
    "MaintenanceWindow",
    "DeploymentPrecheck",
    # Interfaces
    "IImageVerifier",
    "IDeploymentOrchestrator",
    "IConfigDeployer",
    "IFleetNotifier",
    # Implementations
    "ImageVerifier",
    "DeploymentOrchestrator",
    "ConfigDeployer",
    "DeploymentConstraints",
    # Exceptions
    "ImageVerifierError",
    "DeploymentError",
    "RollbackError",
    "ConfigDeployerError",
    "ConfigNotValidError",
    "QuorumNotReachedError",
    "BlockchainAnchorError",
    "ConfigHashMismatchError",
    "DeploymentConstraintsError",
    "LicenseInvalidError",
    "ClusterUnhealthyError",
    "FleetNotificationError",
]
