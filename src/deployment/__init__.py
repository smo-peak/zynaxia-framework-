"""
LOT 7: Déploiement et Distribution

Module de déploiement sécurisé avec:
- Vérification d'images Docker signées (DEPL_001-002)
- Gestion du registry privé (DEPL_003)
- Scan CVE obligatoire (DEPL_004-005)
- Orchestration zero-downtime (DEPL_010-014)

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

__all__ = [
    # Enums
    "CVESeverity",
    "VerificationStatus",
    "DeploymentState",
    "NodeRole",
    # Data classes
    "ImageSignature",
    "CVEResult",
    "ImageVerificationResult",
    "DeploymentConfig",
    "DeploymentResult",
    # Interfaces
    "IImageVerifier",
    "IDeploymentOrchestrator",
    "IConfigDeployer",
    # Implementations
    "ImageVerifier",
    "DeploymentOrchestrator",
    # Exceptions
    "ImageVerifierError",
    "DeploymentError",
    "RollbackError",
]
