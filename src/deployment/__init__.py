"""
LOT 7: Déploiement et Distribution

Module de déploiement sécurisé avec:
- Vérification d'images Docker signées (DEPL_001-002)
- Gestion du registry privé (DEPL_003)
- Scan CVE obligatoire (DEPL_004-005)

Invariants couverts:
- DEPL_001: Images Docker signées obligatoirement
- DEPL_002: Vérification signature avant exécution
- DEPL_003: Registry privé uniquement (pas DockerHub public)
- DEPL_004: Scan CVE avant déploiement
- DEPL_005: Blocage si CVE critique (CVSS >= 9.0)
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

__all__ = [
    # Enums
    "CVESeverity",
    "VerificationStatus",
    # Data classes
    "ImageSignature",
    "CVEResult",
    "ImageVerificationResult",
    # Interfaces
    "IImageVerifier",
    "IDeploymentOrchestrator",
    "IConfigDeployer",
    # Implementations
    "ImageVerifier",
    # Exceptions
    "ImageVerifierError",
]
