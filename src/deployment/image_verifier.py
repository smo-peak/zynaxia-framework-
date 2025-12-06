"""
LOT 7: Image Verifier Implementation

Vérificateur d'images Docker avec signature Cosign et scan CVE.

Invariants:
    DEPL_001: Images Docker signées obligatoirement
    DEPL_002: Vérification signature avant exécution
    DEPL_003: Registry privé uniquement (pas DockerHub public)
    DEPL_004: Scan CVE avant déploiement
    DEPL_005: Blocage si CVE critique (CVSS >= 9.0)
"""

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set

from src.audit.interfaces import AuditEventType, IAuditEmitter
from src.core.interfaces import ICryptoProvider
from src.deployment.interfaces import (
    CVEResult,
    CVESeverity,
    ImageSignature,
    ImageVerificationResult,
    IImageVerifier,
    VerificationStatus,
)


class ImageVerifierError(Exception):
    """Erreur lors de la vérification d'image."""

    pass


# Types pour les clients injectables (pour tests)
CosignClient = Callable[[str], Awaitable[Optional[Dict[str, Any]]]]
TrivyClient = Callable[[str], Awaitable[List[Dict[str, Any]]]]


# Registries publics bloqués par défaut (DEPL_003)
BLOCKED_REGISTRIES: Set[str] = {
    "docker.io",
    "registry.hub.docker.com",
    "index.docker.io",
    "gcr.io",
    "ghcr.io",
    "quay.io",
    "mcr.microsoft.com",
    "public.ecr.aws",
}


@dataclass
class VerificationStats:
    """Statistiques de vérification."""

    total_verified: int = 0
    total_passed: int = 0
    total_blocked_signature: int = 0
    total_blocked_cve: int = 0
    total_blocked_registry: int = 0
    total_errors: int = 0
    critical_cves_found: int = 0
    high_cves_found: int = 0


class ImageVerifier(IImageVerifier):
    """
    Vérificateur d'images Docker.

    Invariants:
        DEPL_001: Images signées obligatoirement
        DEPL_002: Vérification signature avant exécution
        DEPL_003: Registry privé uniquement
        DEPL_004: Scan CVE obligatoire
        DEPL_005: Blocage si CVSS >= 9.0
    """

    # DEPL_005: Seuil CVSS critique par défaut
    DEFAULT_CRITICAL_THRESHOLD: float = 9.0

    # Timeout pour les opérations externes
    VERIFICATION_TIMEOUT_SECONDS: float = 60.0

    def __init__(
        self,
        crypto_provider: ICryptoProvider,
        audit_emitter: IAuditEmitter,
        cosign_client: Optional[CosignClient] = None,
        trivy_client: Optional[TrivyClient] = None,
        allowed_registries: Optional[List[str]] = None,
    ) -> None:
        """
        Initialise le vérificateur d'images.

        Args:
            crypto_provider: Provider de cryptographie.
            audit_emitter: Émetteur d'événements d'audit.
            cosign_client: Client Cosign injectable (pour tests).
            trivy_client: Client Trivy injectable (pour tests).
            allowed_registries: Liste initiale de registries autorisés.
        """
        self._crypto = crypto_provider
        self._audit = audit_emitter
        self._cosign_client = cosign_client or self._default_cosign_client
        self._trivy_client = trivy_client or self._default_trivy_client
        self._allowed_registries: Set[str] = set(allowed_registries or [])
        self._critical_threshold: float = self.DEFAULT_CRITICAL_THRESHOLD
        self._stats = VerificationStats()
        self._verification_cache: Dict[str, ImageVerificationResult] = {}

    async def _default_cosign_client(self, image_ref: str) -> Optional[Dict[str, Any]]:
        """
        Client Cosign par défaut (simule absence de signature).

        En production, ce serait remplacé par un vrai appel à cosign verify.
        """
        return None

    async def _default_trivy_client(self, image_ref: str) -> List[Dict[str, Any]]:
        """
        Client Trivy par défaut (retourne liste vide).

        En production, ce serait remplacé par un vrai appel à trivy image.
        """
        return []

    def _parse_image_ref(self, image_ref: str) -> Dict[str, str]:
        """
        Parse une référence d'image Docker.

        Args:
            image_ref: Référence (ex: registry.example.com/namespace/image:tag).

        Returns:
            Dict avec registry, namespace, image, tag, digest.
        """
        result: Dict[str, str] = {
            "registry": "",
            "namespace": "",
            "image": "",
            "tag": "latest",
            "digest": "",
        }

        ref = image_ref

        # Extraire le digest si présent
        if "@sha256:" in ref:
            ref, digest = ref.split("@", 1)
            result["digest"] = digest

        # Extraire le tag si présent
        if ":" in ref and not ref.startswith("["):
            ref, tag = ref.rsplit(":", 1)
            if "/" not in tag:  # C'est bien un tag, pas un port
                result["tag"] = tag

        # Analyser le reste
        parts = ref.split("/")

        if len(parts) == 1:
            # Image seule: nginx -> docker.io/library/nginx
            result["registry"] = "docker.io"
            result["namespace"] = "library"
            result["image"] = parts[0]
        elif len(parts) == 2:
            # Vérifier si c'est registry/image ou namespace/image
            if "." in parts[0] or ":" in parts[0] or parts[0] == "localhost":
                result["registry"] = parts[0]
                result["image"] = parts[1]
            else:
                result["registry"] = "docker.io"
                result["namespace"] = parts[0]
                result["image"] = parts[1]
        else:
            # registry/namespace.../image
            result["registry"] = parts[0]
            result["namespace"] = "/".join(parts[1:-1])
            result["image"] = parts[-1]

        return result

    def is_registry_allowed(self, image_ref: str) -> bool:
        """
        DEPL_003: Vérifie si le registry est autorisé.

        Bloque les registries publics par défaut.

        Args:
            image_ref: Référence de l'image.

        Returns:
            True si registry autorisé.
        """
        parsed = self._parse_image_ref(image_ref)
        registry = parsed["registry"].lower()

        # Bloquer les registries publics connus
        if registry in BLOCKED_REGISTRIES:
            return False

        # Si aucun registry explicitement autorisé, tout est bloqué
        if not self._allowed_registries:
            return False

        # Vérifier si le registry est dans la liste blanche
        return registry in self._allowed_registries

    def add_allowed_registry(self, registry: str) -> None:
        """Ajoute un registry à la liste blanche."""
        self._allowed_registries.add(registry.lower())

    def remove_allowed_registry(self, registry: str) -> bool:
        """Retire un registry de la liste blanche."""
        registry_lower = registry.lower()
        if registry_lower in self._allowed_registries:
            self._allowed_registries.remove(registry_lower)
            return True
        return False

    def get_allowed_registries(self) -> List[str]:
        """Retourne la liste des registries autorisés."""
        return sorted(self._allowed_registries)

    def set_critical_cvss_threshold(self, threshold: float) -> None:
        """
        DEPL_005: Définit le seuil CVSS critique.

        Args:
            threshold: Seuil CVSS (0.0-10.0).

        Raises:
            ValueError: Si threshold hors limites.
        """
        if not 0.0 <= threshold <= 10.0:
            raise ValueError(f"CVSS threshold must be between 0.0 and 10.0, got {threshold}")
        self._critical_threshold = threshold

    async def verify_signature(self, image_ref: str) -> Optional[ImageSignature]:
        """
        DEPL_001-002: Vérifie la signature Cosign d'une image.

        Args:
            image_ref: Référence de l'image.

        Returns:
            Signature si valide, None sinon.
        """
        try:
            result = await asyncio.wait_for(
                self._cosign_client(image_ref),
                timeout=self.VERIFICATION_TIMEOUT_SECONDS,
            )

            if result is None:
                return None

            # Construire l'objet ImageSignature depuis la réponse
            return ImageSignature(
                image_ref=image_ref,
                digest=result.get("digest", ""),
                signature=result.get("signature", ""),
                signed_at=datetime.fromisoformat(result["signed_at"])
                if "signed_at" in result
                else datetime.now(),
                signer_identity=result.get("signer_identity", ""),
                issuer=result.get("issuer"),
                certificate=result.get("certificate"),
                annotations=result.get("annotations", {}),
            )

        except asyncio.TimeoutError:
            return None
        except Exception:
            return None

    def _parse_cve_severity(self, severity_str: str) -> CVESeverity:
        """Parse une sévérité CVE depuis une chaîne."""
        severity_map = {
            "none": CVESeverity.NONE,
            "low": CVESeverity.LOW,
            "medium": CVESeverity.MEDIUM,
            "high": CVESeverity.HIGH,
            "critical": CVESeverity.CRITICAL,
        }
        return severity_map.get(severity_str.lower(), CVESeverity.MEDIUM)

    async def scan_cve(self, image_ref: str) -> List[CVEResult]:
        """
        DEPL_004: Scanne une image pour les CVE.

        Args:
            image_ref: Référence de l'image.

        Returns:
            Liste des CVE détectées.
        """
        try:
            raw_results = await asyncio.wait_for(
                self._trivy_client(image_ref),
                timeout=self.VERIFICATION_TIMEOUT_SECONDS,
            )

            cve_results: List[CVEResult] = []
            for raw in raw_results:
                cve = CVEResult(
                    cve_id=raw.get("cve_id", ""),
                    severity=self._parse_cve_severity(raw.get("severity", "medium")),
                    cvss_score=float(raw.get("cvss_score", 0.0)),
                    package_name=raw.get("package_name", ""),
                    installed_version=raw.get("installed_version", ""),
                    fixed_version=raw.get("fixed_version"),
                    title=raw.get("title", ""),
                    description=raw.get("description", ""),
                    published_at=datetime.fromisoformat(raw["published_at"])
                    if "published_at" in raw
                    else None,
                    references=raw.get("references", []),
                )
                cve_results.append(cve)

                # Mettre à jour les stats
                if cve.severity == CVESeverity.CRITICAL:
                    self._stats.critical_cves_found += 1
                elif cve.severity == CVESeverity.HIGH:
                    self._stats.high_cves_found += 1

            return cve_results

        except asyncio.TimeoutError:
            raise ImageVerifierError(f"CVE scan timeout for {image_ref}")
        except Exception as e:
            raise ImageVerifierError(f"CVE scan failed: {str(e)}")

    async def verify_image(self, image_ref: str) -> ImageVerificationResult:
        """
        DEPL_001-005: Vérifie une image Docker complètement.

        Effectue dans l'ordre:
        1. Vérification du registry (DEPL_003)
        2. Vérification de la signature (DEPL_001-002)
        3. Scan CVE (DEPL_004)
        4. Blocage si CVE critique (DEPL_005)

        Args:
            image_ref: Référence de l'image.

        Returns:
            Résultat complet de vérification.
        """
        start_time = datetime.now()
        self._stats.total_verified += 1

        parsed = self._parse_image_ref(image_ref)
        digest = parsed.get("digest", "")

        # DEPL_003: Vérifier le registry
        if not self.is_registry_allowed(image_ref):
            self._stats.total_blocked_registry += 1

            await self._audit.emit_event(
                event_type=AuditEventType.SECURITY_BREACH,
                user_id="system",
                tenant_id="system",
                action="image_verification_blocked",
                metadata={
                    "image_ref": image_ref,
                    "reason": "registry_denied",
                    "registry": parsed["registry"],
                },
            )

            return ImageVerificationResult(
                image_ref=image_ref,
                digest=digest,
                status=VerificationStatus.REGISTRY_DENIED,
                verified_at=start_time,
                registry_allowed=False,
                error_message=f"Registry '{parsed['registry']}' is not allowed (DEPL_003)",
                verification_duration_ms=int(
                    (datetime.now() - start_time).total_seconds() * 1000
                ),
            )

        # DEPL_001-002: Vérifier la signature
        signature = await self.verify_signature(image_ref)
        if signature is None:
            self._stats.total_blocked_signature += 1

            await self._audit.emit_event(
                event_type=AuditEventType.SECURITY_BREACH,
                user_id="system",
                tenant_id="system",
                action="image_verification_blocked",
                metadata={
                    "image_ref": image_ref,
                    "reason": "signature_missing",
                },
            )

            return ImageVerificationResult(
                image_ref=image_ref,
                digest=digest,
                status=VerificationStatus.SIGNATURE_MISSING,
                verified_at=start_time,
                registry_allowed=True,
                error_message="Image signature missing or invalid (DEPL_001-002)",
                verification_duration_ms=int(
                    (datetime.now() - start_time).total_seconds() * 1000
                ),
            )

        # Mettre à jour le digest depuis la signature si disponible
        if signature.digest:
            digest = signature.digest

        # DEPL_004: Scan CVE
        try:
            cve_results = await self.scan_cve(image_ref)
        except ImageVerifierError as e:
            self._stats.total_errors += 1

            return ImageVerificationResult(
                image_ref=image_ref,
                digest=digest,
                status=VerificationStatus.ERROR,
                verified_at=start_time,
                signature=signature,
                registry_allowed=True,
                error_message=str(e),
                verification_duration_ms=int(
                    (datetime.now() - start_time).total_seconds() * 1000
                ),
            )

        # DEPL_005: Vérifier les CVE critiques
        critical_cves = [cve for cve in cve_results if cve.cvss_score >= self._critical_threshold]

        if critical_cves:
            self._stats.total_blocked_cve += 1

            await self._audit.emit_event(
                event_type=AuditEventType.SECURITY_BREACH,
                user_id="system",
                tenant_id="system",
                action="image_verification_blocked",
                metadata={
                    "image_ref": image_ref,
                    "reason": "critical_cve",
                    "critical_cves": [cve.cve_id for cve in critical_cves],
                    "cvss_scores": [cve.cvss_score for cve in critical_cves],
                },
            )

            return ImageVerificationResult(
                image_ref=image_ref,
                digest=digest,
                status=VerificationStatus.CVE_BLOCKED,
                verified_at=start_time,
                signature=signature,
                cve_results=cve_results,
                registry_allowed=True,
                error_message=f"Image blocked due to {len(critical_cves)} critical CVE(s) (DEPL_005)",
                verification_duration_ms=int(
                    (datetime.now() - start_time).total_seconds() * 1000
                ),
            )

        # Tout est OK
        self._stats.total_passed += 1

        await self._audit.emit_event(
            event_type=AuditEventType.SYSTEM_CONFIG_CHANGE,
            user_id="system",
            tenant_id="system",
            action="image_verification_passed",
            metadata={
                "image_ref": image_ref,
                "digest": digest,
                "signer": signature.signer_identity,
                "cve_count": len(cve_results),
            },
        )

        result = ImageVerificationResult(
            image_ref=image_ref,
            digest=digest,
            status=VerificationStatus.VERIFIED,
            verified_at=start_time,
            signature=signature,
            cve_results=cve_results,
            registry_allowed=True,
            verification_duration_ms=int((datetime.now() - start_time).total_seconds() * 1000),
        )

        # Mettre en cache
        self._verification_cache[image_ref] = result

        return result

    def get_verification_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques de vérification."""
        return {
            "total_verified": self._stats.total_verified,
            "total_passed": self._stats.total_passed,
            "total_blocked": (
                self._stats.total_blocked_signature
                + self._stats.total_blocked_cve
                + self._stats.total_blocked_registry
            ),
            "blocked_by_signature": self._stats.total_blocked_signature,
            "blocked_by_cve": self._stats.total_blocked_cve,
            "blocked_by_registry": self._stats.total_blocked_registry,
            "total_errors": self._stats.total_errors,
            "critical_cves_found": self._stats.critical_cves_found,
            "high_cves_found": self._stats.high_cves_found,
            "allowed_registries": self.get_allowed_registries(),
            "critical_threshold": self._critical_threshold,
        }

    def get_cached_result(self, image_ref: str) -> Optional[ImageVerificationResult]:
        """
        Récupère un résultat de vérification en cache.

        Args:
            image_ref: Référence de l'image.

        Returns:
            Résultat si en cache, None sinon.
        """
        return self._verification_cache.get(image_ref)

    def clear_cache(self) -> int:
        """
        Vide le cache de vérification.

        Returns:
            Nombre d'entrées supprimées.
        """
        count = len(self._verification_cache)
        self._verification_cache.clear()
        return count

    def reset_stats(self) -> None:
        """Remet les statistiques à zéro."""
        self._stats = VerificationStats()
