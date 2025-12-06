"""
Tests unitaires pour ImageVerifier.

LOT 7: Vérificateur d'images Docker

Invariants testés:
    DEPL_001: Images Docker signées obligatoirement
    DEPL_002: Vérification signature avant exécution
    DEPL_003: Registry privé uniquement
    DEPL_004: Scan CVE avant déploiement
    DEPL_005: Blocage si CVE critique (CVSS >= 9.0)
"""

import pytest
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

from src.audit.interfaces import AuditEventType, IAuditEmitter
from src.core.interfaces import ICryptoProvider
from src.deployment.interfaces import (
    CVEResult,
    CVESeverity,
    ImageSignature,
    ImageVerificationResult,
    VerificationStatus,
)
from src.deployment.image_verifier import (
    BLOCKED_REGISTRIES,
    ImageVerifier,
    ImageVerifierError,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mock_crypto_provider() -> MagicMock:
    """Crée un mock de ICryptoProvider."""
    provider = MagicMock(spec=ICryptoProvider)
    provider.verify_signature = MagicMock(return_value=True)
    return provider


@pytest.fixture
def mock_audit_emitter() -> AsyncMock:
    """Crée un mock de IAuditEmitter."""
    emitter = AsyncMock(spec=IAuditEmitter)
    emitter.emit_event = AsyncMock()
    return emitter


@pytest.fixture
def valid_signature_response() -> Dict[str, Any]:
    """Réponse de signature valide."""
    return {
        "digest": "sha256:abc123def456",
        "signature": "MEUCIQDbase64signature...",
        "signed_at": datetime.now().isoformat(),
        "signer_identity": "developer@example.com",
        "issuer": "https://accounts.google.com",
        "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
        "annotations": {"version": "1.0.0"},
    }


@pytest.fixture
def critical_cve_response() -> List[Dict[str, Any]]:
    """Réponse avec CVE critique."""
    return [
        {
            "cve_id": "CVE-2021-44228",
            "severity": "critical",
            "cvss_score": 10.0,
            "package_name": "log4j",
            "installed_version": "2.14.0",
            "fixed_version": "2.17.0",
            "title": "Log4Shell",
            "description": "Remote code execution vulnerability",
        }
    ]


@pytest.fixture
def high_cve_response() -> List[Dict[str, Any]]:
    """Réponse avec CVE haute seulement."""
    return [
        {
            "cve_id": "CVE-2022-12345",
            "severity": "high",
            "cvss_score": 8.5,
            "package_name": "openssl",
            "installed_version": "1.1.1",
            "fixed_version": "1.1.1n",
            "title": "Buffer overflow",
            "description": "Buffer overflow in OpenSSL",
        }
    ]


@pytest.fixture
def image_verifier(
    mock_crypto_provider: MagicMock,
    mock_audit_emitter: AsyncMock,
) -> ImageVerifier:
    """Crée un ImageVerifier pour les tests."""
    return ImageVerifier(
        crypto_provider=mock_crypto_provider,
        audit_emitter=mock_audit_emitter,
        allowed_registries=["registry.example.com", "private.registry.io"],
    )


# ============================================================================
# Tests DEPL_003: Registry privé uniquement
# ============================================================================


class TestRegistryAllowlist:
    """Tests pour la liste blanche des registries (DEPL_003)."""

    def test_allowed_registry_accepted(self, image_verifier: ImageVerifier) -> None:
        """DEPL_003: Registry autorisé accepté."""
        assert image_verifier.is_registry_allowed("registry.example.com/app:v1")
        assert image_verifier.is_registry_allowed("private.registry.io/namespace/app:latest")

    def test_dockerhub_blocked(self, image_verifier: ImageVerifier) -> None:
        """DEPL_003: DockerHub bloqué."""
        assert not image_verifier.is_registry_allowed("nginx:latest")
        assert not image_verifier.is_registry_allowed("library/nginx:latest")
        assert not image_verifier.is_registry_allowed("docker.io/nginx:latest")

    def test_public_registries_blocked(self, image_verifier: ImageVerifier) -> None:
        """DEPL_003: Registries publics bloqués."""
        for registry in BLOCKED_REGISTRIES:
            assert not image_verifier.is_registry_allowed(f"{registry}/app:v1")

    def test_unknown_registry_blocked(self, image_verifier: ImageVerifier) -> None:
        """DEPL_003: Registry inconnu bloqué."""
        assert not image_verifier.is_registry_allowed("unknown.registry.com/app:v1")

    def test_add_allowed_registry(self, image_verifier: ImageVerifier) -> None:
        """DEPL_003: Ajout de registry à la liste blanche."""
        assert not image_verifier.is_registry_allowed("new.registry.com/app:v1")

        image_verifier.add_allowed_registry("new.registry.com")

        assert image_verifier.is_registry_allowed("new.registry.com/app:v1")

    def test_remove_allowed_registry(self, image_verifier: ImageVerifier) -> None:
        """DEPL_003: Retrait de registry de la liste blanche."""
        assert image_verifier.is_registry_allowed("registry.example.com/app:v1")

        result = image_verifier.remove_allowed_registry("registry.example.com")

        assert result is True
        assert not image_verifier.is_registry_allowed("registry.example.com/app:v1")

    def test_remove_nonexistent_registry(self, image_verifier: ImageVerifier) -> None:
        """DEPL_003: Retrait de registry inexistant."""
        result = image_verifier.remove_allowed_registry("nonexistent.com")
        assert result is False

    def test_get_allowed_registries(self, image_verifier: ImageVerifier) -> None:
        """DEPL_003: Récupération liste des registries."""
        registries = image_verifier.get_allowed_registries()

        assert "registry.example.com" in registries
        assert "private.registry.io" in registries

    def test_empty_allowlist_blocks_all(
        self,
        mock_crypto_provider: MagicMock,
        mock_audit_emitter: AsyncMock,
    ) -> None:
        """DEPL_003: Liste vide bloque tout."""
        verifier = ImageVerifier(
            crypto_provider=mock_crypto_provider,
            audit_emitter=mock_audit_emitter,
            allowed_registries=[],
        )

        assert not verifier.is_registry_allowed("any.registry.com/app:v1")


# ============================================================================
# Tests DEPL_001-002: Signature obligatoire
# ============================================================================


class TestSignatureVerification:
    """Tests pour la vérification de signature (DEPL_001-002)."""

    @pytest.mark.asyncio
    async def test_valid_signature_accepted(
        self,
        image_verifier: ImageVerifier,
        valid_signature_response: Dict[str, Any],
    ) -> None:
        """DEPL_001: Signature valide acceptée."""

        async def mock_cosign(image_ref: str) -> Dict[str, Any]:
            return valid_signature_response

        image_verifier._cosign_client = mock_cosign

        signature = await image_verifier.verify_signature("registry.example.com/app:v1")

        assert signature is not None
        assert signature.signer_identity == "developer@example.com"
        assert signature.digest == "sha256:abc123def456"

    @pytest.mark.asyncio
    async def test_missing_signature_rejected(
        self,
        image_verifier: ImageVerifier,
    ) -> None:
        """DEPL_001: Signature manquante rejetée."""

        async def mock_cosign(image_ref: str) -> None:
            return None

        image_verifier._cosign_client = mock_cosign

        signature = await image_verifier.verify_signature("registry.example.com/app:v1")

        assert signature is None

    @pytest.mark.asyncio
    async def test_keyless_signature_detected(
        self,
        image_verifier: ImageVerifier,
        valid_signature_response: Dict[str, Any],
    ) -> None:
        """DEPL_002: Signature keyless détectée."""

        async def mock_cosign(image_ref: str) -> Dict[str, Any]:
            return valid_signature_response

        image_verifier._cosign_client = mock_cosign

        signature = await image_verifier.verify_signature("registry.example.com/app:v1")

        assert signature is not None
        assert signature.is_keyless() is True
        assert signature.issuer == "https://accounts.google.com"

    @pytest.mark.asyncio
    async def test_traditional_signature_detected(
        self,
        image_verifier: ImageVerifier,
    ) -> None:
        """DEPL_002: Signature traditionnelle détectée."""

        async def mock_cosign(image_ref: str) -> Dict[str, Any]:
            return {
                "digest": "sha256:abc123",
                "signature": "MEUCIQDbase64...",
                "signed_at": datetime.now().isoformat(),
                "signer_identity": "key-id-123",
            }

        image_verifier._cosign_client = mock_cosign

        signature = await image_verifier.verify_signature("registry.example.com/app:v1")

        assert signature is not None
        assert signature.is_keyless() is False

    @pytest.mark.asyncio
    async def test_signature_timeout_handled(
        self,
        image_verifier: ImageVerifier,
    ) -> None:
        """DEPL_002: Timeout de vérification géré."""
        import asyncio

        async def mock_cosign_slow(image_ref: str) -> Dict[str, Any]:
            await asyncio.sleep(100)
            return {}

        image_verifier._cosign_client = mock_cosign_slow
        image_verifier.VERIFICATION_TIMEOUT_SECONDS = 0.01

        signature = await image_verifier.verify_signature("registry.example.com/app:v1")

        assert signature is None


# ============================================================================
# Tests DEPL_004: Scan CVE obligatoire
# ============================================================================


class TestCVEScanning:
    """Tests pour le scan CVE (DEPL_004)."""

    @pytest.mark.asyncio
    async def test_cve_scan_returns_results(
        self,
        image_verifier: ImageVerifier,
        high_cve_response: List[Dict[str, Any]],
    ) -> None:
        """DEPL_004: Scan CVE retourne les résultats."""

        async def mock_trivy(image_ref: str) -> List[Dict[str, Any]]:
            return high_cve_response

        image_verifier._trivy_client = mock_trivy

        results = await image_verifier.scan_cve("registry.example.com/app:v1")

        assert len(results) == 1
        assert results[0].cve_id == "CVE-2022-12345"
        assert results[0].severity == CVESeverity.HIGH

    @pytest.mark.asyncio
    async def test_cve_scan_empty_is_clean(
        self,
        image_verifier: ImageVerifier,
    ) -> None:
        """DEPL_004: Scan vide = image propre."""

        async def mock_trivy(image_ref: str) -> List[Dict[str, Any]]:
            return []

        image_verifier._trivy_client = mock_trivy

        results = await image_verifier.scan_cve("registry.example.com/app:v1")

        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_cve_severity_parsing(
        self,
        image_verifier: ImageVerifier,
    ) -> None:
        """DEPL_004: Parsing correct des sévérités."""

        async def mock_trivy(image_ref: str) -> List[Dict[str, Any]]:
            return [
                {
                    "cve_id": "CVE-1",
                    "severity": "critical",
                    "cvss_score": 9.8,
                    "package_name": "p1",
                    "installed_version": "1.0",
                    "title": "t1",
                    "description": "d1",
                },
                {
                    "cve_id": "CVE-2",
                    "severity": "high",
                    "cvss_score": 7.5,
                    "package_name": "p2",
                    "installed_version": "1.0",
                    "title": "t2",
                    "description": "d2",
                },
                {
                    "cve_id": "CVE-3",
                    "severity": "medium",
                    "cvss_score": 5.0,
                    "package_name": "p3",
                    "installed_version": "1.0",
                    "title": "t3",
                    "description": "d3",
                },
                {
                    "cve_id": "CVE-4",
                    "severity": "low",
                    "cvss_score": 2.0,
                    "package_name": "p4",
                    "installed_version": "1.0",
                    "title": "t4",
                    "description": "d4",
                },
            ]

        image_verifier._trivy_client = mock_trivy

        results = await image_verifier.scan_cve("registry.example.com/app:v1")

        assert results[0].severity == CVESeverity.CRITICAL
        assert results[1].severity == CVESeverity.HIGH
        assert results[2].severity == CVESeverity.MEDIUM
        assert results[3].severity == CVESeverity.LOW

    @pytest.mark.asyncio
    async def test_cve_scan_timeout_raises_error(
        self,
        image_verifier: ImageVerifier,
    ) -> None:
        """DEPL_004: Timeout de scan lève une erreur."""
        import asyncio

        async def mock_trivy_slow(image_ref: str) -> List[Dict[str, Any]]:
            await asyncio.sleep(100)
            return []

        image_verifier._trivy_client = mock_trivy_slow
        image_verifier.VERIFICATION_TIMEOUT_SECONDS = 0.01

        with pytest.raises(ImageVerifierError, match="timeout"):
            await image_verifier.scan_cve("registry.example.com/app:v1")


# ============================================================================
# Tests DEPL_005: Blocage CVE critique
# ============================================================================


class TestCriticalCVEBlocking:
    """Tests pour le blocage des CVE critiques (DEPL_005)."""

    @pytest.mark.asyncio
    async def test_critical_cve_blocks_deployment(
        self,
        image_verifier: ImageVerifier,
        valid_signature_response: Dict[str, Any],
        critical_cve_response: List[Dict[str, Any]],
    ) -> None:
        """DEPL_005: CVE critique bloque le déploiement."""

        async def mock_cosign(image_ref: str) -> Dict[str, Any]:
            return valid_signature_response

        async def mock_trivy(image_ref: str) -> List[Dict[str, Any]]:
            return critical_cve_response

        image_verifier._cosign_client = mock_cosign
        image_verifier._trivy_client = mock_trivy

        result = await image_verifier.verify_image("registry.example.com/app:v1")

        assert result.status == VerificationStatus.CVE_BLOCKED
        assert not result.is_deployable()
        assert "critical CVE" in result.error_message

    @pytest.mark.asyncio
    async def test_high_cve_allowed(
        self,
        image_verifier: ImageVerifier,
        valid_signature_response: Dict[str, Any],
        high_cve_response: List[Dict[str, Any]],
    ) -> None:
        """DEPL_005: CVE haute autorisée par défaut."""

        async def mock_cosign(image_ref: str) -> Dict[str, Any]:
            return valid_signature_response

        async def mock_trivy(image_ref: str) -> List[Dict[str, Any]]:
            return high_cve_response

        image_verifier._cosign_client = mock_cosign
        image_verifier._trivy_client = mock_trivy

        result = await image_verifier.verify_image("registry.example.com/app:v1")

        assert result.status == VerificationStatus.VERIFIED
        assert result.is_deployable()

    @pytest.mark.asyncio
    async def test_custom_cvss_threshold(
        self,
        image_verifier: ImageVerifier,
        valid_signature_response: Dict[str, Any],
        high_cve_response: List[Dict[str, Any]],
    ) -> None:
        """DEPL_005: Seuil CVSS personnalisable."""

        async def mock_cosign(image_ref: str) -> Dict[str, Any]:
            return valid_signature_response

        async def mock_trivy(image_ref: str) -> List[Dict[str, Any]]:
            return high_cve_response

        image_verifier._cosign_client = mock_cosign
        image_verifier._trivy_client = mock_trivy
        image_verifier.set_critical_cvss_threshold(8.0)

        result = await image_verifier.verify_image("registry.example.com/app:v1")

        assert result.status == VerificationStatus.CVE_BLOCKED
        assert not result.is_deployable()

    def test_invalid_cvss_threshold_rejected(
        self,
        image_verifier: ImageVerifier,
    ) -> None:
        """DEPL_005: Seuil CVSS invalide rejeté."""
        with pytest.raises(ValueError):
            image_verifier.set_critical_cvss_threshold(11.0)

        with pytest.raises(ValueError):
            image_verifier.set_critical_cvss_threshold(-1.0)

    @pytest.mark.asyncio
    async def test_multiple_critical_cves_all_reported(
        self,
        image_verifier: ImageVerifier,
        valid_signature_response: Dict[str, Any],
    ) -> None:
        """DEPL_005: Toutes les CVE critiques rapportées."""

        async def mock_cosign(image_ref: str) -> Dict[str, Any]:
            return valid_signature_response

        async def mock_trivy(image_ref: str) -> List[Dict[str, Any]]:
            return [
                {
                    "cve_id": "CVE-2021-44228",
                    "severity": "critical",
                    "cvss_score": 10.0,
                    "package_name": "log4j",
                    "installed_version": "2.14.0",
                    "title": "Log4Shell",
                    "description": "RCE",
                },
                {
                    "cve_id": "CVE-2021-45046",
                    "severity": "critical",
                    "cvss_score": 9.0,
                    "package_name": "log4j",
                    "installed_version": "2.14.0",
                    "title": "Log4Shell 2",
                    "description": "RCE",
                },
            ]

        image_verifier._cosign_client = mock_cosign
        image_verifier._trivy_client = mock_trivy

        result = await image_verifier.verify_image("registry.example.com/app:v1")

        critical_cves = result.get_critical_cves()
        assert len(critical_cves) == 2


# ============================================================================
# Tests verify_image complet
# ============================================================================


class TestFullVerification:
    """Tests pour la vérification complète."""

    @pytest.mark.asyncio
    async def test_full_verification_success(
        self,
        image_verifier: ImageVerifier,
        valid_signature_response: Dict[str, Any],
        mock_audit_emitter: AsyncMock,
    ) -> None:
        """Vérification complète réussie."""

        async def mock_cosign(image_ref: str) -> Dict[str, Any]:
            return valid_signature_response

        async def mock_trivy(image_ref: str) -> List[Dict[str, Any]]:
            return []

        image_verifier._cosign_client = mock_cosign
        image_verifier._trivy_client = mock_trivy

        result = await image_verifier.verify_image("registry.example.com/app:v1")

        assert result.status == VerificationStatus.VERIFIED
        assert result.is_deployable()
        assert result.signature is not None
        assert result.registry_allowed is True
        assert len(result.cve_results) == 0

    @pytest.mark.asyncio
    async def test_registry_denied_before_signature_check(
        self,
        image_verifier: ImageVerifier,
        mock_audit_emitter: AsyncMock,
    ) -> None:
        """DEPL_003: Registry vérifié avant signature."""
        result = await image_verifier.verify_image("docker.io/nginx:latest")

        assert result.status == VerificationStatus.REGISTRY_DENIED
        assert not result.is_deployable()
        assert result.registry_allowed is False

    @pytest.mark.asyncio
    async def test_signature_checked_before_cve(
        self,
        image_verifier: ImageVerifier,
        mock_audit_emitter: AsyncMock,
    ) -> None:
        """DEPL_001: Signature vérifiée avant CVE."""

        async def mock_cosign(image_ref: str) -> None:
            return None

        image_verifier._cosign_client = mock_cosign

        result = await image_verifier.verify_image("registry.example.com/app:v1")

        assert result.status == VerificationStatus.SIGNATURE_MISSING
        assert not result.is_deployable()

    @pytest.mark.asyncio
    async def test_audit_event_on_blocked(
        self,
        image_verifier: ImageVerifier,
        mock_audit_emitter: AsyncMock,
    ) -> None:
        """Événement audit émis lors du blocage."""
        result = await image_verifier.verify_image("docker.io/nginx:latest")

        mock_audit_emitter.emit_event.assert_called()
        call_args = mock_audit_emitter.emit_event.call_args
        assert call_args.kwargs["event_type"] == AuditEventType.SECURITY_BREACH
        assert call_args.kwargs["action"] == "image_verification_blocked"

    @pytest.mark.asyncio
    async def test_audit_event_on_success(
        self,
        image_verifier: ImageVerifier,
        valid_signature_response: Dict[str, Any],
        mock_audit_emitter: AsyncMock,
    ) -> None:
        """Événement audit émis lors du succès."""

        async def mock_cosign(image_ref: str) -> Dict[str, Any]:
            return valid_signature_response

        async def mock_trivy(image_ref: str) -> List[Dict[str, Any]]:
            return []

        image_verifier._cosign_client = mock_cosign
        image_verifier._trivy_client = mock_trivy

        result = await image_verifier.verify_image("registry.example.com/app:v1")

        mock_audit_emitter.emit_event.assert_called()
        call_args = mock_audit_emitter.emit_event.call_args
        assert call_args.kwargs["action"] == "image_verification_passed"

    @pytest.mark.asyncio
    async def test_verification_duration_tracked(
        self,
        image_verifier: ImageVerifier,
        valid_signature_response: Dict[str, Any],
    ) -> None:
        """Durée de vérification mesurée."""

        async def mock_cosign(image_ref: str) -> Dict[str, Any]:
            return valid_signature_response

        async def mock_trivy(image_ref: str) -> List[Dict[str, Any]]:
            return []

        image_verifier._cosign_client = mock_cosign
        image_verifier._trivy_client = mock_trivy

        result = await image_verifier.verify_image("registry.example.com/app:v1")

        assert result.verification_duration_ms >= 0


# ============================================================================
# Tests statistiques et cache
# ============================================================================


class TestStatsAndCache:
    """Tests pour les statistiques et le cache."""

    @pytest.mark.asyncio
    async def test_stats_updated_on_verification(
        self,
        image_verifier: ImageVerifier,
        valid_signature_response: Dict[str, Any],
    ) -> None:
        """Statistiques mises à jour après vérification."""

        async def mock_cosign(image_ref: str) -> Dict[str, Any]:
            return valid_signature_response

        async def mock_trivy(image_ref: str) -> List[Dict[str, Any]]:
            return []

        image_verifier._cosign_client = mock_cosign
        image_verifier._trivy_client = mock_trivy

        await image_verifier.verify_image("registry.example.com/app:v1")
        stats = image_verifier.get_verification_stats()

        assert stats["total_verified"] == 1
        assert stats["total_passed"] == 1

    @pytest.mark.asyncio
    async def test_stats_blocked_registry_counted(
        self,
        image_verifier: ImageVerifier,
    ) -> None:
        """Statistiques: blocage registry compté."""
        await image_verifier.verify_image("docker.io/nginx:latest")
        stats = image_verifier.get_verification_stats()

        assert stats["blocked_by_registry"] == 1

    @pytest.mark.asyncio
    async def test_stats_blocked_signature_counted(
        self,
        image_verifier: ImageVerifier,
    ) -> None:
        """Statistiques: blocage signature compté."""

        async def mock_cosign(image_ref: str) -> None:
            return None

        image_verifier._cosign_client = mock_cosign

        await image_verifier.verify_image("registry.example.com/app:v1")
        stats = image_verifier.get_verification_stats()

        assert stats["blocked_by_signature"] == 1

    @pytest.mark.asyncio
    async def test_result_cached(
        self,
        image_verifier: ImageVerifier,
        valid_signature_response: Dict[str, Any],
    ) -> None:
        """Résultat mis en cache après succès."""

        async def mock_cosign(image_ref: str) -> Dict[str, Any]:
            return valid_signature_response

        async def mock_trivy(image_ref: str) -> List[Dict[str, Any]]:
            return []

        image_verifier._cosign_client = mock_cosign
        image_verifier._trivy_client = mock_trivy

        await image_verifier.verify_image("registry.example.com/app:v1")
        cached = image_verifier.get_cached_result("registry.example.com/app:v1")

        assert cached is not None
        assert cached.status == VerificationStatus.VERIFIED

    def test_clear_cache(self, image_verifier: ImageVerifier) -> None:
        """Vidage du cache."""
        image_verifier._verification_cache["test"] = MagicMock()

        count = image_verifier.clear_cache()

        assert count == 1
        assert image_verifier.get_cached_result("test") is None

    def test_reset_stats(self, image_verifier: ImageVerifier) -> None:
        """Remise à zéro des statistiques."""
        image_verifier._stats.total_verified = 100

        image_verifier.reset_stats()
        stats = image_verifier.get_verification_stats()

        assert stats["total_verified"] == 0


# ============================================================================
# Tests parsing d'image
# ============================================================================


class TestImageRefParsing:
    """Tests pour le parsing des références d'image."""

    def test_parse_simple_image(self, image_verifier: ImageVerifier) -> None:
        """Parse image simple (nginx)."""
        parsed = image_verifier._parse_image_ref("nginx")

        assert parsed["registry"] == "docker.io"
        assert parsed["namespace"] == "library"
        assert parsed["image"] == "nginx"
        assert parsed["tag"] == "latest"

    def test_parse_with_namespace(self, image_verifier: ImageVerifier) -> None:
        """Parse avec namespace (user/image)."""
        parsed = image_verifier._parse_image_ref("myuser/myapp")

        assert parsed["registry"] == "docker.io"
        assert parsed["namespace"] == "myuser"
        assert parsed["image"] == "myapp"

    def test_parse_with_registry(self, image_verifier: ImageVerifier) -> None:
        """Parse avec registry complet."""
        parsed = image_verifier._parse_image_ref("registry.example.com/namespace/app:v1.0")

        assert parsed["registry"] == "registry.example.com"
        assert parsed["namespace"] == "namespace"
        assert parsed["image"] == "app"
        assert parsed["tag"] == "v1.0"

    def test_parse_with_digest(self, image_verifier: ImageVerifier) -> None:
        """Parse avec digest SHA256."""
        parsed = image_verifier._parse_image_ref("registry.example.com/app@sha256:abc123")

        assert parsed["registry"] == "registry.example.com"
        assert parsed["image"] == "app"
        assert parsed["digest"] == "sha256:abc123"

    def test_parse_localhost_registry(self, image_verifier: ImageVerifier) -> None:
        """Parse avec localhost."""
        parsed = image_verifier._parse_image_ref("localhost/myapp:dev")

        assert parsed["registry"] == "localhost"
        assert parsed["image"] == "myapp"
        assert parsed["tag"] == "dev"


# ============================================================================
# Tests dataclasses
# ============================================================================


class TestDataClasses:
    """Tests pour les dataclasses du module."""

    def test_cve_result_is_critical(self) -> None:
        """CVEResult.is_critical() fonctionne."""
        critical = CVEResult(
            cve_id="CVE-2021-44228",
            severity=CVESeverity.CRITICAL,
            cvss_score=10.0,
            package_name="log4j",
            installed_version="2.14.0",
            fixed_version="2.17.0",
            title="Log4Shell",
            description="RCE",
        )

        assert critical.is_critical()

        high = CVEResult(
            cve_id="CVE-2022-1234",
            severity=CVESeverity.HIGH,
            cvss_score=8.9,
            package_name="openssl",
            installed_version="1.0",
            fixed_version="1.1",
            title="Test",
            description="Test",
        )

        assert not high.is_critical()

    def test_cve_result_is_fixable(self) -> None:
        """CVEResult.is_fixable() fonctionne."""
        fixable = CVEResult(
            cve_id="CVE-1",
            severity=CVESeverity.HIGH,
            cvss_score=8.0,
            package_name="pkg",
            installed_version="1.0",
            fixed_version="1.1",
            title="t",
            description="d",
        )

        assert fixable.is_fixable()

        not_fixable = CVEResult(
            cve_id="CVE-2",
            severity=CVESeverity.HIGH,
            cvss_score=8.0,
            package_name="pkg",
            installed_version="1.0",
            fixed_version=None,
            title="t",
            description="d",
        )

        assert not not_fixable.is_fixable()

    def test_image_signature_is_keyless(self) -> None:
        """ImageSignature.is_keyless() fonctionne."""
        keyless = ImageSignature(
            image_ref="test",
            digest="sha256:abc",
            signature="sig",
            signed_at=datetime.now(),
            signer_identity="user@example.com",
            issuer="https://accounts.google.com",
            certificate="-----BEGIN CERTIFICATE-----",
        )

        assert keyless.is_keyless()

        traditional = ImageSignature(
            image_ref="test",
            digest="sha256:abc",
            signature="sig",
            signed_at=datetime.now(),
            signer_identity="key-id",
        )

        assert not traditional.is_keyless()

    def test_verification_result_get_cve_counts(self) -> None:
        """ImageVerificationResult.get_cve_count_by_severity() fonctionne."""
        result = ImageVerificationResult(
            image_ref="test",
            digest="sha256:abc",
            status=VerificationStatus.VERIFIED,
            verified_at=datetime.now(),
            cve_results=[
                CVEResult(
                    cve_id="CVE-1",
                    severity=CVESeverity.CRITICAL,
                    cvss_score=10.0,
                    package_name="p",
                    installed_version="1",
                    fixed_version="2",
                    title="t",
                    description="d",
                ),
                CVEResult(
                    cve_id="CVE-2",
                    severity=CVESeverity.HIGH,
                    cvss_score=8.0,
                    package_name="p",
                    installed_version="1",
                    fixed_version="2",
                    title="t",
                    description="d",
                ),
                CVEResult(
                    cve_id="CVE-3",
                    severity=CVESeverity.HIGH,
                    cvss_score=7.5,
                    package_name="p",
                    installed_version="1",
                    fixed_version=None,
                    title="t",
                    description="d",
                ),
            ],
        )

        counts = result.get_cve_count_by_severity()

        assert counts[CVESeverity.CRITICAL] == 1
        assert counts[CVESeverity.HIGH] == 2
        assert counts[CVESeverity.MEDIUM] == 0
