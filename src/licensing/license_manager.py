"""
LOT 5: License Manager Implementation

Gestionnaire principal de licences avec signature cryptographique et ancrage blockchain.

Invariants:
    LIC_001: Licence signée ECDSA-P384
    LIC_002: Contenu obligatoire site_id org_id dates modules
    LIC_003: Durée maximale 366 jours
    LIC_004: Émission ancrée blockchain
    LIC_005: Une licence = un site
    LIC_006: Émission par License Manager Cloud uniquement
    LIC_061: Révocation requiert quorum
    LIC_090: Tout événement licence = audit
    LIC_091: Critiques = blockchain
"""

import uuid
import base64
import json
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

from .interfaces import (
    ILicenseManager,
    LicenseConfig,
    License,
    ValidationResult,
    Signature,
    LicenseStatus,
    GracePeriodStatus,
)
from ..core.crypto_provider import CryptoProvider
from ..audit.audit_emitter import AuditEmitter
from ..audit.blockchain_anchor import BlockchainAnchor
from ..audit.interfaces import AuditEventType


class LicenseManagerError(Exception):
    """Erreur gestion de licence."""

    pass


class LicenseManager(ILicenseManager):
    """
    Gestionnaire principal de licences Edge avec sécurité cryptographique.

    Conformité:
        LIC_001: Signature ECDSA-P384
        LIC_002-006: Structure et émission
        LIC_061: Quorum révocation
        LIC_090-091: Audit et blockchain

    Note:
        Émission UNIQUEMENT côté Cloud (LIC_006)

    Example:
        manager = LicenseManager(crypto, audit, blockchain)
        license = await manager.issue(config)
    """

    # Durée maximale licence (LIC_003)
    MAX_LICENSE_DURATION_DAYS: int = 366

    # Grace period après expiration (avant kill switch)
    GRACE_PERIOD_DAYS: int = 7

    # Modules disponibles (liste blanche LIC_080)
    AVAILABLE_MODULES = [
        "surveillance",
        "access_control",
        "visitor_management",
        "incident_reporting",
        "staff_scheduling",
        "medical_tracking",
        "inventory_management",
        "transport_coordination",
        "communication_hub",
        "analytics_dashboard",
    ]

    def __init__(
        self,
        crypto_provider: CryptoProvider,
        audit_emitter: AuditEmitter,
        blockchain_anchor: BlockchainAnchor,
        cloud_mode: bool = True,
    ):
        """
        Args:
            crypto_provider: Fournisseur cryptographique
            audit_emitter: Émetteur événements audit
            blockchain_anchor: Service ancrage blockchain
            cloud_mode: True si mode Cloud (LIC_006)
        """
        self.crypto_provider = crypto_provider
        self.audit_emitter = audit_emitter
        self.blockchain_anchor = blockchain_anchor
        self.cloud_mode = cloud_mode

        # Stockage licences actives (MVP - Redis en production)
        self._licenses: Dict[str, License] = {}  # site_id -> license

        # Cache signatures quorum pour révocation
        self._revocation_signatures: Dict[str, List[Signature]] = {}  # site_id -> signatures

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
        if not self.cloud_mode:
            raise LicenseManagerError("LIC_006: Émission autorisée uniquement côté Cloud")

        # Validation configuration
        self._validate_license_config(config)

        try:
            # Générer ID licence unique
            license_id = str(uuid.uuid4())

            # Calculer dates
            now = datetime.now(timezone.utc)
            expires_at = now + timedelta(days=config.duration_days)

            # Créer licence préliminaire
            preliminary_license = License(
                license_id=license_id,
                site_id=config.site_id,
                issued_at=now,
                expires_at=expires_at,
                modules=config.modules.copy(),
                signature="",  # Sera calculé
                issuer_id=config.issuer_id,
                organization_id=config.organization_id,
            )

            # Signer licence (LIC_001)
            signature = self._sign_license(preliminary_license)

            # Créer licence finale signée
            signed_license = License(
                license_id=license_id,
                site_id=config.site_id,
                issued_at=now,
                expires_at=expires_at,
                modules=config.modules.copy(),
                signature=signature,
                issuer_id=config.issuer_id,
                organization_id=config.organization_id,
            )

            # Ancrer sur blockchain (LIC_004)
            license_hash = self._compute_license_hash(signed_license)
            anchor_receipt = await self.blockchain_anchor.anchor_event(license_hash)

            # Licence finale avec ancrage blockchain
            final_license = License(
                license_id=license_id,
                site_id=config.site_id,
                issued_at=now,
                expires_at=expires_at,
                modules=config.modules.copy(),
                signature=signature,
                issuer_id=config.issuer_id,
                organization_id=config.organization_id,
                blockchain_tx_id=anchor_receipt.blockchain_tx_id,
            )

            # Stocker licence (LIC_005: une licence = un site)
            self._licenses[config.site_id] = final_license

            # Audit émission (LIC_090)
            await self.audit_emitter.emit_event(
                AuditEventType.SYSTEM_CONFIG_CHANGE,
                config.issuer_id,
                config.site_id,
                "license_issued",
                resource_id=license_id,
                metadata={
                    "license_id": license_id,
                    "duration_days": config.duration_days,
                    "modules": config.modules,
                    "blockchain_tx_id": anchor_receipt.blockchain_tx_id,
                },
            )

            return final_license

        except Exception as e:
            raise LicenseManagerError(f"Erreur émission licence: {str(e)}")

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
        try:
            # Vérifier révocation
            if license.revoked:
                return ValidationResult(
                    valid=False, status=LicenseStatus.REVOKED, reason=f"Licence révoquée: {license.revoked_reason}"
                )

            # Validation signature (LIC_001, LIC_010)
            if not self._verify_license_signature(license):
                return ValidationResult(
                    valid=False, status=LicenseStatus.INVALID_SIGNATURE, reason="Signature ECDSA-P384 invalide"
                )

            # Validation structure (LIC_002)
            if not self._validate_license_structure(license):
                return ValidationResult(
                    valid=False, status=LicenseStatus.CORRUPTED, reason="Structure licence invalide"
                )

            # Vérifier ancrage blockchain (LIC_014)
            blockchain_verified = await self.verify_blockchain_anchor(license)

            # Calculer dates
            now = datetime.now(timezone.utc)
            expires_in_days = (license.expires_at - now).days

            # Vérifier expiration et grace period
            is_expired = now > license.expires_at
            grace_period_end = license.expires_at + timedelta(days=self.GRACE_PERIOD_DAYS)
            in_grace_period = is_expired and now <= grace_period_end
            grace_expired = now > grace_period_end

            if grace_expired:
                # Grace period expirée = kill switch (LIC_044)
                return ValidationResult(
                    valid=False,
                    status=LicenseStatus.EXPIRED,
                    reason="Grace period expirée - Kill switch requis",
                    expires_in_days=expires_in_days,
                    is_degraded=True,
                    grace_period_status=GracePeriodStatus.EXPIRED,
                    blockchain_verified=blockchain_verified,
                )
            elif in_grace_period:
                # Mode dégradé (LIC_040-043)
                return ValidationResult(
                    valid=True,  # Techniquement valide mais dégradé
                    status=LicenseStatus.EXPIRED,
                    reason="Licence expirée - Mode dégradé actif",
                    expires_in_days=expires_in_days,
                    is_degraded=True,
                    grace_period_status=GracePeriodStatus.ACTIVE,
                    blockchain_verified=blockchain_verified,
                )
            elif is_expired:
                # Juste expirée, début grace period
                return ValidationResult(
                    valid=True,
                    status=LicenseStatus.EXPIRED,
                    reason="Licence expirée - Grace period démarrée",
                    expires_in_days=expires_in_days,
                    is_degraded=True,
                    grace_period_status=GracePeriodStatus.ACTIVE,
                    blockchain_verified=blockchain_verified,
                )
            else:
                # Licence valide
                return ValidationResult(
                    valid=True,
                    status=LicenseStatus.VALID,
                    expires_in_days=expires_in_days,
                    is_degraded=False,
                    grace_period_status=GracePeriodStatus.NONE,
                    blockchain_verified=blockchain_verified,
                )

        except Exception as e:
            return ValidationResult(valid=False, status=LicenseStatus.CORRUPTED, reason=f"Erreur validation: {str(e)}")

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
        if not self.cloud_mode:
            raise LicenseManagerError("LIC_006: Renouvellement autorisé uniquement côté Cloud")

        # Récupérer licence existante
        current_license = self._licenses.get(site_id)
        if not current_license:
            raise LicenseManagerError(f"Aucune licence trouvée pour site {site_id}")

        # Validation durée (LIC_003)
        if duration_days > self.MAX_LICENSE_DURATION_DAYS:
            raise LicenseManagerError(f"LIC_003: Durée max {self.MAX_LICENSE_DURATION_DAYS} jours")

        try:
            # Archiver ancienne licence AVANT émission nouvelle (LIC_053 + éviter LIC_005)
            archived_license = License(
                license_id=current_license.license_id,
                site_id=current_license.site_id,
                issued_at=current_license.issued_at,
                expires_at=current_license.expires_at,
                modules=current_license.modules,
                signature=current_license.signature,
                issuer_id=current_license.issuer_id,
                organization_id=current_license.organization_id,
                blockchain_tx_id=current_license.blockchain_tx_id,
                revoked=True,
                revoked_at=datetime.now(timezone.utc),
                revoked_reason="renewed",
            )

            # Stocker licence archivée pour libérer le site_id (éviter LIC_005)
            self._licenses[site_id] = archived_license

            # Créer nouvelle licence avec même configuration
            new_config = LicenseConfig(
                site_id=site_id,
                modules=current_license.modules,
                duration_days=duration_days,
                issuer_id=current_license.issuer_id,
                organization_id=current_license.organization_id,
            )

            # Émettre nouvelle licence (LIC_050-051)
            new_license = await self.issue(new_config)

            # Audit renouvellement (LIC_090)
            await self.audit_emitter.emit_event(
                AuditEventType.SYSTEM_CONFIG_CHANGE,
                current_license.issuer_id,
                site_id,
                "license_renewed",
                resource_id=new_license.license_id,
                metadata={
                    "old_license_id": current_license.license_id,
                    "new_license_id": new_license.license_id,
                    "duration_days": duration_days,
                    "archived": True,
                },
            )

            return new_license

        except Exception as e:
            raise LicenseManagerError(f"Erreur renouvellement licence: {str(e)}")

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
        if not reason:
            raise LicenseManagerError("LIC_066: Raison révocation obligatoire")

        # Vérifier quorum (LIC_061) - minimum 2 signatures
        if len(signatures) < 2:
            raise LicenseManagerError("LIC_061: Révocation requiert quorum minimum 2 signatures")

        # Récupérer licence
        license = self._licenses.get(site_id)
        if not license:
            raise LicenseManagerError(f"Aucune licence trouvée pour site {site_id}")

        if license.revoked:
            raise LicenseManagerError("Licence déjà révoquée")

        try:
            # Valider signatures quorum
            self._validate_revocation_signatures(site_id, reason, signatures)

            # Marquer révoquée
            now = datetime.now(timezone.utc)
            revoked_license = License(
                license_id=license.license_id,
                site_id=license.site_id,
                issued_at=license.issued_at,
                expires_at=license.expires_at,
                modules=license.modules,
                signature=license.signature,
                issuer_id=license.issuer_id,
                organization_id=license.organization_id,
                blockchain_tx_id=license.blockchain_tx_id,
                revoked=True,
                revoked_at=now,
                revoked_reason=reason,
            )

            # Stocker licence révoquée
            self._licenses[site_id] = revoked_license

            # Ancrer révocation blockchain (LIC_064)
            revocation_data = {
                "license_id": license.license_id,
                "site_id": site_id,
                "reason": reason,
                "revoked_at": now.isoformat(),
                "signatures_count": len(signatures),
            }
            revocation_hash = self._compute_data_hash(revocation_data)
            await self.blockchain_anchor.anchor_event(revocation_hash)

            # Audit révocation critique (LIC_091)
            await self.audit_emitter.emit_event(
                AuditEventType.SECURITY_BREACH,  # Révocation = critique
                signatures[0].signer_id,
                site_id,
                "license_revoked",
                resource_id=license.license_id,
                metadata={
                    "license_id": license.license_id,
                    "reason": reason,
                    "quorum_size": len(signatures),
                    "signers": [sig.signer_id for sig in signatures],
                },
            )

        except Exception as e:
            raise LicenseManagerError(f"Erreur révocation licence: {str(e)}")

    async def get_license(self, site_id: str) -> Optional[License]:
        """
        Récupère licence active pour site.

        Args:
            site_id: Identifiant site

        Returns:
            Licence si trouvée
        """
        return self._licenses.get(site_id)

    async def verify_blockchain_anchor(self, license: License) -> bool:
        """
        Vérifie ancrage blockchain (LIC_004).

        Args:
            license: Licence à vérifier

        Returns:
            True si ancrage vérifié
        """
        if not license.blockchain_tx_id:
            return False

        try:
            # Calculer hash licence
            license_hash = self._compute_license_hash(license)

            # Récupérer preuve ancrage
            anchor_receipt = await self.blockchain_anchor.get_anchor_proof(license_hash)

            if not anchor_receipt:
                return False

            # Vérifier ancrage
            return await self.blockchain_anchor.verify_anchor(anchor_receipt)

        except Exception:
            return False

    def _validate_license_config(self, config: LicenseConfig) -> None:
        """Valide configuration licence."""
        if not config.site_id:
            raise LicenseManagerError("LIC_002: site_id obligatoire")

        if not config.modules:
            raise LicenseManagerError("LIC_002: modules obligatoires")

        if not config.issuer_id:
            raise LicenseManagerError("LIC_002: issuer_id obligatoire")

        # Validation durée (LIC_003)
        if config.duration_days <= 0:
            raise LicenseManagerError("Durée licence doit être positive")

        if config.duration_days > self.MAX_LICENSE_DURATION_DAYS:
            raise LicenseManagerError(f"LIC_003: Durée max {self.MAX_LICENSE_DURATION_DAYS} jours")

        # Validation modules (LIC_080)
        invalid_modules = [m for m in config.modules if m not in self.AVAILABLE_MODULES]
        if invalid_modules:
            raise LicenseManagerError(f"Modules invalides: {invalid_modules}")

        # Vérifier unicité site (LIC_005)
        if config.site_id in self._licenses and not self._licenses[config.site_id].revoked:
            raise LicenseManagerError(f"LIC_005: Site {config.site_id} a déjà une licence active")

    def _sign_license(self, license: License) -> str:
        """Signe licence avec ECDSA-P384 (LIC_001)."""
        # Créer données canoniques pour signature
        license_data = self._create_license_data_for_signature(license)

        # Signer avec ECDSA-P384
        signature_bytes = self.crypto_provider.sign(license_data.encode("utf-8"), "license_key")

        # Retourner base64
        return base64.b64encode(signature_bytes).decode("utf-8")

    def _verify_license_signature(self, license: License) -> bool:
        """Vérifie signature licence (LIC_010)."""
        try:
            # Recréer données signées
            license_data = self._create_license_data_for_signature(license)

            # Décoder signature
            signature_bytes = base64.b64decode(license.signature)

            # Vérifier signature
            return self.crypto_provider.verify_signature(license_data.encode("utf-8"), signature_bytes, "license_key")
        except Exception:
            return False

    def _validate_license_structure(self, license: License) -> bool:
        """Valide structure licence (LIC_002)."""
        required_fields = [
            license.license_id,
            license.site_id,
            license.issued_at,
            license.expires_at,
            license.modules,
            license.signature,
            license.issuer_id,
        ]

        return all(field is not None for field in required_fields) and len(license.modules) > 0

    def _validate_revocation_signatures(self, site_id: str, reason: str, signatures: List[Signature]) -> None:
        """Valide signatures quorum révocation."""
        revocation_data = f"{site_id}:{reason}:{datetime.now(timezone.utc).isoformat()}"

        for signature in signatures:
            try:
                sig_bytes = base64.b64decode(signature.signature)
                if not self.crypto_provider.verify_signature(
                    revocation_data.encode("utf-8"), sig_bytes, "revocation_key"
                ):
                    raise LicenseManagerError(f"Signature invalide pour {signature.signer_id}")
            except Exception as e:
                raise LicenseManagerError(f"Erreur validation signature {signature.signer_id}: {str(e)}")

    def _create_license_data_for_signature(self, license: License) -> str:
        """Crée données canoniques pour signature."""
        signature_data = {
            "license_id": license.license_id,
            "site_id": license.site_id,
            "issued_at": license.issued_at.isoformat(),
            "expires_at": license.expires_at.isoformat(),
            "modules": sorted(license.modules),  # Ordre déterministe
            "issuer_id": license.issuer_id,
            "organization_id": license.organization_id,
        }

        return json.dumps(signature_data, sort_keys=True, separators=(",", ":"))

    def _compute_license_hash(self, license: License) -> str:
        """Calcule hash SHA-384 licence."""
        import hashlib

        license_data = self._create_license_data_for_signature(license)
        return hashlib.sha384(license_data.encode("utf-8")).hexdigest()

    def _compute_data_hash(self, data: Dict[str, Any]) -> str:
        """Calcule hash SHA-384 données."""
        import hashlib

        data_json = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha384(data_json.encode("utf-8")).hexdigest()

    def get_license_stats(self) -> Dict[str, Any]:
        """Statistiques licences pour monitoring."""
        total_licenses = len(self._licenses)
        active_licenses = sum(1 for lic in self._licenses.values() if not lic.revoked)
        revoked_licenses = total_licenses - active_licenses

        # Calcul licences expirant bientôt
        now = datetime.now(timezone.utc)
        expiring_soon = sum(
            1 for lic in self._licenses.values() if not lic.revoked and (lic.expires_at - now).days <= 30
        )

        return {
            "total_licenses": total_licenses,
            "active_licenses": active_licenses,
            "revoked_licenses": revoked_licenses,
            "expiring_soon_30d": expiring_soon,
            "cloud_mode": self.cloud_mode,
            "max_duration_days": self.MAX_LICENSE_DURATION_DAYS,
            "grace_period_days": self.GRACE_PERIOD_DAYS,
        }
