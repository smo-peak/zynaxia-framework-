"""
LOT 4: Audit Emitter Implementation

Émetteur d'événements d'audit avec signature cryptographique.

Invariants:
    RUN_044: Signature cryptographique obligatoire pour tous les événements
    RUN_042: Immutabilité garantie par hachage SHA-384
"""

import uuid
import hashlib
import json
import base64
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from .interfaces import IAuditEmitter, AuditEvent, AuditEventType
from ..core.crypto_provider import CryptoProvider


class AuditEmitterError(Exception):
    """Erreur émission événement audit."""

    pass


class AuditEmitter(IAuditEmitter):
    """
    Émetteur d'événements d'audit avec signature cryptographique.

    Conformité:
        RUN_044: Signature ECDSA-P384 obligatoire
        RUN_042: Immutabilité par hachage SHA-384

    Example:
        emitter = AuditEmitter(crypto_provider)
        event = await emitter.emit_event(
            AuditEventType.USER_LOGIN,
            "user-123",
            "tenant-456",
            "login_success"
        )
    """

    def __init__(self, crypto_provider: CryptoProvider):
        """
        Args:
            crypto_provider: Fournisseur cryptographique pour signature
        """
        self.crypto_provider = crypto_provider

    async def emit_event(
        self,
        event_type: AuditEventType,
        user_id: str,
        tenant_id: str,
        action: str,
        resource_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuditEvent:
        """
        Émet événement d'audit signé (RUN_044).

        Args:
            event_type: Type d'événement
            user_id: Identifiant utilisateur
            tenant_id: Identifiant tenant
            action: Action effectuée
            resource_id: Ressource affectée (optionnel)
            metadata: Métadonnées additionnelles
            ip_address: Adresse IP source
            user_agent: User agent client

        Returns:
            Événement signé et haché

        Raises:
            AuditEmitterError: Erreur création/signature
        """
        if not user_id or not tenant_id or not action:
            raise AuditEmitterError("user_id, tenant_id et action sont obligatoires")

        # Validation type événement
        if not isinstance(event_type, AuditEventType):
            raise AuditEmitterError(f"Type événement invalide: {event_type}")

        try:
            # Générer ID unique événement
            event_id = str(uuid.uuid4())

            # Timestamp UTC précis
            timestamp = datetime.now(timezone.utc)

            # Nettoyer métadonnées
            clean_metadata = self._sanitize_metadata(metadata or {})

            # Créer événement préliminaire (sans signature)
            preliminary_event = AuditEvent(
                event_id=event_id,
                event_type=event_type,
                timestamp=timestamp,
                user_id=user_id,
                tenant_id=tenant_id,
                resource_id=resource_id,
                action=action,
                metadata=clean_metadata,
                ip_address=ip_address,
                user_agent=user_agent,
            )

            # Calculer hash de l'événement (RUN_042)
            event_hash = self.compute_event_hash(preliminary_event)

            # Signer l'événement (RUN_044)
            signature = self._sign_event_data(preliminary_event)

            # Créer événement final avec signature
            signed_event = AuditEvent(
                event_id=event_id,
                event_type=event_type,
                timestamp=timestamp,
                user_id=user_id,
                tenant_id=tenant_id,
                resource_id=resource_id,
                action=action,
                metadata=clean_metadata,
                ip_address=ip_address,
                user_agent=user_agent,
                signature=signature,
                hash_value=event_hash,
            )

            return signed_event

        except Exception as e:
            raise AuditEmitterError(f"Erreur création événement audit: {str(e)}")

    def verify_event_signature(self, event: AuditEvent) -> bool:
        """
        Vérifie signature cryptographique événement.

        Args:
            event: Événement à vérifier

        Returns:
            True si signature valide
        """
        if not event.signature:
            return False

        try:
            # Recréer données signées
            event_data = self._create_event_data_for_signature(event)

            # Décoder signature base64
            signature_bytes = base64.b64decode(event.signature)

            # Vérifier signature
            return self.crypto_provider.verify_signature(event_data.encode("utf-8"), signature_bytes, "audit_key")

        except Exception:
            return False

    def compute_event_hash(self, event: AuditEvent) -> str:
        """
        Calcule hash SHA-384 événement (RUN_042).

        Args:
            event: Événement à hacher

        Returns:
            Hash SHA-384 hexadécimal
        """
        try:
            # Créer représentation canonique pour hash
            canonical_data = self._create_canonical_event_data(event)

            # Hash SHA-384 (conformité RUN_042)
            hash_obj = hashlib.sha384(canonical_data.encode("utf-8"))
            return hash_obj.hexdigest()

        except Exception as e:
            raise AuditEmitterError(f"Erreur calcul hash: {str(e)}")

    def _sanitize_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Nettoie métadonnées pour éviter injection/corruption.

        Args:
            metadata: Métadonnées brutes

        Returns:
            Métadonnées nettoyées
        """
        clean_metadata = {}

        for key, value in metadata.items():
            # Valider clé
            if not isinstance(key, str) or len(key) > 100:
                continue

            # Nettoyer valeur selon type
            if isinstance(value, (str, int, float, bool)):
                # Limiter taille des chaînes
                if isinstance(value, str) and len(value) > 1000:
                    value = value[:1000]
                clean_metadata[key] = value
            elif isinstance(value, dict):
                # Récursion limitée pour dictionnaires
                clean_metadata[key] = self._sanitize_dict(value, max_depth=2)
            elif isinstance(value, list):
                # Listes limitées
                clean_metadata[key] = self._sanitize_list(value, max_items=50)

        return clean_metadata

    def _sanitize_dict(self, data: Dict[str, Any], max_depth: int) -> Dict[str, Any]:
        """Nettoie dictionnaire récursivement."""
        if max_depth <= 0:
            return {}

        clean_dict = {}
        for k, v in data.items():
            if isinstance(k, str) and len(k) <= 50:
                if isinstance(v, (str, int, float, bool)):
                    clean_dict[k] = v
                elif isinstance(v, dict):
                    clean_dict[k] = self._sanitize_dict(v, max_depth - 1)

        return clean_dict

    def _sanitize_list(self, data: list, max_items: int) -> list:
        """Nettoie liste."""
        clean_list = []
        for i, item in enumerate(data):
            if i >= max_items:
                break
            if isinstance(item, (str, int, float, bool)):
                clean_list.append(item)

        return clean_list

    def _sign_event_data(self, event: AuditEvent) -> str:
        """
        Signe données événement (RUN_044).

        Args:
            event: Événement à signer

        Returns:
            Signature ECDSA-P384 base64
        """
        # Créer données canoniques pour signature
        event_data = self._create_event_data_for_signature(event)

        # Signer avec ECDSA-P384 (RUN_044)
        signature_bytes = self.crypto_provider.sign(event_data.encode("utf-8"), "audit_key")

        # Convertir en base64 pour stockage
        return base64.b64encode(signature_bytes).decode("utf-8")

    def _create_event_data_for_signature(self, event: AuditEvent) -> str:
        """
        Crée représentation canonique pour signature.

        Args:
            event: Événement

        Returns:
            Données canoniques
        """
        # Ordre fixe des champs pour signature déterministe
        signature_data = {
            "event_id": event.event_id,
            "event_type": event.event_type.value,
            "timestamp": event.timestamp.isoformat(),
            "user_id": event.user_id,
            "tenant_id": event.tenant_id,
            "resource_id": event.resource_id,
            "action": event.action,
            "metadata": event.metadata,
            "ip_address": event.ip_address,
            "user_agent": event.user_agent,
        }

        # JSON canonique (clés triées)
        return json.dumps(signature_data, sort_keys=True, separators=(",", ":"))

    def _create_canonical_event_data(self, event: AuditEvent) -> str:
        """
        Crée représentation canonique pour hash.

        Args:
            event: Événement

        Returns:
            Données canoniques pour hash
        """
        # Inclure tous les champs sauf signature et hash_value
        hash_data = {
            "event_id": event.event_id,
            "event_type": event.event_type.value,
            "timestamp": event.timestamp.isoformat(),
            "user_id": event.user_id,
            "tenant_id": event.tenant_id,
            "resource_id": event.resource_id,
            "action": event.action,
            "metadata": event.metadata,
            "ip_address": event.ip_address,
            "user_agent": event.user_agent,
        }

        # JSON canonique pour hash déterministe
        return json.dumps(hash_data, sort_keys=True, separators=(",", ":"))

    def get_event_summary(self, event: AuditEvent) -> Dict[str, Any]:
        """
        Génère résumé événement pour logging/monitoring.

        Args:
            event: Événement

        Returns:
            Résumé avec informations clés
        """
        return {
            "event_id": event.event_id,
            "type": event.event_type.value,
            "action": event.action,
            "user": event.user_id,
            "tenant": event.tenant_id,
            "resource": event.resource_id,
            "timestamp": event.timestamp.isoformat(),
            "signed": bool(event.signature),
            "hash": event.hash_value[:16] + "..." if event.hash_value else None,
        }
