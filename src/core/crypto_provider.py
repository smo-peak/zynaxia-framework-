"""
ZYNAXIA Framework - Crypto Provider Implementation
Opérations cryptographiques conformes RGS 3 étoiles.
"""

import hashlib
from typing import Dict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey

from .interfaces import ICryptoProvider


class CryptoProvider(ICryptoProvider):
    """Implémentation des opérations cryptographiques RGS 3 étoiles."""

    def __init__(self):
        self._keys: Dict[str, EllipticCurvePrivateKey] = {}

    def _get_or_create_key(self, key_id: str) -> EllipticCurvePrivateKey:
        """Récupère ou crée une clé ECDSA-P384."""
        if key_id not in self._keys:
            self._keys[key_id] = ec.generate_private_key(ec.SECP384R1())
        return self._keys[key_id]

    def sign(self, data: bytes, key_id: str) -> bytes:
        """
        Signe des données avec ECDSA-P384.

        Args:
            data: Données à signer
            key_id: ID de la clé

        Returns:
            Signature DER-encoded
        """
        private_key = self._get_or_create_key(key_id)
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA384()))
        return signature

    def verify_signature(self, data: bytes, signature: bytes, key_id: str) -> bool:
        """Vérifie une signature ECDSA-P384."""
        try:
            private_key = self._get_or_create_key(key_id)
            public_key = private_key.public_key()
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA384()))
            return True
        except Exception:
            return False

    def hash(self, data: bytes) -> str:
        """
        Calcule hash SHA-384.

        Returns:
            Hash hex string (96 caractères)
        """
        digest = hashlib.sha384(data).hexdigest()
        return digest
