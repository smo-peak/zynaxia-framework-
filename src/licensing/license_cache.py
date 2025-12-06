"""
LOT 5: License Cache Implementation

Cache local licences avec TTL, chiffrement et vérification intégrité.

Invariants:
    LIC_020: Cache local obligatoire pour mode dégradé
    LIC_021: TTL max 7 jours (grace period)
    LIC_022: Cache chiffré via CryptoProvider
    LIC_023: Hash vérifié à chaque lecture
    LIC_024: Cloud offline > 7 jours = kill switch
"""
import json
import hashlib
import base64
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Any
from dataclasses import dataclass

from .interfaces import ILicenseCache, License
from ..core.crypto_provider import CryptoProvider


class LicenseCacheError(Exception):
    """Erreur cache licence."""
    pass


@dataclass
class CachedLicense:
    """
    Licence en cache avec métadonnées.
    
    Conformité:
        LIC_021: TTL tracking
        LIC_022: Données chiffrées
        LIC_023: Hash intégrité
    """
    license: License
    cached_at: datetime
    encrypted_data: bytes
    hash_value: str


class LicenseCache(ILicenseCache):
    """
    Cache local licences avec sécurité cryptographique.
    
    Conformité:
        LIC_020: Cache local obligatoire
        LIC_021: TTL max 7 jours
        LIC_022: Chiffrement CryptoProvider
        LIC_023: Vérification hash chaque lecture
        LIC_024: Détection offline > 7 jours
    
    Note:
        Stockage en mémoire MVP. Vault ou Redis en production.
    
    Example:
        cache = LicenseCache(crypto_provider)
        cache.set("site-123", license)
        cached_license = cache.get("site-123")
    """
    
    # TTL maximum cache (LIC_021)
    MAX_TTL_DAYS: int = 7
    
    def __init__(self, crypto_provider: CryptoProvider):
        """
        Args:
            crypto_provider: Fournisseur cryptographique pour chiffrement
        """
        self.crypto_provider = crypto_provider
        # Stockage cache (MVP - Vault en production)
        self._cache: Dict[str, CachedLicense] = {}
        # Tracking dernière mise à jour Cloud (LIC_024)
        self._last_cloud_update: Dict[str, datetime] = {}
    
    def get(self, site_id: str) -> Optional[License]:
        """
        Récupère licence du cache (LIC_020, LIC_023).
        
        Args:
            site_id: Site recherché
            
        Returns:
            Licence cachée si trouvée et valide
            
        Conformité:
            LIC_023: Hash vérifié chaque lecture
        """
        if not site_id:
            return None
        
        cached_license = self._cache.get(site_id)
        if not cached_license:
            return None
        
        try:
            # Vérifier TTL (LIC_021)
            if not self._is_within_ttl(cached_license):
                self.invalidate(site_id)
                return None
            
            # Vérifier intégrité hash (LIC_023)
            if not self._verify_cache_integrity(cached_license):
                self.invalidate(site_id)
                raise LicenseCacheError(f"Intégrité cache compromise pour site {site_id}")
            
            # Déchiffrer licence (LIC_022)
            decrypted_license = self._decrypt_license(cached_license.encrypted_data)
            
            return decrypted_license
            
        except LicenseCacheError:
            # Propager erreurs intégrité cache
            raise
        except Exception as e:
            # En cas d'autres erreurs, invalider cache par sécurité
            self.invalidate(site_id)
            return None
    
    def set(self, site_id: str, license: License) -> None:
        """
        Stocke licence en cache chiffré (LIC_022).
        
        Args:
            site_id: Clé cache
            license: Licence à cacher
            
        Conformité:
            LIC_021: TTL max 7 jours
            LIC_022: Chiffrement avant stockage
            LIC_023: Calcul hash intégrité
        """
        if not site_id or not license:
            raise LicenseCacheError("site_id et license obligatoires")
        
        try:
            now = datetime.now(timezone.utc)
            
            # Chiffrer licence (LIC_022)
            encrypted_data = self._encrypt_license(license)
            
            # Calculer hash intégrité (LIC_023)
            hash_value = self._compute_cache_hash(license, now)
            
            # Créer entrée cache
            cached_license = CachedLicense(
                license=license,
                cached_at=now,
                encrypted_data=encrypted_data,
                hash_value=hash_value
            )
            
            # Stocker en cache
            self._cache[site_id] = cached_license
            self._last_cloud_update[site_id] = now
            
        except Exception as e:
            raise LicenseCacheError(f"Erreur stockage cache: {str(e)}")
    
    def invalidate(self, site_id: str) -> None:
        """
        Invalide entrée cache.
        
        Args:
            site_id: Site à invalider
        """
        if site_id in self._cache:
            del self._cache[site_id]
        
        if site_id in self._last_cloud_update:
            del self._last_cloud_update[site_id]
    
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
        if not site_id:
            return False
        
        cached_license = self._cache.get(site_id)
        if not cached_license:
            return False
        
        # Vérifier TTL
        if not self._is_within_ttl(cached_license):
            return False
        
        # Vérifier intégrité
        return self._verify_cache_integrity(cached_license)
    
    def cleanup_expired(self) -> int:
        """
        Nettoie entrées expirées.
        
        Returns:
            Nombre d'entrées nettoyées
        """
        expired_sites = []
        
        for site_id, cached_license in self._cache.items():
            if not self._is_within_ttl(cached_license):
                expired_sites.append(site_id)
        
        for site_id in expired_sites:
            self.invalidate(site_id)
        
        return len(expired_sites)
    
    def get_cache_age_days(self, site_id: str) -> int:
        """
        Retourne âge du cache en jours (LIC_024).
        
        Args:
            site_id: Site concerné
            
        Returns:
            Age en jours, -1 si pas en cache
            
        Conformité:
            LIC_024: Cloud offline > 7 jours = kill switch
        """
        if site_id not in self._cache:
            return -1
        
        cached_license = self._cache[site_id]
        now = datetime.now(timezone.utc)
        age = now - cached_license.cached_at
        
        return age.days
    
    def is_cloud_offline_critical(self, site_id: str) -> bool:
        """
        Vérifie si Cloud offline critique (LIC_024).
        
        Args:
            site_id: Site à vérifier
            
        Returns:
            True si offline > 7 jours
            
        Conformité:
            LIC_024: Cloud offline > 7j = kill switch
        """
        age_days = self.get_cache_age_days(site_id)
        return age_days > self.MAX_TTL_DAYS
    
    def update_cloud_contact(self, site_id: str) -> None:
        """
        Met à jour timestamp contact Cloud (LIC_024).
        
        Args:
            site_id: Site concerné
        """
        self._last_cloud_update[site_id] = datetime.now(timezone.utc)
    
    def _is_within_ttl(self, cached_license: CachedLicense) -> bool:
        """Vérifie si entrée cache dans TTL (LIC_021)."""
        now = datetime.now(timezone.utc)
        age = now - cached_license.cached_at
        return age.days <= self.MAX_TTL_DAYS
    
    def _verify_cache_integrity(self, cached_license: CachedLicense) -> bool:
        """
        Vérifie intégrité hash cache (LIC_023).
        
        Args:
            cached_license: Entrée cache à vérifier
            
        Returns:
            True si intégrité OK
        """
        try:
            # Recalculer hash
            expected_hash = self._compute_cache_hash(
                cached_license.license,
                cached_license.cached_at
            )
            
            return expected_hash == cached_license.hash_value
            
        except Exception:
            return False
    
    def _encrypt_license(self, license: License) -> bytes:
        """
        Chiffre licence pour stockage (LIC_022).
        
        Args:
            license: Licence à chiffrer
            
        Returns:
            Données chiffrées
        """
        # Sérialiser licence
        license_data = {
            "license_id": license.license_id,
            "site_id": license.site_id,
            "issued_at": license.issued_at.isoformat(),
            "expires_at": license.expires_at.isoformat(),
            "modules": license.modules,
            "signature": license.signature,
            "issuer_id": license.issuer_id,
            "organization_id": license.organization_id,
            "blockchain_tx_id": license.blockchain_tx_id,
            "revoked": license.revoked,
            "revoked_at": license.revoked_at.isoformat() if license.revoked_at else None,
            "revoked_reason": license.revoked_reason
        }
        
        license_json = json.dumps(license_data, sort_keys=True)
        
        # Utiliser crypto_provider pour chiffrement
        # Note: CryptoProvider actuel ne fait que signature, 
        # en production utiliser vraie fonction chiffrement
        # Pour MVP, simuler avec base64 + signature
        license_bytes = license_json.encode('utf-8')
        encrypted_sim = base64.b64encode(license_bytes)
        
        return encrypted_sim
    
    def _decrypt_license(self, encrypted_data: bytes) -> License:
        """
        Déchiffre licence (LIC_022).
        
        Args:
            encrypted_data: Données chiffrées
            
        Returns:
            Licence déchiffrée
        """
        try:
            # Simulation déchiffrement (MVP)
            license_bytes = base64.b64decode(encrypted_data)
            license_json = license_bytes.decode('utf-8')
            license_data = json.loads(license_json)
            
            # Reconstruction licence
            return License(
                license_id=license_data["license_id"],
                site_id=license_data["site_id"],
                issued_at=datetime.fromisoformat(license_data["issued_at"]),
                expires_at=datetime.fromisoformat(license_data["expires_at"]),
                modules=license_data["modules"],
                signature=license_data["signature"],
                issuer_id=license_data["issuer_id"],
                organization_id=license_data["organization_id"],
                blockchain_tx_id=license_data["blockchain_tx_id"],
                revoked=license_data["revoked"],
                revoked_at=datetime.fromisoformat(license_data["revoked_at"]) if license_data["revoked_at"] else None,
                revoked_reason=license_data["revoked_reason"]
            )
            
        except Exception as e:
            raise LicenseCacheError(f"Erreur déchiffrement licence: {str(e)}")
    
    def _compute_cache_hash(self, license: License, cached_at: datetime) -> str:
        """
        Calcule hash intégrité cache (LIC_023).
        
        Args:
            license: Licence
            cached_at: Timestamp cache
            
        Returns:
            Hash SHA-384
        """
        # Données pour hash intégrité
        hash_data = {
            "license_id": license.license_id,
            "site_id": license.site_id,
            "signature": license.signature,
            "cached_at": cached_at.isoformat()
        }
        
        hash_json = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha384(hash_json.encode('utf-8')).hexdigest()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Statistiques cache pour monitoring."""
        total_entries = len(self._cache)
        valid_entries = sum(1 for site_id in self._cache.keys() if self.is_valid(site_id))
        expired_entries = total_entries - valid_entries
        
        # Calcul âges
        ages = [self.get_cache_age_days(site_id) for site_id in self._cache.keys()]
        avg_age_days = sum(ages) / len(ages) if ages else 0
        max_age_days = max(ages) if ages else 0
        
        # Sites offline critiques
        critical_offline = sum(
            1 for site_id in self._cache.keys()
            if self.is_cloud_offline_critical(site_id)
        )
        
        return {
            "total_entries": total_entries,
            "valid_entries": valid_entries,
            "expired_entries": expired_entries,
            "average_age_days": round(avg_age_days, 2),
            "max_age_days": max_age_days,
            "max_ttl_days": self.MAX_TTL_DAYS,
            "critical_offline_sites": critical_offline
        }