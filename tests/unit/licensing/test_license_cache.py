"""
Tests unitaires LicenseCache

Invariants testés:
    LIC_020: Cache local obligatoire pour mode dégradé
    LIC_021: TTL max 7 jours (grace period)
    LIC_022: Cache chiffré via CryptoProvider
    LIC_023: Hash vérifié à chaque lecture
    LIC_024: Cloud offline > 7 jours = kill switch
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock

from src.licensing.interfaces import ILicenseCache, License
from src.licensing.license_cache import LicenseCache, LicenseCacheError, CachedLicense
from src.core.crypto_provider import CryptoProvider


# ══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def crypto_provider():
    """CryptoProvider mocké pour tests."""
    provider = Mock()
    return provider


@pytest.fixture
def license_cache(crypto_provider):
    """LicenseCache instance pour tests."""
    return LicenseCache(crypto_provider)


@pytest.fixture
def sample_license():
    """Licence échantillon pour tests."""
    now = datetime.now(timezone.utc)
    return License(
        license_id="license-123",
        site_id="site-456",
        issued_at=now - timedelta(days=30),
        expires_at=now + timedelta(days=60),
        modules=["surveillance", "access_control"],
        signature="valid_signature_base64",
        issuer_id="cloud-license-manager",
        organization_id="org-789",
        blockchain_tx_id="0xabc123",
    )


@pytest.fixture
def expired_license():
    """Licence expirée pour tests."""
    now = datetime.now(timezone.utc)
    return License(
        license_id="expired-456",
        site_id="site-expired",
        issued_at=now - timedelta(days=95),
        expires_at=now - timedelta(days=5),
        modules=["surveillance"],
        signature="expired_signature_base64",
        issuer_id="cloud-license-manager",
    )


# ══════════════════════════════════════════════════════════════════════════════
# TESTS INTERFACE
# ══════════════════════════════════════════════════════════════════════════════


class TestLicenseCacheInterface:
    """Vérifie conformité interface."""

    def test_implements_interface(self, license_cache):
        """LicenseCache implémente ILicenseCache."""
        assert isinstance(license_cache, ILicenseCache)

    def test_max_ttl_constant(self):
        """TTL max = 7 jours (LIC_021)."""
        assert LicenseCache.MAX_TTL_DAYS == 7


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_020: CACHE LOCAL OBLIGATOIRE
# ══════════════════════════════════════════════════════════════════════════════


class TestLIC020Compliance:
    """Tests conformité LIC_020: Cache local obligatoire."""

    def test_LIC_020_cache_stores_license(self, license_cache, sample_license):
        """LIC_020: Cache peut stocker licence."""
        # Ne doit pas lever d'exception
        license_cache.set(sample_license.site_id, sample_license)

        # Vérifier stockage
        assert license_cache.is_valid(sample_license.site_id)

    def test_LIC_020_cache_retrieves_license(self, license_cache, sample_license):
        """LIC_020: Cache peut récupérer licence."""
        license_cache.set(sample_license.site_id, sample_license)

        retrieved = license_cache.get(sample_license.site_id)

        assert retrieved is not None
        assert retrieved.license_id == sample_license.license_id
        assert retrieved.site_id == sample_license.site_id

    def test_LIC_020_cache_supports_multiple_sites(self, license_cache, sample_license):
        """LIC_020: Cache supporte multiples sites."""
        # Créer licence pour autre site
        now = datetime.now(timezone.utc)
        license2 = License(
            license_id="license-789",
            site_id="site-other",
            issued_at=now,
            expires_at=now + timedelta(days=90),
            modules=["surveillance"],
            signature="signature2",
            issuer_id="issuer",
        )

        # Stocker les deux
        license_cache.set(sample_license.site_id, sample_license)
        license_cache.set(license2.site_id, license2)

        # Vérifier les deux
        assert license_cache.get(sample_license.site_id) is not None
        assert license_cache.get(license2.site_id) is not None


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_021: TTL MAX 7 JOURS
# ══════════════════════════════════════════════════════════════════════════════


class TestLIC021Compliance:
    """Tests conformité LIC_021: TTL max 7 jours."""

    def test_LIC_021_fresh_cache_within_ttl(self, license_cache, sample_license):
        """LIC_021: Cache récent dans TTL."""
        license_cache.set(sample_license.site_id, sample_license)

        # Cache récent = valide
        assert license_cache.is_valid(sample_license.site_id)
        assert license_cache.get_cache_age_days(sample_license.site_id) == 0

    def test_LIC_021_old_cache_exceeds_ttl(self, license_cache, sample_license):
        """LIC_021: Cache ancien dépasse TTL."""
        license_cache.set(sample_license.site_id, sample_license)

        # Simuler cache ancien en modifiant timestamp
        cached_license = license_cache._cache[sample_license.site_id]
        old_time = datetime.now(timezone.utc) - timedelta(days=8)  # > 7 jours
        license_cache._cache[sample_license.site_id] = CachedLicense(
            license=cached_license.license,
            cached_at=old_time,
            encrypted_data=cached_license.encrypted_data,
            hash_value=cached_license.hash_value,
        )

        # Cache expiré = invalide
        assert not license_cache.is_valid(sample_license.site_id)
        assert license_cache.get_cache_age_days(sample_license.site_id) == 8

    def test_LIC_021_get_returns_none_if_expired(self, license_cache, sample_license):
        """LIC_021: get() retourne None si expiré."""
        license_cache.set(sample_license.site_id, sample_license)

        # Expirer cache
        cached_license = license_cache._cache[sample_license.site_id]
        old_time = datetime.now(timezone.utc) - timedelta(days=8)
        license_cache._cache[sample_license.site_id] = CachedLicense(
            license=cached_license.license,
            cached_at=old_time,
            encrypted_data=cached_license.encrypted_data,
            hash_value=cached_license.hash_value,
        )

        # get() doit retourner None
        result = license_cache.get(sample_license.site_id)
        assert result is None

        # Et invalider l'entrée
        assert sample_license.site_id not in license_cache._cache


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_022: CACHE CHIFFRÉ
# ══════════════════════════════════════════════════════════════════════════════


class TestLIC022Compliance:
    """Tests conformité LIC_022: Cache chiffré."""

    def test_LIC_022_license_encrypted_in_cache(self, license_cache, sample_license):
        """LIC_022: Licence chiffrée en cache."""
        license_cache.set(sample_license.site_id, sample_license)

        # Vérifier chiffrement dans cache interne
        cached_license = license_cache._cache[sample_license.site_id]
        assert cached_license.encrypted_data is not None
        assert len(cached_license.encrypted_data) > 0

        # Données chiffrées ≠ données originales
        assert sample_license.license_id.encode() not in cached_license.encrypted_data

    def test_LIC_022_decryption_restores_license(self, license_cache, sample_license):
        """LIC_022: Déchiffrement restaure licence."""
        license_cache.set(sample_license.site_id, sample_license)
        retrieved = license_cache.get(sample_license.site_id)

        # Licence restaurée identique
        assert retrieved.license_id == sample_license.license_id
        assert retrieved.site_id == sample_license.site_id
        assert retrieved.modules == sample_license.modules
        assert retrieved.signature == sample_license.signature
        assert retrieved.issuer_id == sample_license.issuer_id
        assert retrieved.blockchain_tx_id == sample_license.blockchain_tx_id

    def test_LIC_022_encryption_error_handled(self, license_cache):
        """LIC_022: Erreur chiffrement gérée."""
        # Licence invalide pour tester gestion d'erreur
        invalid_license = None

        with pytest.raises(LicenseCacheError):
            license_cache.set("site-123", invalid_license)


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_023: HASH VÉRIFIÉ CHAQUE LECTURE
# ══════════════════════════════════════════════════════════════════════════════


class TestLIC023Compliance:
    """Tests conformité LIC_023: Hash vérifié chaque lecture."""

    def test_LIC_023_hash_computed_on_set(self, license_cache, sample_license):
        """LIC_023: Hash calculé lors stockage."""
        license_cache.set(sample_license.site_id, sample_license)

        # Hash présent
        cached_license = license_cache._cache[sample_license.site_id]
        assert cached_license.hash_value is not None
        assert len(cached_license.hash_value) == 96  # SHA-384 = 96 caractères hex

    def test_LIC_023_hash_verified_on_get(self, license_cache, sample_license):
        """LIC_023: Hash vérifié à chaque lecture."""
        license_cache.set(sample_license.site_id, sample_license)

        # Première lecture OK
        result1 = license_cache.get(sample_license.site_id)
        assert result1 is not None

        # Corrompre hash
        cached_license = license_cache._cache[sample_license.site_id]
        license_cache._cache[sample_license.site_id] = CachedLicense(
            license=cached_license.license,
            cached_at=cached_license.cached_at,
            encrypted_data=cached_license.encrypted_data,
            hash_value="corrupted_hash_value",
        )

        # Lecture doit échouer et invalider cache
        with pytest.raises(LicenseCacheError, match="Intégrité cache compromise"):
            license_cache.get(sample_license.site_id)

        # Cache invalidé
        assert sample_license.site_id not in license_cache._cache

    def test_LIC_023_is_valid_checks_integrity(self, license_cache, sample_license):
        """LIC_023: is_valid vérifie intégrité."""
        license_cache.set(sample_license.site_id, sample_license)

        # Initialement valide
        assert license_cache.is_valid(sample_license.site_id)

        # Corrompre hash
        cached_license = license_cache._cache[sample_license.site_id]
        license_cache._cache[sample_license.site_id] = CachedLicense(
            license=cached_license.license,
            cached_at=cached_license.cached_at,
            encrypted_data=cached_license.encrypted_data,
            hash_value="invalid_hash",
        )

        # Plus valide
        assert not license_cache.is_valid(sample_license.site_id)


# ══════════════════════════════════════════════════════════════════════════════
# TESTS LIC_024: CLOUD OFFLINE > 7 JOURS = KILL SWITCH
# ══════════════════════════════════════════════════════════════════════════════


class TestLIC024Compliance:
    """Tests conformité LIC_024: Cloud offline > 7 jours."""

    def test_LIC_024_cloud_contact_tracked(self, license_cache, sample_license):
        """LIC_024: Contact Cloud suivi."""
        license_cache.set(sample_license.site_id, sample_license)

        # Mise à jour contact
        license_cache.update_cloud_contact(sample_license.site_id)

        # Age = 0
        assert license_cache.get_cache_age_days(sample_license.site_id) == 0

    def test_LIC_024_offline_critical_detection(self, license_cache, sample_license):
        """LIC_024: Détection offline critique."""
        license_cache.set(sample_license.site_id, sample_license)

        # Pas critique initialement
        assert not license_cache.is_cloud_offline_critical(sample_license.site_id)

        # Simuler offline ancien
        cached_license = license_cache._cache[sample_license.site_id]
        old_time = datetime.now(timezone.utc) - timedelta(days=8)  # > 7 jours
        license_cache._cache[sample_license.site_id] = CachedLicense(
            license=cached_license.license,
            cached_at=old_time,
            encrypted_data=cached_license.encrypted_data,
            hash_value=cached_license.hash_value,
        )

        # Maintenant critique
        assert license_cache.is_cloud_offline_critical(sample_license.site_id)

    def test_LIC_024_offline_critical_returns_false_for_nonexistent(self, license_cache):
        """LIC_024: Offline critique = False pour site inexistant."""
        assert not license_cache.is_cloud_offline_critical("nonexistent-site")


# ══════════════════════════════════════════════════════════════════════════════
# TESTS GESTION CACHE
# ══════════════════════════════════════════════════════════════════════════════


class TestCacheManagement:
    """Tests gestion cache."""

    def test_invalidate_removes_cache(self, license_cache, sample_license):
        """invalidate() supprime cache."""
        license_cache.set(sample_license.site_id, sample_license)
        assert license_cache.is_valid(sample_license.site_id)

        license_cache.invalidate(sample_license.site_id)
        assert not license_cache.is_valid(sample_license.site_id)
        assert license_cache.get(sample_license.site_id) is None

    def test_cleanup_expired_removes_old_entries(self, license_cache, sample_license):
        """cleanup_expired() supprime entrées expirées."""
        # Stocker licence
        license_cache.set(sample_license.site_id, sample_license)

        # Expirer
        cached_license = license_cache._cache[sample_license.site_id]
        old_time = datetime.now(timezone.utc) - timedelta(days=8)
        license_cache._cache[sample_license.site_id] = CachedLicense(
            license=cached_license.license,
            cached_at=old_time,
            encrypted_data=cached_license.encrypted_data,
            hash_value=cached_license.hash_value,
        )

        # Nettoyer
        cleaned = license_cache.cleanup_expired()

        assert cleaned == 1
        assert sample_license.site_id not in license_cache._cache

    def test_get_returns_none_for_empty_site_id(self, license_cache):
        """get() retourne None pour site_id vide."""
        assert license_cache.get("") is None
        assert license_cache.get(None) is None

    def test_get_returns_none_for_nonexistent_site(self, license_cache):
        """get() retourne None pour site inexistant."""
        assert license_cache.get("nonexistent-site") is None


# ══════════════════════════════════════════════════════════════════════════════
# TESTS VALIDATION ENTRÉES
# ══════════════════════════════════════════════════════════════════════════════


class TestInputValidation:
    """Tests validation entrées."""

    def test_set_empty_site_id_fails(self, license_cache, sample_license):
        """set() avec site_id vide échoue."""
        with pytest.raises(LicenseCacheError, match="site_id et license obligatoires"):
            license_cache.set("", sample_license)

    def test_set_none_license_fails(self, license_cache):
        """set() avec licence None échoue."""
        with pytest.raises(LicenseCacheError, match="site_id et license obligatoires"):
            license_cache.set("site-123", None)

    def test_is_valid_empty_site_id_returns_false(self, license_cache):
        """is_valid() avec site_id vide retourne False."""
        assert not license_cache.is_valid("")
        assert not license_cache.is_valid(None)

    def test_get_cache_age_nonexistent_returns_minus_one(self, license_cache):
        """get_cache_age_days() pour site inexistant retourne -1."""
        assert license_cache.get_cache_age_days("nonexistent") == -1


# ══════════════════════════════════════════════════════════════════════════════
# TESTS STATISTIQUES
# ══════════════════════════════════════════════════════════════════════════════


class TestCacheStatistics:
    """Tests statistiques cache."""

    def test_get_cache_stats_empty_cache(self, license_cache):
        """Statistiques cache vide."""
        stats = license_cache.get_cache_stats()

        assert stats["total_entries"] == 0
        assert stats["valid_entries"] == 0
        assert stats["expired_entries"] == 0
        assert stats["max_ttl_days"] == 7
        assert stats["critical_offline_sites"] == 0

    def test_get_cache_stats_with_entries(self, license_cache, sample_license):
        """Statistiques cache avec entrées."""
        # Ajouter licence
        license_cache.set(sample_license.site_id, sample_license)

        # Ajouter licence expirée
        license_cache.set("site-expired", sample_license)
        cached_license = license_cache._cache["site-expired"]
        old_time = datetime.now(timezone.utc) - timedelta(days=8)
        license_cache._cache["site-expired"] = CachedLicense(
            license=cached_license.license,
            cached_at=old_time,
            encrypted_data=cached_license.encrypted_data,
            hash_value=cached_license.hash_value,
        )

        stats = license_cache.get_cache_stats()

        assert stats["total_entries"] == 2
        assert stats["valid_entries"] == 1
        assert stats["expired_entries"] == 1
        assert stats["critical_offline_sites"] == 1
        assert stats["average_age_days"] >= 0
        assert stats["max_age_days"] >= 0
