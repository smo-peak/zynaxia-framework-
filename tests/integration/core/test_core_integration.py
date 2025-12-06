"""
Tests d'intégration pour les composants Core LOT 1.
Vérifie que ConfigLoader, ConfigValidator et CryptoProvider fonctionnent ensemble.
"""

import json
import pytest

from src.core.config_loader import ConfigLoader
from src.core.config_validator import ConfigValidator
from src.core.crypto_provider import CryptoProvider


class TestCoreIntegration:
    """Tests d'intégration pour le module Core."""

    def setup_method(self):
        """Setup avant chaque test."""
        self.loader = ConfigLoader()
        self.validator = ConfigValidator()
        self.crypto = CryptoProvider()

    @pytest.mark.asyncio
    async def test_load_and_validate_valid_config(self):
        """Load + Validate : configuration valide doit passer."""
        # Chargement
        config = await self.loader.load("valid_minimal")

        # Validation
        result = self.validator.validate(config)

        # Vérifications
        assert result.valid is True
        assert len(result.errors) == 0
        assert len(result.warnings) == 0
        assert config["version"] == "1.0"
        assert "hierarchy" in config
        assert "roles" in config

    @pytest.mark.asyncio
    async def test_load_and_validate_invalid_config(self):
        """Load + Validate : configuration invalide doit échouer."""
        # Chargement
        config = await self.loader.load("invalid_wildcard")

        # Validation
        result = self.validator.validate(config)

        # Vérifications
        assert result.valid is False
        assert len(result.errors) >= 1

        # Vérification erreur RUN_021
        run_021_error = next((e for e in result.errors if e.rule_id == "RUN_021"), None)
        assert run_021_error is not None
        assert "Wildcard '*' interdit" in run_021_error.message
        assert "organization:*" in run_021_error.value

    @pytest.mark.asyncio
    async def test_hash_config_after_load(self):
        """Load + Hash : calcule le hash d'une config chargée."""
        # Chargement
        config = await self.loader.load("valid_minimal")

        # Sérialisation pour hash
        config_json = json.dumps(config, sort_keys=True)
        config_bytes = config_json.encode("utf-8")

        # Hash
        config_hash = self.crypto.hash(config_bytes)

        # Vérifications
        assert len(config_hash) == 96
        assert all(c in "0123456789abcdef" for c in config_hash)

        # Hash déterministe
        config_hash2 = self.crypto.hash(config_bytes)
        assert config_hash == config_hash2

    @pytest.mark.asyncio
    async def test_full_flow_load_validate_sign(self):
        """Pipeline complet : Load → Validate → Hash → Sign → Verify."""
        key_id = "integration_test_key"

        # 1. Chargement
        config = await self.loader.load("valid_minimal")
        assert isinstance(config, dict)

        # 2. Validation
        validation_result = self.validator.validate(config)
        assert validation_result.valid is True

        # 3. Sérialisation et Hash
        config_json = json.dumps(config, sort_keys=True)
        config_bytes = config_json.encode("utf-8")
        config_hash = self.crypto.hash(config_bytes)
        assert len(config_hash) == 96

        # 4. Signature
        hash_bytes = config_hash.encode("utf-8")
        signature = self.crypto.sign(hash_bytes, key_id)
        assert signature is not None
        assert len(signature) > 0

        # 5. Vérification signature
        is_valid = self.crypto.verify_signature(hash_bytes, signature, key_id)
        assert is_valid is True

        # 6. Vérification ancrage blockchain (stub)
        anchor_valid = await self.loader.verify_blockchain_anchor("valid_minimal", config_hash)
        assert anchor_valid is True

    @pytest.mark.asyncio
    async def test_multiple_configs_same_flow(self):
        """Vérifier le pipeline avec plusieurs configurations."""
        configs_to_test = ["valid_minimal", "invalid_wildcard"]
        results = {}

        for tenant_id in configs_to_test:
            # Load
            config = await self.loader.load(tenant_id)

            # Validate
            validation = self.validator.validate(config)

            # Hash
            config_json = json.dumps(config, sort_keys=True)
            config_bytes = config_json.encode("utf-8")
            config_hash = self.crypto.hash(config_bytes)

            results[tenant_id] = {
                "config": config,
                "valid": validation.valid,
                "errors": len(validation.errors),
                "hash": config_hash,
            }

        # Vérifications
        assert results["valid_minimal"]["valid"] is True
        assert results["valid_minimal"]["errors"] == 0
        assert len(results["valid_minimal"]["hash"]) == 96

        assert results["invalid_wildcard"]["valid"] is False
        assert results["invalid_wildcard"]["errors"] >= 1
        assert len(results["invalid_wildcard"]["hash"]) == 96

        # Les hash doivent être différents
        assert results["valid_minimal"]["hash"] != results["invalid_wildcard"]["hash"]

    @pytest.mark.asyncio
    async def test_validate_specific_rule_after_load(self):
        """Test de validation d'une règle spécifique après chargement."""
        # Load config invalide
        config = await self.loader.load("invalid_wildcard")

        # Test règle spécifique RUN_021
        error = self.validator.validate_rule("RUN_021", config)
        assert error is not None
        assert error.rule_id == "RUN_021"
        assert "organization:*" in error.value

        # Test règle spécifique RUN_020 (ne devrait pas échouer)
        error_020 = self.validator.validate_rule("RUN_020", config)
        assert error_020 is None  # Pas d'erreur pour cette règle

        # Test règle spécifique LIC_003 (ne devrait pas échouer car pas de license)
        error_003 = self.validator.validate_rule("LIC_003", config)
        assert error_003 is None  # Pas de section license
