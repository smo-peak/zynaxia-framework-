"""
Tests unitaires pour ConfigValidator.
"""

import pytest

from src.core.config_validator import ConfigValidator
from src.core.interfaces import ValidationSeverity


class TestConfigValidator:
    """Tests pour ConfigValidator."""
    
    def setup_method(self):
        """Setup avant chaque test."""
        self.validator = ConfigValidator()
    
    def test_valid_config_passes(self):
        """Une configuration valide doit passer tous les tests."""
        config = {
            "hierarchy": {
                "levels": [
                    {"id": 0, "name": "platform"},
                    {"id": 1, "name": "partner"},
                    {"id": 2, "name": "organization"},
                    {"id": 3, "name": "site"}
                ]
            },
            "roles": [
                {
                    "id": "platform_admin",
                    "level": 0,
                    "permissions": ["platform:*"]
                },
                {
                    "id": "site_operator",
                    "level": 3,
                    "permissions": ["site:events:read", "site:events:write"]
                }
            ],
            "license": {
                "duration_days": 365
            }
        }
        
        result = self.validator.validate(config)
        
        assert result.valid is True
        assert len(result.errors) == 0
        assert len(result.warnings) == 0
    
    def test_wildcard_blocked_for_non_platform(self):
        """RUN_021: Wildcard doit être bloqué pour les rôles non-platform."""
        config = {
            "roles": [
                {
                    "id": "site_admin",
                    "level": 3,
                    "permissions": ["site:*"]
                }
            ]
        }
        
        result = self.validator.validate(config)
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0].rule_id == "RUN_021"
        assert "Wildcard '*' interdit" in result.errors[0].message
        assert result.errors[0].severity == ValidationSeverity.BLOCKING
    
    def test_wildcard_allowed_for_platform(self):
        """RUN_021: Wildcard doit être autorisé pour le niveau 0 (platform)."""
        config = {
            "roles": [
                {
                    "id": "platform_admin",
                    "level": 0,
                    "permissions": ["platform:*", "system:*"]
                }
            ]
        }
        
        result = self.validator.validate(config)
        
        assert result.valid is True
        assert len(result.errors) == 0
    
    def test_role_cannot_have_higher_level_permissions(self):
        """RUN_020: Rôle niveau N ne peut avoir permissions niveau N-1."""
        config = {
            "hierarchy": {
                "levels": [
                    {"id": 0, "name": "platform"},
                    {"id": 1, "name": "partner"},
                    {"id": 2, "name": "organization"},
                    {"id": 3, "name": "site"}
                ]
            },
            "roles": [
                {
                    "id": "site_admin",
                    "level": 3,
                    "permissions": ["organization:manage", "site:events:read"]
                }
            ]
        }
        
        result = self.validator.validate(config)
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0].rule_id == "RUN_020"
        assert "niveau 3 ne peut avoir permission de niveau 2" in result.errors[0].message
        assert result.errors[0].value == "organization:manage"
    
    def test_license_duration_max_366_days(self):
        """LIC_003: Durée licence ne peut dépasser 366 jours."""
        config = {
            "license": {
                "duration_days": 400
            }
        }
        
        result = self.validator.validate(config)
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0].rule_id == "LIC_003"
        assert "dépasse le maximum de 366 jours" in result.errors[0].message
        assert result.errors[0].value == "400"
    
    def test_license_duration_366_days_allowed(self):
        """LIC_003: 366 jours exactement doit être autorisé."""
        config = {
            "license": {
                "duration_days": 366
            }
        }
        
        result = self.validator.validate(config)
        
        assert result.valid is True
        assert len(result.errors) == 0
    
    def test_validate_rule_specific(self):
        """validate_rule doit valider une règle spécifique."""
        config = {
            "roles": [
                {
                    "id": "invalid_role",
                    "level": 2,
                    "permissions": ["role:*"]
                }
            ]
        }
        
        error = self.validator.validate_rule("RUN_021", config)
        
        assert error is not None
        assert error.rule_id == "RUN_021"
        assert "Wildcard '*' interdit" in error.message
    
    def test_validate_unknown_rule(self):
        """validate_rule doit retourner une erreur pour une règle inconnue."""
        config = {}
        
        error = self.validator.validate_rule("UNKNOWN_RULE", config)
        
        assert error is not None
        assert error.rule_id == "UNKNOWN_RULE"
        assert "Règle inconnue" in error.message
    
    def test_multiple_errors_collected(self):
        """validate doit collecter TOUTES les erreurs, pas fail-fast."""
        config = {
            "roles": [
                {
                    "id": "bad_role",
                    "level": 2,
                    "permissions": ["role:*"]
                }
            ],
            "license": {
                "duration_days": 500
            }
        }
        
        result = self.validator.validate(config)
        
        assert result.valid is False
        assert len(result.errors) == 2
        rule_ids = [error.rule_id for error in result.errors]
        assert "RUN_021" in rule_ids
        assert "LIC_003" in rule_ids