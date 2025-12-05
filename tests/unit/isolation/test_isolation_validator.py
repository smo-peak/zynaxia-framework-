"""
Tests unitaires pour IsolationValidator.
"""

import pytest
from unittest.mock import Mock

from src.isolation.isolation_validator import IsolationValidator, IsolationValidatorError, ValidationResult
from src.isolation.tenant_context import TenantContext


class TestIsolationValidator:
    """Tests pour IsolationValidator."""
    
    def setup_method(self):
        """Setup avant chaque test."""
        self.tenant_context = Mock(spec=TenantContext)
        self.validator = IsolationValidator(self.tenant_context)
        self.mock_connection = Mock()
    
    def test_isolation_same_level_effective(self):
        """Même niveau, isolation OK doit retourner True."""
        tenant_a = "550e8400-e29b-41d4-a716-446655440000"
        tenant_b = "660e8400-e29b-41d4-a716-446655440001"
        
        result = self.validator.test_isolation(tenant_a, tenant_b)
        assert result is True  # UUIDs différents = isolation effective
    
    def test_isolation_detects_leak(self):
        """Si fuite détectée, doit retourner False."""
        same_tenant = "550e8400-e29b-41d4-a716-446655440000"
        
        result = self.validator.test_isolation(same_tenant, same_tenant)
        assert result is False  # Même UUID = fuite détectée
    
    def test_cross_level_isolation_child_blocked(self):
        """Enfant ne voit pas parent doit retourner True."""
        child_tenant = "550e8400-e29b-41d4-a716-446655440000"
        parent_tenant = "660e8400-e29b-41d4-a716-446655440001"
        
        result = self.validator.test_cross_level_isolation(
            child_tenant, 3, parent_tenant, 2
        )
        assert result is True  # Level 3 > 2 = isolation effective
    
    def test_validate_all_returns_result(self):
        """validate_all doit retourner ValidationResult correct."""
        tenants = [
            {"id": "550e8400-e29b-41d4-a716-446655440000", "level": 3},
            {"id": "660e8400-e29b-41d4-a716-446655440001", "level": 3},
            {"id": "770e8400-e29b-41d4-a716-446655440002", "level": 2}
        ]
        
        result = self.validator.validate_all(self.mock_connection, tenants)
        
        assert isinstance(result, ValidationResult)
        assert hasattr(result, 'passed')
        assert hasattr(result, 'tests_run')
        assert hasattr(result, 'failures')
        assert result.tests_run > 0
        assert result.passed is True  # Pas de fuites dans ce cas
        assert isinstance(result.failures, list)
    
    def test_invalid_uuid_raises_error(self):
        """UUID invalide doit lever exception."""
        invalid_uuid = "not-a-uuid"
        valid_uuid = "550e8400-e29b-41d4-a716-446655440000"
        
        with pytest.raises(IsolationValidatorError) as exc_info:
            self.validator.test_isolation(invalid_uuid, valid_uuid)
        
        assert "tenant_id invalide" in str(exc_info.value)
        assert invalid_uuid in str(exc_info.value)
    
    def test_requires_tenant_context(self):
        """Vérifie injection dépendance."""
        assert self.validator.tenant_context is self.tenant_context
        
        # Vérifier qu'on ne peut pas créer sans tenant_context
        with pytest.raises(TypeError):
            IsolationValidator()  # Manque tenant_context
    
    def test_cross_level_isolation_invalid_levels(self):
        """Levels incorrects doivent lever exception."""
        child_tenant = "550e8400-e29b-41d4-a716-446655440000"
        parent_tenant = "660e8400-e29b-41d4-a716-446655440001"
        
        # Child level <= parent level doit échouer
        with pytest.raises(IsolationValidatorError) as exc_info:
            self.validator.test_cross_level_isolation(
                child_tenant, 2, parent_tenant, 2  # Même level
            )
        
        assert "child_level doit être > parent_level" in str(exc_info.value)
        
        # Child level < parent level doit aussi échouer
        with pytest.raises(IsolationValidatorError):
            self.validator.test_cross_level_isolation(
                child_tenant, 1, parent_tenant, 2  # Child < parent
            )
    
    def test_validate_all_calculates_tests_correctly(self):
        """validate_all doit calculer correctement le nombre de tests."""
        tenants = [
            {"id": "550e8400-e29b-41d4-a716-446655440000", "level": 3},  # site A
            {"id": "660e8400-e29b-41d4-a716-446655440001", "level": 3},  # site B
            {"id": "770e8400-e29b-41d4-a716-446655440002", "level": 2}   # org
        ]
        
        result = self.validator.validate_all(self.mock_connection, tenants)
        
        # Tests attendus :
        # - Inter-tenant même niveau : site A vs site B (2 tests)
        # - Enfant/parent : site A vs org + site B vs org (2 tests)
        # Total : 4 tests
        assert result.tests_run == 4
        assert result.passed is True
        assert len(result.failures) == 0
    
    def test_validate_all_detects_failures(self):
        """validate_all doit détecter les échecs."""
        # Tenants avec même ID mais levels différents pour forcer échec
        tenants = [
            {"id": "550e8400-e29b-41d4-a716-446655440000", "level": 3},
            {"id": "550e8400-e29b-41d4-a716-446655440000", "level": 3}  # Même ID
        ]
        
        result = self.validator.validate_all(self.mock_connection, tenants)
        
        assert result.tests_run == 2  # 2 tests inter-tenant
        assert result.passed is False
        assert len(result.failures) == 2  # 2 échecs détectés
        assert all("Fuite:" in failure for failure in result.failures)
    
    def test_validate_all_handles_errors(self):
        """validate_all doit gérer les erreurs de validation."""
        tenants = [
            {"id": "invalid-uuid", "level": 3},
            {"id": "660e8400-e29b-41d4-a716-446655440001", "level": 3}
        ]
        
        result = self.validator.validate_all(self.mock_connection, tenants)
        
        assert result.tests_run == 2  # 2 tests tentés
        assert result.passed is False
        assert len(result.failures) == 2  # 2 erreurs capturées
        assert all("Erreur test" in failure for failure in result.failures)
    
    def test_validation_result_structure(self):
        """ValidationResult doit avoir la structure attendue."""
        result = ValidationResult(passed=True, tests_run=5, failures=[])
        
        assert result.passed is True
        assert result.tests_run == 5
        assert result.failures == []
        
        result_with_failures = ValidationResult(
            passed=False, 
            tests_run=3, 
            failures=["error1", "error2"]
        )
        
        assert result_with_failures.passed is False
        assert result_with_failures.tests_run == 3
        assert len(result_with_failures.failures) == 2