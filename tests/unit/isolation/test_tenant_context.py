"""
Tests unitaires pour TenantContext.
"""

import pytest
from unittest.mock import Mock

from src.isolation.tenant_context import TenantContext, TenantContextError


class TestTenantContext:
    """Tests pour TenantContext."""

    def setup_method(self):
        """Setup avant chaque test."""
        self.context = TenantContext()
        self.mock_connection = Mock()

    def test_set_context_valid_uuid(self):
        """UUID valide doit fonctionner."""
        valid_uuid = "550e8400-e29b-41d4-a716-446655440000"
        level = 3

        self.context.set_context(self.mock_connection, valid_uuid, level)

        # Vérifier les 2 appels SQL
        assert self.mock_connection.execute.call_count == 2
        calls = self.mock_connection.execute.call_args_list
        assert calls[0][0][0] == f"SET app.tenant_id = '{valid_uuid}'"
        assert calls[1][0][0] == f"SET app.tenant_level = {level}"

    def test_set_context_invalid_uuid(self):
        """UUID invalide doit lever exception."""
        invalid_uuid = "invalid-uuid-format"

        with pytest.raises(TenantContextError) as exc_info:
            self.context.set_context(self.mock_connection, invalid_uuid, 3)

        assert "tenant_id invalide" in str(exc_info.value)
        assert invalid_uuid in str(exc_info.value)
        # Aucun appel ne doit être fait
        assert self.mock_connection.execute.call_count == 0

    def test_set_context_sql_injection_blocked(self):
        """Tentative injection SQL doit être bloquée."""
        injection_attempt = "'; DROP TABLE events; --"

        with pytest.raises(TenantContextError) as exc_info:
            self.context.set_context(self.mock_connection, injection_attempt, 3)

        assert "tenant_id invalide" in str(exc_info.value)
        # Aucun appel ne doit être fait
        assert self.mock_connection.execute.call_count == 0

    def test_clear_context(self):
        """Clear doit exécuter les RESET."""
        self.context.clear_context(self.mock_connection)

        # Vérifier les 2 appels RESET
        assert self.mock_connection.execute.call_count == 2
        calls = self.mock_connection.execute.call_args_list
        assert calls[0][0][0] == "RESET app.tenant_id"
        assert calls[1][0][0] == "RESET app.tenant_level"

    def test_set_context_negative_level(self):
        """Level négatif doit lever exception."""
        valid_uuid = "550e8400-e29b-41d4-a716-446655440000"
        negative_level = -1

        with pytest.raises(TenantContextError) as exc_info:
            self.context.set_context(self.mock_connection, valid_uuid, negative_level)

        assert "level invalide" in str(exc_info.value)
        assert str(negative_level) in str(exc_info.value)
        # Aucun appel ne doit être fait
        assert self.mock_connection.execute.call_count == 0

    def test_set_context_non_integer_level(self):
        """Level non-entier doit lever exception."""
        valid_uuid = "550e8400-e29b-41d4-a716-446655440000"
        string_level = "3"

        with pytest.raises(TenantContextError):
            self.context.set_context(self.mock_connection, valid_uuid, string_level)

        # Aucun appel ne doit être fait
        assert self.mock_connection.execute.call_count == 0

    def test_set_context_zero_level_allowed(self):
        """Level 0 (platform) doit être autorisé."""
        valid_uuid = "550e8400-e29b-41d4-a716-446655440000"
        platform_level = 0

        self.context.set_context(self.mock_connection, valid_uuid, platform_level)

        # Doit fonctionner normalement
        assert self.mock_connection.execute.call_count == 2

    def test_validate_uuid_edge_cases(self):
        """Tests de validation UUID avec cas limites."""
        valid_uuid = "550e8400-e29b-41d4-a716-446655440000"

        # Cas valides
        self.context._validate_uuid(valid_uuid)
        self.context._validate_uuid("00000000-0000-0000-0000-000000000000")

        # Cas invalides
        with pytest.raises(TenantContextError):
            self.context._validate_uuid("")

        with pytest.raises(TenantContextError):
            self.context._validate_uuid("not-a-uuid")

        with pytest.raises(TenantContextError):
            self.context._validate_uuid(None)
