"""
Tests unitaires pour LOT 11: Logging - Sensitive Masker

Tests de l'invariant:
- LOG_005: Données sensibles JAMAIS en clair (masquées)
"""

import pytest

from src.logging import (
    SensitiveMasker,
    ISensitiveMasker,
)


class TestLOG005SensitiveDataMasking:
    """Tests LOG_005: Données sensibles JAMAIS en clair."""

    def test_LOG_005_password_masked(self) -> None:
        """LOG_005: Password masqué."""
        masker = SensitiveMasker()
        data = {"username": "john", "password": "secret123"}
        result = masker.mask(data)

        assert result["username"] == "john"
        assert result["password"] == "***MASKED***"

    def test_LOG_005_token_masked(self) -> None:
        """LOG_005: Token masqué."""
        masker = SensitiveMasker()
        data = {"user_id": "123", "access_token": "eyJhbGc..."}
        result = masker.mask(data)

        assert result["user_id"] == "123"
        assert result["access_token"] == "***MASKED***"

    def test_LOG_005_api_key_masked(self) -> None:
        """LOG_005: API key masquée."""
        masker = SensitiveMasker()
        data = {"service": "api", "api_key": "sk-abc123"}
        result = masker.mask(data)

        assert result["service"] == "api"
        assert result["api_key"] == "***MASKED***"

    def test_LOG_005_secret_masked(self) -> None:
        """LOG_005: Secret masqué."""
        masker = SensitiveMasker()
        data = {"app": "myapp", "client_secret": "xyz789"}
        result = masker.mask(data)

        assert result["app"] == "myapp"
        assert result["client_secret"] == "***MASKED***"

    def test_LOG_005_credential_masked(self) -> None:
        """LOG_005: Credential masqué."""
        masker = SensitiveMasker()
        data = {"type": "oauth", "credential": "cred123"}
        result = masker.mask(data)

        assert result["type"] == "oauth"
        assert result["credential"] == "***MASKED***"

    def test_LOG_005_nested_dict_masked(self) -> None:
        """LOG_005: Dict imbriqué masqué."""
        masker = SensitiveMasker()
        data = {
            "user": {"name": "john", "password": "secret"},
            "config": {"api_key": "key123"},
        }
        result = masker.mask(data)

        assert result["user"]["name"] == "john"
        assert result["user"]["password"] == "***MASKED***"
        assert result["config"]["api_key"] == "***MASKED***"

    def test_LOG_005_list_with_dicts_masked(self) -> None:
        """LOG_005: Liste avec dicts masquée."""
        masker = SensitiveMasker()
        data = {
            "users": [
                {"name": "john", "password": "pass1"},
                {"name": "jane", "password": "pass2"},
            ]
        }
        result = masker.mask(data)

        assert result["users"][0]["name"] == "john"
        assert result["users"][0]["password"] == "***MASKED***"
        assert result["users"][1]["name"] == "jane"
        assert result["users"][1]["password"] == "***MASKED***"

    def test_LOG_005_case_insensitive(self) -> None:
        """LOG_005: Masquage case-insensitive."""
        masker = SensitiveMasker()
        data = {
            "PASSWORD": "upper",
            "Password": "mixed",
            "password": "lower",
        }
        result = masker.mask(data)

        assert result["PASSWORD"] == "***MASKED***"
        assert result["Password"] == "***MASKED***"
        assert result["password"] == "***MASKED***"

    def test_LOG_005_partial_match(self) -> None:
        """LOG_005: Masquage sur match partiel."""
        masker = SensitiveMasker()
        data = {
            "user_password": "secret",
            "password_hash": "hash123",
            "my_api_key": "key",
        }
        result = masker.mask(data)

        assert result["user_password"] == "***MASKED***"
        assert result["password_hash"] == "***MASKED***"
        assert result["my_api_key"] == "***MASKED***"

    def test_LOG_005_non_sensitive_preserved(self) -> None:
        """LOG_005: Données non sensibles préservées."""
        masker = SensitiveMasker()
        data = {
            "id": 123,
            "name": "test",
            "count": 42,
            "active": True,
            "tags": ["a", "b"],
        }
        result = masker.mask(data)

        assert result["id"] == 123
        assert result["name"] == "test"
        assert result["count"] == 42
        assert result["active"] is True
        assert result["tags"] == ["a", "b"]

    def test_LOG_005_empty_dict(self) -> None:
        """LOG_005: Dict vide retourne dict vide."""
        masker = SensitiveMasker()
        result = masker.mask({})
        assert result == {}

    def test_LOG_005_multiple_sensitive_fields(self) -> None:
        """LOG_005: Multiples champs sensibles masqués."""
        masker = SensitiveMasker()
        data = {
            "password": "p1",
            "token": "t1",
            "api_key": "k1",
            "secret": "s1",
            "auth": "a1",
        }
        result = masker.mask(data)

        for value in result.values():
            assert value == "***MASKED***"

    def test_LOG_005_jwt_masked(self) -> None:
        """LOG_005: JWT masqué."""
        masker = SensitiveMasker()
        data = {"jwt_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
        result = masker.mask(data)

        assert result["jwt_token"] == "***MASKED***"

    def test_LOG_005_bearer_token_masked(self) -> None:
        """LOG_005: Bearer token masqué."""
        masker = SensitiveMasker()
        data = {"bearer_token": "Bearer xyz123"}
        result = masker.mask(data)

        assert result["bearer_token"] == "***MASKED***"


class TestSensitiveMaskerPatterns:
    """Tests gestion des patterns sensibles."""

    def test_default_patterns_loaded(self) -> None:
        """Patterns par défaut chargés."""
        masker = SensitiveMasker()
        patterns = masker.patterns

        assert "password" in patterns
        assert "token" in patterns
        assert "api_key" in patterns
        assert "secret" in patterns

    def test_additional_patterns_added(self) -> None:
        """Patterns additionnels ajoutés."""
        masker = SensitiveMasker(additional_patterns=["custom_field"])
        assert "custom_field" in masker.patterns

    def test_add_pattern(self) -> None:
        """add_pattern ajoute pattern."""
        masker = SensitiveMasker()
        masker.add_pattern("my_custom")

        assert "my_custom" in masker.patterns

        data = {"my_custom_field": "secret"}
        result = masker.mask(data)
        assert result["my_custom_field"] == "***MASKED***"

    def test_add_pattern_empty_rejected(self) -> None:
        """add_pattern rejette pattern vide."""
        masker = SensitiveMasker()

        with pytest.raises(ValueError) as exc:
            masker.add_pattern("")
        assert "empty" in str(exc.value).lower()

    def test_add_pattern_whitespace_rejected(self) -> None:
        """add_pattern rejette whitespace."""
        masker = SensitiveMasker()

        with pytest.raises(ValueError):
            masker.add_pattern("   ")

    def test_add_pattern_no_duplicates(self) -> None:
        """add_pattern évite doublons."""
        masker = SensitiveMasker()
        initial_count = len(masker.patterns)

        masker.add_pattern("password")  # Déjà présent
        assert len(masker.patterns) == initial_count

    def test_remove_pattern(self) -> None:
        """remove_pattern retire pattern."""
        masker = SensitiveMasker()
        masker.add_pattern("custom_pattern")

        result = masker.remove_pattern("custom_pattern")
        assert result is True
        assert "custom_pattern" not in masker.patterns

    def test_remove_pattern_not_found(self) -> None:
        """remove_pattern retourne False si non trouvé."""
        masker = SensitiveMasker()
        result = masker.remove_pattern("nonexistent")
        assert result is False


class TestSensitiveMaskerMethods:
    """Tests méthodes SensitiveMasker."""

    def test_is_sensitive_key_true(self) -> None:
        """is_sensitive_key True pour clé sensible."""
        masker = SensitiveMasker()

        assert masker.is_sensitive_key("password") is True
        assert masker.is_sensitive_key("user_password") is True
        assert masker.is_sensitive_key("PASSWORD") is True
        assert masker.is_sensitive_key("api_key") is True

    def test_is_sensitive_key_false(self) -> None:
        """is_sensitive_key False pour clé non sensible."""
        masker = SensitiveMasker()

        assert masker.is_sensitive_key("username") is False
        assert masker.is_sensitive_key("id") is False
        assert masker.is_sensitive_key("name") is False

    def test_is_sensitive_key_empty(self) -> None:
        """is_sensitive_key False pour clé vide."""
        masker = SensitiveMasker()
        assert masker.is_sensitive_key("") is False

    def test_mask_string(self) -> None:
        """mask_string retourne MASK_VALUE."""
        masker = SensitiveMasker()
        result = masker.mask_string("any_value")
        assert result == "***MASKED***"

    def test_mask_value_if_sensitive_masks(self) -> None:
        """mask_value_if_sensitive masque si clé sensible."""
        masker = SensitiveMasker()
        result = masker.mask_value_if_sensitive("password", "secret")
        assert result == "***MASKED***"

    def test_mask_value_if_sensitive_preserves(self) -> None:
        """mask_value_if_sensitive préserve si clé non sensible."""
        masker = SensitiveMasker()
        result = masker.mask_value_if_sensitive("username", "john")
        assert result == "john"


class TestSensitiveMaskerInterface:
    """Tests conformité interface ISensitiveMasker."""

    def test_implements_interface(self) -> None:
        """SensitiveMasker implémente ISensitiveMasker."""
        masker = SensitiveMasker()
        assert isinstance(masker, ISensitiveMasker)

    def test_mask_value_constant(self) -> None:
        """MASK_VALUE constant défini."""
        assert SensitiveMasker.MASK_VALUE == "***MASKED***"

    def test_sensitive_patterns_defined(self) -> None:
        """SENSITIVE_PATTERNS défini."""
        patterns = ISensitiveMasker.SENSITIVE_PATTERNS
        assert len(patterns) > 0
        assert "password" in patterns


class TestSensitiveMaskerEdgeCases:
    """Tests cas limites SensitiveMasker."""

    def test_mask_non_dict_returns_input(self) -> None:
        """mask retourne input si non dict."""
        masker = SensitiveMasker()
        result = masker.mask("not a dict")  # type: ignore
        assert result == "not a dict"

    def test_deeply_nested_structures(self) -> None:
        """Masquage structures profondément imbriquées."""
        masker = SensitiveMasker()
        data = {
            "level1": {
                "level2": {
                    "level3": {
                        "password": "deep_secret"
                    }
                }
            }
        }
        result = masker.mask(data)

        assert result["level1"]["level2"]["level3"]["password"] == "***MASKED***"

    def test_mixed_list_types(self) -> None:
        """Masquage liste avec types mixtes."""
        masker = SensitiveMasker()
        data = {
            "items": [
                "string",
                123,
                {"password": "secret"},
                ["nested", {"token": "abc"}],
            ]
        }
        result = masker.mask(data)

        assert result["items"][0] == "string"
        assert result["items"][1] == 123
        assert result["items"][2]["password"] == "***MASKED***"
        assert result["items"][3][0] == "nested"
        assert result["items"][3][1]["token"] == "***MASKED***"

    def test_none_values_preserved(self) -> None:
        """Valeurs None préservées."""
        masker = SensitiveMasker()
        data = {"name": None, "password": None}
        result = masker.mask(data)

        assert result["name"] is None
        # Même si la clé est sensible, None est masqué
        assert result["password"] == "***MASKED***"

    def test_numeric_values_in_sensitive_keys(self) -> None:
        """Valeurs numériques masquées si clé sensible."""
        masker = SensitiveMasker()
        data = {"pin": 1234, "secret_code": 5678}
        result = masker.mask(data)

        assert result["pin"] == "***MASKED***"
        assert result["secret_code"] == "***MASKED***"
