"""
Tests unitaires pour LOT 10: Network - TimeoutManager

Tests des invariants:
- NET_001: Timeout connexion 10 secondes max
- NET_002: Timeout requête 30 secondes max (configurable par endpoint)
"""

import pytest

from src.network import (
    TimeoutManager,
    TimeoutConfig,
    TimeoutType,
    TimeoutExceededError,
    InvalidTimeoutError,
    ITimeoutManager,
)


class TestNET001ConnectionTimeout:
    """Tests NET_001: Timeout connexion 10 secondes max."""

    def test_NET_001_default_connection_timeout_is_10s(self) -> None:
        """NET_001: Timeout connexion par défaut = 10s."""
        manager = TimeoutManager()
        timeout = manager.get_timeout(TimeoutType.CONNECTION)
        assert timeout == 10.0

    def test_NET_001_connection_timeout_cannot_exceed_10s(self) -> None:
        """NET_001: Connection timeout ne peut pas dépasser 10s."""
        config = TimeoutConfig(connection_timeout=15.0)
        with pytest.raises(InvalidTimeoutError) as exc:
            TimeoutManager(default_config=config)
        assert "NET_001" in str(exc.value)
        assert "10" in str(exc.value)

    def test_NET_001_connection_timeout_at_limit(self) -> None:
        """NET_001: Connection timeout = 10s est valide."""
        config = TimeoutConfig(connection_timeout=10.0)
        manager = TimeoutManager(default_config=config)
        assert manager.get_timeout(TimeoutType.CONNECTION) == 10.0

    def test_NET_001_connection_timeout_below_limit(self) -> None:
        """NET_001: Connection timeout < 10s est valide."""
        config = TimeoutConfig(connection_timeout=5.0)
        manager = TimeoutManager(default_config=config)
        assert manager.get_timeout(TimeoutType.CONNECTION) == 5.0

    def test_NET_001_connection_timeout_must_be_positive(self) -> None:
        """NET_001: Connection timeout doit être positif."""
        config = TimeoutConfig(connection_timeout=0.0)
        with pytest.raises(InvalidTimeoutError) as exc:
            TimeoutManager(default_config=config)
        assert "positive" in str(exc.value)

    def test_NET_001_connection_timeout_negative_rejected(self) -> None:
        """NET_001: Connection timeout négatif rejeté."""
        config = TimeoutConfig(connection_timeout=-1.0)
        with pytest.raises(InvalidTimeoutError):
            TimeoutManager(default_config=config)

    def test_NET_001_validate_connection_timeout_valid(self) -> None:
        """NET_001: Validation connection timeout valide."""
        manager = TimeoutManager()
        assert manager.validate_timeout(TimeoutType.CONNECTION, 5.0) is True
        assert manager.validate_timeout(TimeoutType.CONNECTION, 10.0) is True

    def test_NET_001_validate_connection_timeout_invalid(self) -> None:
        """NET_001: Validation connection timeout invalide."""
        manager = TimeoutManager()
        assert manager.validate_timeout(TimeoutType.CONNECTION, 15.0) is False
        assert manager.validate_timeout(TimeoutType.CONNECTION, 0.0) is False
        assert manager.validate_timeout(TimeoutType.CONNECTION, -1.0) is False

    def test_NET_001_max_connection_timeout_constant(self) -> None:
        """NET_001: Constante MAX_CONNECTION_TIMEOUT = 10."""
        assert TimeoutManager.MAX_CONNECTION_TIMEOUT == 10.0

    def test_NET_001_connection_timeout_fractional(self) -> None:
        """NET_001: Connection timeout fractionnaire valide."""
        config = TimeoutConfig(connection_timeout=5.5)
        manager = TimeoutManager(default_config=config)
        assert manager.get_timeout(TimeoutType.CONNECTION) == 5.5

    def test_NET_001_connection_timeout_very_small(self) -> None:
        """NET_001: Connection timeout très petit valide."""
        config = TimeoutConfig(connection_timeout=0.1)
        manager = TimeoutManager(default_config=config)
        assert manager.get_timeout(TimeoutType.CONNECTION) == 0.1

    def test_NET_001_connection_timeout_just_above_limit(self) -> None:
        """NET_001: Connection timeout légèrement au-dessus de la limite rejeté."""
        config = TimeoutConfig(connection_timeout=10.001)
        with pytest.raises(InvalidTimeoutError) as exc:
            TimeoutManager(default_config=config)
        assert "NET_001" in str(exc.value)


class TestNET002RequestTimeout:
    """Tests NET_002: Timeout requête 30 secondes max (configurable par endpoint)."""

    def test_NET_002_default_request_timeout_is_30s(self) -> None:
        """NET_002: Timeout requête par défaut = 30s."""
        manager = TimeoutManager()
        timeout = manager.get_timeout(TimeoutType.REQUEST)
        assert timeout == 30.0

    def test_NET_002_request_timeout_cannot_exceed_30s(self) -> None:
        """NET_002: Request timeout ne peut pas dépasser 30s."""
        config = TimeoutConfig(request_timeout=45.0)
        with pytest.raises(InvalidTimeoutError) as exc:
            TimeoutManager(default_config=config)
        assert "NET_002" in str(exc.value)
        assert "30" in str(exc.value)

    def test_NET_002_request_timeout_at_limit(self) -> None:
        """NET_002: Request timeout = 30s est valide."""
        config = TimeoutConfig(request_timeout=30.0)
        manager = TimeoutManager(default_config=config)
        assert manager.get_timeout(TimeoutType.REQUEST) == 30.0

    def test_NET_002_request_timeout_below_limit(self) -> None:
        """NET_002: Request timeout < 30s est valide."""
        config = TimeoutConfig(request_timeout=15.0)
        manager = TimeoutManager(default_config=config)
        assert manager.get_timeout(TimeoutType.REQUEST) == 15.0

    def test_NET_002_request_timeout_must_be_positive(self) -> None:
        """NET_002: Request timeout doit être positif."""
        config = TimeoutConfig(request_timeout=0.0)
        with pytest.raises(InvalidTimeoutError):
            TimeoutManager(default_config=config)

    def test_NET_002_endpoint_specific_timeout(self) -> None:
        """NET_002: Timeout configurable par endpoint."""
        manager = TimeoutManager()
        endpoint_config = TimeoutConfig(request_timeout=15.0)
        manager.set_endpoint_timeout("/api/slow", endpoint_config)

        # Endpoint spécifique
        assert manager.get_timeout(TimeoutType.REQUEST, "/api/slow") == 15.0
        # Autre endpoint = default
        assert manager.get_timeout(TimeoutType.REQUEST, "/api/fast") == 30.0

    def test_NET_002_endpoint_timeout_cannot_exceed_30s(self) -> None:
        """NET_002: Endpoint timeout ne peut pas dépasser 30s."""
        manager = TimeoutManager()
        config = TimeoutConfig(request_timeout=45.0)
        with pytest.raises(InvalidTimeoutError) as exc:
            manager.set_endpoint_timeout("/api/test", config)
        assert "NET_002" in str(exc.value)

    def test_NET_002_multiple_endpoints_different_timeouts(self) -> None:
        """NET_002: Plusieurs endpoints avec timeouts différents."""
        manager = TimeoutManager()
        manager.set_endpoint_timeout("/api/fast", TimeoutConfig(request_timeout=5.0))
        manager.set_endpoint_timeout("/api/slow", TimeoutConfig(request_timeout=25.0))

        assert manager.get_timeout(TimeoutType.REQUEST, "/api/fast") == 5.0
        assert manager.get_timeout(TimeoutType.REQUEST, "/api/slow") == 25.0

    def test_NET_002_validate_request_timeout_valid(self) -> None:
        """NET_002: Validation request timeout valide."""
        manager = TimeoutManager()
        assert manager.validate_timeout(TimeoutType.REQUEST, 15.0) is True
        assert manager.validate_timeout(TimeoutType.REQUEST, 30.0) is True

    def test_NET_002_validate_request_timeout_invalid(self) -> None:
        """NET_002: Validation request timeout invalide."""
        manager = TimeoutManager()
        assert manager.validate_timeout(TimeoutType.REQUEST, 45.0) is False
        assert manager.validate_timeout(TimeoutType.REQUEST, 0.0) is False

    def test_NET_002_max_request_timeout_constant(self) -> None:
        """NET_002: Constante MAX_REQUEST_TIMEOUT = 30."""
        assert TimeoutManager.MAX_REQUEST_TIMEOUT == 30.0

    def test_NET_002_endpoint_empty_rejected(self) -> None:
        """NET_002: Endpoint vide rejeté."""
        manager = TimeoutManager()
        with pytest.raises(ValueError) as exc:
            manager.set_endpoint_timeout("", TimeoutConfig())
        assert "empty" in str(exc.value)


class TestTimeoutManagerGeneral:
    """Tests généraux TimeoutManager."""

    def test_implements_interface(self) -> None:
        """TimeoutManager implémente ITimeoutManager."""
        manager = TimeoutManager()
        assert isinstance(manager, ITimeoutManager)

    def test_default_config_creation(self) -> None:
        """Création avec config par défaut."""
        manager = TimeoutManager()
        config = manager.get_default_config()
        assert config.connection_timeout == 10.0
        assert config.request_timeout == 30.0

    def test_custom_default_config(self) -> None:
        """Création avec config personnalisée."""
        config = TimeoutConfig(connection_timeout=5.0, request_timeout=15.0)
        manager = TimeoutManager(default_config=config)
        assert manager.get_timeout(TimeoutType.CONNECTION) == 5.0
        assert manager.get_timeout(TimeoutType.REQUEST) == 15.0

    def test_read_timeout_fallback_to_request(self) -> None:
        """Read timeout fallback sur request si non défini."""
        config = TimeoutConfig(request_timeout=20.0)
        manager = TimeoutManager(default_config=config)
        assert manager.get_timeout(TimeoutType.READ) == 20.0

    def test_write_timeout_fallback_to_request(self) -> None:
        """Write timeout fallback sur request si non défini."""
        config = TimeoutConfig(request_timeout=20.0)
        manager = TimeoutManager(default_config=config)
        assert manager.get_timeout(TimeoutType.WRITE) == 20.0

    def test_read_timeout_explicit(self) -> None:
        """Read timeout explicite utilisé."""
        config = TimeoutConfig(request_timeout=20.0, read_timeout=10.0)
        manager = TimeoutManager(default_config=config)
        assert manager.get_timeout(TimeoutType.READ) == 10.0

    def test_write_timeout_explicit(self) -> None:
        """Write timeout explicite utilisé."""
        config = TimeoutConfig(request_timeout=20.0, write_timeout=15.0)
        manager = TimeoutManager(default_config=config)
        assert manager.get_timeout(TimeoutType.WRITE) == 15.0

    def test_get_all_endpoints_empty(self) -> None:
        """Liste endpoints vide initialement."""
        manager = TimeoutManager()
        assert manager.get_all_endpoints() == []

    def test_get_all_endpoints_with_configs(self) -> None:
        """Liste endpoints avec configurations."""
        manager = TimeoutManager()
        manager.set_endpoint_timeout("/api/a", TimeoutConfig())
        manager.set_endpoint_timeout("/api/b", TimeoutConfig())
        endpoints = manager.get_all_endpoints()
        assert len(endpoints) == 2
        assert "/api/a" in endpoints
        assert "/api/b" in endpoints

    def test_remove_endpoint_config(self) -> None:
        """Suppression configuration endpoint."""
        manager = TimeoutManager()
        manager.set_endpoint_timeout("/api/test", TimeoutConfig())
        assert manager.remove_endpoint_config("/api/test") is True
        assert "/api/test" not in manager.get_all_endpoints()

    def test_remove_nonexistent_endpoint(self) -> None:
        """Suppression endpoint inexistant retourne False."""
        manager = TimeoutManager()
        assert manager.remove_endpoint_config("/api/nonexistent") is False

    def test_get_endpoint_config_exists(self) -> None:
        """Récupération config endpoint existant."""
        manager = TimeoutManager()
        config = TimeoutConfig(request_timeout=15.0)
        manager.set_endpoint_timeout("/api/test", config)
        retrieved = manager.get_endpoint_config("/api/test")
        assert retrieved is not None
        assert retrieved.request_timeout == 15.0

    def test_get_endpoint_config_not_exists(self) -> None:
        """Récupération config endpoint inexistant retourne None."""
        manager = TimeoutManager()
        assert manager.get_endpoint_config("/api/nonexistent") is None

    def test_clear_all_endpoints(self) -> None:
        """Suppression toutes configurations endpoints."""
        manager = TimeoutManager()
        manager.set_endpoint_timeout("/api/a", TimeoutConfig())
        manager.set_endpoint_timeout("/api/b", TimeoutConfig())
        manager.clear_all_endpoints()
        assert manager.get_all_endpoints() == []


class TestTimeoutExceededError:
    """Tests TimeoutExceededError."""

    def test_error_creation(self) -> None:
        """Création d'erreur TimeoutExceeded."""
        error = TimeoutExceededError(TimeoutType.CONNECTION, 10.0)
        assert error.timeout_type == TimeoutType.CONNECTION
        assert error.timeout_value == 10.0

    def test_error_message_format(self) -> None:
        """Format du message d'erreur."""
        error = TimeoutExceededError(TimeoutType.REQUEST, 30.0)
        assert "request" in str(error)
        assert "30.0" in str(error)
        assert "exceeded" in str(error)

    def test_error_is_exception(self) -> None:
        """TimeoutExceededError est une Exception."""
        error = TimeoutExceededError(TimeoutType.CONNECTION, 5.0)
        assert isinstance(error, Exception)


class TestInvalidTimeoutError:
    """Tests InvalidTimeoutError."""

    def test_error_creation(self) -> None:
        """Création d'erreur InvalidTimeout."""
        error = InvalidTimeoutError("Test message")
        assert str(error) == "Test message"

    def test_error_is_exception(self) -> None:
        """InvalidTimeoutError est une Exception."""
        error = InvalidTimeoutError("test")
        assert isinstance(error, Exception)


class TestTimeoutConfigDataclass:
    """Tests TimeoutConfig dataclass."""

    def test_default_values(self) -> None:
        """Valeurs par défaut TimeoutConfig."""
        config = TimeoutConfig()
        assert config.connection_timeout == 10.0
        assert config.request_timeout == 30.0
        assert config.read_timeout is None
        assert config.write_timeout is None

    def test_custom_values(self) -> None:
        """Valeurs personnalisées TimeoutConfig."""
        config = TimeoutConfig(
            connection_timeout=5.0,
            request_timeout=15.0,
            read_timeout=10.0,
            write_timeout=20.0,
        )
        assert config.connection_timeout == 5.0
        assert config.request_timeout == 15.0
        assert config.read_timeout == 10.0
        assert config.write_timeout == 20.0


class TestTimeoutTypeEnum:
    """Tests TimeoutType enum."""

    def test_all_types_exist(self) -> None:
        """Tous les types de timeout existent."""
        assert TimeoutType.CONNECTION.value == "connection"
        assert TimeoutType.REQUEST.value == "request"
        assert TimeoutType.READ.value == "read"
        assert TimeoutType.WRITE.value == "write"

    def test_enum_count(self) -> None:
        """Nombre de types de timeout."""
        assert len(TimeoutType) == 4
