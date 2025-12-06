"""
Tests unitaires pour LOT 10: Network - Circuit Breaker

Tests des invariants:
- NET_004: Circuit breaker ouvert après 5 échecs consécutifs
- NET_005: Circuit breaker half-open après 30 secondes
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from src.network import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerState,
    CircuitState,
    CircuitOpenError,
    with_circuit_breaker,
)


class TestNET004CircuitOpen:
    """Tests NET_004: Circuit breaker ouvert après 5 échecs consécutifs."""

    def test_NET_004_default_failure_threshold_is_5(self) -> None:
        """NET_004: Seuil d'échecs par défaut = 5."""
        breaker = CircuitBreaker("test")
        assert breaker._config.failure_threshold == 5

    def test_NET_004_circuit_opens_after_5_failures(self) -> None:
        """NET_004: Circuit ouvert après 5 échecs consécutifs."""
        breaker = CircuitBreaker("test")

        # 4 échecs → circuit reste fermé
        for _ in range(4):
            breaker.record_failure()
        assert breaker.state == CircuitState.CLOSED

        # 5ème échec → circuit s'ouvre
        breaker.record_failure()
        assert breaker.state == CircuitState.OPEN

    def test_NET_004_can_execute_false_when_open(self) -> None:
        """NET_004: can_execute retourne False quand OPEN."""
        breaker = CircuitBreaker("test")

        # Ouvrir le circuit
        for _ in range(5):
            breaker.record_failure()

        assert breaker.can_execute() is False

    def test_NET_004_can_execute_true_when_closed(self) -> None:
        """NET_004: can_execute retourne True quand CLOSED."""
        breaker = CircuitBreaker("test")
        assert breaker.can_execute() is True

    def test_NET_004_success_resets_failure_count(self) -> None:
        """NET_004: Un succès reset le compteur d'échecs."""
        breaker = CircuitBreaker("test")

        # 3 échecs
        for _ in range(3):
            breaker.record_failure()
        assert breaker._failure_count == 3

        # Succès reset le compteur
        breaker.record_success()
        assert breaker._failure_count == 0

    def test_NET_004_custom_failure_threshold(self) -> None:
        """NET_004: Seuil d'échecs configurable."""
        config = CircuitBreakerConfig(failure_threshold=3)
        breaker = CircuitBreaker("test", config=config)

        for _ in range(3):
            breaker.record_failure()

        assert breaker.state == CircuitState.OPEN

    def test_NET_004_failure_threshold_constant(self) -> None:
        """NET_004: Constante DEFAULT_FAILURE_THRESHOLD = 5."""
        assert CircuitBreaker.DEFAULT_FAILURE_THRESHOLD == 5

    def test_NET_004_total_failures_tracked(self) -> None:
        """NET_004: Total des échecs tracké."""
        breaker = CircuitBreaker("test")

        for _ in range(3):
            breaker.record_failure()

        state = breaker.get_state()
        assert state.total_failures == 3

    def test_NET_004_consecutive_failures_required(self) -> None:
        """NET_004: Échecs consécutifs requis (succès interrompt)."""
        breaker = CircuitBreaker("test")

        # 4 échecs
        for _ in range(4):
            breaker.record_failure()

        # Un succès interrompt
        breaker.record_success()

        # 4 autres échecs (total 8, mais consécutifs = 4)
        for _ in range(4):
            breaker.record_failure()

        assert breaker.state == CircuitState.CLOSED

    def test_NET_004_failure_count_in_state(self) -> None:
        """NET_004: failure_count présent dans l'état."""
        breaker = CircuitBreaker("test")
        for _ in range(3):
            breaker.record_failure()

        state = breaker.get_state()
        assert state.failure_count == 3

    def test_NET_004_last_failure_time_recorded(self) -> None:
        """NET_004: last_failure_time enregistré."""
        breaker = CircuitBreaker("test")
        breaker.record_failure()

        state = breaker.get_state()
        assert state.last_failure_time is not None

    def test_NET_004_empty_name_rejected(self) -> None:
        """NET_004: Nom vide rejeté."""
        with pytest.raises(ValueError) as exc:
            CircuitBreaker("")
        assert "empty" in str(exc.value)


class TestNET005HalfOpen:
    """Tests NET_005: Circuit breaker half-open après 30 secondes."""

    def test_NET_005_default_recovery_timeout_is_30s(self) -> None:
        """NET_005: Timeout de récupération par défaut = 30s."""
        breaker = CircuitBreaker("test")
        assert breaker._config.recovery_timeout == 30.0

    def test_NET_005_transitions_to_half_open_after_timeout(self) -> None:
        """NET_005: Transition vers HALF_OPEN après timeout."""
        breaker = CircuitBreaker("test")

        # Ouvrir le circuit
        for _ in range(5):
            breaker.record_failure()
        assert breaker.state == CircuitState.OPEN

        # Simuler passage du temps (31 secondes)
        past_time = datetime.now(timezone.utc) - timedelta(seconds=31)
        breaker._last_failure_time = past_time

        # Vérifier la transition
        assert breaker.state == CircuitState.HALF_OPEN

    def test_NET_005_can_execute_true_in_half_open(self) -> None:
        """NET_005: can_execute retourne True en HALF_OPEN."""
        breaker = CircuitBreaker("test")

        # Ouvrir puis transition vers half-open
        for _ in range(5):
            breaker.record_failure()
        breaker._last_failure_time = datetime.now(timezone.utc) - timedelta(seconds=31)

        assert breaker.can_execute() is True

    def test_NET_005_success_in_half_open_closes_circuit(self) -> None:
        """NET_005: Succès en HALF_OPEN ferme le circuit."""
        config = CircuitBreakerConfig(success_threshold=1)
        breaker = CircuitBreaker("test", config=config)

        # Ouvrir puis transition vers half-open
        for _ in range(5):
            breaker.record_failure()
        breaker._last_failure_time = datetime.now(timezone.utc) - timedelta(seconds=31)
        _ = breaker.state  # Déclenche check_recovery

        # Succès ferme le circuit
        breaker.record_success()
        assert breaker.state == CircuitState.CLOSED

    def test_NET_005_failure_in_half_open_reopens_circuit(self) -> None:
        """NET_005: Échec en HALF_OPEN réouvre le circuit."""
        breaker = CircuitBreaker("test")

        # Ouvrir puis transition vers half-open
        for _ in range(5):
            breaker.record_failure()
        breaker._last_failure_time = datetime.now(timezone.utc) - timedelta(seconds=31)
        _ = breaker.state  # Déclenche check_recovery

        # Échec réouvre
        breaker.record_failure()
        assert breaker.state == CircuitState.OPEN

    def test_NET_005_recovery_timeout_constant(self) -> None:
        """NET_005: Constante DEFAULT_RECOVERY_TIMEOUT = 30."""
        assert CircuitBreaker.DEFAULT_RECOVERY_TIMEOUT == 30.0

    def test_NET_005_custom_recovery_timeout(self) -> None:
        """NET_005: Timeout de récupération configurable."""
        config = CircuitBreakerConfig(recovery_timeout=10.0)
        breaker = CircuitBreaker("test", config=config)

        for _ in range(5):
            breaker.record_failure()
        breaker._last_failure_time = datetime.now(timezone.utc) - timedelta(seconds=11)

        assert breaker.state == CircuitState.HALF_OPEN

    def test_NET_005_stays_open_before_timeout(self) -> None:
        """NET_005: Reste OPEN avant timeout."""
        breaker = CircuitBreaker("test")

        for _ in range(5):
            breaker.record_failure()

        # Seulement 10 secondes écoulées
        breaker._last_failure_time = datetime.now(timezone.utc) - timedelta(seconds=10)

        assert breaker.state == CircuitState.OPEN

    def test_NET_005_multiple_successes_required(self) -> None:
        """NET_005: Plusieurs succès requis avant fermeture."""
        config = CircuitBreakerConfig(success_threshold=2)
        breaker = CircuitBreaker("test", config=config)

        # Ouvrir puis transition vers half-open
        for _ in range(5):
            breaker.record_failure()
        breaker._last_failure_time = datetime.now(timezone.utc) - timedelta(seconds=31)
        _ = breaker.state

        # Premier succès
        breaker.record_success()
        assert breaker.state == CircuitState.HALF_OPEN

        # Deuxième succès
        breaker.record_success()
        assert breaker.state == CircuitState.CLOSED

    def test_NET_005_get_time_until_recovery(self) -> None:
        """NET_005: get_time_until_recovery retourne temps restant."""
        breaker = CircuitBreaker("test")

        for _ in range(5):
            breaker.record_failure()

        # 20 secondes écoulées, 10 restantes
        breaker._last_failure_time = datetime.now(timezone.utc) - timedelta(seconds=20)

        remaining = breaker.get_time_until_recovery()
        assert remaining is not None
        assert 9.0 <= remaining <= 11.0  # Tolérance

    def test_NET_005_get_time_until_recovery_none_when_closed(self) -> None:
        """NET_005: get_time_until_recovery None quand CLOSED."""
        breaker = CircuitBreaker("test")
        assert breaker.get_time_until_recovery() is None


class TestCircuitBreakerDecorator:
    """Tests decorator @with_circuit_breaker."""

    @pytest.mark.asyncio
    async def test_decorator_allows_execution_when_closed(self) -> None:
        """Decorator permet exécution quand circuit fermé."""
        breaker = CircuitBreaker("test")

        @with_circuit_breaker(breaker)
        async def my_func() -> str:
            return "success"

        result = await my_func()
        assert result == "success"

    @pytest.mark.asyncio
    async def test_decorator_blocks_when_open(self) -> None:
        """Decorator bloque quand circuit ouvert."""
        breaker = CircuitBreaker("test")

        # Ouvrir le circuit
        for _ in range(5):
            breaker.record_failure()

        @with_circuit_breaker(breaker)
        async def my_func() -> str:
            return "success"

        with pytest.raises(CircuitOpenError) as exc:
            await my_func()

        assert exc.value.breaker_name == "test"

    @pytest.mark.asyncio
    async def test_decorator_records_success(self) -> None:
        """Decorator enregistre les succès."""
        breaker = CircuitBreaker("test")

        @with_circuit_breaker(breaker)
        async def my_func() -> str:
            return "success"

        await my_func()
        state = breaker.get_state()
        assert state.total_requests == 1

    @pytest.mark.asyncio
    async def test_decorator_records_failure(self) -> None:
        """Decorator enregistre les échecs."""
        breaker = CircuitBreaker("test")

        @with_circuit_breaker(breaker)
        async def failing_func() -> str:
            raise ConnectionError("Test error")

        with pytest.raises(ConnectionError):
            await failing_func()

        state = breaker.get_state()
        assert state.failure_count == 1

    @pytest.mark.asyncio
    async def test_decorator_preserves_function_metadata(self) -> None:
        """Decorator préserve les métadonnées."""
        breaker = CircuitBreaker("test")

        @with_circuit_breaker(breaker)
        async def documented_func() -> str:
            """This is a docstring."""
            return "test"

        assert documented_func.__name__ == "documented_func"
        assert documented_func.__doc__ == "This is a docstring."


class TestCircuitBreakerState:
    """Tests CircuitBreakerState."""

    def test_reset_restores_closed_state(self) -> None:
        """reset() restaure l'état CLOSED."""
        breaker = CircuitBreaker("test")

        # Ouvrir le circuit
        for _ in range(5):
            breaker.record_failure()
        assert breaker.state == CircuitState.OPEN

        # Reset
        breaker.reset()
        assert breaker.state == CircuitState.CLOSED
        assert breaker._failure_count == 0

    def test_get_state_returns_complete_state(self) -> None:
        """get_state retourne état complet."""
        breaker = CircuitBreaker("test")
        breaker.record_failure()
        breaker.record_failure()

        state = breaker.get_state()

        assert isinstance(state, CircuitBreakerState)
        assert state.state == CircuitState.CLOSED
        assert state.failure_count == 2
        assert state.total_failures == 2

    def test_state_change_time_updated(self) -> None:
        """last_state_change mis à jour à chaque transition."""
        breaker = CircuitBreaker("test")
        initial_time = breaker._last_state_change

        # Ouvrir le circuit
        for _ in range(5):
            breaker.record_failure()

        assert breaker._last_state_change > initial_time


class TestCircuitBreakerDataclasses:
    """Tests dataclasses Circuit Breaker."""

    def test_config_default_values(self) -> None:
        """Valeurs par défaut CircuitBreakerConfig."""
        config = CircuitBreakerConfig()
        assert config.failure_threshold == 5
        assert config.recovery_timeout == 30.0
        assert config.success_threshold == 2

    def test_config_custom_values(self) -> None:
        """Valeurs personnalisées CircuitBreakerConfig."""
        config = CircuitBreakerConfig(
            failure_threshold=10,
            recovery_timeout=60.0,
            success_threshold=5,
        )
        assert config.failure_threshold == 10
        assert config.recovery_timeout == 60.0
        assert config.success_threshold == 5

    def test_state_dataclass_creation(self) -> None:
        """Création CircuitBreakerState."""
        now = datetime.now(timezone.utc)
        state = CircuitBreakerState(
            state=CircuitState.CLOSED,
            failure_count=0,
            success_count=0,
            last_failure_time=None,
            last_state_change=now,
            total_requests=0,
            total_failures=0,
        )
        assert state.state == CircuitState.CLOSED


class TestCircuitOpenError:
    """Tests CircuitOpenError."""

    def test_error_creation(self) -> None:
        """Création de l'erreur."""
        error = CircuitOpenError("api", 10.0)
        assert error.breaker_name == "api"
        assert error.retry_after == 10.0

    def test_error_message_format(self) -> None:
        """Format du message d'erreur."""
        error = CircuitOpenError("api", 10.0)
        assert "api" in str(error)
        assert "OPEN" in str(error)
        assert "10.0" in str(error)

    def test_error_is_exception(self) -> None:
        """CircuitOpenError est une Exception."""
        error = CircuitOpenError("test", 5.0)
        assert isinstance(error, Exception)


class TestCircuitStateEnum:
    """Tests CircuitState enum."""

    def test_all_states_exist(self) -> None:
        """Tous les états existent."""
        assert CircuitState.CLOSED.value == "closed"
        assert CircuitState.OPEN.value == "open"
        assert CircuitState.HALF_OPEN.value == "half_open"

    def test_enum_count(self) -> None:
        """Nombre d'états."""
        assert len(CircuitState) == 3
