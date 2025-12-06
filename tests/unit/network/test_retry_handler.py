"""
Tests unitaires pour LOT 10: Network - RetryHandler

Tests de l'invariant:
- NET_003: Retry automatique 3 tentatives avec backoff exponentiel
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.network import (
    RetryHandler,
    RetryConfig,
    RetryResult,
    MaxRetriesExceededError,
    IRetryHandler,
    with_retry,
    with_retry_sync,
)


class TestNET003RetryWithBackoff:
    """Tests NET_003: Retry automatique 3 tentatives avec backoff exponentiel."""

    @pytest.mark.asyncio
    async def test_NET_003_default_max_attempts_is_3(self) -> None:
        """NET_003: Nombre de tentatives par défaut = 3."""
        handler = RetryHandler()
        call_count = 0

        async def failing_func() -> None:
            nonlocal call_count
            call_count += 1
            raise ConnectionError("Test error")

        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await handler.execute_with_retry(failing_func)

        assert call_count == 3
        assert result.attempts == 3
        assert result.success is False

    @pytest.mark.asyncio
    async def test_NET_003_success_on_first_attempt(self) -> None:
        """NET_003: Succès au premier essai."""
        handler = RetryHandler()

        async def success_func() -> str:
            return "success"

        result = await handler.execute_with_retry(success_func)

        assert result.success is True
        assert result.result == "success"
        assert result.attempts == 1
        assert result.total_delay == 0.0

    @pytest.mark.asyncio
    async def test_NET_003_success_after_retry(self) -> None:
        """NET_003: Succès après retry."""
        handler = RetryHandler()
        call_count = 0

        async def eventual_success() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("Transient error")
            return "success"

        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await handler.execute_with_retry(eventual_success)

        assert result.success is True
        assert result.result == "success"
        assert result.attempts == 2

    @pytest.mark.asyncio
    async def test_NET_003_backoff_exponential_calculation(self) -> None:
        """NET_003: Calcul backoff exponentiel correct."""
        handler = RetryHandler()
        config = RetryConfig(
            initial_delay=1.0,
            exponential_base=2.0,
            max_delay=10.0,
        )

        # Attempt 0: 1 * 2^0 = 1s
        assert handler.calculate_delay(0, config) == 1.0
        # Attempt 1: 1 * 2^1 = 2s
        assert handler.calculate_delay(1, config) == 2.0
        # Attempt 2: 1 * 2^2 = 4s
        assert handler.calculate_delay(2, config) == 4.0
        # Attempt 3: 1 * 2^3 = 8s
        assert handler.calculate_delay(3, config) == 8.0
        # Attempt 4: 1 * 2^4 = 16s -> capped at 10s
        assert handler.calculate_delay(4, config) == 10.0

    @pytest.mark.asyncio
    async def test_NET_003_backoff_max_delay_cap(self) -> None:
        """NET_003: Backoff limité par max_delay."""
        handler = RetryHandler()
        config = RetryConfig(
            initial_delay=5.0,
            exponential_base=2.0,
            max_delay=8.0,
        )

        # 5 * 2^2 = 20s -> capped at 8s
        assert handler.calculate_delay(2, config) == 8.0

    @pytest.mark.asyncio
    async def test_NET_003_custom_max_attempts(self) -> None:
        """NET_003: Nombre de tentatives configurable."""
        handler = RetryHandler()
        call_count = 0

        async def failing_func() -> None:
            nonlocal call_count
            call_count += 1
            raise ConnectionError("Test")

        config = RetryConfig(max_attempts=5)

        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await handler.execute_with_retry(failing_func, config=config)

        assert call_count == 5
        assert result.attempts == 5

    @pytest.mark.asyncio
    async def test_NET_003_retryable_exceptions(self) -> None:
        """NET_003: Seules les exceptions retryables sont retryées."""
        handler = RetryHandler()
        call_count = 0

        async def non_retryable_error() -> None:
            nonlocal call_count
            call_count += 1
            raise ValueError("Not retryable")

        config = RetryConfig(retryable_exceptions=(ConnectionError, TimeoutError))

        result = await handler.execute_with_retry(non_retryable_error, config=config)

        assert call_count == 1  # Pas de retry
        assert result.success is False
        assert isinstance(result.last_error, ValueError)

    @pytest.mark.asyncio
    async def test_NET_003_total_delay_accumulated(self) -> None:
        """NET_003: Délai total accumulé correctement."""
        handler = RetryHandler()
        call_count = 0

        async def failing_func() -> None:
            nonlocal call_count
            call_count += 1
            raise ConnectionError("Test")

        config = RetryConfig(
            max_attempts=3,
            initial_delay=1.0,
            exponential_base=2.0,
        )

        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            result = await handler.execute_with_retry(failing_func, config=config)

        # Delays: 1s (after attempt 1) + 2s (after attempt 2) = 3s total
        assert result.total_delay == 3.0
        assert mock_sleep.call_count == 2

    @pytest.mark.asyncio
    async def test_NET_003_sleep_called_with_correct_delays(self) -> None:
        """NET_003: asyncio.sleep appelé avec bons délais."""
        handler = RetryHandler()

        async def failing_func() -> None:
            raise ConnectionError("Test")

        config = RetryConfig(
            max_attempts=3,
            initial_delay=1.0,
            exponential_base=2.0,
        )

        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await handler.execute_with_retry(failing_func, config=config)

        # Premier délai: 1s, Deuxième délai: 2s
        assert mock_sleep.call_args_list[0][0][0] == 1.0
        assert mock_sleep.call_args_list[1][0][0] == 2.0

    def test_NET_003_is_retryable_connection_error(self) -> None:
        """NET_003: ConnectionError est retryable par défaut."""
        handler = RetryHandler()
        config = RetryConfig()
        assert handler.is_retryable(ConnectionError("test"), config) is True

    def test_NET_003_is_retryable_timeout_error(self) -> None:
        """NET_003: TimeoutError est retryable par défaut."""
        handler = RetryHandler()
        config = RetryConfig()
        assert handler.is_retryable(TimeoutError("test"), config) is True

    def test_NET_003_is_not_retryable_value_error(self) -> None:
        """NET_003: ValueError n'est pas retryable par défaut."""
        handler = RetryHandler()
        config = RetryConfig()
        assert handler.is_retryable(ValueError("test"), config) is False

    def test_NET_003_default_constants(self) -> None:
        """NET_003: Constantes par défaut correctes."""
        assert RetryHandler.DEFAULT_MAX_ATTEMPTS == 3
        assert RetryHandler.DEFAULT_INITIAL_DELAY == 1.0
        assert RetryHandler.DEFAULT_MAX_DELAY == 10.0
        assert RetryHandler.DEFAULT_EXPONENTIAL_BASE == 2.0

    @pytest.mark.asyncio
    async def test_NET_003_last_error_captured(self) -> None:
        """NET_003: Dernière erreur capturée dans résultat."""
        handler = RetryHandler()

        async def failing_func() -> None:
            raise ConnectionError("Final error")

        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await handler.execute_with_retry(failing_func)

        assert result.last_error is not None
        assert isinstance(result.last_error, ConnectionError)
        assert "Final error" in str(result.last_error)

    @pytest.mark.asyncio
    async def test_NET_003_single_attempt_config(self) -> None:
        """NET_003: Config avec 1 seule tentative."""
        handler = RetryHandler()
        call_count = 0

        async def failing_func() -> None:
            nonlocal call_count
            call_count += 1
            raise ConnectionError("Test")

        config = RetryConfig(max_attempts=1)

        result = await handler.execute_with_retry(failing_func, config=config)

        assert call_count == 1
        assert result.success is False


class TestRetryHandlerSyncFunctions:
    """Tests RetryHandler avec fonctions synchrones."""

    @pytest.mark.asyncio
    async def test_sync_function_success(self) -> None:
        """Fonction synchrone réussit."""
        handler = RetryHandler()

        def sync_func() -> str:
            return "sync success"

        result = await handler.execute_with_retry(sync_func)

        assert result.success is True
        assert result.result == "sync success"

    @pytest.mark.asyncio
    async def test_sync_function_with_args(self) -> None:
        """Fonction synchrone avec arguments."""
        handler = RetryHandler()

        def sync_func(a: int, b: int) -> int:
            return a + b

        result = await handler.execute_with_retry(sync_func, 2, 3)

        assert result.success is True
        assert result.result == 5

    @pytest.mark.asyncio
    async def test_sync_function_with_kwargs(self) -> None:
        """Fonction synchrone avec kwargs."""
        handler = RetryHandler()

        def sync_func(name: str = "default") -> str:
            return f"Hello {name}"

        result = await handler.execute_with_retry(sync_func, name="World")

        assert result.success is True
        assert result.result == "Hello World"


class TestRetryHandlerStats:
    """Tests statistiques RetryHandler."""

    @pytest.mark.asyncio
    async def test_stats_initial_state(self) -> None:
        """Stats initialement à zéro."""
        handler = RetryHandler()
        stats = handler.get_retry_stats()
        assert stats["total_retries"] == 0
        assert stats["successful_retries"] == 0
        assert stats["failed_retries"] == 0

    @pytest.mark.asyncio
    async def test_stats_after_retries(self) -> None:
        """Stats après retries."""
        handler = RetryHandler()
        call_count = 0

        async def eventual_success() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("Transient")
            return "ok"

        with patch("asyncio.sleep", new_callable=AsyncMock):
            await handler.execute_with_retry(eventual_success)

        stats = handler.get_retry_stats()
        assert stats["total_retries"] == 1
        assert stats["successful_retries"] == 1

    @pytest.mark.asyncio
    async def test_stats_after_failure(self) -> None:
        """Stats après échec complet."""
        handler = RetryHandler()

        async def always_fail() -> None:
            raise ConnectionError("Always fails")

        with patch("asyncio.sleep", new_callable=AsyncMock):
            await handler.execute_with_retry(always_fail)

        stats = handler.get_retry_stats()
        assert stats["total_retries"] == 3
        assert stats["failed_retries"] == 1

    def test_stats_reset(self) -> None:
        """Reset des stats."""
        handler = RetryHandler()
        handler._retry_stats["total_retries"] = 10
        handler.reset_stats()
        stats = handler.get_retry_stats()
        assert stats["total_retries"] == 0


class TestWithRetryDecorator:
    """Tests decorator @with_retry."""

    @pytest.mark.asyncio
    async def test_decorator_success(self) -> None:
        """Decorator avec succès."""
        @with_retry()
        async def successful_func() -> str:
            return "decorated success"

        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await successful_func()

        assert result == "decorated success"

    @pytest.mark.asyncio
    async def test_decorator_retry_then_success(self) -> None:
        """Decorator retry puis succès."""
        call_count = 0

        @with_retry(max_attempts=3)
        async def eventual_success() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("Transient")
            return "ok"

        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await eventual_success()

        assert result == "ok"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_decorator_max_retries_exceeded(self) -> None:
        """Decorator lève MaxRetriesExceededError après épuisement."""
        @with_retry(max_attempts=2)
        async def always_fail() -> None:
            raise ConnectionError("Always fails")

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(MaxRetriesExceededError) as exc:
                await always_fail()

        assert exc.value.attempts == 2
        assert isinstance(exc.value.last_error, ConnectionError)

    @pytest.mark.asyncio
    async def test_decorator_custom_params(self) -> None:
        """Decorator avec paramètres personnalisés."""
        call_count = 0

        @with_retry(
            max_attempts=5,
            initial_delay=0.5,
            max_delay=5.0,
            retryable_exceptions=(ValueError,),
        )
        async def custom_func() -> None:
            nonlocal call_count
            call_count += 1
            raise ValueError("Custom error")

        with patch("asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(MaxRetriesExceededError):
                await custom_func()

        assert call_count == 5

    @pytest.mark.asyncio
    async def test_decorator_preserves_function_metadata(self) -> None:
        """Decorator préserve les métadonnées de la fonction."""
        @with_retry()
        async def documented_func() -> str:
            """This is a docstring."""
            return "test"

        assert documented_func.__name__ == "documented_func"
        assert documented_func.__doc__ == "This is a docstring."


class TestWithRetrySyncDecorator:
    """Tests decorator @with_retry_sync."""

    def test_sync_decorator_success(self) -> None:
        """Decorator sync avec succès."""
        @with_retry_sync()
        def successful_func() -> str:
            return "sync success"

        result = successful_func()
        assert result == "sync success"

    def test_sync_decorator_retry_then_success(self) -> None:
        """Decorator sync retry puis succès."""
        call_count = 0

        @with_retry_sync(max_attempts=3)
        def eventual_success() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("Transient")
            return "ok"

        with patch("time.sleep"):
            result = eventual_success()

        assert result == "ok"
        assert call_count == 2

    def test_sync_decorator_max_retries_exceeded(self) -> None:
        """Decorator sync lève MaxRetriesExceededError."""
        @with_retry_sync(max_attempts=2)
        def always_fail() -> None:
            raise ConnectionError("Always fails")

        with patch("time.sleep"):
            with pytest.raises(MaxRetriesExceededError) as exc:
                always_fail()

        assert exc.value.attempts == 2

    def test_sync_decorator_non_retryable_error(self) -> None:
        """Decorator sync ne retry pas les erreurs non-retryables."""
        call_count = 0

        @with_retry_sync(retryable_exceptions=(ConnectionError,))
        def raises_value_error() -> None:
            nonlocal call_count
            call_count += 1
            raise ValueError("Not retryable")

        with pytest.raises(ValueError):
            raises_value_error()

        assert call_count == 1


class TestMaxRetriesExceededError:
    """Tests MaxRetriesExceededError."""

    def test_error_creation(self) -> None:
        """Création de l'erreur."""
        original = ConnectionError("Original error")
        error = MaxRetriesExceededError(3, original)
        assert error.attempts == 3
        assert error.last_error is original

    def test_error_message_format(self) -> None:
        """Format du message d'erreur."""
        error = MaxRetriesExceededError(3, ConnectionError("test"))
        assert "3" in str(error)
        assert "exceeded" in str(error)

    def test_error_is_exception(self) -> None:
        """MaxRetriesExceededError est une Exception."""
        error = MaxRetriesExceededError(1, Exception())
        assert isinstance(error, Exception)


class TestRetryConfigDataclass:
    """Tests RetryConfig dataclass."""

    def test_default_values(self) -> None:
        """Valeurs par défaut RetryConfig."""
        config = RetryConfig()
        assert config.max_attempts == 3
        assert config.initial_delay == 1.0
        assert config.max_delay == 10.0
        assert config.exponential_base == 2.0
        assert ConnectionError in config.retryable_exceptions
        assert TimeoutError in config.retryable_exceptions

    def test_custom_values(self) -> None:
        """Valeurs personnalisées RetryConfig."""
        config = RetryConfig(
            max_attempts=5,
            initial_delay=0.5,
            max_delay=20.0,
            exponential_base=3.0,
            retryable_exceptions=(ValueError,),
        )
        assert config.max_attempts == 5
        assert config.initial_delay == 0.5
        assert config.max_delay == 20.0
        assert config.exponential_base == 3.0
        assert ValueError in config.retryable_exceptions


class TestRetryResultDataclass:
    """Tests RetryResult dataclass."""

    def test_success_result(self) -> None:
        """Création résultat succès."""
        result = RetryResult(
            success=True,
            result="value",
            attempts=1,
            total_delay=0.0,
            last_error=None,
        )
        assert result.success is True
        assert result.result == "value"
        assert result.attempts == 1
        assert result.total_delay == 0.0
        assert result.last_error is None

    def test_failure_result(self) -> None:
        """Création résultat échec."""
        error = ConnectionError("Test")
        result = RetryResult(
            success=False,
            result=None,
            attempts=3,
            total_delay=3.0,
            last_error=error,
        )
        assert result.success is False
        assert result.result is None
        assert result.attempts == 3
        assert result.total_delay == 3.0
        assert result.last_error is error


class TestRetryHandlerInterface:
    """Tests interface IRetryHandler."""

    def test_implements_interface(self) -> None:
        """RetryHandler implémente IRetryHandler."""
        handler = RetryHandler()
        assert isinstance(handler, IRetryHandler)

    def test_default_config_in_constructor(self) -> None:
        """Config par défaut dans constructeur."""
        config = RetryConfig(max_attempts=5)
        handler = RetryHandler(default_config=config)
        assert handler._default_config.max_attempts == 5
