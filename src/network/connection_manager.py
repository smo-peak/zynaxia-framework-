"""
LOT 10: Network - Connection Manager

Gestion des connexions avec mode dégradé et reconnexion.

Invariants:
    NET_006: Connexion Cloud perdue = mode dégradé (pas crash)
    NET_007: Reconnexion automatique avec backoff
    NET_008: Keep-alive TCP activé (détection connexion morte)
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Optional

from .interfaces import IRetryHandler, RetryConfig
from .retry_handler import RetryHandler


class ConnectionState(Enum):
    """États d'une connexion."""

    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    DEGRADED = "degraded"  # NET_006
    RECONNECTING = "reconnecting"


@dataclass
class KeepAliveConfig:
    """
    Configuration keep-alive TCP.

    Invariant:
        NET_008: Keep-alive activé par défaut
    """

    enabled: bool = True  # NET_008
    interval: float = 30.0  # Secondes entre pings
    timeout: float = 10.0  # Timeout pour réponse
    max_failures: int = 3  # Échecs avant déconnexion


@dataclass
class ConnectionStatus:
    """Statut complet d'une connexion."""

    state: ConnectionState
    endpoint: str
    connected_at: Optional[datetime]
    last_activity: Optional[datetime]
    reconnect_attempts: int
    degraded_since: Optional[datetime]  # NET_006
    keep_alive_failures: int = 0


class ConnectionLostError(Exception):
    """Connexion perdue."""

    def __init__(self, endpoint: str, reason: str = "") -> None:
        self.endpoint = endpoint
        self.reason = reason
        super().__init__(f"Connection lost to '{endpoint}': {reason}")


class DegradedModeError(Exception):
    """Opération non disponible en mode dégradé."""

    def __init__(self, operation: str) -> None:
        self.operation = operation
        super().__init__(
            f"Operation '{operation}' not available in degraded mode - NET_006"
        )


class ConnectionManager:
    """
    Gestion connexions avec mode dégradé et reconnexion.

    Gère le cycle de vie des connexions réseau avec:
    - Mode dégradé en cas de perte de connexion
    - Reconnexion automatique avec backoff exponentiel
    - Keep-alive pour détection de connexions mortes

    Invariants:
        NET_006: Connexion Cloud perdue = mode dégradé (pas crash)
        NET_007: Reconnexion automatique avec backoff
        NET_008: Keep-alive TCP activé (détection connexion morte)
    """

    DEFAULT_KEEP_ALIVE_INTERVAL: float = 30.0
    DEFAULT_KEEP_ALIVE_TIMEOUT: float = 10.0
    DEFAULT_MAX_KEEP_ALIVE_FAILURES: int = 3

    def __init__(
        self,
        retry_handler: Optional[IRetryHandler] = None,
        keep_alive_config: Optional[KeepAliveConfig] = None,
    ) -> None:
        """
        Initialise le gestionnaire de connexions.

        Args:
            retry_handler: Handler pour retries avec backoff (NET_007)
            keep_alive_config: Configuration keep-alive (NET_008)
        """
        self._retry = retry_handler or RetryHandler()
        self._keep_alive = keep_alive_config or KeepAliveConfig()
        self._connections: Dict[str, ConnectionStatus] = {}
        self._degraded_mode = False
        self._degraded_since: Optional[datetime] = None
        self._degraded_reason: Optional[str] = None
        self._connect_func: Optional[Callable] = None
        self._disconnect_func: Optional[Callable] = None
        self._ping_func: Optional[Callable] = None

    def set_connect_handler(self, handler: Callable) -> None:
        """Définit la fonction de connexion."""
        self._connect_func = handler

    def set_disconnect_handler(self, handler: Callable) -> None:
        """Définit la fonction de déconnexion."""
        self._disconnect_func = handler

    def set_ping_handler(self, handler: Callable) -> None:
        """Définit la fonction de ping keep-alive."""
        self._ping_func = handler

    async def connect(self, endpoint: str) -> ConnectionStatus:
        """
        Établit une connexion vers un endpoint.

        Args:
            endpoint: URL ou identifiant de l'endpoint

        Returns:
            ConnectionStatus avec état CONNECTED

        Raises:
            ValueError: Si endpoint vide
            ConnectionLostError: Si connexion échoue
        """
        if not endpoint or not endpoint.strip():
            raise ValueError("Endpoint cannot be empty")

        now = datetime.now(timezone.utc)

        # Simuler ou utiliser le handler réel
        if self._connect_func:
            try:
                await self._connect_func(endpoint)
            except Exception as e:
                status = ConnectionStatus(
                    state=ConnectionState.DISCONNECTED,
                    endpoint=endpoint,
                    connected_at=None,
                    last_activity=now,
                    reconnect_attempts=0,
                    degraded_since=None,
                )
                self._connections[endpoint] = status
                raise ConnectionLostError(endpoint, str(e))

        status = ConnectionStatus(
            state=ConnectionState.CONNECTED,
            endpoint=endpoint,
            connected_at=now,
            last_activity=now,
            reconnect_attempts=0,
            degraded_since=None,
        )

        self._connections[endpoint] = status
        return status

    async def disconnect(self, endpoint: str) -> bool:
        """
        Ferme une connexion proprement.

        Args:
            endpoint: Endpoint à déconnecter

        Returns:
            True si déconnecté, False si non trouvé
        """
        if endpoint not in self._connections:
            return False

        if self._disconnect_func:
            try:
                await self._disconnect_func(endpoint)
            except Exception:
                pass  # Ignorer les erreurs de déconnexion

        status = self._connections[endpoint]
        status.state = ConnectionState.DISCONNECTED
        status.last_activity = datetime.now(timezone.utc)

        return True

    def enter_degraded_mode(self, reason: str) -> None:
        """
        Passe en mode dégradé.

        Le système continue à fonctionner avec fonctionnalités réduites
        au lieu de crasher.

        Args:
            reason: Raison de l'entrée en mode dégradé

        Invariant:
            NET_006: Connexion Cloud perdue = mode dégradé (pas crash)
        """
        if self._degraded_mode:
            return  # Déjà en mode dégradé

        self._degraded_mode = True
        self._degraded_since = datetime.now(timezone.utc)
        self._degraded_reason = reason

        # Marquer toutes les connexions comme dégradées
        for status in self._connections.values():
            if status.state == ConnectionState.CONNECTED:
                status.state = ConnectionState.DEGRADED
                status.degraded_since = self._degraded_since

    def exit_degraded_mode(self) -> None:
        """
        Sort du mode dégradé.

        Restaure le fonctionnement normal après rétablissement
        des connexions.
        """
        if not self._degraded_mode:
            return

        self._degraded_mode = False
        self._degraded_since = None
        self._degraded_reason = None

        # Restaurer les connexions dégradées
        for status in self._connections.values():
            if status.state == ConnectionState.DEGRADED:
                status.state = ConnectionState.CONNECTED
                status.degraded_since = None

    def is_degraded(self) -> bool:
        """
        Vérifie si le système est en mode dégradé.

        Returns:
            True si en mode dégradé

        Invariant:
            NET_006: Mode dégradé détectable
        """
        return self._degraded_mode

    def get_degraded_info(self) -> Optional[Dict[str, Any]]:
        """
        Retourne les informations sur le mode dégradé.

        Returns:
            Dict avec since et reason, ou None si pas dégradé
        """
        if not self._degraded_mode:
            return None

        return {
            "since": self._degraded_since,
            "reason": self._degraded_reason,
            "duration_seconds": (
                datetime.now(timezone.utc) - self._degraded_since
            ).total_seconds()
            if self._degraded_since
            else 0,
        }

    async def reconnect(self, endpoint: str) -> ConnectionStatus:
        """
        Reconnexion automatique avec backoff exponentiel.

        Utilise RetryHandler pour appliquer le backoff.

        Args:
            endpoint: Endpoint à reconnecter

        Returns:
            ConnectionStatus après reconnexion

        Raises:
            ConnectionLostError: Si reconnexion échoue après retries

        Invariant:
            NET_007: Reconnexion automatique avec backoff
        """
        if endpoint not in self._connections:
            # Créer une entrée initiale
            self._connections[endpoint] = ConnectionStatus(
                state=ConnectionState.DISCONNECTED,
                endpoint=endpoint,
                connected_at=None,
                last_activity=datetime.now(timezone.utc),
                reconnect_attempts=0,
                degraded_since=None,
            )

        status = self._connections[endpoint]
        status.state = ConnectionState.RECONNECTING
        status.reconnect_attempts += 1

        async def do_connect() -> ConnectionStatus:
            if self._connect_func:
                await self._connect_func(endpoint)

            now = datetime.now(timezone.utc)
            status.state = ConnectionState.CONNECTED
            status.connected_at = now
            status.last_activity = now
            status.reconnect_attempts = 0

            # Sortir du mode dégradé si toutes les connexions sont rétablies
            if self._degraded_mode:
                all_connected = all(
                    s.state == ConnectionState.CONNECTED
                    for s in self._connections.values()
                )
                if all_connected:
                    self.exit_degraded_mode()

            return status

        # Utiliser RetryHandler pour backoff (NET_007)
        config = RetryConfig(
            max_attempts=3,
            initial_delay=1.0,
            max_delay=10.0,
            exponential_base=2.0,
            retryable_exceptions=(ConnectionError, TimeoutError, Exception),
        )

        result = await self._retry.execute_with_retry(do_connect, config=config)

        if result.success:
            return result.result
        else:
            status.state = ConnectionState.DISCONNECTED
            # Entrer en mode dégradé si reconnexion échoue (NET_006)
            self.enter_degraded_mode(f"Reconnection failed to {endpoint}")
            raise ConnectionLostError(
                endpoint, f"Reconnection failed after {result.attempts} attempts"
            )

    async def send_keep_alive(self, endpoint: str) -> bool:
        """
        Envoie un ping keep-alive vers un endpoint.

        Args:
            endpoint: Endpoint à pinger

        Returns:
            True si ping réussi, False sinon

        Invariant:
            NET_008: Keep-alive TCP activé
        """
        if not self._keep_alive.enabled:
            return True  # Keep-alive désactivé, considéré OK

        if endpoint not in self._connections:
            return False

        status = self._connections[endpoint]

        if status.state not in (ConnectionState.CONNECTED, ConnectionState.DEGRADED):
            return False

        try:
            if self._ping_func:
                await self._ping_func(endpoint)

            # Reset failure count on success
            status.keep_alive_failures = 0
            status.last_activity = datetime.now(timezone.utc)
            return True

        except Exception:
            status.keep_alive_failures += 1

            # NET_008: Détection connexion morte après max_failures
            if status.keep_alive_failures >= self._keep_alive.max_failures:
                status.state = ConnectionState.DISCONNECTED
                self.enter_degraded_mode(
                    f"Keep-alive failed {self._keep_alive.max_failures} times to {endpoint}"
                )

            return False

    async def check_connection_health(self, endpoint: str) -> bool:
        """
        Vérifie la santé d'une connexion via keep-alive.

        Args:
            endpoint: Endpoint à vérifier

        Returns:
            True si connexion saine

        Invariant:
            NET_008: Détection connexion morte
        """
        if endpoint not in self._connections:
            return False

        status = self._connections[endpoint]

        # Connexion déconnectée n'est pas saine
        if status.state == ConnectionState.DISCONNECTED:
            return False

        # Envoyer keep-alive pour vérifier
        return await self.send_keep_alive(endpoint)

    def get_connection_status(self, endpoint: str) -> Optional[ConnectionStatus]:
        """
        Retourne le statut d'une connexion.

        Args:
            endpoint: Endpoint à rechercher

        Returns:
            ConnectionStatus ou None si non trouvé
        """
        return self._connections.get(endpoint)

    def get_all_connections(self) -> Dict[str, ConnectionStatus]:
        """
        Liste toutes les connexions.

        Returns:
            Dict endpoint → ConnectionStatus
        """
        return dict(self._connections)

    def get_connected_endpoints(self) -> list:
        """
        Liste les endpoints connectés.

        Returns:
            Liste des endpoints en état CONNECTED
        """
        return [
            endpoint
            for endpoint, status in self._connections.items()
            if status.state == ConnectionState.CONNECTED
        ]

    def get_degraded_endpoints(self) -> list:
        """
        Liste les endpoints en mode dégradé.

        Returns:
            Liste des endpoints en état DEGRADED
        """
        return [
            endpoint
            for endpoint, status in self._connections.items()
            if status.state == ConnectionState.DEGRADED
        ]

    def clear_all_connections(self) -> None:
        """Supprime toutes les connexions (pour tests)."""
        self._connections.clear()
        self._degraded_mode = False
        self._degraded_since = None
        self._degraded_reason = None
