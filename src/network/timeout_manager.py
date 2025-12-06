"""
LOT 10: Network - Timeout Manager

Gestion centralisée des timeouts réseau.

Invariants:
    NET_001: Timeout connexion 10 secondes max
    NET_002: Timeout requête 30 secondes max (configurable par endpoint)
"""

from typing import Dict, List, Optional

from .interfaces import ITimeoutManager, TimeoutConfig, TimeoutType


class TimeoutExceededError(Exception):
    """Timeout dépassé."""

    def __init__(self, timeout_type: TimeoutType, timeout_value: float) -> None:
        self.timeout_type = timeout_type
        self.timeout_value = timeout_value
        super().__init__(f"{timeout_type.value} timeout exceeded: {timeout_value}s")


class InvalidTimeoutError(Exception):
    """Configuration timeout invalide."""

    pass


class TimeoutManager(ITimeoutManager):
    """
    Gestion centralisée des timeouts.

    Invariants:
        NET_001: Timeout connexion max 10s
        NET_002: Timeout requête max 30s (configurable par endpoint)
    """

    # Limites strictes (invariants)
    MAX_CONNECTION_TIMEOUT: float = 10.0  # NET_001
    MAX_REQUEST_TIMEOUT: float = 30.0  # NET_002
    MAX_READ_TIMEOUT: float = 60.0
    MAX_WRITE_TIMEOUT: float = 60.0

    def __init__(self, default_config: Optional[TimeoutConfig] = None) -> None:
        """
        Initialise le gestionnaire de timeouts.

        Args:
            default_config: Configuration par défaut (optionnel)
        """
        self._default = default_config or TimeoutConfig()
        self._endpoint_configs: Dict[str, TimeoutConfig] = {}

        # Valider la config par défaut
        self._validate_config(self._default)

    def _validate_config(self, config: TimeoutConfig) -> None:
        """
        Valide une configuration complète.

        Args:
            config: Configuration à valider

        Raises:
            InvalidTimeoutError: Si configuration invalide
        """
        # NET_001: connection timeout max 10s
        if config.connection_timeout > self.MAX_CONNECTION_TIMEOUT:
            raise InvalidTimeoutError(
                f"connection_timeout ({config.connection_timeout}s) exceeds "
                f"maximum ({self.MAX_CONNECTION_TIMEOUT}s) - NET_001 violation"
            )

        if config.connection_timeout <= 0:
            raise InvalidTimeoutError("connection_timeout must be positive")

        # NET_002: request timeout max 30s
        if config.request_timeout > self.MAX_REQUEST_TIMEOUT:
            raise InvalidTimeoutError(
                f"request_timeout ({config.request_timeout}s) exceeds "
                f"maximum ({self.MAX_REQUEST_TIMEOUT}s) - NET_002 violation"
            )

        if config.request_timeout <= 0:
            raise InvalidTimeoutError("request_timeout must be positive")

        # Read timeout
        if config.read_timeout is not None:
            if config.read_timeout <= 0:
                raise InvalidTimeoutError("read_timeout must be positive")
            if config.read_timeout > self.MAX_READ_TIMEOUT:
                raise InvalidTimeoutError(
                    f"read_timeout ({config.read_timeout}s) exceeds "
                    f"maximum ({self.MAX_READ_TIMEOUT}s)"
                )

        # Write timeout
        if config.write_timeout is not None:
            if config.write_timeout <= 0:
                raise InvalidTimeoutError("write_timeout must be positive")
            if config.write_timeout > self.MAX_WRITE_TIMEOUT:
                raise InvalidTimeoutError(
                    f"write_timeout ({config.write_timeout}s) exceeds "
                    f"maximum ({self.MAX_WRITE_TIMEOUT}s)"
                )

    def get_timeout(
        self, timeout_type: TimeoutType, endpoint: Optional[str] = None
    ) -> float:
        """
        Retourne timeout configuré (endpoint-specific ou default).

        Args:
            timeout_type: Type de timeout demandé
            endpoint: Endpoint pour config spécifique (optionnel)

        Returns:
            Valeur du timeout en secondes

        Invariants:
            NET_001: Connection timeout max 10s
            NET_002: Request timeout max 30s
        """
        # Utiliser config endpoint si disponible
        config = self._default
        if endpoint and endpoint in self._endpoint_configs:
            config = self._endpoint_configs[endpoint]

        # Retourner selon le type
        if timeout_type == TimeoutType.CONNECTION:
            return config.connection_timeout
        elif timeout_type == TimeoutType.REQUEST:
            return config.request_timeout
        elif timeout_type == TimeoutType.READ:
            return config.read_timeout or config.request_timeout
        elif timeout_type == TimeoutType.WRITE:
            return config.write_timeout or config.request_timeout
        else:
            raise ValueError(f"Unknown timeout type: {timeout_type}")

    def set_endpoint_timeout(self, endpoint: str, config: TimeoutConfig) -> None:
        """
        Configure timeout spécifique par endpoint.

        Args:
            endpoint: URL ou identifiant de l'endpoint
            config: Configuration timeout

        Raises:
            InvalidTimeoutError: Si configuration invalide
            ValueError: Si endpoint vide

        Invariant:
            NET_002: Request timeout configurable par endpoint (max 30s)
        """
        if not endpoint or not endpoint.strip():
            raise ValueError("endpoint cannot be empty")

        # Valider la configuration
        self._validate_config(config)

        # Stocker
        self._endpoint_configs[endpoint] = config

    def validate_timeout(self, timeout_type: TimeoutType, value: float) -> bool:
        """
        Valide que timeout respecte les limites.

        Args:
            timeout_type: Type de timeout
            value: Valeur à valider

        Returns:
            True si valide, False sinon
        """
        if value <= 0:
            return False

        if timeout_type == TimeoutType.CONNECTION:
            return value <= self.MAX_CONNECTION_TIMEOUT
        elif timeout_type == TimeoutType.REQUEST:
            return value <= self.MAX_REQUEST_TIMEOUT
        elif timeout_type == TimeoutType.READ:
            return value <= self.MAX_READ_TIMEOUT
        elif timeout_type == TimeoutType.WRITE:
            return value <= self.MAX_WRITE_TIMEOUT
        else:
            return False

    def get_all_endpoints(self) -> List[str]:
        """
        Liste tous les endpoints configurés.

        Returns:
            Liste des endpoints avec configuration spécifique
        """
        return list(self._endpoint_configs.keys())

    def remove_endpoint_config(self, endpoint: str) -> bool:
        """
        Supprime la configuration d'un endpoint.

        Args:
            endpoint: Endpoint à supprimer

        Returns:
            True si supprimé, False si non trouvé
        """
        if endpoint in self._endpoint_configs:
            del self._endpoint_configs[endpoint]
            return True
        return False

    def get_endpoint_config(self, endpoint: str) -> Optional[TimeoutConfig]:
        """
        Récupère la configuration d'un endpoint.

        Args:
            endpoint: Endpoint à rechercher

        Returns:
            TimeoutConfig ou None
        """
        return self._endpoint_configs.get(endpoint)

    def get_default_config(self) -> TimeoutConfig:
        """
        Retourne la configuration par défaut.

        Returns:
            Configuration par défaut
        """
        return self._default

    def clear_all_endpoints(self) -> None:
        """Supprime toutes les configurations endpoint."""
        self._endpoint_configs.clear()
