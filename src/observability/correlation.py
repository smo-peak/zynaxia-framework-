"""
LOT 9: Observability - Correlation ID Management

Implémente la gestion des correlation IDs avec:
- Génération d'UUID uniques (OBS_001)
- Propagation entre services (OBS_002)
- Inclusion automatique dans les logs (OBS_003)

Invariants:
    OBS_001: Chaque requête DOIT avoir un correlation_id unique (UUID)
    OBS_002: correlation_id propagé dans TOUS les appels (Edge→Cloud→DB→Blockchain)
    OBS_003: correlation_id présent dans TOUS les logs liés à la requête
"""

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .interfaces import (
    CorrelationContext,
    ICorrelatedLogger,
    ICorrelationManager,
    ICorrelationPropagator,
    correlation_id_var,
)


# UUID v4 regex pattern
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


class CorrelationError(Exception):
    """Erreur liée à la gestion des correlation IDs."""

    pass


class CorrelationManager(ICorrelationManager):
    """
    Gestion des correlation IDs.

    Utilise ContextVar pour propagation thread-safe automatique.

    Invariant:
        OBS_001: Chaque requête DOIT avoir un correlation_id unique (UUID)
    """

    # Header standard pour propagation HTTP
    HEADER_NAME: str = "X-Correlation-ID"

    def __init__(self) -> None:
        """Initialise le gestionnaire de correlation."""
        self._contexts: Dict[str, CorrelationContext] = {}

    def generate(self) -> str:
        """
        Génère un UUID v4 unique pour correlation.

        Returns:
            UUID v4 sous forme de string

        Invariant:
            OBS_001: UUID unique pour chaque requête
        """
        return str(uuid.uuid4())

    def get_current(self) -> Optional[str]:
        """
        Retourne le correlation_id courant du contexte.

        Returns:
            correlation_id ou None si non défini
        """
        return correlation_id_var.get()

    def set_current(self, correlation_id: str) -> None:
        """
        Définit le correlation_id dans le contexte.

        Args:
            correlation_id: ID à définir

        Raises:
            ValueError: Si correlation_id invalide (pas UUID v4)
        """
        if not correlation_id or not correlation_id.strip():
            raise ValueError("correlation_id cannot be empty")

        if not self.is_valid_uuid(correlation_id):
            raise ValueError(f"Invalid correlation_id format: {correlation_id}")

        correlation_id_var.set(correlation_id)

    def create_context(
        self,
        correlation_id: Optional[str] = None,
        parent_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        user_id: Optional[str] = None,
        source: str = "unknown",
    ) -> CorrelationContext:
        """
        Crée un contexte complet de corrélation.

        Args:
            correlation_id: ID existant ou None pour en générer un
            parent_id: ID parent pour tracing hiérarchique
            tenant_id: Identifiant du tenant
            user_id: Identifiant de l'utilisateur
            source: Source de la requête

        Returns:
            CorrelationContext complet
        """
        # Générer si non fourni
        if correlation_id is None:
            correlation_id = self.generate()
        elif not self.is_valid_uuid(correlation_id):
            raise ValueError(f"Invalid correlation_id format: {correlation_id}")

        # Valider parent_id si fourni
        if parent_id is not None and not self.is_valid_uuid(parent_id):
            raise ValueError(f"Invalid parent_id format: {parent_id}")

        context = CorrelationContext(
            correlation_id=correlation_id,
            parent_id=parent_id,
            tenant_id=tenant_id,
            user_id=user_id,
            source=source,
            created_at=datetime.now(timezone.utc),
        )

        # Stocker le contexte
        self._contexts[correlation_id] = context

        # Définir comme courant
        correlation_id_var.set(correlation_id)

        return context

    def clear(self) -> None:
        """
        Nettoie le contexte courant (fin de requête).
        """
        correlation_id_var.set(None)

    def get_context(self, correlation_id: str) -> Optional[CorrelationContext]:
        """
        Récupère un contexte par correlation_id.

        Args:
            correlation_id: ID à rechercher

        Returns:
            CorrelationContext ou None
        """
        return self._contexts.get(correlation_id)

    def is_valid_uuid(self, value: str) -> bool:
        """
        Vérifie si une valeur est un UUID v4 valide.

        Args:
            value: Valeur à vérifier

        Returns:
            True si UUID v4 valide
        """
        if not value:
            return False
        return bool(UUID_PATTERN.match(value))

    def clear_all_contexts(self) -> None:
        """Efface tous les contextes stockés (pour tests)."""
        self._contexts.clear()
        correlation_id_var.set(None)


class CorrelationPropagator(ICorrelationPropagator):
    """
    Propagation correlation ID entre services.

    Gère l'injection et l'extraction des correlation IDs
    dans les headers HTTP et les logs.

    Invariants:
        OBS_002: correlation_id propagé dans TOUS les appels
        OBS_003: correlation_id présent dans TOUS les logs
    """

    def __init__(self, manager: ICorrelationManager) -> None:
        """
        Initialise le propagateur.

        Args:
            manager: Gestionnaire de correlation IDs
        """
        self._manager = manager

    def inject_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Injecte correlation_id dans headers HTTP.

        Si pas de correlation_id courant, en génère un nouveau.

        Args:
            headers: Headers existants

        Returns:
            Headers enrichis avec X-Correlation-ID

        Invariant:
            OBS_002: Propagation dans tous les appels
        """
        # Copier les headers pour ne pas modifier l'original
        result = dict(headers)

        # Obtenir ou générer correlation_id
        correlation_id = self._manager.get_current()
        if correlation_id is None:
            correlation_id = self._manager.generate()
            self._manager.set_current(correlation_id)

        result[CorrelationManager.HEADER_NAME] = correlation_id

        return result

    def extract_from_headers(self, headers: Dict[str, str]) -> Optional[str]:
        """
        Extrait correlation_id des headers entrants.

        Gère les variations de casse du nom du header.

        Args:
            headers: Headers HTTP de la requête

        Returns:
            correlation_id extrait ou None

        Invariant:
            OBS_002: Extraction automatique
        """
        # Recherche case-insensitive
        header_name = CorrelationManager.HEADER_NAME.lower()

        for key, value in headers.items():
            if key.lower() == header_name:
                # Valider le format
                if self._manager.is_valid_uuid(value):
                    # Définir comme courant
                    self._manager.set_current(value)
                    return value
                # Format invalide, ignorer
                return None

        return None

    def propagate_to_log(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ajoute correlation_id aux données de log.

        Args:
            log_data: Données de log existantes

        Returns:
            log_data enrichi avec correlation_id

        Invariant:
            OBS_003: correlation_id dans tous les logs
        """
        # Copier pour ne pas modifier l'original
        result = dict(log_data)

        correlation_id = self._manager.get_current()
        if correlation_id is not None:
            result["correlation_id"] = correlation_id

        return result

    def create_child_correlation(self) -> str:
        """
        Crée un correlation_id enfant avec parent.

        Utile pour le tracing hiérarchique.

        Returns:
            Nouveau correlation_id
        """
        parent_id = self._manager.get_current()
        child_id = self._manager.generate()

        self._manager.create_context(
            correlation_id=child_id,
            parent_id=parent_id,
        )

        return child_id


class CorrelatedLogger(ICorrelatedLogger):
    """
    Logger qui inclut automatiquement correlation_id.

    Chaque entrée de log contient automatiquement le
    correlation_id courant pour traçabilité complète.

    Invariant:
        OBS_003: correlation_id présent dans TOUS les logs
    """

    def __init__(
        self,
        manager: ICorrelationManager,
        propagator: ICorrelationPropagator,
        logger_name: str = "zynaxia",
    ) -> None:
        """
        Initialise le logger corrélé.

        Args:
            manager: Gestionnaire de correlation IDs
            propagator: Propagateur pour enrichissement
            logger_name: Nom du logger
        """
        self._manager = manager
        self._propagator = propagator
        self._logger_name = logger_name
        self._logs: List[Dict[str, Any]] = []

    def log(self, level: str, message: str, **kwargs: Any) -> None:
        """
        Log avec correlation_id automatique.

        Format: {timestamp, level, message, correlation_id, logger, ...kwargs}

        Args:
            level: Niveau de log
            message: Message à logger
            **kwargs: Données additionnelles

        Invariant:
            OBS_003: correlation_id automatiquement inclus
        """
        # Créer l'entrée de base
        entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level.upper(),
            "message": message,
            "logger": self._logger_name,
        }

        # Ajouter kwargs
        entry.update(kwargs)

        # Enrichir avec correlation_id (OBS_003)
        entry = self._propagator.propagate_to_log(entry)

        # Stocker
        self._logs.append(entry)

    def info(self, message: str, **kwargs: Any) -> None:
        """Log niveau INFO."""
        self.log("INFO", message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        """Log niveau WARNING."""
        self.log("WARNING", message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        """Log niveau ERROR."""
        self.log("ERROR", message, **kwargs)

    def debug(self, message: str, **kwargs: Any) -> None:
        """Log niveau DEBUG."""
        self.log("DEBUG", message, **kwargs)

    def critical(self, message: str, **kwargs: Any) -> None:
        """Log niveau CRITICAL."""
        self.log("CRITICAL", message, **kwargs)

    def get_logs(self) -> List[Dict[str, Any]]:
        """
        Retourne les logs capturés.

        Returns:
            Liste des entrées de log
        """
        return list(self._logs)

    def get_logs_by_correlation(self, correlation_id: str) -> List[Dict[str, Any]]:
        """
        Filtre les logs par correlation_id.

        Args:
            correlation_id: ID à filtrer

        Returns:
            Logs correspondants
        """
        return [
            log for log in self._logs
            if log.get("correlation_id") == correlation_id
        ]

    def clear_logs(self) -> None:
        """Efface les logs capturés (pour tests)."""
        self._logs.clear()
