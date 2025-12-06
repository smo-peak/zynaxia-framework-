"""
LOT 6: Degraded Mode Controller Implementation

Contrôleur mode dégradé pour Edge offline avec gestion
des fonctionnalités disponibles et file d'attente de synchronisation.

Invariants:
    RUN_052: Mode dégradé si Cloud offline
        - Lecture données locales: OK
        - Écriture événements locaux: OK
        - Sync vers Cloud: File d'attente
        - Nouvelles configs: Cache local uniquement
    RUN_053: Cache config TTL 7 jours max
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from src.audit.interfaces import IAuditEmitter, AuditEventType
from src.ha.interfaces import IDegradedModeController
from src.licensing.interfaces import ILicenseCache


class DegradedModeError(Exception):
    """Erreur du contrôleur de mode dégradé."""

    pass


class DegradedModeController(IDegradedModeController):
    """
    Contrôleur mode dégradé pour Edge offline.

    Invariants:
        RUN_052: Mode dégradé si Cloud offline
        RUN_053: Cache config TTL 7 jours max
    """

    # RUN_053: TTL max du cache config en jours
    CONFIG_CACHE_MAX_TTL_DAYS: int = 7

    # RUN_052: Features disponibles en mode dégradé
    DEGRADED_FEATURES: List[str] = [
        "events:read",
        "events:write:local",
        "config:read:cached",
        "auth:cached_tokens",
        "data:read:local",
        "data:write:local",
    ]

    # Features désactivées en mode dégradé
    DISABLED_FEATURES: List[str] = [
        "sync:cloud",
        "config:refresh",
        "license:online_check",
        "data:sync:cloud",
        "auth:refresh_tokens",
    ]

    # Taille max de la file d'attente d'événements
    MAX_EVENT_QUEUE_SIZE: int = 10000

    def __init__(
        self,
        audit_emitter: IAuditEmitter,
        license_cache: ILicenseCache,
        config_cache_timestamp: Optional[datetime] = None,
    ) -> None:
        """
        Initialise le contrôleur de mode dégradé.

        Args:
            audit_emitter: Émetteur d'événements d'audit.
            license_cache: Cache de licences (LOT 5).
            config_cache_timestamp: Timestamp de la dernière mise à jour du cache config.
        """
        self._audit = audit_emitter
        self._license_cache = license_cache
        self._is_degraded = False
        self._degraded_since: Optional[datetime] = None
        self._reason: Optional[str] = None
        self._event_queue: List[Dict[str, Any]] = []
        self._config_cache_timestamp = config_cache_timestamp or datetime.now()

    def enter_degraded_mode(self, reason: str) -> None:
        """
        Entre en mode dégradé.

        RUN_052: Active le mode dégradé avec les fonctionnalités limitées.

        Args:
            reason: Raison de l'activation pour audit.
        """
        if self._is_degraded:
            return  # Déjà en mode dégradé

        self._is_degraded = True
        self._degraded_since = datetime.now()
        self._reason = reason

        # Note: L'émission d'audit est synchrone car on ne peut pas
        # await dans une méthode non-async. L'événement sera mis en queue.
        self.queue_event_for_sync(
            {
                "type": "degraded_mode_entered",
                "reason": reason,
                "timestamp": self._degraded_since.isoformat(),
            }
        )

    def exit_degraded_mode(self) -> None:
        """
        Sort du mode dégradé.

        Les événements en file d'attente seront synchronisés ultérieurement.
        """
        if not self._is_degraded:
            return  # Pas en mode dégradé

        exit_timestamp = datetime.now()
        duration_seconds = (exit_timestamp - self._degraded_since).total_seconds() if self._degraded_since else 0

        # Enregistrer l'événement de sortie
        self.queue_event_for_sync(
            {
                "type": "degraded_mode_exited",
                "entered_at": self._degraded_since.isoformat() if self._degraded_since else None,
                "exited_at": exit_timestamp.isoformat(),
                "duration_seconds": duration_seconds,
                "events_queued": len(self._event_queue),
            }
        )

        self._is_degraded = False
        self._degraded_since = None
        self._reason = None

    def is_degraded(self) -> bool:
        """
        Vérifie si le système est en mode dégradé.

        Returns:
            True si mode dégradé actif.
        """
        return self._is_degraded

    def get_available_features(self) -> List[str]:
        """
        Récupère les fonctionnalités disponibles.

        RUN_052: En mode dégradé, seules certaines fonctionnalités sont disponibles.

        Returns:
            Liste des features actives (toutes si normal, limitées si dégradé).
        """
        if self._is_degraded:
            return list(self.DEGRADED_FEATURES)

        # En mode normal, toutes les features sont disponibles
        return list(self.DEGRADED_FEATURES) + list(self.DISABLED_FEATURES)

    def get_disabled_features(self) -> List[str]:
        """
        Récupère les fonctionnalités désactivées en mode dégradé.

        Returns:
            Liste des features désactivées (vide si mode normal).
        """
        if self._is_degraded:
            return list(self.DISABLED_FEATURES)
        return []

    def get_degraded_since(self) -> Optional[datetime]:
        """
        Récupère le timestamp d'entrée en mode dégradé.

        Returns:
            Datetime si dégradé, None sinon.
        """
        return self._degraded_since

    def get_degraded_reason(self) -> Optional[str]:
        """
        Récupère la raison du mode dégradé.

        Returns:
            Raison si dégradé, None sinon.
        """
        return self._reason

    def get_degraded_duration_seconds(self) -> float:
        """
        Récupère la durée en mode dégradé.

        Returns:
            Durée en secondes, 0 si pas dégradé.
        """
        if not self._is_degraded or not self._degraded_since:
            return 0.0
        return (datetime.now() - self._degraded_since).total_seconds()

    def queue_event_for_sync(self, event: Dict[str, Any]) -> bool:
        """
        Met un événement en file d'attente pour synchronisation ultérieure.

        RUN_052: Les événements sont mis en file d'attente quand le Cloud est offline.

        Args:
            event: Événement à mettre en file d'attente.

        Returns:
            True si l'événement a été ajouté, False si la file est pleine.
        """
        if len(self._event_queue) >= self.MAX_EVENT_QUEUE_SIZE:
            return False

        # Ajouter timestamp si non présent
        if "queued_at" not in event:
            event["queued_at"] = datetime.now().isoformat()

        self._event_queue.append(event)
        return True

    def get_pending_events(self) -> List[Dict[str, Any]]:
        """
        Récupère les événements en attente de synchronisation.

        Returns:
            Liste des événements en file d'attente.
        """
        return list(self._event_queue)

    def get_pending_events_count(self) -> int:
        """
        Récupère le nombre d'événements en attente.

        Returns:
            Nombre d'événements dans la file.
        """
        return len(self._event_queue)

    def clear_pending_events(self) -> int:
        """
        Vide la file d'attente d'événements.

        Returns:
            Nombre d'événements supprimés.
        """
        count = len(self._event_queue)
        self._event_queue.clear()
        return count

    def pop_pending_events(self, count: int) -> List[Dict[str, Any]]:
        """
        Récupère et supprime les N premiers événements de la file.

        Args:
            count: Nombre d'événements à récupérer.

        Returns:
            Liste des événements récupérés.
        """
        events = self._event_queue[:count]
        self._event_queue = self._event_queue[count:]
        return events

    def is_config_cache_valid(self) -> bool:
        """
        Vérifie si le cache de configuration est encore valide.

        RUN_053: Le cache config ne doit pas dépasser 7 jours.

        Returns:
            True si le cache est valide (< 7 jours).
        """
        if not self._config_cache_timestamp:
            return False

        cache_age = datetime.now() - self._config_cache_timestamp
        max_age = timedelta(days=self.CONFIG_CACHE_MAX_TTL_DAYS)

        return cache_age <= max_age

    def get_config_cache_age_days(self) -> float:
        """
        Récupère l'âge du cache de configuration en jours.

        Returns:
            Âge en jours, ou -1 si pas de cache.
        """
        if not self._config_cache_timestamp:
            return -1.0

        cache_age = datetime.now() - self._config_cache_timestamp
        return cache_age.total_seconds() / 86400  # Secondes par jour

    def update_config_cache_timestamp(self, timestamp: Optional[datetime] = None) -> None:
        """
        Met à jour le timestamp du cache de configuration.

        Args:
            timestamp: Nouveau timestamp (now si non spécifié).
        """
        self._config_cache_timestamp = timestamp or datetime.now()

    def is_feature_available(self, feature: str) -> bool:
        """
        Vérifie si une fonctionnalité est disponible.

        Args:
            feature: Nom de la fonctionnalité.

        Returns:
            True si la fonctionnalité est disponible.
        """
        available = self.get_available_features()
        return feature in available

    def get_status(self) -> Dict[str, Any]:
        """
        Récupère le status complet du mode dégradé.

        Returns:
            Dictionnaire avec toutes les informations de status.
        """
        return {
            "is_degraded": self._is_degraded,
            "degraded_since": (self._degraded_since.isoformat() if self._degraded_since else None),
            "degraded_duration_seconds": self.get_degraded_duration_seconds(),
            "reason": self._reason,
            "available_features": self.get_available_features(),
            "disabled_features": self.get_disabled_features(),
            "pending_events_count": self.get_pending_events_count(),
            "config_cache_valid": self.is_config_cache_valid(),
            "config_cache_age_days": self.get_config_cache_age_days(),
        }
