"""
LOT 6: Config Sync Service Implementation

Service de synchronisation configuration Edge ↔ Cloud avec
gestion du cache local et file d'attente d'événements.

Invariants:
    RUN_053: Cache config TTL 7 jours max
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Awaitable, Dict, List, Optional

from src.audit.interfaces import IAuditEmitter, AuditEventType
from src.ha.interfaces import IConfigSyncService, IDegradedModeController, SyncResult


class ConfigSyncError(Exception):
    """Erreur lors de la synchronisation."""

    pass


# Type pour le client cloud (injectable pour tests)
CloudClient = Callable[[str, Dict[str, Any]], Awaitable[Dict[str, Any]]]


class ConfigSyncService(IConfigSyncService):
    """
    Service de synchronisation config Edge ↔ Cloud.

    Invariants:
        RUN_053: Cache config TTL 7 jours max
    """

    # Intervalle de synchronisation en heures
    SYNC_INTERVAL_HOURS: int = 6

    # RUN_053: TTL max du cache en jours
    MAX_CACHE_AGE_DAYS: int = 7

    # Taille max de la file d'attente d'événements
    MAX_PENDING_EVENTS: int = 10000

    # Timeout pour les opérations cloud
    CLOUD_TIMEOUT_SECONDS: float = 30.0

    def __init__(
        self,
        node_id: str,
        audit_emitter: IAuditEmitter,
        degraded_controller: IDegradedModeController,
        cloud_client: Optional[CloudClient] = None,
    ) -> None:
        """
        Initialise le service de synchronisation.

        Args:
            node_id: Identifiant unique du noeud.
            audit_emitter: Émetteur d'événements d'audit.
            degraded_controller: Contrôleur de mode dégradé.
            cloud_client: Client cloud injectable (pour tests).
        """
        self._node_id = node_id
        self._audit = audit_emitter
        self._degraded = degraded_controller
        self._cloud_client = cloud_client or self._default_cloud_client
        self._last_sync: Optional[datetime] = None
        self._last_sync_success: bool = False
        self._cached_config: Dict[str, Any] = {}
        self._config_cache_timestamp: Optional[datetime] = None
        self._pending_events: List[Dict[str, Any]] = []
        self._sync_errors: List[str] = []

    async def _default_cloud_client(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Client cloud par défaut (simule erreur de connexion).

        En production, ce serait remplacé par un vrai client HTTP.
        """
        raise ConfigSyncError("Cloud client not configured")

    async def sync_from_cloud(self) -> SyncResult:
        """
        Récupère la configuration depuis le Cloud.

        Met à jour le cache local si succès.

        Returns:
            Résultat de la synchronisation.
        """
        sync_start = datetime.now()
        errors: List[str] = []
        items_synced = 0

        try:
            # Appel au cloud pour récupérer la config
            response = await asyncio.wait_for(
                self._cloud_client("config/sync", {"node_id": self._node_id}),
                timeout=self.CLOUD_TIMEOUT_SECONDS,
            )

            # Mettre à jour le cache local
            if "config" in response:
                self._cached_config = response["config"]
                self._config_cache_timestamp = datetime.now()
                items_synced = len(response["config"])

                # Mettre à jour le timestamp du cache dans le degraded controller
                self._degraded.update_config_cache_timestamp(datetime.now())

            self._last_sync = datetime.now()
            self._last_sync_success = True
            self._sync_errors.clear()

            # Émettre événement audit
            await self._audit.emit_event(
                event_type=AuditEventType.SYSTEM_CONFIG_CHANGE,
                user_id="system",
                tenant_id="system",
                action="config_sync_from_cloud",
                metadata={
                    "node_id": self._node_id,
                    "items_synced": items_synced,
                    "success": True,
                },
            )

            # Sortir du mode dégradé si on y était
            if self._degraded.is_degraded():
                self._degraded.exit_degraded_mode()

            return SyncResult(
                success=True,
                synced_at=sync_start,
                items_synced=items_synced,
                items_failed=0,
                error_message=None,
            )

        except asyncio.TimeoutError:
            errors.append(f"Cloud sync timeout after {self.CLOUD_TIMEOUT_SECONDS}s")
        except ConfigSyncError as e:
            errors.append(str(e))
        except Exception as e:
            errors.append(f"Unexpected error: {str(e)}")

        # En cas d'erreur
        self._last_sync = datetime.now()
        self._last_sync_success = False
        self._sync_errors = errors

        # Entrer en mode dégradé si pas déjà
        if not self._degraded.is_degraded():
            self._degraded.enter_degraded_mode(f"Cloud sync failed: {errors[0]}")

        return SyncResult(
            success=False,
            synced_at=sync_start,
            items_synced=0,
            items_failed=1,
            error_message="; ".join(errors),
        )

    async def push_events_to_cloud(self) -> SyncResult:
        """
        Pousse les événements locaux vers le Cloud.

        Vide la file d'attente si succès.

        Returns:
            Résultat de la synchronisation.
        """
        sync_start = datetime.now()

        if not self._pending_events:
            return SyncResult(
                success=True,
                synced_at=sync_start,
                items_synced=0,
                items_failed=0,
                error_message=None,
            )

        events_to_sync = list(self._pending_events)
        errors: List[str] = []
        items_synced = 0
        items_failed = 0

        try:
            # Appel au cloud pour pousser les événements
            response = await asyncio.wait_for(
                self._cloud_client(
                    "events/push",
                    {
                        "node_id": self._node_id,
                        "events": events_to_sync,
                    },
                ),
                timeout=self.CLOUD_TIMEOUT_SECONDS,
            )

            # Traiter la réponse
            if response.get("success"):
                items_synced = response.get("synced", len(events_to_sync))
                items_failed = response.get("failed", 0)

                # Vider les événements synchronisés
                if items_failed == 0:
                    self._pending_events.clear()
                else:
                    # Garder uniquement les événements échoués
                    failed_ids = set(response.get("failed_ids", []))
                    self._pending_events = [e for e in self._pending_events if e.get("id") in failed_ids]

                # Émettre événement audit
                await self._audit.emit_event(
                    event_type=AuditEventType.SYSTEM_CONFIG_CHANGE,
                    user_id="system",
                    tenant_id="system",
                    action="events_push_to_cloud",
                    metadata={
                        "node_id": self._node_id,
                        "items_synced": items_synced,
                        "items_failed": items_failed,
                    },
                )

                return SyncResult(
                    success=items_failed == 0,
                    synced_at=sync_start,
                    items_synced=items_synced,
                    items_failed=items_failed,
                    error_message=None if items_failed == 0 else f"{items_failed} events failed",
                )

        except asyncio.TimeoutError:
            errors.append(f"Cloud push timeout after {self.CLOUD_TIMEOUT_SECONDS}s")
        except ConfigSyncError as e:
            errors.append(str(e))
        except Exception as e:
            errors.append(f"Unexpected error: {str(e)}")

        # En cas d'erreur, les événements restent en file
        return SyncResult(
            success=False,
            synced_at=sync_start,
            items_synced=0,
            items_failed=len(events_to_sync),
            error_message="; ".join(errors),
        )

    def get_last_sync(self) -> Optional[datetime]:
        """
        Récupère le timestamp de la dernière synchronisation réussie.

        Returns:
            Datetime de la dernière sync, None si jamais sync.
        """
        if self._last_sync_success:
            return self._last_sync
        return None

    def get_last_sync_attempt(self) -> Optional[datetime]:
        """
        Récupère le timestamp de la dernière tentative de sync.

        Returns:
            Datetime de la dernière tentative.
        """
        return self._last_sync

    def is_sync_overdue(self) -> bool:
        """
        Vérifie si une synchronisation est en retard.

        RUN_053: True si dernière sync > SYNC_INTERVAL_HOURS.

        Returns:
            True si la sync est en retard.
        """
        if not self._last_sync:
            return True

        sync_age = datetime.now() - self._last_sync
        max_age = timedelta(hours=self.SYNC_INTERVAL_HOURS)

        return sync_age > max_age

    def is_cache_expired(self) -> bool:
        """
        Vérifie si le cache de configuration est expiré.

        RUN_053: True si cache > 7 jours.

        Returns:
            True si le cache est expiré.
        """
        if not self._config_cache_timestamp:
            return True

        cache_age = datetime.now() - self._config_cache_timestamp
        max_age = timedelta(days=self.MAX_CACHE_AGE_DAYS)

        return cache_age > max_age

    def get_cache_age_hours(self) -> float:
        """
        Récupère l'âge du cache en heures.

        Returns:
            Âge en heures, ou -1 si pas de cache.
        """
        if not self._config_cache_timestamp:
            return -1.0

        cache_age = datetime.now() - self._config_cache_timestamp
        return cache_age.total_seconds() / 3600

    def get_cached_config(self, key: str) -> Optional[Any]:
        """
        Récupère une valeur de configuration depuis le cache.

        Args:
            key: Clé de configuration.

        Returns:
            Valeur si trouvée, None sinon.
        """
        return self._cached_config.get(key)

    def get_all_cached_config(self) -> Dict[str, Any]:
        """
        Récupère toute la configuration cachée.

        Returns:
            Dictionnaire de configuration.
        """
        return dict(self._cached_config)

    def set_cached_config(self, key: str, value: Any) -> None:
        """
        Définit une valeur de configuration en cache.

        Args:
            key: Clé de configuration.
            value: Valeur à stocker.
        """
        self._cached_config[key] = value
        if not self._config_cache_timestamp:
            self._config_cache_timestamp = datetime.now()

    def queue_event(self, event: Dict[str, Any]) -> bool:
        """
        Met un événement en file d'attente pour synchronisation.

        Args:
            event: Événement à mettre en file.

        Returns:
            True si ajouté, False si file pleine.
        """
        if len(self._pending_events) >= self.MAX_PENDING_EVENTS:
            return False

        # Ajouter metadata si absent
        if "queued_at" not in event:
            event["queued_at"] = datetime.now().isoformat()
        if "node_id" not in event:
            event["node_id"] = self._node_id

        self._pending_events.append(event)

        # Mettre aussi en file dans le degraded controller
        self._degraded.queue_event_for_sync(event)

        return True

    def get_pending_events_count(self) -> int:
        """
        Récupère le nombre d'événements en attente.

        Returns:
            Nombre d'événements.
        """
        return len(self._pending_events)

    def get_pending_events(self) -> List[Dict[str, Any]]:
        """
        Récupère les événements en attente.

        Returns:
            Liste des événements.
        """
        return list(self._pending_events)

    def clear_pending_events(self) -> int:
        """
        Vide la file d'attente d'événements.

        Returns:
            Nombre d'événements supprimés.
        """
        count = len(self._pending_events)
        self._pending_events.clear()
        return count

    def get_sync_status(self) -> Dict[str, Any]:
        """
        Récupère le status complet de synchronisation.

        Returns:
            Dictionnaire avec toutes les informations de sync.
        """
        return {
            "node_id": self._node_id,
            "last_sync": self._last_sync.isoformat() if self._last_sync else None,
            "last_sync_success": self._last_sync_success,
            "sync_overdue": self.is_sync_overdue(),
            "cache_expired": self.is_cache_expired(),
            "cache_age_hours": self.get_cache_age_hours(),
            "pending_events_count": self.get_pending_events_count(),
            "sync_errors": list(self._sync_errors),
            "is_degraded": self._degraded.is_degraded(),
        }

    def get_next_sync_due(self) -> datetime:
        """
        Calcule quand la prochaine sync est due.

        Returns:
            Datetime de la prochaine sync prévue.
        """
        if not self._last_sync:
            return datetime.now()

        return self._last_sync + timedelta(hours=self.SYNC_INTERVAL_HOURS)

    @property
    def node_id(self) -> str:
        """Retourne l'ID du noeud."""
        return self._node_id
