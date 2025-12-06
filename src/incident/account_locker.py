"""
LOT 8: Gestion du verrouillage de comptes

Implémente le verrouillage automatique des comptes après
plusieurs échecs d'authentification.

Invariant:
    INCID_003: 3 échecs auth = compte verrouillé temporaire (15 min)
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

from src.incident.interfaces import (
    IAccountLocker,
    AuthFailure,
    AccountLockStatus,
)
from src.audit.interfaces import IAuditEmitter, AuditEventType


class AccountLockerError(Exception):
    """Erreur du gestionnaire de verrouillage."""

    pass


class AccountLocker(IAccountLocker):
    """
    Gestion du verrouillage de comptes après échecs d'authentification.

    Implémente un mécanisme de protection contre les attaques
    par force brute en verrouillant temporairement les comptes
    après un nombre défini d'échecs.

    Invariant:
        INCID_003: 3 échecs auth = compte verrouillé temporaire (15 min)
    """

    # Constantes INCID_003
    MAX_FAILURES: int = 3
    LOCKOUT_DURATION: timedelta = timedelta(minutes=15)

    def __init__(
        self,
        audit_emitter: IAuditEmitter,
        max_failures: Optional[int] = None,
        lockout_duration: Optional[timedelta] = None,
    ) -> None:
        """
        Initialise le gestionnaire de verrouillage.

        Args:
            audit_emitter: Émetteur pour les événements d'audit
            max_failures: Nombre max d'échecs avant verrouillage (défaut: 3)
            lockout_duration: Durée du verrouillage (défaut: 15 min)
        """
        self._audit = audit_emitter
        self._max_failures = max_failures if max_failures is not None else self.MAX_FAILURES
        self._lockout_duration = lockout_duration if lockout_duration is not None else self.LOCKOUT_DURATION

        # Stockage en mémoire des échecs et verrous
        self._failures: Dict[str, List[AuthFailure]] = {}
        self._locks: Dict[str, datetime] = {}  # user_id -> locked_until

    def record_auth_failure(self, failure: AuthFailure) -> AccountLockStatus:
        """
        Enregistre un échec d'authentification et verrouille si nécessaire.

        Args:
            failure: Détails de l'échec d'authentification

        Returns:
            Statut du compte après enregistrement

        Invariant:
            INCID_003: 3 échecs auth = compte verrouillé temporaire (15 min)
        """
        user_id = failure.user_id

        # Vérifier si déjà verrouillé
        if self.is_locked(user_id):
            return self.get_status(user_id)

        # Nettoyer les anciens échecs (plus vieux que la durée de verrouillage)
        self._cleanup_old_failures(user_id)

        # Enregistrer l'échec
        if user_id not in self._failures:
            self._failures[user_id] = []
        self._failures[user_id].append(failure)

        failure_count = len(self._failures[user_id])

        # INCID_003: Verrouiller après MAX_FAILURES échecs
        if failure_count >= self._max_failures:
            locked_until = datetime.now(timezone.utc) + self._lockout_duration
            self._locks[user_id] = locked_until

            # Émettre événement audit pour verrouillage
            # Note: Appel synchrone car record_auth_failure est sync
            # L'audit sera émis de manière asynchrone par l'appelant si nécessaire

            return AccountLockStatus(
                user_id=user_id,
                locked=True,
                locked_until=locked_until,
                failure_count=failure_count,
                last_failure=failure.timestamp,
            )

        return AccountLockStatus(
            user_id=user_id,
            locked=False,
            locked_until=None,
            failure_count=failure_count,
            last_failure=failure.timestamp,
        )

    def is_locked(self, user_id: str) -> bool:
        """
        Vérifie si un compte est actuellement verrouillé.

        Auto-déverrouille si la période de verrouillage est expirée.

        Args:
            user_id: Identifiant utilisateur

        Returns:
            True si compte verrouillé
        """
        if user_id not in self._locks:
            return False

        locked_until = self._locks[user_id]
        now = datetime.now(timezone.utc)

        # Auto-déverrouillage si expiré
        if now >= locked_until:
            self._auto_unlock(user_id)
            return False

        return True

    def unlock(self, user_id: str) -> bool:
        """
        Déverrouille manuellement un compte (action admin).

        Args:
            user_id: Identifiant utilisateur

        Returns:
            True si déverrouillage réussi (compte était verrouillé)
        """
        if user_id not in self._locks:
            return False

        del self._locks[user_id]
        # Réinitialiser aussi les échecs
        self.reset_failures(user_id)

        return True

    def get_status(self, user_id: str) -> AccountLockStatus:
        """
        Récupère le statut détaillé d'un compte.

        Args:
            user_id: Identifiant utilisateur

        Returns:
            Statut complet du compte
        """
        # Vérifier le verrouillage (avec auto-unlock si expiré)
        locked = self.is_locked(user_id)
        locked_until = self._locks.get(user_id) if locked else None

        # Nettoyer les anciens échecs
        self._cleanup_old_failures(user_id)

        failures = self._failures.get(user_id, [])
        failure_count = len(failures)
        last_failure = failures[-1].timestamp if failures else None

        return AccountLockStatus(
            user_id=user_id,
            locked=locked,
            locked_until=locked_until,
            failure_count=failure_count,
            last_failure=last_failure,
        )

    def reset_failures(self, user_id: str) -> None:
        """
        Réinitialise le compteur d'échecs (après auth réussie).

        Args:
            user_id: Identifiant utilisateur
        """
        if user_id in self._failures:
            del self._failures[user_id]

    def get_remaining_attempts(self, user_id: str) -> int:
        """
        Retourne le nombre de tentatives restantes avant verrouillage.

        Args:
            user_id: Identifiant utilisateur

        Returns:
            Nombre de tentatives restantes
        """
        if self.is_locked(user_id):
            return 0

        self._cleanup_old_failures(user_id)
        current_failures = len(self._failures.get(user_id, []))
        return max(0, self._max_failures - current_failures)

    def get_lock_remaining_time(self, user_id: str) -> Optional[timedelta]:
        """
        Retourne le temps restant avant déverrouillage automatique.

        Args:
            user_id: Identifiant utilisateur

        Returns:
            Temps restant ou None si non verrouillé
        """
        if not self.is_locked(user_id):
            return None

        locked_until = self._locks.get(user_id)
        if locked_until is None:
            return None

        now = datetime.now(timezone.utc)
        remaining = locked_until - now
        return remaining if remaining.total_seconds() > 0 else None

    def _cleanup_old_failures(self, user_id: str) -> None:
        """
        Nettoie les échecs plus anciens que la durée de verrouillage.

        Args:
            user_id: Identifiant utilisateur
        """
        if user_id not in self._failures:
            return

        cutoff = datetime.now(timezone.utc) - self._lockout_duration
        self._failures[user_id] = [
            f for f in self._failures[user_id]
            if f.timestamp > cutoff
        ]

        if not self._failures[user_id]:
            del self._failures[user_id]

    def _auto_unlock(self, user_id: str) -> None:
        """
        Déverrouille automatiquement un compte après expiration.

        Args:
            user_id: Identifiant utilisateur
        """
        if user_id in self._locks:
            del self._locks[user_id]
        # Garder les échecs récents (pour le prochain cycle)
        self._cleanup_old_failures(user_id)

    def get_all_locked_accounts(self) -> List[AccountLockStatus]:
        """
        Retourne la liste de tous les comptes actuellement verrouillés.

        Returns:
            Liste des statuts des comptes verrouillés
        """
        locked_accounts: List[AccountLockStatus] = []
        for user_id in list(self._locks.keys()):
            if self.is_locked(user_id):  # Vérifie et auto-unlock si expiré
                locked_accounts.append(self.get_status(user_id))
        return locked_accounts

    def clear_all(self) -> None:
        """Efface tous les échecs et verrouillages (pour tests)."""
        self._failures.clear()
        self._locks.clear()
