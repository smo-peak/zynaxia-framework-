"""
Tests unitaires pour AccountLocker (LOT 8 - PARTIE 1).

Vérifie l'invariant:
    INCID_003: 3 échecs auth = compte verrouillé temporaire (15 min)
"""

import pytest
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List
from unittest.mock import AsyncMock

from src.incident.account_locker import AccountLocker, AccountLockerError
from src.incident.interfaces import (
    AuthFailure,
    AccountLockStatus,
)
from src.audit.interfaces import IAuditEmitter, AuditEvent, AuditEventType


# =============================================================================
# FIXTURES
# =============================================================================


class MockAuditEmitter(IAuditEmitter):
    """Mock de l'émetteur d'audit."""

    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []

    async def emit_event(
        self,
        event_type: AuditEventType,
        user_id: str,
        tenant_id: str,
        action: str,
        resource_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuditEvent:
        self.events.append({
            "event_type": event_type,
            "user_id": user_id,
            "tenant_id": tenant_id,
            "action": action,
        })
        return AuditEvent(
            event_id="evt-123",
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            tenant_id=tenant_id,
            resource_id=resource_id,
            action=action,
            metadata=metadata or {},
            ip_address=ip_address,
            user_agent=user_agent,
        )

    def verify_event_signature(self, event: AuditEvent) -> bool:
        return True

    def compute_event_hash(self, event: AuditEvent) -> str:
        return "hash-123"


def create_auth_failure(
    user_id: str = "user-1",
    tenant_id: str = "tenant-1",
    source_ip: str = "192.168.1.1",
    reason: str = "Invalid password",
    timestamp: Optional[datetime] = None,
) -> AuthFailure:
    """Crée un échec d'authentification pour les tests."""
    return AuthFailure(
        user_id=user_id,
        tenant_id=tenant_id,
        source_ip=source_ip,
        timestamp=timestamp or datetime.now(timezone.utc),
        reason=reason,
    )


@pytest.fixture
def audit_emitter() -> MockAuditEmitter:
    return MockAuditEmitter()


@pytest.fixture
def locker(audit_emitter: MockAuditEmitter) -> AccountLocker:
    return AccountLocker(audit_emitter=audit_emitter)


# =============================================================================
# TEST INCID_003: 3 ÉCHECS = VERROUILLAGE 15 MIN
# =============================================================================


class TestINCID003AccountLocking:
    """Tests pour INCID_003: 3 échecs auth = compte verrouillé temporaire (15 min)."""

    def test_INCID_003_first_failure_not_locked(
        self,
        locker: AccountLocker,
    ) -> None:
        """INCID_003: 1er échec ne verrouille pas le compte."""
        failure = create_auth_failure()
        status = locker.record_auth_failure(failure)

        assert status.locked is False
        assert status.failure_count == 1

    def test_INCID_003_second_failure_not_locked(
        self,
        locker: AccountLocker,
    ) -> None:
        """INCID_003: 2ème échec ne verrouille pas le compte."""
        for _ in range(2):
            failure = create_auth_failure()
            status = locker.record_auth_failure(failure)

        assert status.locked is False
        assert status.failure_count == 2

    def test_INCID_003_third_failure_locks_account(
        self,
        locker: AccountLocker,
    ) -> None:
        """INCID_003: 3ème échec verrouille le compte."""
        for i in range(3):
            failure = create_auth_failure()
            status = locker.record_auth_failure(failure)

        assert status.locked is True
        assert status.failure_count == 3

    def test_INCID_003_locked_for_15_minutes(
        self,
        locker: AccountLocker,
    ) -> None:
        """INCID_003: Verrouillage dure 15 minutes."""
        for _ in range(3):
            failure = create_auth_failure()
            locker.record_auth_failure(failure)

        status = locker.get_status("user-1")

        assert status.locked is True
        assert status.locked_until is not None

        expected_unlock = datetime.now(timezone.utc) + timedelta(minutes=15)
        # Tolérance de 5 secondes
        assert abs((status.locked_until - expected_unlock).total_seconds()) < 5

    def test_INCID_003_is_locked_returns_true(
        self,
        locker: AccountLocker,
    ) -> None:
        """INCID_003: is_locked() retourne True après verrouillage."""
        for _ in range(3):
            failure = create_auth_failure()
            locker.record_auth_failure(failure)

        assert locker.is_locked("user-1") is True

    def test_INCID_003_is_locked_returns_false_before_lock(
        self,
        locker: AccountLocker,
    ) -> None:
        """INCID_003: is_locked() retourne False avant verrouillage."""
        failure = create_auth_failure()
        locker.record_auth_failure(failure)

        assert locker.is_locked("user-1") is False

    def test_INCID_003_different_users_independent(
        self,
        locker: AccountLocker,
    ) -> None:
        """INCID_003: Échecs de différents utilisateurs sont indépendants."""
        # 3 échecs pour user-1 (verrouillé)
        for _ in range(3):
            failure = create_auth_failure(user_id="user-1")
            locker.record_auth_failure(failure)

        # 1 échec pour user-2 (pas verrouillé)
        failure = create_auth_failure(user_id="user-2")
        locker.record_auth_failure(failure)

        assert locker.is_locked("user-1") is True
        assert locker.is_locked("user-2") is False

    def test_INCID_003_auto_unlock_after_expiry(
        self,
        audit_emitter: MockAuditEmitter,
    ) -> None:
        """INCID_003: Auto-déverrouillage après expiration."""
        # Utiliser une durée de verrouillage très courte pour le test
        locker = AccountLocker(
            audit_emitter=audit_emitter,
            lockout_duration=timedelta(milliseconds=1),
        )

        for _ in range(3):
            failure = create_auth_failure()
            locker.record_auth_failure(failure)

        # Attendre l'expiration
        import time
        time.sleep(0.01)

        # Devrait être auto-déverrouillé
        assert locker.is_locked("user-1") is False

    def test_INCID_003_manual_unlock(
        self,
        locker: AccountLocker,
    ) -> None:
        """INCID_003: Déverrouillage manuel par admin."""
        for _ in range(3):
            failure = create_auth_failure()
            locker.record_auth_failure(failure)

        assert locker.is_locked("user-1") is True

        result = locker.unlock("user-1")

        assert result is True
        assert locker.is_locked("user-1") is False

    def test_INCID_003_unlock_non_locked_returns_false(
        self,
        locker: AccountLocker,
    ) -> None:
        """INCID_003: unlock() retourne False si compte non verrouillé."""
        result = locker.unlock("non-existent-user")
        assert result is False

    def test_INCID_003_reset_failures_after_success(
        self,
        locker: AccountLocker,
    ) -> None:
        """INCID_003: reset_failures() réinitialise le compteur."""
        # 2 échecs
        for _ in range(2):
            failure = create_auth_failure()
            locker.record_auth_failure(failure)

        # Réinitialiser (auth réussie)
        locker.reset_failures("user-1")

        # 1 nouvel échec ne devrait pas verrouiller
        failure = create_auth_failure()
        status = locker.record_auth_failure(failure)

        assert status.locked is False
        assert status.failure_count == 1


# =============================================================================
# TESTS STATUT ET INFORMATIONS
# =============================================================================


class TestAccountStatus:
    """Tests pour les informations de statut."""

    def test_get_status_unknown_user(
        self,
        locker: AccountLocker,
    ) -> None:
        """get_status() pour utilisateur inconnu."""
        status = locker.get_status("unknown-user")

        assert status.user_id == "unknown-user"
        assert status.locked is False
        assert status.failure_count == 0
        assert status.last_failure is None

    def test_get_status_with_failures(
        self,
        locker: AccountLocker,
    ) -> None:
        """get_status() avec des échecs enregistrés."""
        failure = create_auth_failure()
        locker.record_auth_failure(failure)

        status = locker.get_status("user-1")

        assert status.failure_count == 1
        assert status.last_failure is not None

    def test_get_remaining_attempts_full(
        self,
        locker: AccountLocker,
    ) -> None:
        """get_remaining_attempts() retourne 3 initialement."""
        remaining = locker.get_remaining_attempts("user-1")
        assert remaining == 3

    def test_get_remaining_attempts_after_failures(
        self,
        locker: AccountLocker,
    ) -> None:
        """get_remaining_attempts() décrémente après échecs."""
        failure = create_auth_failure()
        locker.record_auth_failure(failure)

        remaining = locker.get_remaining_attempts("user-1")
        assert remaining == 2

    def test_get_remaining_attempts_when_locked(
        self,
        locker: AccountLocker,
    ) -> None:
        """get_remaining_attempts() retourne 0 quand verrouillé."""
        for _ in range(3):
            failure = create_auth_failure()
            locker.record_auth_failure(failure)

        remaining = locker.get_remaining_attempts("user-1")
        assert remaining == 0

    def test_get_lock_remaining_time(
        self,
        locker: AccountLocker,
    ) -> None:
        """get_lock_remaining_time() retourne temps restant."""
        for _ in range(3):
            failure = create_auth_failure()
            locker.record_auth_failure(failure)

        remaining = locker.get_lock_remaining_time("user-1")

        assert remaining is not None
        # Devrait être proche de 15 minutes
        assert remaining.total_seconds() > 14 * 60
        assert remaining.total_seconds() <= 15 * 60

    def test_get_lock_remaining_time_not_locked(
        self,
        locker: AccountLocker,
    ) -> None:
        """get_lock_remaining_time() retourne None si non verrouillé."""
        remaining = locker.get_lock_remaining_time("user-1")
        assert remaining is None


# =============================================================================
# TESTS CONFIGURATION
# =============================================================================


class TestConfiguration:
    """Tests pour la configuration personnalisée."""

    def test_custom_max_failures(
        self,
        audit_emitter: MockAuditEmitter,
    ) -> None:
        """Nombre d'échecs personnalisé avant verrouillage."""
        locker = AccountLocker(
            audit_emitter=audit_emitter,
            max_failures=5,
        )

        # 4 échecs ne devraient pas verrouiller
        for _ in range(4):
            failure = create_auth_failure()
            status = locker.record_auth_failure(failure)

        assert status.locked is False

        # 5ème échec verrouille
        failure = create_auth_failure()
        status = locker.record_auth_failure(failure)

        assert status.locked is True
        assert status.failure_count == 5

    def test_custom_lockout_duration(
        self,
        audit_emitter: MockAuditEmitter,
    ) -> None:
        """Durée de verrouillage personnalisée."""
        locker = AccountLocker(
            audit_emitter=audit_emitter,
            lockout_duration=timedelta(hours=1),
        )

        for _ in range(3):
            failure = create_auth_failure()
            locker.record_auth_failure(failure)

        status = locker.get_status("user-1")

        expected_unlock = datetime.now(timezone.utc) + timedelta(hours=1)
        assert abs((status.locked_until - expected_unlock).total_seconds()) < 5

    def test_constants_default_values(
        self,
        locker: AccountLocker,
    ) -> None:
        """Vérification des valeurs par défaut."""
        assert AccountLocker.MAX_FAILURES == 3
        assert AccountLocker.LOCKOUT_DURATION == timedelta(minutes=15)


# =============================================================================
# TESTS GESTION MULTI-COMPTES
# =============================================================================


class TestMultipleAccounts:
    """Tests pour la gestion de plusieurs comptes."""

    def test_get_all_locked_accounts_empty(
        self,
        locker: AccountLocker,
    ) -> None:
        """get_all_locked_accounts() retourne liste vide initialement."""
        locked = locker.get_all_locked_accounts()
        assert locked == []

    def test_get_all_locked_accounts(
        self,
        locker: AccountLocker,
    ) -> None:
        """get_all_locked_accounts() retourne comptes verrouillés."""
        # Verrouiller 2 comptes
        for user_id in ["user-1", "user-2"]:
            for _ in range(3):
                failure = create_auth_failure(user_id=user_id)
                locker.record_auth_failure(failure)

        locked = locker.get_all_locked_accounts()

        assert len(locked) == 2
        user_ids = [s.user_id for s in locked]
        assert "user-1" in user_ids
        assert "user-2" in user_ids

    def test_clear_all(
        self,
        locker: AccountLocker,
    ) -> None:
        """clear_all() efface tous les échecs et verrouillages."""
        for _ in range(3):
            failure = create_auth_failure()
            locker.record_auth_failure(failure)

        assert locker.is_locked("user-1") is True

        locker.clear_all()

        assert locker.is_locked("user-1") is False
        assert locker.get_status("user-1").failure_count == 0


# =============================================================================
# TESTS NETTOYAGE AUTOMATIQUE
# =============================================================================


class TestAutoCleanup:
    """Tests pour le nettoyage automatique des anciennes entrées."""

    def test_old_failures_cleaned(
        self,
        audit_emitter: MockAuditEmitter,
    ) -> None:
        """Les échecs plus vieux que la durée de verrouillage sont nettoyés."""
        locker = AccountLocker(
            audit_emitter=audit_emitter,
            lockout_duration=timedelta(milliseconds=1),
        )

        # Enregistrer un échec
        failure = create_auth_failure()
        locker.record_auth_failure(failure)

        # Attendre l'expiration
        import time
        time.sleep(0.01)

        # Enregistrer un nouvel échec (devrait nettoyer l'ancien)
        failure = create_auth_failure()
        status = locker.record_auth_failure(failure)

        # Le compteur devrait être à 1, pas 2
        assert status.failure_count == 1

    def test_record_failure_on_locked_account_ignored(
        self,
        locker: AccountLocker,
    ) -> None:
        """Nouveaux échecs ignorés sur compte déjà verrouillé."""
        # Verrouiller le compte
        for _ in range(3):
            failure = create_auth_failure()
            locker.record_auth_failure(failure)

        # Essayer d'ajouter un 4ème échec
        failure = create_auth_failure()
        status = locker.record_auth_failure(failure)

        # Le compte reste verrouillé avec 3 échecs
        assert status.locked is True
        assert status.failure_count == 3


# =============================================================================
# TESTS DATACLASSES
# =============================================================================


class TestDataclasses:
    """Tests pour les dataclasses."""

    def test_auth_failure_creation(self) -> None:
        """AuthFailure création correcte."""
        now = datetime.now(timezone.utc)
        failure = AuthFailure(
            user_id="user-1",
            tenant_id="tenant-1",
            source_ip="10.0.0.1",
            timestamp=now,
            reason="Bad password",
        )

        assert failure.user_id == "user-1"
        assert failure.tenant_id == "tenant-1"
        assert failure.source_ip == "10.0.0.1"
        assert failure.timestamp == now
        assert failure.reason == "Bad password"

    def test_account_lock_status_creation(self) -> None:
        """AccountLockStatus création correcte."""
        now = datetime.now(timezone.utc)
        status = AccountLockStatus(
            user_id="user-1",
            locked=True,
            locked_until=now + timedelta(minutes=15),
            failure_count=3,
            last_failure=now,
        )

        assert status.user_id == "user-1"
        assert status.locked is True
        assert status.failure_count == 3
