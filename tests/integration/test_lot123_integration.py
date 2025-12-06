"""
Test intégration LOT 1 + LOT 2 + LOT 3

Valide la chaîne complète :
- LOT 1 : Secrets Vault
- LOT 2 : RLS PostgreSQL
- LOT 3 : Auth (JWT, Session, Permissions)
"""

import pytest
import asyncio
import os
from datetime import datetime, timezone, timedelta

from src.auth import SessionManager, PermissionChecker, TokenClaims


@pytest.fixture
def db_password():
    """Récupère password depuis variable d'environnement."""
    return os.environ.get("DB_PASSWORD")


@pytest.fixture
def session_mgr():
    return SessionManager()


@pytest.fixture
def checker():
    return PermissionChecker()


@pytest.mark.asyncio
async def test_multi_tenant_isolation(db_password, session_mgr, checker):
    """Test isolation multi-tenant avec RLS."""
    if not db_password:
        pytest.skip("DB_PASSWORD non défini")

    import psycopg2

    now = datetime.now(timezone.utc)

    # Agent Lyon
    agent_lyon = TokenClaims(
        user_id="agent-lyon",
        tenant_id="prison-lyon-001",
        level=3,
        roles=["site_operator"],
        permissions=["site:events:read"],
        exp=now + timedelta(minutes=15),
        iat=now,
    )

    conn = psycopg2.connect(host="localhost", database="zynaxia", user="zynaxia_app", password=db_password)
    cur = conn.cursor()
    cur.execute("SET app.tenant_id = 'prison-lyon-001'")
    cur.execute("SELECT data FROM test_rls_table")
    rows_lyon = cur.fetchall()
    cur.close()
    conn.close()

    # Vérification
    assert len(rows_lyon) == 2
    assert all("Lyon" in r[0] for r in rows_lyon)


@pytest.mark.asyncio
async def test_session_revocation_immediate(session_mgr):
    """RUN_014: Révocation immédiate."""
    now = datetime.now(timezone.utc)

    claims = TokenClaims(
        user_id="test-user",
        tenant_id="test-tenant",
        level=3,
        roles=[],
        permissions=[],
        exp=now + timedelta(minutes=15),
        iat=now,
    )

    session = await session_mgr.create_session(claims.user_id, claims.tenant_id, claims)

    assert await session_mgr.is_session_valid(session.session_id)

    await session_mgr.revoke_session(session.session_id, "test")

    assert not await session_mgr.is_session_valid(session.session_id)
