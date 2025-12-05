"""
LOT 3: Session Manager Implementation

Gestion des sessions utilisateur avec révocation immédiate.

Invariants:
    RUN_014: Révocation immédiate à distance
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional

from .interfaces import ISessionManager, TokenClaims, Session


class SessionManagerError(Exception):
    """Erreur de gestion de session."""
    pass


class SessionManager(ISessionManager):
    """
    Gestionnaire de sessions utilisateur.
    
    Conformité:
        RUN_014: Révocation immédiate à distance
    
    Note:
        Stockage en mémoire pour MVP. Redis viendra après.
    
    Example:
        session_manager = SessionManager()
        session = await session_manager.create_session(user_id, tenant_id, claims)
        is_valid = await session_manager.is_session_valid(session.session_id)
    """
    
    def __init__(self, default_session_duration_hours: int = 24):
        """
        Args:
            default_session_duration_hours: Durée par défaut des sessions (défaut: 24h)
        """
        self.default_session_duration_hours = default_session_duration_hours
        # Stockage en mémoire (MVP) - Redis viendra après
        self._sessions: Dict[str, Session] = {}
        self._user_sessions: Dict[str, set[str]] = {}  # user_id -> set of session_ids
    
    async def create_session(
        self, 
        user_id: str, 
        tenant_id: str, 
        token_claims: TokenClaims
    ) -> Session:
        """
        Crée une nouvelle session.
        
        Args:
            user_id: Identifiant utilisateur
            tenant_id: Identifiant tenant
            token_claims: Claims JWT validés
            
        Returns:
            Session créée
            
        Raises:
            SessionManagerError: Erreur de création
        """
        if not user_id or not tenant_id:
            raise SessionManagerError("user_id et tenant_id sont obligatoires")
        
        # Générer ID session unique
        session_id = str(uuid.uuid4())
        
        # Calculer expiration (basée sur token ou durée par défaut)
        now = datetime.now(timezone.utc)
        
        # Utiliser l'expiration du token si disponible et dans les limites
        if token_claims.exp > now:
            # Prendre le minimum entre l'expiration du token et la durée max de session
            max_session_end = now + timedelta(hours=self.default_session_duration_hours)
            expires_at = min(token_claims.exp, max_session_end)
        else:
            expires_at = now + timedelta(hours=self.default_session_duration_hours)
        
        # Créer session
        session = Session(
            session_id=session_id,
            user_id=user_id,
            tenant_id=tenant_id,
            created_at=now,
            expires_at=expires_at
        )
        
        # Stocker session
        self._sessions[session_id] = session
        
        # Indexer par user_id pour révocation en masse
        if user_id not in self._user_sessions:
            self._user_sessions[user_id] = set()
        self._user_sessions[user_id].add(session_id)
        
        return session
    
    async def get_session(self, session_id: str) -> Optional[Session]:
        """
        Récupère session par ID.
        
        Args:
            session_id: Identifiant session
            
        Returns:
            Session si trouvée, None sinon
        """
        if not session_id:
            return None
        
        return self._sessions.get(session_id)
    
    async def revoke_session(self, session_id: str, reason: str = "manual") -> bool:
        """
        Révoque immédiatement une session (RUN_014).
        
        Args:
            session_id: Session à révoquer
            reason: Motif révocation (audit)
            
        Returns:
            True si révoquée, False si inexistante
        """
        session = self._sessions.get(session_id)
        if not session:
            return False
        
        # Marquer comme révoquée (RUN_014: immédiat)
        session.revoked = True
        session.revoked_at = datetime.now(timezone.utc)
        session.revoked_reason = reason
        
        return True
    
    async def revoke_all_user_sessions(self, user_id: str, reason: str = "security") -> int:
        """
        Révoque toutes les sessions d'un utilisateur.
        
        Args:
            user_id: Utilisateur cible
            reason: Motif (audit)
            
        Returns:
            Nombre de sessions révoquées
        """
        if user_id not in self._user_sessions:
            return 0
        
        session_ids = list(self._user_sessions[user_id])  # Copie pour éviter modification pendant itération
        revoked_count = 0
        
        for session_id in session_ids:
            if await self.revoke_session(session_id, reason):
                revoked_count += 1
        
        return revoked_count
    
    async def is_session_valid(self, session_id: str) -> bool:
        """
        Vérifie validité session (non révoquée, non expirée).
        
        Args:
            session_id: Identifiant session
            
        Returns:
            True si session valide
        """
        session = await self.get_session(session_id)
        if not session:
            return False
        
        # Vérifier révocation (RUN_014)
        if session.revoked:
            return False
        
        # Vérifier expiration
        now = datetime.now(timezone.utc)
        if now > session.expires_at:
            # Auto-expirer la session
            await self.revoke_session(session_id, "expired")
            return False
        
        return True
    
    async def cleanup_expired_sessions(self) -> int:
        """
        Nettoie les sessions expirées.
        
        Returns:
            Nombre de sessions nettoyées
        """
        now = datetime.now(timezone.utc)
        expired_session_ids = []
        
        for session_id, session in self._sessions.items():
            if not session.revoked and now > session.expires_at:
                expired_session_ids.append(session_id)
        
        cleaned_count = 0
        for session_id in expired_session_ids:
            if await self.revoke_session(session_id, "expired"):
                cleaned_count += 1
        
        return cleaned_count
    
    async def get_user_sessions(self, user_id: str, include_revoked: bool = False) -> list[Session]:
        """
        Récupère toutes les sessions d'un utilisateur.
        
        Args:
            user_id: Identifiant utilisateur
            include_revoked: Inclure sessions révoquées
            
        Returns:
            Liste des sessions
        """
        if user_id not in self._user_sessions:
            return []
        
        sessions = []
        for session_id in self._user_sessions[user_id]:
            session = self._sessions.get(session_id)
            if session and (include_revoked or not session.revoked):
                sessions.append(session)
        
        # Trier par date de création (plus récentes en premier)
        sessions.sort(key=lambda s: s.created_at, reverse=True)
        return sessions