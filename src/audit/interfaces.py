"""
LOT 4: Interfaces Audit & Tracabilité

Définit les contrats pour le système d'audit avec signature cryptographique
et ancrage blockchain pour garantir l'immutabilité.

Invariants:
    RUN_041: Ancrage blockchain actions critiques
    RUN_042: Immutabilité des logs d'audit
    RUN_044: Signature cryptographique événements
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum


class AuditEventType(Enum):
    """Types d'événements d'audit selon RUN_044."""
    # Actions utilisateur
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_CREATE = "user_create"
    USER_DELETE = "user_delete"
    USER_PERMISSION_CHANGE = "user_permission_change"
    
    # Actions système critiques (RUN_041)
    SYSTEM_CONFIG_CHANGE = "system_config_change"
    PLATFORM_SHUTDOWN = "platform_shutdown"
    BACKUP_RESTORE = "backup_restore"
    KEY_ROTATION = "key_rotation"
    
    # Actions tenant
    TENANT_CREATE = "tenant_create"
    TENANT_DELETE = "tenant_delete"
    TENANT_CONFIG_CHANGE = "tenant_config_change"
    
    # Actions sécurité
    SECURITY_BREACH = "security_breach"
    FAILED_AUTH = "failed_auth"
    SESSION_REVOKED = "session_revoked"
    
    # Événements audit système
    AUDIT_LOG_ACCESS = "audit_log_access"
    AUDIT_PURGE = "audit_purge"


@dataclass(frozen=True)
class AuditEvent:
    """
    Événement d'audit signé cryptographiquement (RUN_044).
    
    Immutable pour garantir intégrité après signature.
    """
    event_id: str
    event_type: AuditEventType
    timestamp: datetime
    user_id: str
    tenant_id: str
    resource_id: Optional[str]
    action: str
    metadata: Dict[str, Any]
    ip_address: Optional[str]
    user_agent: Optional[str]
    signature: Optional[str] = None  # Signature ECDSA-P384
    hash_value: Optional[str] = None  # SHA-384 de l'événement


@dataclass
class AnchorReceipt:
    """
    Reçu d'ancrage blockchain (RUN_041).
    
    Prouve qu'un hash d'événement critique a été ancré.
    """
    event_hash: str
    blockchain_tx_id: str
    block_height: int
    anchor_timestamp: datetime
    confirmation_count: int
    anchor_proof: str  # Merkle proof ou équivalent


class IAuditEmitter(ABC):
    """
    Interface émetteur d'événements d'audit.
    
    Responsabilités:
        - Création événements audit (RUN_044)
        - Signature cryptographique
        - Hachage SHA-384
        - Garantie immutabilité (RUN_042)
    """
    
    @abstractmethod
    async def emit_event(
        self,
        event_type: AuditEventType,
        user_id: str,
        tenant_id: str,
        action: str,
        resource_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditEvent:
        """
        Émet un événement d'audit signé (RUN_044).
        
        Args:
            event_type: Type d'événement
            user_id: Identifiant utilisateur
            tenant_id: Identifiant tenant
            action: Action effectuée
            resource_id: Ressource affectée (optionnel)
            metadata: Métadonnées additionnelles
            ip_address: Adresse IP source
            user_agent: User agent client
            
        Returns:
            Événement signé et haché
            
        Raises:
            AuditEmitterError: Erreur création/signature
        """
        pass
    
    @abstractmethod
    def verify_event_signature(self, event: AuditEvent) -> bool:
        """
        Vérifie signature cryptographique d'un événement.
        
        Args:
            event: Événement à vérifier
            
        Returns:
            True si signature valide
        """
        pass
    
    @abstractmethod
    def compute_event_hash(self, event: AuditEvent) -> str:
        """
        Calcule hash SHA-384 d'un événement pour RUN_042.
        
        Args:
            event: Événement à hacher
            
        Returns:
            Hash SHA-384 hexadécimal
        """
        pass


class IBlockchainAnchor(ABC):
    """
    Interface ancrage blockchain pour actions critiques.
    
    Responsabilités:
        - Ancrage hash événements critiques (RUN_041)
        - Génération reçus ancrage
        - Vérification intégrité blockchain
    """
    
    @abstractmethod
    async def anchor_event(self, event_hash: str) -> AnchorReceipt:
        """
        Ancre un hash d'événement critique sur blockchain (RUN_041).
        
        Args:
            event_hash: Hash SHA-384 de l'événement
            
        Returns:
            Reçu d'ancrage avec preuves
            
        Raises:
            BlockchainAnchorError: Erreur ancrage
        """
        pass
    
    @abstractmethod
    async def verify_anchor(self, receipt: AnchorReceipt) -> bool:
        """
        Vérifie validité d'un ancrage blockchain.
        
        Args:
            receipt: Reçu d'ancrage à vérifier
            
        Returns:
            True si ancrage valide et confirmé
        """
        pass
    
    @abstractmethod
    async def get_anchor_proof(self, event_hash: str) -> Optional[AnchorReceipt]:
        """
        Récupère preuve d'ancrage pour un hash.
        
        Args:
            event_hash: Hash recherché
            
        Returns:
            Reçu d'ancrage si trouvé, None sinon
        """
        pass
    
    @abstractmethod
    def requires_anchoring(self, event_type: AuditEventType) -> bool:
        """
        Détermine si un type d'événement requiert ancrage (RUN_041).
        
        Args:
            event_type: Type d'événement
            
        Returns:
            True si ancrage obligatoire
        """
        pass


class IAuditValidator(ABC):
    """
    Interface validation chaîne d'audit.
    
    Responsabilités:
        - Validation intégrité logs (RUN_042)
        - Vérification signatures
        - Détection altérations
    """
    
    @abstractmethod
    async def validate_event_chain(self, events: List[AuditEvent]) -> bool:
        """
        Valide intégrité d'une chaîne d'événements.
        
        Args:
            events: Liste chronologique d'événements
            
        Returns:
            True si chaîne intègre
        """
        pass
    
    @abstractmethod
    async def detect_tampering(self, events: List[AuditEvent]) -> List[str]:
        """
        Détecte altérations dans les logs.
        
        Args:
            events: Événements à analyser
            
        Returns:
            Liste des event_ids altérés
        """
        pass


class IAuditQuery(ABC):
    """
    Interface requêtes audit.
    
    Responsabilités:
        - Recherche événements
        - Filtrage sécurisé
        - Respect isolation tenant
    """
    
    @abstractmethod
    async def get_events_by_user(
        self,
        user_id: str,
        tenant_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        event_types: Optional[List[AuditEventType]] = None
    ) -> List[AuditEvent]:
        """
        Récupère événements par utilisateur.
        
        Args:
            user_id: Utilisateur cible
            tenant_id: Isolation tenant
            start_date: Date début (optionnel)
            end_date: Date fin (optionnel)
            event_types: Types filtrés (optionnel)
            
        Returns:
            Événements correspondants
        """
        pass
    
    @abstractmethod
    async def get_critical_events(
        self,
        tenant_id: str,
        hours_back: int = 24
    ) -> List[AuditEvent]:
        """
        Récupère événements critiques récents.
        
        Args:
            tenant_id: Isolation tenant
            hours_back: Période en heures
            
        Returns:
            Événements critiques
        """
        pass
    
    @abstractmethod
    async def search_events(
        self,
        tenant_id: str,
        query: Dict[str, Any]
    ) -> List[AuditEvent]:
        """
        Recherche avancée dans les logs.
        
        Args:
            tenant_id: Isolation tenant
            query: Critères de recherche
            
        Returns:
            Événements correspondants
        """
        pass