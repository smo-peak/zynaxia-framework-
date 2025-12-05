"""
ZYNAXIA Framework - LOT 2 Isolation Interfaces
Interfaces pour isolation multi-tenant hermétique.
"""

from abc import ABC, abstractmethod
from typing import Any, List, Protocol


class Connection(Protocol):
    """Protocol pour connexion base de données."""
    
    def execute(self, sql: str) -> Any:
        """Exécute une requête SQL."""
        ...
    
    def fetchall(self) -> List[Any]:
        """Récupère tous les résultats de la dernière requête."""
        ...


class IRLSEngine(ABC):
    """Génère et applique policies Row Level Security."""
    
    @abstractmethod 
    def generate_policies(self, hierarchy: dict) -> List[str]:
        """
        Génère policies SQL depuis config hiérarchique.
        
        Args:
            hierarchy: Configuration hiérarchique des niveaux tenant
            
        Returns:
            Liste des requêtes SQL CREATE POLICY
            
        Invariant: RUN_001 - Policy RLS par niveau hiérarchique
        """
        pass
    
    @abstractmethod
    def apply_policies(self, connection: Connection) -> None:
        """
        Applique policies sur connexion DB.
        
        Args:
            connection: Connexion à la base de données
            
        Invariant: RUN_001 - Policy RLS par niveau hiérarchique  
        """
        pass


class ITenantContext(ABC):
    """Injection/nettoyage contexte tenant."""
    
    @abstractmethod
    def set_context(self, connection: Connection, tenant_id: str, level: int) -> None:
        """
        Injecte contexte tenant dans session.
        
        Args:
            connection: Connexion à la base de données
            tenant_id: Identifiant unique du tenant
            level: Niveau hiérarchique du tenant
            
        Invariant: RUN_004 - Contexte tenant obligatoire
        """
        pass
    
    @abstractmethod
    def clear_context(self, connection: Connection) -> None:
        """
        Nettoie contexte tenant.
        
        Args:
            connection: Connexion à la base de données
            
        Invariant: RUN_004 - Contexte tenant obligatoire
        """
        pass


class IIsolationValidator(ABC):
    """Tests d'isolation entre tenants."""
    
    @abstractmethod
    def test_isolation(self, tenant_a: str, tenant_b: str) -> bool:
        """
        Teste étanchéité entre 2 tenants.
        
        Args:
            tenant_a: Identifiant du premier tenant
            tenant_b: Identifiant du second tenant
            
        Returns:
            True si isolation effective, False sinon
            
        Invariants: 
        - RUN_002 - Isolation inter-tenant même niveau
        - RUN_003 - Isolation enfant/parent
        """
        pass