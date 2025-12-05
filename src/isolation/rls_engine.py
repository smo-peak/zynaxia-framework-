"""
ZYNAXIA Framework - RLS Engine Implementation
Génération et application de policies Row Level Security PostgreSQL.
"""

from typing import List

from .interfaces import IRLSEngine, Connection


class RLSEngineError(Exception):
    """Erreur du moteur RLS."""
    pass


class RLSEngine(IRLSEngine):
    """Générateur de policies Row Level Security pour isolation multi-tenant."""
    
    def __init__(self):
        self._policies: List[str] = []
    
    def generate_policies(self, hierarchy: dict) -> List[str]:
        """
        Génère policies SQL depuis config hiérarchique.
        
        Args:
            hierarchy: Configuration hiérarchique avec levels et tables
            
        Returns:
            Liste des requêtes SQL (ENABLE RLS + CREATE POLICY)
            
        Raises:
            RLSEngineError: Si structure hierarchy invalide
            
        Invariant: RUN_001 - Policy RLS par niveau hiérarchique
        """
        # 1. Validation structure hierarchy
        self._validate_hierarchy(hierarchy)
        
        # 2. Extraire levels et tables
        levels = hierarchy["levels"]
        tables = hierarchy["tables"]
        
        # 3. Générer policies
        policies = []
        
        # Enable RLS pour chaque table
        for table in tables:
            policies.append(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        
        # Policy pour chaque (table, level)
        for table in tables:
            for level in levels:
                level_name = level["name"]
                column = level["column"]
                policy_name = f"{table}_{level_name}_isolation"
                
                policy_sql = f"""CREATE POLICY {policy_name} ON {table}
  FOR ALL
  USING (
    {column} = current_setting('app.tenant_id')::uuid
  );"""
                policies.append(policy_sql)
        
        self._policies = policies
        return policies
    
    def apply_policies(self, connection: Connection) -> None:
        """
        Applique policies sur connexion DB.
        
        Args:
            connection: Connexion à la base de données
            
        Invariant: RUN_001 - Policy RLS par niveau hiérarchique
        """
        for policy in self._policies:
            connection.execute(policy)
    
    def _validate_hierarchy(self, hierarchy: dict) -> None:
        """
        Validation structure hierarchy.
        
        Args:
            hierarchy: Structure à valider
            
        Raises:
            RLSEngineError: Si structure invalide
        """
        if not isinstance(hierarchy, dict):
            raise RLSEngineError("hierarchy doit être un dictionnaire")
        
        if "levels" not in hierarchy:
            raise RLSEngineError("hierarchy doit contenir 'levels'")
        
        if "tables" not in hierarchy:
            raise RLSEngineError("hierarchy doit contenir 'tables'")
        
        if not hierarchy["tables"]:
            raise RLSEngineError("tables ne peut être vide")
        
        # Validation levels
        levels = hierarchy["levels"]
        if not isinstance(levels, list):
            raise RLSEngineError("levels doit être une liste")
        
        for level in levels:
            if not isinstance(level, dict):
                raise RLSEngineError("chaque level doit être un dictionnaire")
            
            required_keys = ["id", "name", "column"]
            for key in required_keys:
                if key not in level:
                    raise RLSEngineError(f"level doit contenir '{key}'")