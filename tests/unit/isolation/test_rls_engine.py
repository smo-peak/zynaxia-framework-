"""
Tests unitaires pour RLSEngine.
"""

import pytest
from unittest.mock import Mock

from src.isolation.rls_engine import RLSEngine, RLSEngineError


class TestRLSEngine:
    """Tests pour RLSEngine."""
    
    def setup_method(self):
        """Setup avant chaque test."""
        self.engine = RLSEngine()
        self.mock_connection = Mock()
        
        self.valid_hierarchy = {
            "levels": [
                {"id": 1, "name": "dap", "column": "dap_id"},
                {"id": 2, "name": "disp", "column": "disp_id"},
                {"id": 3, "name": "site", "column": "site_id"}
            ],
            "tables": ["events", "alerts", "reports"]
        }
    
    def test_generate_policies_valid_hierarchy(self):
        """Hiérarchie valide doit générer policies SQL."""
        policies = self.engine.generate_policies(self.valid_hierarchy)
        
        # Doit générer : 3 ENABLE RLS + (3 tables × 3 levels) = 12 policies
        assert len(policies) == 12  # 3 + 9
        assert len(self.engine._policies) == 12
        
        # Vérifier que policies sont stockées
        assert self.engine._policies == policies
    
    def test_generate_policies_creates_enable_rls(self):
        """Doit créer ENABLE ROW LEVEL SECURITY pour chaque table."""
        policies = self.engine.generate_policies(self.valid_hierarchy)
        
        enable_rls_policies = [p for p in policies if "ENABLE ROW LEVEL SECURITY" in p]
        assert len(enable_rls_policies) == 3
        
        for table in self.valid_hierarchy["tables"]:
            expected = f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;"
            assert expected in policies
    
    def test_generate_policies_all_tables_covered(self):
        """Chaque table doit avoir ses policies pour chaque niveau."""
        policies = self.engine.generate_policies(self.valid_hierarchy)
        
        for table in self.valid_hierarchy["tables"]:
            for level in self.valid_hierarchy["levels"]:
                policy_name = f"{table}_{level['name']}_isolation"
                # Chercher policy dans la liste
                found = any(policy_name in policy for policy in policies)
                assert found, f"Policy {policy_name} manquante"
    
    def test_generate_policies_all_levels_covered(self):
        """Chaque niveau doit avoir ses policies pour chaque table."""
        policies = self.engine.generate_policies(self.valid_hierarchy)
        
        for level in self.valid_hierarchy["levels"]:
            level_name = level["name"]
            column = level["column"]
            
            # Vérifier que ce niveau apparaît dans les policies
            level_policies = [p for p in policies if level_name in p and "CREATE POLICY" in p]
            # Doit avoir autant de policies que de tables
            assert len(level_policies) == len(self.valid_hierarchy["tables"])
            
            # Vérifier que la colonne correcte est utilisée
            for policy in level_policies:
                assert column in policy
                assert "current_setting('app.tenant_id')::uuid" in policy
    
    def test_generate_policies_invalid_hierarchy_no_levels(self):
        """Manque levels doit lever exception."""
        invalid_hierarchy = {"tables": ["events"]}
        
        with pytest.raises(RLSEngineError) as exc_info:
            self.engine.generate_policies(invalid_hierarchy)
        
        assert "levels" in str(exc_info.value)
    
    def test_generate_policies_invalid_hierarchy_no_tables(self):
        """Manque tables doit lever exception."""
        invalid_hierarchy = {"levels": [{"id": 1, "name": "site", "column": "site_id"}]}
        
        with pytest.raises(RLSEngineError) as exc_info:
            self.engine.generate_policies(invalid_hierarchy)
        
        assert "tables" in str(exc_info.value)
    
    def test_apply_policies_executes_all(self):
        """apply_policies doit exécuter toutes les policies."""
        self.engine.generate_policies(self.valid_hierarchy)
        self.engine.apply_policies(self.mock_connection)
        
        # Doit avoir appelé execute pour chaque policy
        assert self.mock_connection.execute.call_count == 12
        
        # Vérifier que toutes les policies ont été exécutées
        executed_policies = [call[0][0] for call in self.mock_connection.execute.call_args_list]
        assert len(executed_policies) == 12
        
        # Vérifier qu'on a bien les ENABLE RLS
        enable_policies = [p for p in executed_policies if "ENABLE ROW LEVEL SECURITY" in p]
        assert len(enable_policies) == 3
    
    def test_generate_policies_sql_format(self):
        """Vérifier le format SQL exact des policies."""
        policies = self.engine.generate_policies(self.valid_hierarchy)
        
        # Vérifier format d'une policy spécifique
        site_events_policy = next(p for p in policies if "events_site_isolation" in p)
        expected_fragments = [
            "CREATE POLICY events_site_isolation ON events",
            "FOR ALL",
            "USING (",
            "site_id = current_setting('app.tenant_id')::uuid"
        ]
        
        for fragment in expected_fragments:
            assert fragment in site_events_policy
    
    def test_generate_policies_empty_tables(self):
        """Tables vide doit lever exception."""
        invalid_hierarchy = {
            "levels": [{"id": 1, "name": "site", "column": "site_id"}],
            "tables": []
        }
        
        with pytest.raises(RLSEngineError) as exc_info:
            self.engine.generate_policies(invalid_hierarchy)
        
        assert "tables ne peut être vide" in str(exc_info.value)
    
    def test_generate_policies_invalid_level_missing_keys(self):
        """Level sans clés requises doit lever exception."""
        invalid_hierarchy = {
            "levels": [{"id": 1}],  # Manque name et column
            "tables": ["events"]
        }
        
        with pytest.raises(RLSEngineError) as exc_info:
            self.engine.generate_policies(invalid_hierarchy)
        
        assert "level doit contenir" in str(exc_info.value)
    
    def test_generate_policies_not_dict(self):
        """Hierarchy qui n'est pas un dict doit lever exception."""
        with pytest.raises(RLSEngineError) as exc_info:
            self.engine.generate_policies("not a dict")
        
        assert "hierarchy doit être un dictionnaire" in str(exc_info.value)
    
    def test_apply_policies_before_generate_policies(self):
        """apply_policies sans generate_policies d'abord."""
        # Pas d'exception, mais aucune policy n'est exécutée
        self.engine.apply_policies(self.mock_connection)
        assert self.mock_connection.execute.call_count == 0