"""
Tests unitaires pour ConfigLoader.
"""

import pytest

from src.core.config_loader import ConfigLoader, ConfigIntegrityError, ConfigSignatureError


class TestConfigLoader:
    """Tests pour ConfigLoader."""
    
    def setup_method(self):
        """Setup avant chaque test."""
        self.loader = ConfigLoader()
    
    @pytest.mark.asyncio
    async def test_load_valid_config(self):
        """Le chargement d'une config valide doit réussir."""
        config = await self.loader.load("valid_minimal")
        
        assert isinstance(config, dict)
        assert "version" in config
        assert "hierarchy" in config
        assert "roles" in config
        assert config["version"] == "1.0"
        
        # Vérification structure hierarchy
        hierarchy = config["hierarchy"]
        assert "levels" in hierarchy
        assert isinstance(hierarchy["levels"], list)
        assert len(hierarchy["levels"]) > 0
        
        # Vérification structure roles
        roles = config["roles"]
        assert isinstance(roles, list)
        assert len(roles) > 0
        
        # Vérification d'un rôle
        platform_admin = next((r for r in roles if r["id"] == "platform_admin"), None)
        assert platform_admin is not None
        assert platform_admin["level"] == 0
        assert "permissions" in platform_admin
        assert "platform:*" in platform_admin["permissions"]
    
    @pytest.mark.asyncio
    async def test_load_nonexistent_tenant_raises(self):
        """Le chargement d'un tenant inexistant doit lever une exception."""
        with pytest.raises(ConfigIntegrityError) as exc_info:
            await self.loader.load("nonexistent_tenant")
        
        assert "Configuration non trouvée" in str(exc_info.value)
        assert "nonexistent_tenant" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_verify_blockchain_anchor_stub(self):
        """verify_blockchain_anchor doit retourner True (stub)."""
        result = await self.loader.verify_blockchain_anchor("any_tenant", "any_hash")
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_custom_configs_path(self):
        """ConfigLoader doit accepter un chemin de configs personnalisé."""
        custom_loader = ConfigLoader("custom/path")
        
        with pytest.raises(ConfigIntegrityError):
            await custom_loader.load("valid_minimal")
    
    @pytest.mark.asyncio
    async def test_validate_basic_structure_missing_version(self):
        """La validation doit échouer si version manque."""
        # Créer un fichier YAML temporaire sans version
        import tempfile
        import yaml
        
        invalid_config = {
            "hierarchy": {"levels": []},
            "roles": []
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(invalid_config, f)
            temp_path = f.name
        
        try:
            # Modifier temporairement le chemin du loader
            import os
            from pathlib import Path
            
            temp_dir = Path(temp_path).parent
            temp_name = Path(temp_path).stem
            
            temp_loader = ConfigLoader(str(temp_dir))
            
            with pytest.raises(ConfigIntegrityError) as exc_info:
                await temp_loader.load(temp_name)
            
            assert "version" in str(exc_info.value).lower()
            
        finally:
            os.unlink(temp_path)
    
    @pytest.mark.asyncio
    async def test_validate_basic_structure_missing_hierarchy(self):
        """La validation doit échouer si hierarchy manque."""
        import tempfile
        import yaml
        
        invalid_config = {
            "version": "1.0",
            "roles": []
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(invalid_config, f)
            temp_path = f.name
        
        try:
            import os
            from pathlib import Path
            
            temp_dir = Path(temp_path).parent
            temp_name = Path(temp_path).stem
            
            temp_loader = ConfigLoader(str(temp_dir))
            
            with pytest.raises(ConfigIntegrityError) as exc_info:
                await temp_loader.load(temp_name)
            
            assert "hierarchy" in str(exc_info.value).lower()
            
        finally:
            os.unlink(temp_path)
    
    @pytest.mark.asyncio
    async def test_validate_basic_structure_missing_roles(self):
        """La validation doit échouer si roles manque."""
        import tempfile
        import yaml
        
        invalid_config = {
            "version": "1.0",
            "hierarchy": {"levels": []}
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(invalid_config, f)
            temp_path = f.name
        
        try:
            import os
            from pathlib import Path
            
            temp_dir = Path(temp_path).parent
            temp_name = Path(temp_path).stem
            
            temp_loader = ConfigLoader(str(temp_dir))
            
            with pytest.raises(ConfigIntegrityError) as exc_info:
                await temp_loader.load(temp_name)
            
            assert "roles" in str(exc_info.value).lower()
            
        finally:
            os.unlink(temp_path)