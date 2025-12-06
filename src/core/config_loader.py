"""
ZYNAXIA Framework - Config Loader Implementation
Charge configuration depuis fichiers et vérifie intégrité.
"""

import os
from pathlib import Path
from typing import Any, Dict

import yaml

from .interfaces import IConfigLoader


class ConfigIntegrityError(Exception):
    """Erreur d'intégrité de configuration."""

    pass


class ConfigSignatureError(Exception):
    """Erreur de signature de configuration."""

    pass


class ConfigLoader(IConfigLoader):
    """Chargement des configurations depuis fichiers YAML."""

    def __init__(self, configs_path: str = "fixtures/configs"):
        self.configs_path = Path(configs_path)

    async def load(self, tenant_id: str) -> Dict[str, Any]:
        """
        Charge la config d'un tenant.

        Args:
            tenant_id: ID du tenant

        Returns:
            Configuration sous forme de dictionnaire

        Raises:
            ConfigIntegrityError: Si fichier inexistant ou structure invalide
        """
        config_file = self.configs_path / f"{tenant_id}.yaml"

        if not config_file.exists():
            raise ConfigIntegrityError(f"Configuration non trouvée pour tenant: {tenant_id}")

        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ConfigIntegrityError(f"Erreur de parsing YAML: {e}")
        except Exception as e:
            raise ConfigIntegrityError(f"Erreur de lecture fichier: {e}")

        if not isinstance(config, dict):
            raise ConfigIntegrityError("Configuration doit être un objet YAML")

        # Validation structure de base
        self._validate_basic_structure(config)

        return config

    async def verify_blockchain_anchor(self, tenant_id: str, config_hash: str) -> bool:
        """
        Vérifie que la config est ancrée blockchain.

        Note: Implémentation stub - retourne toujours True pour le moment.
        """
        return True

    def _validate_basic_structure(self, config: Dict[str, Any]) -> None:
        """Valide la structure de base de la configuration."""
        required_fields = ["version", "hierarchy", "roles"]

        for field in required_fields:
            if field not in config:
                raise ConfigIntegrityError(f"Champ obligatoire manquant: {field}")

        # Validation hierarchy
        hierarchy = config["hierarchy"]
        if not isinstance(hierarchy, dict) or "levels" not in hierarchy:
            raise ConfigIntegrityError("hierarchy.levels manquant ou invalide")

        # Validation roles
        roles = config["roles"]
        if not isinstance(roles, list):
            raise ConfigIntegrityError("roles doit être une liste")

        # Validation version
        version = config["version"]
        if not isinstance(version, str):
            raise ConfigIntegrityError("version doit être une chaîne")
