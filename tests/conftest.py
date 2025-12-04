"""
ZYNAXIA Framework - Pytest Configuration
Fixtures partagées pour tous les tests.
"""

import pytest
from pathlib import Path


@pytest.fixture
def fixtures_path() -> Path:
    """Chemin vers le dossier fixtures."""
    return Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def valid_minimal_config(fixtures_path: Path) -> dict:
    """Charge la configuration minimale valide."""
    import yaml
    config_path = fixtures_path / "configs" / "valid_minimal.yaml"
    with open(config_path) as f:
        return yaml.safe_load(f)


@pytest.fixture
def all_invariants() -> dict:
    """Retourne tous les invariants."""
    from src.invariants.rules import ALL_INVARIANTS
    return ALL_INVARIANTS
