"""
Test que toutes les règles sont définies correctement.
"""

import re
import pytest
from src.invariants.rules import (
    ALL_INVARIANTS,
    EXPECTED_COUNTS,
    TOTAL_INVARIANTS,
    Invariant,
    Severity,
)


class TestInvariantsExist:
    """Vérifie que toutes les règles attendues sont définies."""

    def test_total_count(self):
        """Le nombre total d'invariants doit être 252."""
        assert TOTAL_INVARIANTS == 252, f"Expected 252, got {TOTAL_INVARIANTS}"

    def test_counts_match_expected(self):
        """Le compte par section doit correspondre."""
        counts = {}
        for id in ALL_INVARIANTS.keys():
            prefix = id.split("_")[0]
            counts[prefix] = counts.get(prefix, 0) + 1

        for prefix, expected in EXPECTED_COUNTS.items():
            actual = counts.get(prefix, 0)
            assert actual == expected, f"{prefix}: expected {expected}, got {actual}"

    def test_all_invariants_have_id(self):
        """Chaque invariant doit avoir un ID correspondant à sa clé."""
        for id, invariant in ALL_INVARIANTS.items():
            assert invariant.id == id, f"ID mismatch: key={id}, invariant.id={invariant.id}"

    def test_all_invariants_have_rule(self):
        """Chaque invariant doit avoir une règle non vide."""
        for id, invariant in ALL_INVARIANTS.items():
            assert invariant.rule, f"Invariant {id} has no rule"
            assert len(invariant.rule) >= 10, f"Invariant {id} rule too short: {invariant.rule}"

    def test_id_format(self):
        """Les IDs doivent respecter le format PREFIX_NNN."""
        pattern = r"^[A-Z]+_\d{3}$"
        for id in ALL_INVARIANTS.keys():
            assert re.match(pattern, id), f"Invalid ID format: {id}"

    def test_all_invariants_are_invariant_type(self):
        """Tous les éléments doivent être de type Invariant."""
        for id, invariant in ALL_INVARIANTS.items():
            assert isinstance(invariant, Invariant), f"{id} is not an Invariant"

    def test_severity_is_valid(self):
        """Toutes les sévérités doivent être valides."""
        for id, invariant in ALL_INVARIANTS.items():
            assert isinstance(invariant.severity, Severity), f"{id} has invalid severity"


class TestInvariantSections:
    """Vérifie que chaque section est correctement définie."""

    @pytest.mark.parametrize(
        "prefix,min_count",
        [
            ("PROV", 10),
            ("DEPL", 15),
            ("RUN", 20),
            ("MAINT", 30),
            ("LIC", 50),
            ("DECOM", 15),
            ("MIGR", 5),
            ("API", 5),
            ("INCID", 10),
            ("OBS", 5),
            ("NET", 5),
            ("RATE", 5),
            ("LOG", 5),
            ("HEALTH", 5),
            ("TIME", 5),
        ],
    )
    def test_section_has_minimum_rules(self, prefix: str, min_count: int):
        """Chaque section doit avoir un nombre minimum de règles."""
        count = sum(1 for id in ALL_INVARIANTS.keys() if id.startswith(prefix))
        assert count >= min_count, f"{prefix} has only {count} rules, expected >= {min_count}"


class TestCriticalInvariants:
    """Vérifie que les invariants critiques sont présents."""

    @pytest.mark.parametrize(
        "rule_id",
        [
            "RUN_001",  # RLS obligatoire
            "RUN_010",  # Keycloak obligatoire
            "RUN_030",  # ECDSA-P384
            "RUN_033",  # Secrets jamais en clair
            "LIC_012",  # Invalide = kill switch
            "LIC_070",  # Kill switch arrêt contrôlé
            "PROV_010",  # Vault KMS auto-unseal
        ],
    )
    def test_critical_invariant_exists(self, rule_id: str):
        """Les invariants critiques doivent exister."""
        assert rule_id in ALL_INVARIANTS, f"Critical invariant {rule_id} missing"

    @pytest.mark.parametrize(
        "rule_id",
        [
            "RUN_001",
            "RUN_010",
            "RUN_030",
            "LIC_012",
            "LIC_070",
        ],
    )
    def test_critical_invariants_are_blocking(self, rule_id: str):
        """Les invariants critiques doivent être BLOCKING."""
        invariant = ALL_INVARIANTS[rule_id]
        assert invariant.severity == Severity.BLOCKING, f"{rule_id} should be BLOCKING"
