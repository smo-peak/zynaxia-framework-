"""
ZYNAXIA Framework - Config Validator Implementation
Valide configuration contre les invariants de sécurité.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from ..invariants.rules import ALL_INVARIANTS
from .interfaces import IConfigValidator, ValidationError, ValidationResult, ValidationSeverity


class ConfigValidator(IConfigValidator):
    """Validation des configurations contre les invariants de sécurité."""

    def __init__(self):
        self._validators = {
            "RUN_020": self._validate_run_020,
            "RUN_021": self._validate_run_021,
            "LIC_003": self._validate_lic_003,
        }

    def validate(self, config: Dict[str, Any]) -> ValidationResult:
        """
        Valide une config contre TOUS les invariants.
        Retourne TOUTES les erreurs (pas fail-fast).
        """
        errors = []
        warnings = []

        for rule_id in self._validators:
            error = self.validate_rule(rule_id, config)
            if error:
                if error.severity == ValidationSeverity.BLOCKING:
                    errors.append(error)
                elif error.severity == ValidationSeverity.WARNING:
                    warnings.append(error)

        return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings, checked_at=datetime.now())

    def validate_rule(self, rule_id: str, config: Dict[str, Any]) -> Optional[ValidationError]:
        """Valide UNE règle spécifique."""
        if rule_id not in self._validators:
            return ValidationError(
                rule_id=rule_id,
                message=f"Règle inconnue: {rule_id}",
                location="config",
                severity=ValidationSeverity.BLOCKING,
            )

        return self._validators[rule_id](config)

    def _validate_run_021(self, config: Dict[str, Any]) -> Optional[ValidationError]:
        """RUN_021: Wildcard interdit sauf Platform (level 0)."""
        roles = config.get("roles", [])

        for role in roles:
            role_id = role.get("id", "unknown")
            level = role.get("level")
            permissions = role.get("permissions", [])

            for permission in permissions:
                if "*" in permission and level != 0:
                    return ValidationError(
                        rule_id="RUN_021",
                        message=f"Wildcard '*' interdit pour rôle niveau {level} (seul niveau 0 autorisé)",
                        location=f"roles[{role_id}].permissions",
                        value=permission,
                        severity=ValidationSeverity.BLOCKING,
                    )

        return None

    def _validate_run_020(self, config: Dict[str, Any]) -> Optional[ValidationError]:
        """RUN_020: Rôle niveau N ne peut avoir permissions N-1."""
        roles = config.get("roles", [])
        hierarchy = config.get("hierarchy", {})
        levels = hierarchy.get("levels", [])

        # Construire mapping level -> name
        level_names = {}
        for level_def in levels:
            level_names[level_def.get("id")] = level_def.get("name")

        for role in roles:
            role_id = role.get("id", "unknown")
            level = role.get("level")
            permissions = role.get("permissions", [])

            if level is None or level <= 0:
                continue

            # Niveau parent (N-1)
            parent_level = level - 1
            parent_name = level_names.get(parent_level)

            if parent_name:
                for permission in permissions:
                    if permission.startswith(f"{parent_name}:"):
                        return ValidationError(
                            rule_id="RUN_020",
                            message=f"Rôle niveau {level} ne peut avoir permission de niveau {parent_level}",
                            location=f"roles[{role_id}].permissions",
                            value=permission,
                            severity=ValidationSeverity.BLOCKING,
                        )

        return None

    def _validate_lic_003(self, config: Dict[str, Any]) -> Optional[ValidationError]:
        """LIC_003: Durée maximale 366 jours."""
        license_config = config.get("license", {})
        duration_days = license_config.get("duration_days")

        if duration_days is None:
            return None

        if duration_days > 366:
            return ValidationError(
                rule_id="LIC_003",
                message=f"Durée licence {duration_days} jours dépasse le maximum de 366 jours",
                location="license.duration_days",
                value=str(duration_days),
                severity=ValidationSeverity.BLOCKING,
            )

        return None
