"""
LOT 5: Licensing & Module Control

Invariants couverts:
- LIC_001-006 (Structure licence)
- LIC_010-015 (Validation)
- LIC_020-024 (Cache)
- LIC_030-035 (Alertes expiration)
- LIC_040-045 (Expiration)
- LIC_050-055 (Renouvellement)
- LIC_060-066 (Révocation)
- LIC_070-077 (Kill Switch)
- LIC_080-085 (Contrôle modules)
- LIC_090-094 (Audit)
- LIC_100-104 (Anti-fraude)
"""
from .interfaces import (
    ILicenseManager,
    ILicenseCache,
    IKillSwitchController,
    IModuleGate,
    LicenseConfig,
    License,
    ValidationResult,
    Signature
)
from .license_manager import LicenseManager, LicenseManagerError
from .license_cache import LicenseCache, LicenseCacheError
from .kill_switch_controller import KillSwitchController, KillSwitchError
from .module_gate import ModuleGate, ModuleAccessDeniedError
from .license_alert_service import (
    LicenseAlertService,
    AlertLevel,
    AlertChannel,
    AlertConfig
)

__all__ = [
    # Interfaces
    "ILicenseManager",
    "ILicenseCache", 
    "IKillSwitchController",
    "IModuleGate",
    # Data classes
    "LicenseConfig",
    "License",
    "ValidationResult",
    "Signature",
    "AlertConfig",
    # Enums
    "AlertLevel",
    "AlertChannel",
    # Implementations
    "LicenseManager",
    "LicenseCache", 
    "KillSwitchController",
    "ModuleGate",
    "LicenseAlertService",
    # Exceptions
    "LicenseManagerError",
    "LicenseCacheError",
    "KillSwitchError",
    "ModuleAccessDeniedError",
]