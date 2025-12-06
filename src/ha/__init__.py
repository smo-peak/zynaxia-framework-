"""
LOT 6: Haute Disponibilité (HA)

Module de haute disponibilité pour sites Edge avec:
- Monitoring de santé (HEALTH_001-008)
- Gestion cluster (RUN_050-053)
- Mode dégradé
- Synchronisation cloud

Invariants couverts:
- HEALTH_001: Endpoint /health obligatoire
- HEALTH_002: /health/live (liveness)
- HEALTH_003: /health/ready (readiness)
- HEALTH_004: Format JSON {status, checks[], timestamp}
- HEALTH_005: Checks: database, vault, keycloak, disk, memory
- HEALTH_006: Status: healthy, degraded, unhealthy
- HEALTH_007: Unhealthy = ne reçoit plus de trafic
- HEALTH_008: Health check < 5 secondes
- RUN_050: Cluster minimum 2 noeuds
- RUN_051: Failover < 10 secondes
- RUN_052: Mode dégradé si Cloud offline
- RUN_053: Cache config TTL 7 jours max
"""
from .interfaces import (
    # Enums
    HealthStatus,
    # Data classes
    HealthCheck,
    HealthReport,
    ClusterStatus,
    SyncResult,
    # Interfaces
    IHealthMonitor,
    IFailoverManager,
    IDegradedModeController,
    IConfigSyncService,
)
from .health_monitor import HealthMonitor, HealthMonitorError
from .failover_manager import FailoverManager, FailoverError, NodeInfo
from .degraded_mode_controller import DegradedModeController, DegradedModeError
from .config_sync_service import ConfigSyncService, ConfigSyncError

__all__ = [
    # Enums
    "HealthStatus",
    # Data classes
    "HealthCheck",
    "HealthReport",
    "ClusterStatus",
    "SyncResult",
    "NodeInfo",
    # Interfaces
    "IHealthMonitor",
    "IFailoverManager",
    "IDegradedModeController",
    "IConfigSyncService",
    # Implementations
    "HealthMonitor",
    "FailoverManager",
    "DegradedModeController",
    "ConfigSyncService",
    # Exceptions
    "HealthMonitorError",
    "FailoverError",
    "DegradedModeError",
    "ConfigSyncError",
]
