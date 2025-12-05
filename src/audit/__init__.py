"""
LOT 4: Audit & Tracabilité

Invariants couverts:
- RUN_041 (Ancrage blockchain)
- RUN_042 (Immutabilité logs)
- RUN_044 (Signature cryptographique)
"""
from .interfaces import (
    IAuditEmitter, 
    IBlockchainAnchor, 
    IAuditValidator, 
    IAuditQuery, 
    AuditEvent, 
    AnchorReceipt,
    AuditEventType
)
from .audit_emitter import AuditEmitter, AuditEmitterError
from .blockchain_anchor import BlockchainAnchor, BlockchainAnchorError

__all__ = [
    # Interfaces
    "IAuditEmitter",
    "IBlockchainAnchor",
    "IAuditValidator",
    "IAuditQuery",
    # Data classes
    "AuditEvent",
    "AnchorReceipt",
    "AuditEventType",
    # Implementations
    "AuditEmitter",
    "BlockchainAnchor",
    # Exceptions
    "AuditEmitterError",
    "BlockchainAnchorError",
]