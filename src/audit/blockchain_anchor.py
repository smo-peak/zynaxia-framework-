"""
LOT 4: Blockchain Anchor Implementation

Ancrage blockchain pour actions critiques.

Invariants:
    RUN_041: Ancrage blockchain obligatoire pour actions critiques
    RUN_042: Garantie immutabilité par blockchain
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from .interfaces import IBlockchainAnchor, AnchorReceipt, AuditEventType


class BlockchainAnchorError(Exception):
    """Erreur ancrage blockchain."""
    pass


class BlockchainAnchor(IBlockchainAnchor):
    """
    Service d'ancrage blockchain pour événements critiques.
    
    Conformité:
        RUN_041: Ancrage obligatoire actions critiques
        RUN_042: Immutabilité blockchain
    
    Note:
        Implémentation MVP avec simulation. Blockchain réelle en production.
    
    Example:
        anchor = BlockchainAnchor()
        receipt = await anchor.anchor_event(event_hash)
    """
    
    # Types d'événements nécessitant ancrage (RUN_041)
    CRITICAL_EVENT_TYPES = {
        AuditEventType.SYSTEM_CONFIG_CHANGE,
        AuditEventType.PLATFORM_SHUTDOWN,
        AuditEventType.BACKUP_RESTORE,
        AuditEventType.KEY_ROTATION,
        AuditEventType.TENANT_DELETE,
        AuditEventType.USER_DELETE,
        AuditEventType.AUDIT_PURGE,
        AuditEventType.SECURITY_BREACH
    }
    
    def __init__(self, blockchain_network: str = "ethereum-sepolia"):
        """
        Args:
            blockchain_network: Réseau blockchain cible
        """
        self.blockchain_network = blockchain_network
        # Simulation stockage MVP - base données réelle en production
        self._anchored_hashes = {}  # hash -> receipt
        self._next_block_height = 1000000  # Simulation hauteur bloc
    
    async def anchor_event(self, event_hash: str) -> AnchorReceipt:
        """
        Ancre hash événement sur blockchain (RUN_041).
        
        Args:
            event_hash: Hash SHA-384 événement
            
        Returns:
            Reçu d'ancrage avec preuves
            
        Raises:
            BlockchainAnchorError: Erreur ancrage
        """
        if not event_hash:
            raise BlockchainAnchorError("Hash événement obligatoire")
        
        if len(event_hash) != 96:  # SHA-384 = 96 caractères hex
            raise BlockchainAnchorError("Hash SHA-384 invalide")
        
        # Vérifier si déjà ancré
        if event_hash in self._anchored_hashes:
            return self._anchored_hashes[event_hash]
        
        try:
            # Simulation transaction blockchain (MVP)
            # En production: appel API blockchain réelle
            tx_id = await self._simulate_blockchain_transaction(event_hash)
            
            # Générer reçu ancrage
            receipt = AnchorReceipt(
                event_hash=event_hash,
                blockchain_tx_id=tx_id,
                block_height=self._next_block_height,
                anchor_timestamp=datetime.now(timezone.utc),
                confirmation_count=6,  # Simulation 6 confirmations
                anchor_proof=await self._generate_anchor_proof(event_hash, tx_id)
            )
            
            # Stocker reçu (MVP)
            self._anchored_hashes[event_hash] = receipt
            self._next_block_height += 1
            
            return receipt
            
        except Exception as e:
            raise BlockchainAnchorError(f"Erreur ancrage blockchain: {str(e)}")
    
    async def verify_anchor(self, receipt: AnchorReceipt) -> bool:
        """
        Vérifie validité ancrage blockchain.
        
        Args:
            receipt: Reçu à vérifier
            
        Returns:
            True si ancrage valide et confirmé
        """
        if not receipt or not receipt.blockchain_tx_id:
            return False
        
        try:
            # Vérifier présence dans stockage local (MVP)
            stored_receipt = self._anchored_hashes.get(receipt.event_hash)
            if not stored_receipt:
                return False
            
            # Vérifier correspondance données
            if (stored_receipt.blockchain_tx_id != receipt.blockchain_tx_id or
                stored_receipt.block_height != receipt.block_height):
                return False
            
            # Simulation vérification blockchain (MVP)
            # En production: vérification réelle sur blockchain
            return await self._verify_blockchain_transaction(receipt.blockchain_tx_id)
            
        except Exception:
            return False
    
    async def get_anchor_proof(self, event_hash: str) -> Optional[AnchorReceipt]:
        """
        Récupère preuve ancrage pour hash.
        
        Args:
            event_hash: Hash recherché
            
        Returns:
            Reçu ancrage si trouvé
        """
        return self._anchored_hashes.get(event_hash)
    
    def requires_anchoring(self, event_type: AuditEventType) -> bool:
        """
        Détermine si événement requiert ancrage (RUN_041).
        
        Args:
            event_type: Type événement
            
        Returns:
            True si ancrage obligatoire
        """
        return event_type in self.CRITICAL_EVENT_TYPES
    
    async def _simulate_blockchain_transaction(self, event_hash: str) -> str:
        """
        Simule transaction blockchain (MVP).
        
        En production: vraie transaction avec gas fees, etc.
        
        Args:
            event_hash: Hash à ancrer
            
        Returns:
            ID transaction simulé
        """
        # Simulation ID transaction Ethereum
        tx_id = f"0x{uuid.uuid4().hex}"
        
        # Simulation latence réseau blockchain
        # await asyncio.sleep(2)  # Commenté pour tests rapides
        
        return tx_id
    
    async def _verify_blockchain_transaction(self, tx_id: str) -> bool:
        """
        Vérifie transaction sur blockchain (simulation MVP).
        
        Args:
            tx_id: ID transaction
            
        Returns:
            True si transaction confirmée
        """
        # Simulation vérification - toujours True pour MVP
        # En production: appel API explorateur blockchain
        return tx_id.startswith("0x") and len(tx_id) == 66
    
    async def _generate_anchor_proof(self, event_hash: str, tx_id: str) -> str:
        """
        Génère preuve cryptographique ancrage.
        
        Args:
            event_hash: Hash événement
            tx_id: ID transaction
            
        Returns:
            Preuve Merkle ou équivalent
        """
        # Simulation preuve Merkle (MVP)
        # En production: vraie preuve cryptographique
        proof_data = f"{event_hash}:{tx_id}:{self._next_block_height}"
        
        # Simulation hash preuve
        import hashlib
        proof_hash = hashlib.sha256(proof_data.encode()).hexdigest()
        
        return f"merkle_proof_{proof_hash[:32]}"
    
    def get_anchor_stats(self) -> dict:
        """
        Statistiques ancrages pour monitoring.
        
        Returns:
            Statistiques système
        """
        total_anchored = len(self._anchored_hashes)
        
        # Calcul par type d'événement (simulation)
        recent_count = sum(
            1 for receipt in self._anchored_hashes.values()
            if (datetime.now(timezone.utc) - receipt.anchor_timestamp).days <= 7
        )
        
        return {
            "total_anchored_events": total_anchored,
            "recent_anchors_7days": recent_count,
            "blockchain_network": self.blockchain_network,
            "current_block_height": self._next_block_height,
            "critical_event_types_count": len(self.CRITICAL_EVENT_TYPES)
        }
    
    async def get_anchor_history(self, hours_back: int = 24) -> list[AnchorReceipt]:
        """
        Historique ancrages récents.
        
        Args:
            hours_back: Période en heures
            
        Returns:
            Liste reçus ancrages récents
        """
        cutoff_time = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        cutoff_time = cutoff_time.replace(hour=cutoff_time.hour - hours_back)
        
        recent_receipts = [
            receipt for receipt in self._anchored_hashes.values()
            if receipt.anchor_timestamp >= cutoff_time
        ]
        
        # Trier par timestamp (plus récents en premier)
        recent_receipts.sort(key=lambda r: r.anchor_timestamp, reverse=True)
        
        return recent_receipts