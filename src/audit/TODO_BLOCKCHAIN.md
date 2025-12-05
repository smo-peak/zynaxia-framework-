# TODO - Implémentation Blockchain Réelle

**Status:** STUB (simulation MVP)  
**Priorité:** Avant livraison H1 (1er avril 2026)  
**Fichier concerné:** `blockchain_anchor.py`

---

## Ce qui est implémenté (STUB)

- ✅ Interface `IBlockchainAnchor` complète
- ✅ `CRITICAL_EVENT_TYPES` définis (RUN_041)
- ✅ Simulation transaction avec UUID
- ✅ Stockage en mémoire `_anchored_hashes`
- ✅ Simulation preuve Merkle
- ✅ Tests unitaires passants

---

## Ce qui reste à faire (PRODUCTION)

### 1. Déployer Hyperledger Fabric
- [ ] Réseau permissionné souverain
- [ ] 2 organisations minimum (ZYNAXIA, Client)
- [ ] Channel dédié événements critiques
- [ ] Chaincode (smart contract) d'ancrage

### 2. Remplacer simulation par appels réels
```python
# À remplacer dans _simulate_blockchain_transaction()
# Actuel: tx_id = f"0x{uuid.uuid4().hex}"
# Production: tx_id = await self.fabric_client.submit_transaction(...)
```

### 3. Adapter les méthodes
- [ ] `anchor_event()` → Appel chaincode Fabric
- [ ] `verify_anchor()` → Query ledger Fabric
- [ ] `_generate_anchor_proof()` → Preuve Merkle réelle

### 4. Configuration
- [ ] Certificats TLS pour Fabric
- [ ] Identités MSP (Membership Service Provider)
- [ ] Connection profile Fabric
- [ ] Secrets dans Vault

---

## Dépendances

- Hyperledger Fabric SDK Python (`fabric-sdk-py`)
- Certificats organisation ZYNAXIA
- Infrastructure Fabric déployée (OVH ou on-premise)

---

## Références

- Devis V4 : "Ancrage blockchain des événements critiques"
- Livrable 1 : 1er avril 2026
- Invariant : RUN_041

---

*Créé le 5 décembre 2025*
