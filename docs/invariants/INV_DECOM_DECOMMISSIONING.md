# INVARIANTS DECOMMISSIONING (DECOM_001-033)

> Version: 1.0 | Date: 2024-12-04 | Status: VALIDÉ
> 33 règles | Phase: Fin de vie et suppression

---

## 1. Vue d'ensemble

| Sous-section | Règles | Objectif |
|--------------|--------|----------|
| Révocation accès | DECOM_001-005 | Couper accès |
| Archivage données | DECOM_010-013 | Préservation légale |
| Suppression sécurisée | DECOM_020-023 | Effacement définitif |
| Cleanup infrastructure | DECOM_030-033 | Nettoyage ressources |

---

## 2. RÉVOCATION ACCÈS (DECOM_001-005)

### DECOM_001 : Révocation licence avant décom

**Règle** : Révocation licence AVANT décommissionnement.

---

### DECOM_002 : Kill switch activé

**Règle** : Kill switch activé = plus aucune opération possible.

---

### DECOM_003 : IAM révoqués

**Règle** : Credentials IAM révoqués immédiatement.

---

### DECOM_004 : Sessions Keycloak révoquées

**Règle** : Sessions Keycloak révoquées.

---

### DECOM_005 : Certificats révoqués

**Règle** : Certificats révoqués (CRL mise à jour).

---

## 3. ARCHIVAGE DONNÉES (DECOM_010-013)

### DECOM_010 : Backup final obligatoire

**Règle** : Backup final OBLIGATOIRE avant suppression.

---

### DECOM_011 : Données exportées si demandé

**Règle** : Données client exportées et remises (si demandé).

---

### DECOM_012 : Logs archivés 10 ans

**Règle** : Logs audit archivés 10 ans (obligation légale).

---

### DECOM_013 : Décom ancré blockchain

**Règle** : Preuve décommissionnement ancrée blockchain.

---

## 4. SUPPRESSION SÉCURISÉE (DECOM_020-023)

### DECOM_020 : Suppression sécurisée

**Règle** : Données supprimées de manière sécurisée (pas simple DELETE).
```python
async def secure_delete(table: str, tenant_id: str):
    # 1. Overwrite avec données aléatoires
    await db.execute(f"""
        UPDATE {table} 
        SET data = gen_random_bytes(length(data))
        WHERE tenant_id = %s
    """, [tenant_id])
    
    # 2. DELETE
    await db.execute(f"DELETE FROM {table} WHERE tenant_id = %s", [tenant_id])
    
    # 3. VACUUM pour libérer espace
    await db.execute(f"VACUUM FULL {table}")
```

---

### DECOM_021 : Secrets Vault purgés

**Règle** : Secrets Vault purgés définitivement.

---

### DECOM_022 : Destruction clé = inaccessible

**Règle** : Volumes chiffrés → destruction clé = données inaccessibles.

---

### DECOM_023 : Certificat destruction

**Règle** : Certificat de destruction généré.

---

## 5. CLEANUP INFRASTRUCTURE (DECOM_030-033)

### DECOM_030 : IAM User supprimé

**Règle** : IAM User supprimé après archivage.

---

### DECOM_031 : Ressources cloud nettoyées

**Règle** : Ressources cloud nettoyées (pas de ressources orphelines).

---

### DECOM_032 : DNS supprimés

**Règle** : DNS records supprimés.

---

### DECOM_033 : Retrait Fleet Manager

**Règle** : Retrait du Fleet Manager.

---

## 6. LOT

Invariants DECOM_* implémentés dans **LOT 7 (Deployment)**.