# INVARIANTS MIGRATION (MIGR_001-010)

> Version: 1.0 | Date: 2024-12-04 | Status: VALIDÉ
> 10 règles | Phase: Upgrade du framework

---

## 1. Règles

### MIGR_001 : Migration réversible

**Règle** : Migration DOIT être réversible (rollback possible).

---

### MIGR_002 : Backup avant migration

**Règle** : Backup OBLIGATOIRE avant toute migration.

---

### MIGR_003 : Migration sur standby d'abord

**Règle** : Migration exécutée sur STANDBY d'abord.

---

### MIGR_004 : Validation post-migration

**Règle** : Validation données post-migration OBLIGATOIRE.

---

### MIGR_005 : Échec = rollback auto

**Règle** : Migration échouée = rollback automatique.

---

### MIGR_006 : Scripts versionnés

**Règle** : Scripts migration versionnés avec le code.
```
migrations/
├── 001_initial_schema.py
├── 002_add_audit_table.py
├── 003_add_license_cache.py
└── ...
```

---

### MIGR_007 : Migration ancrée blockchain

**Règle** : Migration ancrée blockchain (preuve).

---

### MIGR_008 : Downtime documenté

**Règle** : Downtime migration documenté et communiqué.

---

### MIGR_009 : Test sur zynaxia_test d'abord

**Règle** : Migration testée sur zynaxia_test AVANT prod.

---

### MIGR_010 : Anciennes données archivées

**Règle** : Anciennes données JAMAIS supprimées (archivées).

---

## 2. LOT

Invariants MIGR_* implémentés dans **LOT 7 (Deployment)**.