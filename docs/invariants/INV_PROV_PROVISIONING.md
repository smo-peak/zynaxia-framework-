# INVARIANTS PROVISIONING (PROV_001-023)

> Version: 1.0 | Date: 2024-12-04 | Status: VALIDÉ
> 23 règles | Phase: Création nouveaux sites/tenants

---

## 1. Vue d'ensemble

| Sous-section | Règles | Objectif |
|--------------|--------|----------|
| Identité & Credentials | PROV_001-005 | Accès sécurisés |
| Vault & Secrets | PROV_010-013 | Secrets isolés |
| Enregistrement | PROV_020-023 | Activation contrôlée |

---

## 2. IDENTITÉ & CREDENTIALS (PROV_001-005)

### PROV_001 : IAM User dédié par site

**Règle** : Chaque site DOIT avoir un IAM User dédié (pas de credentials partagés).

---

### PROV_002 : Credentials générés automatiquement

**Règle** : Credentials générés automatiquement (pas de saisie manuelle).

---

### PROV_003 : Credentials jamais transmis en clair

**Règle** : Credentials JAMAIS transmis en clair (package chiffré).

---

### PROV_004 : Recovery keys dans AWS Secrets Manager

**Règle** : Recovery keys stockées dans AWS Secrets Manager (pas local).

---

### PROV_005 : Changement credentials premier login

**Règle** : Première connexion DOIT forcer changement credentials admin.

---

## 3. VAULT & SECRETS (PROV_010-013)

### PROV_010 : Vault avec KMS auto-unseal

**Règle** : Vault initialisé avec KMS auto-unseal (pas Shamir manuel).

---

### PROV_011 : Recovery keys threshold 3/5

**Règle** : Recovery keys threshold 3/5 minimum.

---

### PROV_012 : Root token révoqué après setup

**Règle** : Root token révoqué après setup initial.

---

### PROV_013 : Policies Vault depuis config

**Règle** : Policies Vault créées automatiquement depuis config.

---

## 4. ENREGISTREMENT (PROV_020-023)

### PROV_020 : Provisioning ancré blockchain

**Règle** : Provisioning DOIT être ancré blockchain (preuve création).

---

### PROV_021 : Auto-enregistrement Fleet Manager

**Règle** : Site auto-enregistrement auprès Fleet Manager obligatoire.

---

### PROV_022 : Healthcheck avant activation

**Règle** : Healthcheck validé AVANT activation licence.

---

### PROV_023 : Package déploiement signé

**Règle** : Package déploiement signé cryptographiquement.

---

## 5. Tests compliance
```python
# tests/compliance/test_prov_rules.py

class TestCredentials:
    def test_PROV_001_dedicated_iam_user(self): ...
    def test_PROV_002_auto_generated_credentials(self): ...
    def test_PROV_003_encrypted_transmission(self): ...
    def test_PROV_004_recovery_keys_in_secrets_manager(self): ...
    def test_PROV_005_force_password_change(self): ...

class TestVault:
    def test_PROV_010_kms_auto_unseal(self): ...
    def test_PROV_011_threshold_3_of_5(self): ...
    def test_PROV_012_root_token_revoked(self): ...
    def test_PROV_013_policies_from_config(self): ...

class TestRegistration:
    def test_PROV_020_blockchain_anchor(self): ...
    def test_PROV_021_fleet_manager_registration(self): ...
    def test_PROV_022_healthcheck_before_license(self): ...
    def test_PROV_023_signed_deployment_package(self): ...
```

---

## 6. LOT

Invariants PROV_* implémentés dans **LOT 1 (Core)** et **LOT 7 (Deployment)**.