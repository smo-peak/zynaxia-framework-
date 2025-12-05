# INVARIANTS DEPLOYMENT (DEPL_001-033)

> Version: 1.0 | Date: 2024-12-04 | Status: VALIDÉ
> 33 règles | Phase: Déploiement code et configuration

---

## 1. Vue d'ensemble

| Sous-section | Règles | Objectif |
|--------------|--------|----------|
| Images & Artefacts | DEPL_001-005 | Intégrité code |
| Stratégie déploiement | DEPL_010-014 | Zero-downtime |
| Configuration | DEPL_020-024 | Config signée |
| Contraintes | DEPL_030-033 | Conditions préalables |

---

## 2. IMAGES & ARTEFACTS (DEPL_001-005)

### DEPL_001 : Images Docker signées

**Règle** : Images Docker signées (Cosign) OBLIGATOIRE.
```bash
# Signature image
cosign sign --key cosign.key ghcr.io/zynaxia/framework:v1.2.0

# Vérification
cosign verify --key cosign.pub ghcr.io/zynaxia/framework:v1.2.0
```

---

### DEPL_002 : Vérification signature avant exécution

**Règle** : Vérification signature AVANT exécution sur chaque nœud.

---

### DEPL_003 : Registry privé uniquement

**Règle** : Registry privé uniquement (pas Docker Hub public).

---

### DEPL_004 : Scan CVE avant déploiement

**Règle** : Scan vulnérabilités (Trivy) AVANT déploiement.
```bash
trivy image --severity CRITICAL,HIGH ghcr.io/zynaxia/framework:v1.2.0
```

---

### DEPL_005 : CVE critique = bloqué

**Règle** : CVE critiques = déploiement BLOQUÉ.

---

## 3. STRATÉGIE DÉPLOIEMENT (DEPL_010-014)

### DEPL_010 : Standby-first obligatoire

**Règle** : Déploiement STANDBY-FIRST obligatoire (jamais sur PRIMARY).
```
1. Deploy sur STANDBY
2. Healthcheck STANDBY
3. Bascule STANDBY → PRIMARY
4. Ancien PRIMARY → STANDBY
5. Update STANDBY
```

---

### DEPL_011 : Healthcheck avant bascule

**Règle** : Healthcheck validé sur STANDBY avant bascule.

---

### DEPL_012 : Rollback auto < 60s

**Règle** : Rollback automatique si healthcheck échoue < 60 secondes.
```python
async def deploy_with_rollback(config: DeploymentConfig):
    snapshot = await create_snapshot()
    try:
        await deploy_to_standby(config)
        health = await check_health(timeout=60)
        if health.status != "healthy":
            raise HealthCheckFailed()
        await promote_standby()
    except Exception as e:
        await rollback_to_snapshot(snapshot)
        raise DeploymentFailed(f"Rolled back: {e}")
```

---

### DEPL_013 : Zero-downtime obligatoire

**Règle** : Zero-downtime obligatoire (pas de maintenance window).

---

### DEPL_014 : Déploiement progressif

**Règle** : Déploiement progressif : 1 nœud → validation → autres nœuds.

---

## 4. CONFIGURATION (DEPL_020-024)

### DEPL_020 : Config validée avant déploiement

**Règle** : Config validée par ConfigValidator AVANT déploiement.

---

### DEPL_021 : Config signée (quorum)

**Règle** : Config signée (quorum atteint) AVANT déploiement.

---

### DEPL_022 : Config ancrée blockchain

**Règle** : Config ancrée blockchain AVANT déploiement.

---

### DEPL_023 : Hash vérifié sur chaque nœud

**Règle** : Hash config vérifié sur chaque nœud après réception.

---

### DEPL_024 : Ancienne config archivée

**Règle** : Ancienne config archivée (JAMAIS supprimée).

---

## 5. CONTRAINTES (DEPL_030-033)

### DEPL_030 : Fenêtre maintenance respectée

**Règle** : Déploiement OTA respecte fenêtre maintenance si définie.

**Criticité** : WARNING

---

### DEPL_031 : Bloqué si licence invalide

**Règle** : Déploiement BLOQUÉ si licence invalide.

---

### DEPL_032 : Bloqué si cluster non-healthy

**Règle** : Déploiement BLOQUÉ si cluster non-healthy.

---

### DEPL_033 : Notification Fleet Manager

**Règle** : Notification Fleet Manager AVANT et APRÈS déploiement.

---

## 6. Tests compliance
```python
# tests/compliance/test_depl_rules.py

class TestImages:
    def test_DEPL_001_images_signed(self): ...
    def test_DEPL_002_signature_verified(self): ...
    def test_DEPL_003_private_registry(self): ...
    def test_DEPL_004_cve_scan(self): ...
    def test_DEPL_005_critical_cve_blocks(self): ...

class TestStrategy:
    def test_DEPL_010_standby_first(self): ...
    def test_DEPL_011_healthcheck_before_switch(self): ...
    def test_DEPL_012_rollback_under_60s(self): ...
    def test_DEPL_013_zero_downtime(self): ...
    def test_DEPL_014_progressive_rollout(self): ...
```

---

## 7. LOT

Tous les invariants DEPL_* sont implémentés dans **LOT 7 (Deployment)**.