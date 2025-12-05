# INVARIANTS LICENSING (LIC_001-104)

> Version: 1.0 | Date: 2024-12-04 | Status: VALIDÉ
> 104 règles | Phase: Gestion des licences

---

## 1. Vue d'ensemble

| Sous-section | Règles | Objectif |
|--------------|--------|----------|
| Structure & Émission | LIC_001-006 | Format licence |
| Validation | LIC_010-015 | Vérification continue |
| Cache & Mode dégradé | LIC_020-024 | Fonctionnement offline |
| Alertes expiration | LIC_030-035 | Prévention |
| Expiration | LIC_040-045 | Comportement fin licence |
| Renouvellement | LIC_050-055 | Cycle renouvellement |
| Révocation | LIC_060-066 | Arrêt forcé |
| Kill Switch | LIC_070-077 | Mécanisme arrêt |
| Modules | LIC_080-085 | Contrôle features |
| Audit | LIC_090-094 | Traçabilité |
| Anti-fraude | LIC_100-104 | Protection |

---

## 2. STRUCTURE & ÉMISSION (LIC_001-006)

### LIC_001 : Licence signée cryptographiquement

**Règle** : Licence DOIT être signée ECDSA-P384.

**Vérification** : Test unitaire signature valide.
```yaml
# Structure licence
license:
  id: "LIC-2026-00001"
  site_id: "site-fleury-001"
  valid_until: "2027-01-14T23:59:59Z"
  
signature:
  algorithm: "ECDSA-P384"
  key_id: "zynaxia-license-signing-2026"
  value: "MEUCIQDx7..."
```

---

### LIC_002 : Contenu obligatoire

**Règle** : Licence DOIT contenir : site_id, org_id, date_emission, date_expiration, modules.

---

### LIC_003 : Durée maximale 366 jours

**Règle** : Licence DOIT avoir durée maximale 366 jours.

**Justification** : Forcer renouvellement annuel, révision contrat.

---

### LIC_004 : Émission ancrée blockchain

**Règle** : Émission licence → ancrage blockchain OBLIGATOIRE.

**Justification** : Preuve horodatée non-répudiable.

---

### LIC_005 : Une licence = un site

**Règle** : Une licence = un site. Pas de licence multi-sites.

**Justification** : Granularité fine, révocation ciblée.

---

### LIC_006 : Émission par License Manager Cloud

**Règle** : Licence générée UNIQUEMENT par License Manager Cloud.

**Justification** : Source unique de vérité.

---

## 3. VALIDATION (LIC_010-015)

### LIC_010 : Validation au démarrage

**Règle** : Validation signature licence à CHAQUE démarrage service.
```python
async def startup():
    license = await license_cache.get(site_id)
    if not license_validator.validate(license):
        raise LicenseInvalidError("Cannot start with invalid license")
```

---

### LIC_011 : Validation toutes les 60 secondes

**Règle** : Validation signature licence toutes les 60 secondes (runtime).

---

### LIC_012 : Invalide = kill switch immédiat

**Règle** : Licence invalide (signature) = kill switch IMMÉDIAT.

---

### LIC_013 : Altérée = alerte + kill switch

**Règle** : Licence altérée = alerte sécurité CRITICAL + kill switch + blockchain.

---

### LIC_014 : Vérification online toutes les 6 heures

**Règle** : Vérification auprès License Manager Cloud toutes les 6 heures (si connecté).

---

### LIC_015 : Réponse License Manager signée

**Règle** : Réponse License Manager signée (anti-replay, anti-MITM).

---

## 4. CACHE & MODE DÉGRADÉ (LIC_020-024)

### LIC_020 : Cache local obligatoire

**Règle** : Cache licence local OBLIGATOIRE pour mode dégradé.

---

### LIC_021 : Cache TTL max 7 jours

**Règle** : Cache licence TTL MAX 7 jours (grace period).

---

### LIC_022 : Cache chiffré

**Règle** : Cache licence chiffré (Vault local).

---

### LIC_023 : Hash vérifié à chaque lecture

**Règle** : Hash intégrité cache vérifié à chaque lecture.

---

### LIC_024 : Cloud offline > 7 jours = kill switch

**Règle** : Si Cloud offline > 7 jours ET cache expiré → kill switch.

---

## 5. ALERTES EXPIRATION (LIC_030-035)

### LIC_030 : Alerte J-60

**Règle** : Alerte J-60 avant expiration (email intégrateur + org).

---

### LIC_031 : Alerte J-30

**Règle** : Alerte J-30 (email + dashboard warning).

---

### LIC_032 : Alerte J-14

**Règle** : Alerte J-14 (email + SMS).

---

### LIC_033 : Alerte J-7

**Règle** : Alerte J-7 (email + SMS + dashboard critical).

---

### LIC_034 : Alerte J-1

**Règle** : Alerte J-1 (tous canaux + webhook).

---

### LIC_035 : Alertes non désactivables

**Règle** : Alertes expiration NON désactivables par configuration.

**Justification** : Protection business, impossible d'ignorer.

---

## 6. EXPIRATION (LIC_040-045)

### LIC_040 : Expirée = mode dégradé

**Règle** : Licence expirée → mode dégradé (grace period 7 jours).

---

### LIC_041 : Mode dégradé = lecture seule

**Règle** : Mode dégradé : fonctionnement LECTURE SEULE.

---

### LIC_042 : Écritures bloquées

**Règle** : Mode dégradé : nouvelles écritures BLOQUÉES.
```python
def check_write_permission():
    if license_manager.is_degraded():
        raise LicenseDegradedError("Write operations disabled")
```

---

### LIC_043 : Alerte permanente dashboard

**Règle** : Mode dégradé : alerte permanente sur tous dashboards.

---

### LIC_044 : Grace period expirée = kill switch

**Règle** : Grace period expirée → kill switch automatique.

---

### LIC_045 : Expiration ancrée blockchain

**Règle** : Expiration → ancrage blockchain (preuve horodatée).

---

## 7. RENOUVELLEMENT (LIC_050-055)

### LIC_050 : Renouvellement = nouvelle licence

**Règle** : Renouvellement = nouvelle licence (pas modification existante).

---

### LIC_051 : Nouvelle licence signée + blockchain

**Règle** : Nouvelle licence DOIT être signée + ancrée blockchain.

---

### LIC_052 : Injection via Sync License

**Règle** : Injection nouvelle licence via Sync License (chiffré).

---

### LIC_053 : Ancienne archivée

**Règle** : Ancienne licence archivée (jamais supprimée).

---

### LIC_054 : Renouvellement après expiration OK

**Règle** : Renouvellement possible même après expiration (réactivation).

---

### LIC_055 : Réactivation = healthcheck d'abord

**Règle** : Réactivation après kill switch → healthcheck AVANT déblocage.
```python
async def reactivate(site_id: str, new_license: License):
    # Injecter nouvelle licence
    await license_cache.set(site_id, new_license)
    
    # Healthcheck AVANT déblocage
    health = await health_monitor.check()
    if health.status != "healthy":
        raise ReactivationError("Site not healthy, cannot reactivate")
    
    # Débloquer
    await kill_switch.deactivate(site_id)
```

---

## 8. RÉVOCATION (LIC_060-066)

### LIC_060 : Révocation explicite

**Règle** : Révocation = décision explicite dans License Manager.

---

### LIC_061 : Révocation requiert quorum

**Règle** : Révocation REQUIERT quorum (2 signatures minimum).

---

### LIC_062 : Push < 60 secondes

**Règle** : Révocation → push immédiat vers site (< 60 secondes).

---

### LIC_063 : Kill switch immédiat

**Règle** : Révocation → kill switch IMMÉDIAT (pas de grace period).

---

### LIC_064 : Révocation ancrée blockchain

**Règle** : Révocation → ancrage blockchain (preuve non-répudiable).

---

### LIC_065 : Notification tous canaux

**Règle** : Révocation → notification tous canaux (email, SMS, webhook).

---

### LIC_066 : Raison obligatoire

**Règle** : Raison révocation OBLIGATOIRE et auditée.
```python
async def revoke(site_id: str, reason: str, signatures: List[Signature]):
    if len(signatures) < 2:
        raise QuorumError("Revocation requires 2 signatures")
    if not reason:
        raise ValueError("Revocation reason is mandatory")
    
    await audit.emit_critical("license.revoked", 
        site_id=site_id, 
        reason=reason,
        signatures=[s.signer for s in signatures]
    )
```

---

## 9. KILL SWITCH (LIC_070-077)

### LIC_070 : Arrêt contrôlé services

**Règle** : Kill switch = arrêt contrôlé de TOUS les services applicatifs.

---

### LIC_071 : Données préservées

**Règle** : Kill switch PRÉSERVE les données (pas de suppression).

---

### LIC_072 : Logs audit préservés

**Règle** : Kill switch PRÉSERVE les logs audit.

---

### LIC_073 : Monitoring maintenu

**Règle** : Kill switch MAINTIENT monitoring (heartbeat continue).

---

### LIC_074 : Message explicite dashboard

**Règle** : Kill switch AFFICHE message explicite sur dashboard.
```
╔═══════════════════════════════════════════════════════════╗
║                    SERVICE SUSPENDU                        ║
║                                                           ║
║  Licence invalide ou révoquée.                            ║
║  Contactez votre intégrateur pour renouvellement.         ║
║                                                           ║
║  Référence : LIC-2026-00001                               ║
║  Site : site-fleury-001                                   ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
```

---

### LIC_075 : Réversible par nouvelle licence

**Règle** : Kill switch RÉVERSIBLE uniquement par nouvelle licence valide.

---

### LIC_076 : Kill switch ancré blockchain

**Règle** : Kill switch → ancrage blockchain.

---

### LIC_077 : Contournement = alerte CRITICAL

**Règle** : Tentative contournement kill switch = alerte sécurité CRITICAL.

---

## 10. MODULES (LIC_080-085)

### LIC_080 : Modules en liste blanche

**Règle** : Licence définit modules activés (liste blanche).
```yaml
license:
  modules:
    - id: "core"
      enabled: true
    - id: "blockchain"
      enabled: true
    - id: "advanced_analytics"
      enabled: false  # Non licencié
```

---

### LIC_081 : Module non licencié = 403

**Règle** : Module non licencié = API retourne 403 Forbidden.

---

### LIC_082 : UI masque fonctionnalité

**Règle** : Module non licencié = UI masque fonctionnalité.

---

### LIC_083 : Tentative accès = audit

**Règle** : Tentative accès module non licencié = audit log.

---

### LIC_084 : Upgrade = nouvelle licence

**Règle** : Upgrade licence (nouveaux modules) = nouvelle licence complète.

---

### LIC_085 : Downgrade = nouvelle licence

**Règle** : Downgrade licence = nouvelle licence (modules retirés inaccessibles).

---

## 11. AUDIT (LIC_090-094)

### LIC_090 : Tout événement → audit

**Règle** : Tout événement licence → audit log.

---

### LIC_091 : Critiques → blockchain

**Règle** : Événements critiques licence → blockchain.

**Événements critiques** : émission, révocation, kill switch, expiration.

---

### LIC_092 : Historique jamais purgé

**Règle** : Historique complet licences conservé (jamais purgé).

---

### LIC_093 : Dashboard temps réel

**Règle** : Dashboard License Manager : vue temps réel tous sites.

---

### LIC_094 : Export audit compliance

**Règle** : Export audit licences pour compliance disponible.

---

## 12. ANTI-FRAUDE (LIC_100-104)

### LIC_100 : Licence liée site_id unique

**Règle** : Licence liée à site_id unique (pas de copie possible).

---

### LIC_101 : Hardware fingerprint (H2+)

**Règle** : Licence liée à hardware fingerprint (optionnel, H2+).

**Criticité** : WARNING (pas BLOQUANT pour H1)

---

### LIC_102 : Clonage = révocation + alerte

**Règle** : Détection clonage licence = révocation immédiate + alerte.

---

### LIC_103 : Horloge vérifiée

**Règle** : Horloge système vérifiée (anti-manipulation date).

---

### LIC_104 : Drift horloge > 5min = dégradé

**Règle** : Désynchronisation horloge > 5 min = alerte + mode dégradé.

---

## 13. Tests compliance
```python
# tests/compliance/test_lic_rules.py

class TestLicenseStructure:
    def test_LIC_001_signature_ecdsa_p384(self): ...
    def test_LIC_002_mandatory_fields(self): ...
    def test_LIC_003_max_duration_366_days(self): ...
    def test_LIC_004_emission_blockchain(self): ...
    def test_LIC_005_one_license_one_site(self): ...
    def test_LIC_006_cloud_only_emission(self): ...

class TestLicenseValidation:
    def test_LIC_010_validation_at_startup(self): ...
    def test_LIC_011_validation_every_60s(self): ...
    def test_LIC_012_invalid_kills_immediately(self): ...
    # ... etc
```

---

## 14. Référence LOT

| Composant | LOT |
|-----------|-----|
| LicenseManager | LOT 5 |
| LicenseCache | LOT 5 |
| KillSwitchController | LOT 5 |
| LicenseAlertService | LOT 5 |
| ModuleGate | LOT 5 |