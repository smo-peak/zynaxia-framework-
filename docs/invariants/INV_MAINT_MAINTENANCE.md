# INVARIANTS MAINTENANCE (MAINT_001-063)

> Version: 1.0 | Date: 2024-12-04 | Status: VALIDÉ
> 63 règles | Phase: Opérations courantes

---

## 1. Vue d'ensemble

| Sous-section | Règles | Objectif |
|--------------|--------|----------|
| Monitoring & Alerting | MAINT_001-005 | Surveillance |
| Backup & Recovery | MAINT_010-016 | Sauvegarde |
| Rotation Secrets | MAINT_020-024 | Renouvellement |
| Patch Sécurité | MAINT_030-035 | Mises à jour |
| Logs | MAINT_040-043 | Conservation |
| Capacité | MAINT_050-054 | Performance |
| Documentation | MAINT_060-063 | Procédures |

---

## 2. MONITORING & ALERTING (MAINT_001-005)

### MAINT_001 : Heartbeat 60s

**Règle** : Heartbeat vers Fleet Manager OBLIGATOIRE (60s interval).

---

### MAINT_002 : Alerte heartbeat > 2min

**Règle** : Alerte si heartbeat manquant > 2 minutes.

---

### MAINT_003 : Métriques Prometheus

**Règle** : Métriques système exposées (Prometheus format).

---

### MAINT_004 : Dashboards Grafana

**Règle** : Dashboards monitoring accessibles (Grafana).

---

### MAINT_005 : Alertes multi-canal

**Règle** : Alertes multi-canal (email + SMS pour critiques).

---

## 3. BACKUP & RECOVERY (MAINT_010-016)

### MAINT_010 : Backup quotidien

**Règle** : Backup automatique quotidien OBLIGATOIRE.

---

### MAINT_011 : Backup chiffré GPG

**Règle** : Backup chiffré (GPG) avant transfert.

---

### MAINT_012 : Backup hors-site

**Règle** : Backup stocké hors-site (AWS S3 + région différente).

---

### MAINT_013 : Rétention 90 jours

**Règle** : Rétention backup 90 jours minimum.

---

### MAINT_014 : Test restore mensuel

**Règle** : Test restauration automatique mensuel.

---

### MAINT_015 : RPO < 1 heure

**Règle** : RPO (Recovery Point Objective) < 1 heure.

---

### MAINT_016 : RTO < 10 minutes

**Règle** : RTO (Recovery Time Objective) < 10 minutes.

---

## 4. ROTATION SECRETS (MAINT_020-024)

### MAINT_020 : Rotation KMS annuelle

**Règle** : Rotation clés KMS annuelle OBLIGATOIRE.

---

### MAINT_021 : Rotation credentials DB trimestrielle

**Règle** : Rotation credentials DB trimestrielle.

---

### MAINT_022 : Rotation TLS avant expiration

**Règle** : Rotation certificats TLS avant expiration (30j alerte).

---

### MAINT_023 : Rotation API keys sur incident

**Règle** : Rotation API keys sur demande ou incident.

---

### MAINT_024 : Ancienne clé conservée 30 jours

**Règle** : Ancienne clé conservée 30 jours (rollback possible).

---

## 5. PATCH SÉCURITÉ (MAINT_030-035)

### MAINT_030 : Scan CVE quotidien

**Règle** : Scan CVE quotidien sur images déployées.

---

### MAINT_031 : CVE critique < 24h

**Règle** : CVE critique → patch < 24 heures.

---

### MAINT_032 : CVE haute < 7 jours

**Règle** : CVE haute → patch < 7 jours.

---

### MAINT_033 : CVE moyenne < 30 jours

**Règle** : CVE moyenne → patch < 30 jours.

---

### MAINT_034 : OS updates auto

**Règle** : OS updates automatiques (sécurité uniquement).

---

### MAINT_035 : Audit dépendances

**Règle** : Dépendances Python/Node auditées (Dependabot).

---

## 6. LOGS (MAINT_040-043)

### MAINT_040 : Logs centralisés 90 jours

**Règle** : Logs centralisés (Loki) rétention 90 jours online.

---

### MAINT_041 : Logs archivés 10 ans

**Règle** : Logs archivés (S3) rétention 10 ans.

---

### MAINT_042 : Logs compressés après 7 jours

**Règle** : Logs compressés après 7 jours.

---

### MAINT_043 : Intégrité logs vérifiable

**Règle** : Intégrité logs vérifiable (hash chain).

---

## 7. CAPACITÉ (MAINT_050-054)

### MAINT_050 : Alerte disque > 80%

**Règle** : Alerte si disque > 80%.

**Criticité** : WARNING

---

### MAINT_051 : Alerte RAM > 90%

**Règle** : Alerte si RAM > 90%.

**Criticité** : WARNING

---

### MAINT_052 : Alerte CPU > 80% 5min

**Règle** : Alerte si CPU > 80% pendant 5 minutes.

**Criticité** : WARNING

---

### MAINT_053 : Alerte latence > 500ms

**Règle** : Alerte si latence API > 500ms (p95).

**Criticité** : WARNING

---

### MAINT_054 : Auto-scaling

**Règle** : Auto-scaling si supporté par infra.

**Criticité** : WARNING

---

## 8. DOCUMENTATION (MAINT_060-063)

### MAINT_060 : Runbook obligatoire

**Règle** : Runbook opérationnel OBLIGATOIRE et à jour.

---

### MAINT_061 : DR testé trimestriellement

**Règle** : Procédures disaster recovery testées trimestriellement.

---

### MAINT_062 : Changelog automatique

**Règle** : Changelog automatique pour chaque déploiement.

---

### MAINT_063 : Post-mortem incidents

**Règle** : Post-mortem obligatoire pour incidents majeurs.

---

## 9. LOT

Invariants MAINT_* principalement implémentés dans **LOT 6 (HA)** et **LOT 7 (Deployment)**.