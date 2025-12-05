# ZYNAXIA FRAMEWORK - INDEX DES INVARIANTS

> Version: 1.0 | Date: 2024-12-04 | Status: VALIDÉ
> Total: 392 règles | 15 sections

---

## 1. Qu'est-ce qu'un invariant ?

Un **invariant** est une règle de sécurité ou de fonctionnement **immuable**.
```
INVARIANT = Règle qui ne peut JAMAIS être violée par la configuration
```

**Caractéristiques :**
- En dur dans le code (pas configurable)
- Vérifié automatiquement
- Violation = blocage (pas de contournement)
- Justifié par compliance ou sécurité

---

## 2. Sections et comptage

| Section | Préfixe | Nombre | Phase cycle de vie |
|---------|---------|--------|-------------------|
| Provisioning | PROV_ | 23 | Création |
| Deployment | DEPL_ | 33 | Déploiement |
| Runtime | RUN_ | 62 | Fonctionnement |
| Maintenance | MAINT_ | 63 | Opérations |
| Licensing | LIC_ | 104 | Licences |
| Decommissioning | DECOM_ | 33 | Fin de vie |
| Migration | MIGR_ | 10 | Upgrade |
| API Compatibility | API_ | 8 | Versioning |
| Incident Response | INCID_ | 11 | Sécurité |
| Observability | OBS_ | 7 | Tracing |
| Network | NET_ | 8 | Connectivité |
| Rate Limiting | RATE_ | 7 | Protection |
| Logging | LOG_ | 7 | Logs |
| Health Checks | HEALTH_ | 8 | Santé |
| Time Sync | TIME_ | 8 | Horloge |
| **TOTAL** | | **392** | |

---

## 3. Index par section

### 3.1 PROVISIONING (PROV_001-023)

Création de nouveaux sites et tenants.

| ID | Règle résumée | Criticité |
|----|---------------|-----------|
| PROV_001 | IAM User dédié par site | BLOQUANT |
| PROV_002 | Credentials générés automatiquement | BLOQUANT |
| PROV_003 | Credentials jamais transmis en clair | BLOQUANT |
| PROV_004 | Recovery keys dans AWS Secrets Manager | BLOQUANT |
| PROV_005 | Changement credentials obligatoire premier login | BLOQUANT |
| PROV_010 | Vault avec KMS auto-unseal | BLOQUANT |
| PROV_011 | Recovery keys threshold 3/5 | BLOQUANT |
| PROV_012 | Root token révoqué après setup | BLOQUANT |
| PROV_013 | Policies Vault depuis config | BLOQUANT |
| PROV_020 | Provisioning ancré blockchain | BLOQUANT |
| PROV_021 | Auto-enregistrement Fleet Manager | BLOQUANT |
| PROV_022 | Healthcheck avant activation licence | BLOQUANT |
| PROV_023 | Package déploiement signé | BLOQUANT |

→ Détails : `invariants/INV_PROV_PROVISIONING.md`

---

### 3.2 DEPLOYMENT (DEPL_001-033)

Déploiement code et configuration.

| ID | Règle résumée | Criticité |
|----|---------------|-----------|
| DEPL_001 | Images Docker signées (Cosign) | BLOQUANT |
| DEPL_002 | Vérification signature avant exécution | BLOQUANT |
| DEPL_003 | Registry privé uniquement | BLOQUANT |
| DEPL_004 | Scan CVE (Trivy) avant déploiement | BLOQUANT |
| DEPL_005 | CVE critique = déploiement bloqué | BLOQUANT |
| DEPL_010 | Déploiement STANDBY-FIRST | BLOQUANT |
| DEPL_011 | Healthcheck sur standby avant bascule | BLOQUANT |
| DEPL_012 | Rollback auto si healthcheck échoue < 60s | BLOQUANT |
| DEPL_013 | Zero-downtime obligatoire | BLOQUANT |
| DEPL_014 | Déploiement progressif | BLOQUANT |
| DEPL_020 | Config validée avant déploiement | BLOQUANT |
| DEPL_021 | Config signée (quorum) | BLOQUANT |
| DEPL_022 | Config ancrée blockchain | BLOQUANT |
| DEPL_023 | Hash config vérifié sur chaque nœud | BLOQUANT |
| DEPL_024 | Ancienne config archivée | BLOQUANT |
| DEPL_030 | Respect fenêtre maintenance | WARNING |
| DEPL_031 | Déploiement bloqué si licence invalide | BLOQUANT |
| DEPL_032 | Déploiement bloqué si cluster non-healthy | BLOQUANT |
| DEPL_033 | Notification Fleet Manager | BLOQUANT |

→ Détails : `invariants/INV_DEPL_DEPLOYMENT.md`

---

### 3.3 RUNTIME (RUN_001-062)

Fonctionnement normal du système.

| ID | Règle résumée | Criticité |
|----|---------------|-----------|
| **Isolation** | | |
| RUN_001 | Policy RLS par niveau hiérarchique | BLOQUANT |
| RUN_002 | Tenant ne voit jamais autre tenant | BLOQUANT |
| RUN_003 | Enfant ne voit pas parent | BLOQUANT |
| RUN_004 | Toute requête passe par contexte tenant | BLOQUANT |
| **Authentification** | | |
| RUN_010 | Keycloak obligatoire | BLOQUANT |
| RUN_011 | JWT expiration max 15 min | BLOQUANT |
| RUN_012 | Refresh token max 24h | BLOQUANT |
| RUN_013 | MFA pour permissions élevées | BLOQUANT |
| RUN_014 | Session révocable à distance | BLOQUANT |
| **Permissions** | | |
| RUN_020 | Rôle N ne peut avoir permissions N-1 | BLOQUANT |
| RUN_021 | Wildcard interdit sauf Platform | BLOQUANT |
| RUN_022 | Permissions élevées requièrent quorum | BLOQUANT |
| RUN_023 | Durée permissions élevées limitée | BLOQUANT |
| **Cryptographie** | | |
| RUN_030 | ECDSA-P384 minimum | BLOQUANT |
| RUN_031 | SHA-384 minimum | BLOQUANT |
| RUN_032 | TLS 1.3 obligatoire | BLOQUANT |
| RUN_033 | Secrets jamais en clair | BLOQUANT |
| RUN_034 | Rotation clés annuelle | BLOQUANT |
| **Audit** | | |
| RUN_040 | Toute action génère événement | BLOQUANT |
| RUN_041 | Actions critiques → blockchain | BLOQUANT |
| RUN_042 | Événements immuables | BLOQUANT |
| RUN_043 | Rétention 10 ans | BLOQUANT |
| RUN_044 | Logs signés | BLOQUANT |
| **Haute Disponibilité** | | |
| RUN_050 | Cluster min 2 nœuds | BLOQUANT |
| RUN_051 | Failover < 10 secondes | BLOQUANT |
| RUN_052 | Mode dégradé si Cloud offline | BLOQUANT |
| RUN_053 | Cache config local TTL 7 jours | BLOQUANT |

→ Détails : `invariants/INV_RUN_RUNTIME.md`

---

### 3.4 MAINTENANCE (MAINT_001-063)

Opérations courantes.

| ID | Règle résumée | Criticité |
|----|---------------|-----------|
| **Monitoring** | | |
| MAINT_001 | Heartbeat 60s vers Fleet Manager | BLOQUANT |
| MAINT_002 | Alerte si heartbeat > 2 min | BLOQUANT |
| MAINT_003 | Métriques Prometheus | BLOQUANT |
| MAINT_004 | Dashboards Grafana | BLOQUANT |
| MAINT_005 | Alertes multi-canal | BLOQUANT |
| **Backup** | | |
| MAINT_010 | Backup quotidien | BLOQUANT |
| MAINT_011 | Backup chiffré GPG | BLOQUANT |
| MAINT_012 | Backup hors-site (S3) | BLOQUANT |
| MAINT_013 | Rétention 90 jours | BLOQUANT |
| MAINT_014 | Test restore mensuel | BLOQUANT |
| MAINT_015 | RPO < 1 heure | BLOQUANT |
| MAINT_016 | RTO < 10 minutes | BLOQUANT |
| **Rotation secrets** | | |
| MAINT_020 | Rotation KMS annuelle | BLOQUANT |
| MAINT_021 | Rotation credentials DB trimestrielle | BLOQUANT |
| MAINT_022 | Rotation TLS avant expiration | BLOQUANT |
| MAINT_023 | Rotation API keys sur incident | BLOQUANT |
| MAINT_024 | Ancienne clé conservée 30 jours | BLOQUANT |
| **Patch sécurité** | | |
| MAINT_030 | Scan CVE quotidien | BLOQUANT |
| MAINT_031 | CVE critique < 24h | BLOQUANT |
| MAINT_032 | CVE haute < 7 jours | BLOQUANT |
| MAINT_033 | CVE moyenne < 30 jours | BLOQUANT |
| MAINT_034 | OS updates auto (sécurité) | BLOQUANT |
| MAINT_035 | Audit dépendances | BLOQUANT |
| **Logs** | | |
| MAINT_040 | Logs centralisés 90 jours | BLOQUANT |
| MAINT_041 | Logs archivés 10 ans | BLOQUANT |
| MAINT_042 | Logs compressés après 7 jours | BLOQUANT |
| MAINT_043 | Intégrité logs vérifiable | BLOQUANT |
| **Capacité** | | |
| MAINT_050 | Alerte disque > 80% | WARNING |
| MAINT_051 | Alerte RAM > 90% | WARNING |
| MAINT_052 | Alerte CPU > 80% 5min | WARNING |
| MAINT_053 | Alerte latence API > 500ms p95 | WARNING |
| MAINT_054 | Auto-scaling si supporté | WARNING |
| **Documentation** | | |
| MAINT_060 | Runbook obligatoire | BLOQUANT |
| MAINT_061 | DR testé trimestriellement | BLOQUANT |
| MAINT_062 | Changelog automatique | BLOQUANT |
| MAINT_063 | Post-mortem incidents majeurs | BLOQUANT |

→ Détails : `invariants/INV_MAINT_MAINTENANCE.md`

---

### 3.5 LICENSING (LIC_001-104)

Gestion complète des licences.

| ID | Règle résumée | Criticité |
|----|---------------|-----------|
| **Structure** | | |
| LIC_001 | Licence signée ECDSA-P384 | BLOQUANT |
| LIC_002 | Contenu obligatoire défini | BLOQUANT |
| LIC_003 | Durée max 366 jours | BLOQUANT |
| LIC_004 | Émission ancrée blockchain | BLOQUANT |
| LIC_005 | Une licence = un site | BLOQUANT |
| LIC_006 | Émission par License Manager Cloud | BLOQUANT |
| **Validation** | | |
| LIC_010 | Validation au démarrage | BLOQUANT |
| LIC_011 | Validation toutes les 60s | BLOQUANT |
| LIC_012 | Invalide = kill switch immédiat | BLOQUANT |
| LIC_013 | Altérée = alerte + kill switch | BLOQUANT |
| LIC_014 | Vérification online 6h | BLOQUANT |
| LIC_015 | Réponse License Manager signée | BLOQUANT |
| **Cache** | | |
| LIC_020 | Cache local obligatoire | BLOQUANT |
| LIC_021 | Cache TTL max 7 jours | BLOQUANT |
| LIC_022 | Cache chiffré | BLOQUANT |
| LIC_023 | Hash vérifié à chaque lecture | BLOQUANT |
| LIC_024 | Cloud offline > 7j = kill switch | BLOQUANT |
| **Alertes** | | |
| LIC_030 | Alerte J-60 | BLOQUANT |
| LIC_031 | Alerte J-30 | BLOQUANT |
| LIC_032 | Alerte J-14 | BLOQUANT |
| LIC_033 | Alerte J-7 | BLOQUANT |
| LIC_034 | Alerte J-1 | BLOQUANT |
| LIC_035 | Alertes non désactivables | BLOQUANT |
| **Expiration** | | |
| LIC_040 | Expirée = mode dégradé | BLOQUANT |
| LIC_041 | Mode dégradé = lecture seule | BLOQUANT |
| LIC_042 | Écritures bloquées | BLOQUANT |
| LIC_043 | Alerte permanente dashboard | BLOQUANT |
| LIC_044 | Grace period expirée = kill switch | BLOQUANT |
| LIC_045 | Expiration ancrée blockchain | BLOQUANT |
| **Renouvellement** | | |
| LIC_050 | Renouvellement = nouvelle licence | BLOQUANT |
| LIC_051 | Nouvelle licence signée + blockchain | BLOQUANT |
| LIC_052 | Injection via Sync License | BLOQUANT |
| LIC_053 | Ancienne archivée | BLOQUANT |
| LIC_054 | Renouvellement après expiration OK | BLOQUANT |
| LIC_055 | Réactivation = healthcheck d'abord | BLOQUANT |
| **Révocation** | | |
| LIC_060 | Révocation explicite | BLOQUANT |
| LIC_061 | Révocation requiert quorum 2 | BLOQUANT |
| LIC_062 | Push < 60 secondes | BLOQUANT |
| LIC_063 | Kill switch immédiat | BLOQUANT |
| LIC_064 | Révocation ancrée blockchain | BLOQUANT |
| LIC_065 | Notification tous canaux | BLOQUANT |
| LIC_066 | Raison obligatoire | BLOQUANT |
| **Kill Switch** | | |
| LIC_070 | Arrêt contrôlé services | BLOQUANT |
| LIC_071 | Données préservées | BLOQUANT |
| LIC_072 | Logs audit préservés | BLOQUANT |
| LIC_073 | Monitoring maintenu | BLOQUANT |
| LIC_074 | Message explicite dashboard | BLOQUANT |
| LIC_075 | Réversible par nouvelle licence | BLOQUANT |
| LIC_076 | Kill switch ancré blockchain | BLOQUANT |
| LIC_077 | Contournement = alerte CRITICAL | BLOQUANT |
| **Modules** | | |
| LIC_080 | Modules en liste blanche | BLOQUANT |
| LIC_081 | Module non licencié = 403 | BLOQUANT |
| LIC_082 | UI masque fonctionnalité | BLOQUANT |
| LIC_083 | Tentative accès = audit | BLOQUANT |
| LIC_084 | Upgrade = nouvelle licence | BLOQUANT |
| LIC_085 | Downgrade = nouvelle licence | BLOQUANT |
| **Audit** | | |
| LIC_090 | Tout événement → audit | BLOQUANT |
| LIC_091 | Critiques → blockchain | BLOQUANT |
| LIC_092 | Historique jamais purgé | BLOQUANT |
| LIC_093 | Dashboard temps réel | BLOQUANT |
| LIC_094 | Export audit compliance | BLOQUANT |
| **Anti-fraude** | | |
| LIC_100 | Licence liée site_id unique | BLOQUANT |
| LIC_101 | Hardware fingerprint (H2+) | WARNING |
| LIC_102 | Clonage = révocation + alerte | BLOQUANT |
| LIC_103 | Horloge vérifiée | BLOQUANT |
| LIC_104 | Drift horloge > 5min = dégradé | BLOQUANT |

→ Détails : `invariants/INV_LIC_LICENSING.md`

---

### 3.6 DECOMMISSIONING (DECOM_001-033)

Fin de vie et suppression.

| ID | Règle résumée | Criticité |
|----|---------------|-----------|
| DECOM_001 | Révocation licence avant décom | BLOQUANT |
| DECOM_002 | Kill switch activé | BLOQUANT |
| DECOM_003 | IAM révoqués | BLOQUANT |
| DECOM_004 | Sessions Keycloak révoquées | BLOQUANT |
| DECOM_005 | Certificats révoqués | BLOQUANT |
| DECOM_010 | Backup final obligatoire | BLOQUANT |
| DECOM_011 | Données exportées si demandé | BLOQUANT |
| DECOM_012 | Logs archivés 10 ans | BLOQUANT |
| DECOM_013 | Décom ancré blockchain | BLOQUANT |
| DECOM_020 | Suppression sécurisée | BLOQUANT |
| DECOM_021 | Secrets Vault purgés | BLOQUANT |
| DECOM_022 | Destruction clé = données inaccessibles | BLOQUANT |
| DECOM_023 | Certificat destruction généré | BLOQUANT |
| DECOM_030 | IAM User supprimé | BLOQUANT |
| DECOM_031 | Ressources cloud nettoyées | BLOQUANT |
| DECOM_032 | DNS supprimés | BLOQUANT |
| DECOM_033 | Retrait Fleet Manager | BLOQUANT |

→ Détails : `invariants/INV_DECOM_DECOMMISSIONING.md`

---

### 3.7 MIGRATION (MIGR_001-010)

Upgrade du framework.

| ID | Règle résumée | Criticité |
|----|---------------|-----------|
| MIGR_001 | Migration réversible | BLOQUANT |
| MIGR_002 | Backup avant migration | BLOQUANT |
| MIGR_003 | Migration sur standby d'abord | BLOQUANT |
| MIGR_004 | Validation post-migration | BLOQUANT |
| MIGR_005 | Échec = rollback auto | BLOQUANT |
| MIGR_006 | Scripts versionnés | BLOQUANT |
| MIGR_007 | Migration ancrée blockchain | BLOQUANT |
| MIGR_008 | Downtime documenté | BLOQUANT |
| MIGR_009 | Test sur zynaxia_test d'abord | BLOQUANT |
| MIGR_010 | Anciennes données archivées | BLOQUANT |

→ Détails : `invariants/INV_MIGR_MIGRATION.md`

---

### 3.8 API COMPATIBILITY (API_001-008)

Versioning des APIs.

| ID | Règle résumée | Criticité |
|----|---------------|-----------|
| API_001 | Version dans URL (/api/v1/) | BLOQUANT |
| API_002 | Support N-1 (backward compat) | BLOQUANT |
| API_003 | Dépréciation 6 mois minimum | BLOQUANT |
| API_004 | Header X-API-Version | BLOQUANT |
| API_005 | Changelog documenté | BLOQUANT |
| API_006 | Breaking change = version majeure | BLOQUANT |
| API_007 | Edge compatible Cloud N±1 | BLOQUANT |
| API_008 | Incompatibilité = alerte pas crash | BLOQUANT |

→ Détails : `invariants/INV_API_COMPATIBILITY.md`

---

### 3.9 INCIDENT RESPONSE (INCID_001-011)

Réponse aux incidents sécurité.

| ID | Règle résumée | Criticité |
|----|---------------|-----------|
| INCID_001 | Intrusion = alerte immédiate | BLOQUANT |
| INCID_002 | Accès non autorisé = log + alerte | BLOQUANT |
| INCID_003 | 3 échecs auth = verrouillage | BLOQUANT |
| INCID_004 | Activité DB anormale = alerte | BLOQUANT |
| INCID_005 | Breach = isolation tenant | BLOQUANT |
| INCID_006 | Breach = notification RSSI < 1h | BLOQUANT |
| INCID_007 | Breach = révocation tokens | BLOQUANT |
| INCID_008 | Breach = snapshot forensics | BLOQUANT |
| INCID_009 | Post-incident < 72h (RGPD) | BLOQUANT |
| INCID_010 | Incident ancré blockchain | BLOQUANT |
| INCID_011 | Procédure testée trimestriellement | BLOQUANT |

→ Détails : `invariants/INV_INCID_INCIDENT.md`

---

### 3.10 OBSERVABILITY (OBS_001-007)

Tracing distribué.

| ID | Règle résumée | Criticité |
|----|---------------|-----------|
| OBS_001 | correlation_id unique par requête | BLOQUANT |
| OBS_002 | correlation_id propagé partout | BLOQUANT |
| OBS_003 | correlation_id dans tous les logs | BLOQUANT |
| OBS_004 | Format OpenTelemetry | BLOQUANT |
| OBS_005 | Retention traces 30 jours | BLOQUANT |
| OBS_006 | Latence spans mesurée | BLOQUANT |
| OBS_007 | Erreurs avec stack trace | BLOQUANT |

→ Détails : `invariants/INV_OBS_OBSERVABILITY.md`

---

### 3.11 NETWORK (NET_001-008)

Connectivité et résilience réseau.

| ID | Règle résumée | Criticité |
|----|---------------|-----------|
| NET_001 | Timeout connexion 10s max | BLOQUANT |
| NET_002 | Timeout requête 30s max | BLOQUANT |
| NET_003 | Retry 3x avec backoff | BLOQUANT |
| NET_004 | Circuit breaker après 5 échecs | BLOQUANT |
| NET_005 | Half-open après 30s | BLOQUANT |
| NET_006 | Cloud perdu = mode dégradé | BLOQUANT |
| NET_007 | Reconnexion auto avec backoff | BLOQUANT |
| NET_008 | Keep-alive TCP | BLOQUANT |

→ Détails : `invariants/INV_NET_NETWORK.md`

---

### 3.12 RATE LIMITING (RATE_001-007)

Protection contre abus.

| ID | Règle résumée | Criticité |
|----|---------------|-----------|
| RATE_001 | Rate limit par tenant | BLOQUANT |
| RATE_002 | Configurable par endpoint | BLOQUANT |
| RATE_003 | Dépassement = 429 | BLOQUANT |
| RATE_004 | Rate limit loggé | BLOQUANT |
| RATE_005 | Burst 2x 10 secondes | BLOQUANT |
| RATE_006 | Auth : 10 req/min/IP | BLOQUANT |
| RATE_007 | Standard : 100 req/min/tenant | BLOQUANT |

→ Détails : `invariants/INV_RATE_LIMITING.md`

---

### 3.13 LOGGING (LOG_001-007)

Format des logs.

| ID | Règle résumée | Criticité |
|----|---------------|-----------|
| LOG_001 | JSON structuré | BLOQUANT |
| LOG_002 | Champs obligatoires définis | BLOQUANT |
| LOG_003 | Timestamp ISO 8601 UTC | BLOQUANT |
| LOG_004 | Niveaux standard | BLOQUANT |
| LOG_005 | Données sensibles masquées | BLOQUANT |
| LOG_006 | Rotation automatique | BLOQUANT |
| LOG_007 | ERROR/CRITICAL = alerte auto | BLOQUANT |

→ Détails : `invariants/INV_LOG_LOGGING.md`

---

### 3.14 HEALTH CHECKS (HEALTH_001-008)

Endpoints de santé.

| ID | Règle résumée | Criticité |
|----|---------------|-----------|
| HEALTH_001 | /health obligatoire | BLOQUANT |
| HEALTH_002 | /health/live (liveness) | BLOQUANT |
| HEALTH_003 | /health/ready (readiness) | BLOQUANT |
| HEALTH_004 | Format JSON standard | BLOQUANT |
| HEALTH_005 | Checks : db, vault, keycloak, disk, mem | BLOQUANT |
| HEALTH_006 | Status : healthy, degraded, unhealthy | BLOQUANT |
| HEALTH_007 | Unhealthy = plus de trafic | BLOQUANT |
| HEALTH_008 | Health check < 5s | BLOQUANT |

→ Détails : `invariants/INV_HEALTH_CHECKS.md`

---

### 3.15 TIME SYNC (TIME_001-008)

Synchronisation horloge.

| ID | Règle résumée | Criticité |
|----|---------------|-----------|
| TIME_001 | NTP obligatoire | BLOQUANT |
| TIME_002 | Serveurs NTP FR/EU | BLOQUANT |
| TIME_003 | Drift max 1 seconde | BLOQUANT |
| TIME_004 | Drift > 1s = WARNING | WARNING |
| TIME_005 | Drift > 5s = CRITICAL + dégradé | BLOQUANT |
| TIME_006 | Timestamps en UTC | BLOQUANT |
| TIME_007 | Vérification drift au démarrage | BLOQUANT |
| TIME_008 | Vérification drift horaire | BLOQUANT |

→ Détails : `invariants/INV_TIME_SYNC.md`

---

## 4. Criticité

| Niveau | Signification | Action si violation |
|--------|---------------|---------------------|
| **BLOQUANT** | Sécurité ou compliance | Déploiement impossible |
| **WARNING** | Best practice | Alerte, déploiement possible |

---

## 5. Vérification

Chaque invariant est vérifié par :
- **Test compliance** automatique (CI)
- **ConfigValidator** pour invariants liés à la config
- **Runtime checks** pour invariants dynamiques

---

## 6. Modification d'un invariant

Voir `04_CONTRIBUTION.md` pour le processus complet.

Résumé :
1. RFC obligatoire si BLOQUANT
2. Validation Stéphane
3. Mise à jour tests compliance
4. PR avec label `invariant-change`