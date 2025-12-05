# ZYNAXIA FRAMEWORK v1.0

> **Document de référence maître**
> Version: 1.0 | Date: 2024-12-04 | Status: VALIDÉ
> Auteur: Stéphane MUSIC - CEO ZYNAXIA SAS

---

## 1. Vision

Le **ZYNAXIA Framework** est un socle logiciel pour plateformes B2B2B multi-tenant de niveau Défense.
```
FRAMEWORK = Règles immuables + Mécanismes génériques + Configuration flexible
```

**Ce que le framework IMPOSE (non négociable) :**
- Isolation hermétique des données (RLS PostgreSQL)
- Authentification centralisée (Keycloak SSO/MFA)
- Audit non-répudiable (blockchain Hyperledger)
- Cryptographie forte (ECDSA-P384, SHA-384)
- Haute disponibilité (cluster N nœuds, failover < 10s)
- Licences signées avec kill switch

**Ce que le framework PERMET de configurer :**
- Hiérarchie métier (niveaux, labels)
- Rôles et permissions
- Modules activés
- Règles métier (seuils, alertes)
- Personnalisation UI

---

## 2. Principes fondamentaux

### 2.1 Secure by Design

La sécurité n'est pas une couche ajoutée. Elle est dans l'ADN du framework.

| Principe | Implémentation |
|----------|----------------|
| Zero Trust | Chaque requête authentifiée et autorisée |
| Least Privilege | Permissions minimales par défaut |
| Defense in Depth | Plusieurs couches de protection |
| Non-répudiation | Tout événement critique ancré blockchain |

### 2.2 Configuration-Driven

Le code est générique. Le comportement vient de la configuration.
```
CODE (immuable)          CONFIG (flexible)
     │                        │
     │  Charge et             │  Définit
     │  interprète            │  le comportement
     │                        │
     └────────┬───────────────┘
              │
              ▼
        RUNTIME
        (comportement)
```

### 2.3 Compliance by Default

Toute configuration est validée contre les invariants de sécurité AVANT déploiement.
```
Config invalide = Déploiement BLOQUÉ (pas de contournement possible)
```

### 2.4 Zero Bricolage

Production-ready dès jour 1. Pas de solutions temporaires.

---

## 3. Architecture haut niveau
```
┌─────────────────────────────────────────────────────────────┐
│                      FRAMEWORK                               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  INVARIANTS (392 règles en dur)                             │
│  ├── Provisioning (23)    ├── Migration (10)               │
│  ├── Deployment (33)      ├── API Compat (8)               │
│  ├── Runtime (62)         ├── Incident (11)                │
│  ├── Maintenance (63)     ├── Observability (7)            │
│  ├── Licensing (104)      ├── Network (8)                  │
│  ├── Decommissioning (33) ├── Rate Limiting (7)            │
│  │                        ├── Logging (7)                  │
│  │                        ├── Health (8)                   │
│  │                        └── Time Sync (8)                │
│  │                                                         │
│  ENGINES (génériques)                                       │
│  ├── ConfigValidator      ├── LicenseManager               │
│  ├── RLSEngine            ├── FailoverManager              │
│  ├── KeycloakSync         ├── IncidentHandler              │
│  ├── AuditEmitter         └── DeploymentOrchestrator       │
│  │                                                         │
│  ADAPTERS (pluggables)                                      │
│  ├── PostgreSQL           ├── Hyperledger                  │
│  ├── Vault                └── AWS (KMS, S3)                │
│  └── Keycloak                                              │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  CONFIGURATION (validée par invariants)                     │
│  ├── hierarchy.yaml       ├── modules.yaml                 │
│  ├── roles.yaml           └── rules.yaml                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Cycle de vie couvert

Le framework couvre l'intégralité du cycle de vie :
```
PROVISIONING → DEPLOYMENT → RUNTIME → MAINTENANCE
                                           │
              DECOMMISSIONING ←────────────┘
```

Chaque phase a ses invariants. Aucune phase ne peut violer les règles.

---

## 5. Compliance automatique

| Norme | Couvert par |
|-------|-------------|
| RGS 3★ (ANSSI) | Crypto, signatures, rotation clés |
| IEC 62443 | HA, zones, résilience |
| RGPD | Audit, rétention, suppression |
| OIV/OSE | Non-répudiation, traçabilité |

---

## 6. Comment utiliser cette documentation

### Structure des documents
```
docs/
├── 00_FRAMEWORK_MASTER.md      ← Vous êtes ici
├── 01_INVARIANTS_OVERVIEW.md   ← Index des 392 règles
├── 02_TESTING_STRATEGY.md      ← Comment tester
├── 03_LOTS_OVERVIEW.md         ← Les 8 lots de dev
├── 04_CONTRIBUTION.md          ← Comment contribuer
│
└── invariants/                 ← Détail par section
    ├── INV_PROV_*.md
    ├── INV_DEPL_*.md
    └── ...
```

### Pour comprendre une règle

1. Trouver la règle dans `01_INVARIANTS_OVERVIEW.md`
2. Aller dans le fichier détaillé correspondant
3. Lire : règle, justification, vérification, exemples

### Pour implémenter un lot

1. Lire `03_LOTS_OVERVIEW.md` pour les dépendances
2. Lire les invariants concernés par le lot
3. Implémenter selon les interfaces
4. Vérifier avec les tests compliance

### Pour modifier une règle

1. Lire `04_CONTRIBUTION.md`
2. Suivre le processus (RFC si majeur)
3. Mettre à jour tests compliance
4. PR avec label `invariant-change`

---

## 7. Versioning du framework
```
ZYNAXIA Framework vX.Y.Z

X = MAJOR : Changement invariants (breaking)
Y = MINOR : Nouvelle fonctionnalité (compatible)
Z = PATCH : Bug fix (compatible)
```

---

## 8. Équipe

| Rôle | Responsabilité |
|------|----------------|
| **Stéphane** (CEO) | Vision, validation, arbitrage |
| **Claude** (Architecte) | Specs, interfaces, review |
| **Claude Code** (Dev) | Implémentation, tests |

---

## 9. Liens

| Document | Description |
|----------|-------------|
| `01_INVARIANTS_OVERVIEW.md` | Index complet des règles |
| `02_TESTING_STRATEGY.md` | Stratégie de tests |
| `03_LOTS_OVERVIEW.md` | Découpage en lots |
| `04_CONTRIBUTION.md` | Guide contribution |

---

> **Ce framework est la fondation de ZYNAXIA.**
> Toute déviation doit être justifiée et validée.
> En cas de doute, l'invariant prévaut.