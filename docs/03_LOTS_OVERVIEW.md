# ZYNAXIA FRAMEWORK - VUE D'ENSEMBLE DES LOTS

> Version: 1.0 | Date: 2024-12-04 | Status: VALIDÉ
> 8 lots de développement indépendants

---

## 1. Principe

Le framework est découpé en **8 lots indépendants**.
```
LOT = Module autonome + Interfaces stables + Tests propres
```

**Avantages** :
- Développement parallèle possible
- Tests isolés par lot
- Déploiement incrémental
- Maintenance ciblée

---

## 2. Vue d'ensemble
```
┌─────────────────────────────────────────────────────────────┐
│                      LES 8 LOTS                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  LOT 1 : CORE           Fondations (config, crypto, valid)  │
│  LOT 2 : ISOLATION      Multi-tenant (RLS, context)         │
│  LOT 3 : AUTH           Authentification (Keycloak, JWT)    │
│  LOT 4 : AUDIT          Traçabilité (events, blockchain)    │
│  LOT 5 : LICENSING      Licences (émission, kill switch)    │
│  LOT 6 : HA             Haute dispo (failover, sync)        │
│  LOT 7 : DEPLOYMENT     Déploiement (OTA, rollback)         │
│  LOT 8 : INCIDENT       Sécurité (détection, réponse)       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Graphe de dépendances
```
                      ┌─────────────┐
                      │   LOT 1     │
                      │    CORE     │
                      └──────┬──────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
       ┌──────────┐   ┌──────────┐   ┌──────────┐
       │  LOT 2   │   │  LOT 3   │   │  LOT 4   │
       │ISOLATION │   │   AUTH   │   │  AUDIT   │
       └────┬─────┘   └────┬─────┘   └────┬─────┘
            │              │              │
            └──────────────┼──────────────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
       ┌──────────┐ ┌──────────┐ ┌──────────┐
       │  LOT 5   │ │  LOT 6   │ │  LOT 8   │
       │LICENSING │ │    HA    │ │ INCIDENT │
       └────┬─────┘ └────┬─────┘ └────┬─────┘
            │            │            │
            └────────────┼────────────┘
                         │
                         ▼
                  ┌──────────┐
                  │  LOT 7   │
                  │DEPLOYMENT│
                  └──────────┘
```

**Ordre de développement** :
1. LOT 1 (obligatoire en premier)
2. LOT 2, 3, 4 (parallélisables)
3. LOT 5, 6, 8 (parallélisables)
4. LOT 7 (en dernier, dépend de tous)

---

## 4. Détail par lot

### LOT 1 : CORE

**Objectif** : Fondations du framework.

**Composants** :
| Composant | Responsabilité |
|-----------|----------------|
| `ConfigLoader` | Charge config depuis Vault, vérifie hash |
| `ConfigValidator` | Valide config vs invariants |
| `CryptoProvider` | ECDSA-P384, SHA-384, signatures |
| `SchemaValidator` | Validation JSON Schema |

**Invariants couverts** :
- RUN_030-034 (Cryptographie)
- DEPL_020-024 (Config signée)
- Validation tous invariants

**Interfaces exposées** :
```python
class IConfigLoader(ABC):
    async def load(self, tenant_id: str) -> dict
    async def verify_blockchain_anchor(self, tenant_id: str, hash: str) -> bool

class IConfigValidator(ABC):
    def validate(self, config: dict) -> ValidationResult
    def validate_rule(self, rule_id: str, config: dict) -> Optional[ValidationError]

class ICryptoProvider(ABC):
    def sign(self, data: bytes, key_id: str) -> bytes
    def verify_signature(self, data: bytes, signature: bytes, key_id: str) -> bool
    def hash(self, data: bytes) -> str
```

**Dépendances** :
- Vault (adapter)
- Hyperledger (adapter, pour verify_blockchain_anchor)

**Estimation** : 2-3 jours

---

### LOT 2 : ISOLATION

**Objectif** : Isolation multi-tenant hermétique.

**Composants** :
| Composant | Responsabilité |
|-----------|----------------|
| `RLSEngine` | Génère policies SQL depuis config |
| `TenantContext` | Injecte contexte tenant dans requêtes |
| `IsolationValidator` | Teste que l'isolation fonctionne |

**Invariants couverts** :
- RUN_001-004 (Isolation)

**Interfaces exposées** :
```python
class IRLSEngine(ABC):
    def generate_policies(self, hierarchy: dict) -> List[str]
    def apply_policies(self, connection: Connection) -> None

class ITenantContext(ABC):
    def set_context(self, connection: Connection, tenant_id: str, level: int) -> None
    def clear_context(self, connection: Connection) -> None

class IIsolationValidator(ABC):
    def test_isolation(self, tenant_a: str, tenant_b: str) -> bool
```

**Dépendances** :
- LOT 1 (ConfigLoader pour hiérarchie)
- PostgreSQL (adapter)

**Estimation** : 2-3 jours

---

### LOT 3 : AUTH

**Objectif** : Authentification et autorisation.

**Composants** :
| Composant | Responsabilité |
|-----------|----------------|
| `KeycloakSync` | Synchronise rôles/permissions vers Keycloak |
| `JWTValidator` | Valide tokens JWT |
| `SessionManager` | Gestion sessions, révocation |
| `PermissionChecker` | Vérifie permissions par action |

**Invariants couverts** :
- RUN_010-014 (Authentification)
- RUN_020-023 (Permissions)
- INCID_003 (Verrouillage après échecs)

**Interfaces exposées** :
```python
class IKeycloakSync(ABC):
    async def sync_roles(self, roles: List[dict]) -> None
    async def sync_permissions(self, permissions: List[dict]) -> None

class IJWTValidator(ABC):
    def validate(self, token: str) -> TokenClaims
    def is_expired(self, token: str) -> bool

class ISessionManager(ABC):
    async def create_session(self, user_id: str, tenant_id: str) -> Session
    async def revoke_session(self, session_id: str) -> None
    async def revoke_all_sessions(self, user_id: str) -> None

class IPermissionChecker(ABC):
    def check(self, user: User, action: str, resource: str) -> bool
    def requires_quorum(self, action: str) -> bool
```

**Dépendances** :
- LOT 1 (ConfigLoader pour rôles)
- Keycloak (adapter)

**Estimation** : 3-4 jours

---

### LOT 4 : AUDIT

**Objectif** : Traçabilité non-répudiable.

**Composants** :
| Composant | Responsabilité |
|-----------|----------------|
| `AuditEmitter` | Émet événements audit |
| `BlockchainAnchor` | Ancre événements critiques |
| `AuditValidator` | Vérifie intégrité chaîne audit |
| `AuditQuery` | Requête historique audit |

**Invariants couverts** :
- RUN_040-044 (Audit)
- OBS_001-007 (Observability)
- LOG_001-007 (Logging)

**Interfaces exposées** :
```python
class IAuditEmitter(ABC):
    async def emit(self, event: AuditEvent) -> str
    async def emit_critical(self, event: AuditEvent) -> str  # + blockchain

class IBlockchainAnchor(ABC):
    async def anchor(self, data_hash: str, metadata: dict) -> AnchorReceipt
    async def verify(self, data_hash: str, tx_hash: str) -> bool

class IAuditValidator(ABC):
    def verify_chain_integrity(self, start: datetime, end: datetime) -> bool

class IAuditQuery(ABC):
    async def query(self, filters: AuditFilters) -> List[AuditEvent]
    async def export(self, filters: AuditFilters, format: str) -> bytes
```

**Dépendances** :
- LOT 1 (CryptoProvider pour signatures)
- Hyperledger (adapter)
- Loki/PostgreSQL (stockage)

**Estimation** : 3-4 jours

---

### LOT 5 : LICENSING

**Objectif** : Gestion complète des licences.

**Composants** :
| Composant | Responsabilité |
|-----------|----------------|
| `LicenseManager` | Émission, validation, renouvellement |
| `LicenseCache` | Cache local avec TTL |
| `KillSwitchController` | Arrêt/reprise contrôlé |
| `LicenseAlertService` | Alertes expiration |
| `ModuleGate` | Contrôle accès modules |

**Invariants couverts** :
- LIC_001-104 (tous)

**Interfaces exposées** :
```python
class ILicenseManager(ABC):
    async def issue(self, site_id: str, config: LicenseConfig) -> License
    async def validate(self, license: License) -> ValidationResult
    async def renew(self, site_id: str, days: int) -> License
    async def revoke(self, site_id: str, reason: str, quorum: List[Signature]) -> None

class ILicenseCache(ABC):
    def get(self, site_id: str) -> Optional[License]
    def set(self, site_id: str, license: License) -> None
    def is_valid(self, site_id: str) -> bool

class IKillSwitchController(ABC):
    async def activate(self, site_id: str, reason: str) -> None
    async def deactivate(self, site_id: str, new_license: License) -> None
    def is_active(self, site_id: str) -> bool

class IModuleGate(ABC):
    def is_module_licensed(self, site_id: str, module_id: str) -> bool
    def get_licensed_modules(self, site_id: str) -> List[str]
```

**Dépendances** :
- LOT 1 (CryptoProvider, ConfigValidator)
- LOT 4 (AuditEmitter, BlockchainAnchor)
- Vault (stockage licences)

**Estimation** : 4-5 jours

---

### LOT 6 : HA (Haute Disponibilité)

**Objectif** : Résilience et continuité de service.

**Composants** :
| Composant | Responsabilité |
|-----------|----------------|
| `FailoverManager` | Bascule automatique primary/standby |
| `HealthMonitor` | Heartbeat, health checks |
| `ReplicationEngine` | Synchronisation données |
| `DegradedModeController` | Mode offline |
| `ConfigSyncService` | Synchronisation config Edge/Cloud |

**Invariants couverts** :
- RUN_050-053 (HA)
- MAINT_001-005 (Monitoring)
- NET_001-008 (Network)
- HEALTH_001-008 (Health checks)
- TIME_001-008 (Time sync)

**Interfaces exposées** :
```python
class IFailoverManager(ABC):
    async def trigger_failover(self, reason: str) -> None
    async def promote_to_primary(self, node_id: str) -> None
    def get_current_primary(self) -> str
    def get_cluster_status(self) -> ClusterStatus

class IHealthMonitor(ABC):
    async def check_health(self) -> HealthStatus
    async def send_heartbeat(self) -> None
    def get_health_history(self, minutes: int) -> List[HealthStatus]

class IDegradedModeController(ABC):
    def enter_degraded_mode(self, reason: str) -> None
    def exit_degraded_mode(self) -> None
    def is_degraded(self) -> bool
    def get_available_features(self) -> List[str]

class IConfigSyncService(ABC):
    async def sync_from_cloud(self) -> SyncResult
    async def push_events_to_cloud(self) -> SyncResult
    def get_last_sync(self) -> datetime
```

**Dépendances** :
- LOT 1 (ConfigLoader)
- LOT 4 (AuditEmitter)
- LOT 5 (LicenseCache pour mode dégradé)

**Estimation** : 4-5 jours

---

### LOT 7 : DEPLOYMENT

**Objectif** : Déploiement sûr et réversible.

**Composants** :
| Composant | Responsabilité |
|-----------|----------------|
| `DeploymentOrchestrator` | Orchestration standby-first |
| `RollbackManager` | Retour arrière automatique |
| `OTAController` | Mises à jour over-the-air |
| `MigrationManager` | Migrations de données |
| `ImageVerifier` | Vérification signatures images |

**Invariants couverts** :
- DEPL_001-033 (Deployment)
- PROV_020-023 (Provisioning)
- MIGR_001-010 (Migration)
- API_001-008 (API compatibility)

**Interfaces exposées** :
```python
class IDeploymentOrchestrator(ABC):
    async def deploy(self, config: DeploymentConfig) -> DeploymentResult
    async def get_deployment_status(self, deployment_id: str) -> DeploymentStatus
    async def abort_deployment(self, deployment_id: str) -> None

class IRollbackManager(ABC):
    async def rollback(self, deployment_id: str) -> RollbackResult
    async def rollback_to_version(self, version: str) -> RollbackResult
    def get_available_versions(self) -> List[str]

class IOTAController(ABC):
    async def check_for_updates(self) -> Optional[UpdateInfo]
    async def download_update(self, update_id: str) -> bytes
    async def apply_update(self, update_id: str) -> UpdateResult

class IMigrationManager(ABC):
    async def run_migrations(self, from_version: str, to_version: str) -> MigrationResult
    async def rollback_migration(self, migration_id: str) -> MigrationResult
    def get_pending_migrations(self) -> List[Migration]
```

**Dépendances** :
- LOT 1 (ConfigValidator)
- LOT 4 (AuditEmitter, BlockchainAnchor)
- LOT 5 (LicenseManager - vérifie licence avant deploy)
- LOT 6 (FailoverManager, HealthMonitor)

**Estimation** : 5-6 jours

---

### LOT 8 : INCIDENT

**Objectif** : Détection et réponse aux incidents sécurité.

**Composants** :
| Composant | Responsabilité |
|-----------|----------------|
| `IncidentDetector` | Détection anomalies |
| `IncidentHandler` | Actions automatiques |
| `ForensicsCollector` | Collecte preuves |
| `AlertDispatcher` | Notifications multi-canal |
| `TenantIsolator` | Isolation tenant compromis |

**Invariants couverts** :
- INCID_001-011 (Incident)
- RATE_001-007 (Rate limiting)

**Interfaces exposées** :
```python
class IIncidentDetector(ABC):
    def analyze_event(self, event: SecurityEvent) -> Optional[Incident]
    def get_threat_level(self, tenant_id: str) -> ThreatLevel

class IIncidentHandler(ABC):
    async def handle(self, incident: Incident) -> HandlingResult
    async def escalate(self, incident: Incident) -> None

class IForensicsCollector(ABC):
    async def collect_snapshot(self, tenant_id: str) -> ForensicsSnapshot
    async def export_evidence(self, incident_id: str) -> bytes

class ITenantIsolator(ABC):
    async def isolate(self, tenant_id: str, reason: str) -> None
    async def restore(self, tenant_id: str) -> None
    def is_isolated(self, tenant_id: str) -> bool

class IAlertDispatcher(ABC):
    async def dispatch(self, alert: Alert, channels: List[str]) -> None
    def get_available_channels(self) -> List[str]
```

**Dépendances** :
- LOT 3 (SessionManager pour révocation)
- LOT 4 (AuditEmitter, BlockchainAnchor)
- LOT 5 (KillSwitchController si breach majeure)

**Estimation** : 3-4 jours

---

## 5. Récapitulatif

| LOT | Nom | Dépend de | Estimation |
|-----|-----|-----------|------------|
| 1 | CORE | - | 2-3 jours |
| 2 | ISOLATION | 1 | 2-3 jours |
| 3 | AUTH | 1 | 3-4 jours |
| 4 | AUDIT | 1 | 3-4 jours |
| 5 | LICENSING | 1, 4 | 4-5 jours |
| 6 | HA | 1, 4, 5 | 4-5 jours |
| 7 | DEPLOYMENT | 1, 4, 5, 6 | 5-6 jours |
| 8 | INCIDENT | 3, 4, 5 | 3-4 jours |
| **TOTAL** | | | **~30 jours** |

---

## 6. Planning suggéré
```
SEMAINE 1
─────────
LOT 1 : CORE (Stéphane + Claude Code)

SEMAINE 2
─────────
LOT 2 : ISOLATION  ┐
LOT 3 : AUTH       ├── Parallélisables
LOT 4 : AUDIT      ┘

SEMAINE 3
─────────
LOT 5 : LICENSING  ┐
LOT 6 : HA         ├── Parallélisables
LOT 8 : INCIDENT   ┘

SEMAINE 4
─────────
LOT 7 : DEPLOYMENT
Tests E2E complets
Stabilisation
```

---

## 7. Comment développer un lot

### 7.1 Workflow
```
1. LIRE la spec du lot (ce document)
2. LIRE les invariants concernés
3. IMPLÉMENTER les interfaces
4. ÉCRIRE les tests unitaires (TDD)
5. VÉRIFIER tests compliance passent
6. PR + Review
7. Merge
```

### 7.2 Checklist par lot
```
□ Interfaces implémentées
□ Tests unitaires (coverage ≥ 80%)
□ Tests compliance passent
□ Documentation mise à jour
□ Pas de régression autres lots
```

---

## 8. Matrice tests intégration

Quels lots doivent être testés ensemble :
```
         LOT1  LOT2  LOT3  LOT4  LOT5  LOT6  LOT7  LOT8
LOT1      -
LOT2      ✅    -
LOT3      ✅          -
LOT4      ✅                -
LOT5      ✅          ✅    ✅    -
LOT6      ✅    ✅          ✅    ✅    -
LOT7      ✅    ✅    ✅    ✅    ✅    ✅    -
LOT8            ✅    ✅    ✅    ✅                -

✅ = Test intégration requis
```

**Fichiers tests intégration** :
- `test_core_isolation.py` (LOT1 + LOT2)
- `test_core_auth.py` (LOT1 + LOT3)
- `test_core_audit.py` (LOT1 + LOT4)
- `test_licensing_audit.py` (LOT4 + LOT5)
- `test_ha_licensing.py` (LOT5 + LOT6)
- `test_deployment_all.py` (LOT7 + tous)
- `test_incident_response.py` (LOT3 + LOT4 + LOT5 + LOT8)