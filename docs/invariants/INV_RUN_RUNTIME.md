# INVARIANTS RUNTIME (RUN_001-062)

> Version: 1.0 | Date: 2024-12-04 | Status: VALIDÉ
> 62 règles | Phase: Fonctionnement normal du système

---

## 1. Vue d'ensemble

Les invariants RUNTIME gouvernent le comportement du système en fonctionnement normal.

| Sous-section | Règles | Objectif |
|--------------|--------|----------|
| Isolation | RUN_001-004 | Multi-tenant hermétique |
| Authentification | RUN_010-014 | Identité vérifiée |
| Permissions | RUN_020-023 | Moindre privilège |
| Cryptographie | RUN_030-034 | RGS 3★ ready |
| Audit | RUN_040-044 | Non-répudiation |
| Haute Disponibilité | RUN_050-053 | Continuité service |

---

## 2. ISOLATION (RUN_001-004)

**Objectif** : Un tenant ne voit JAMAIS les données d'un autre tenant.

---

### RUN_001 : Policy RLS par niveau hiérarchique

**Règle** : Chaque niveau hiérarchique DOIT avoir une policy RLS PostgreSQL.

**Justification** : L'isolation doit être garantie au niveau base de données, pas applicatif. Une erreur de code ne doit pas exposer les données.

**Vérification** :
- Test compliance : Générer config → Vérifier policies SQL générées
- Test intégration : Requête sans contexte → Doit échouer

**Exemple conforme** :
```sql
-- Policy générée pour niveau "site" (level 3)
CREATE POLICY site_isolation ON events
  FOR ALL
  USING (
    site_id = current_setting('app.tenant_id')::uuid
  );
```

**Exemple violation** :
```sql
-- Table sans policy = VIOLATION
CREATE TABLE events (
  id UUID PRIMARY KEY,
  site_id UUID,
  data JSONB
);
-- Manque: ENABLE ROW LEVEL SECURITY + CREATE POLICY
```

**LOT** : LOT 2 (Isolation)

---

### RUN_002 : Isolation inter-tenant même niveau

**Règle** : Un tenant ne peut JAMAIS accéder aux données d'un autre tenant du même niveau.

**Justification** : Deux sites (niveau 3) ne doivent jamais voir les données l'un de l'autre, même s'ils appartiennent à la même organisation.

**Vérification** :
- Test intégration : Site A requête → Ne voit pas données Site B

**Exemple conforme** :
```python
# Contexte Site A
db.execute("SET app.tenant_id = 'site-a-uuid'")
events_a = db.execute("SELECT * FROM events").fetchall()
# events_a contient UNIQUEMENT les événements de site-a
```

**Exemple violation** :
```python
# Requête sans contexte ou avec mauvais contexte
events = db.execute("SELECT * FROM events").fetchall()
# VIOLATION: Retourne tous les événements de tous les sites
```

**LOT** : LOT 2 (Isolation)

---

### RUN_003 : Isolation enfant/parent

**Règle** : Un niveau enfant ne peut JAMAIS accéder aux données du niveau parent (sauf agrégation explicite configurée).

**Justification** : Un opérateur de site ne doit pas voir les données consolidées de l'organisation.

**Vérification** :
- Test intégration : User niveau 3 → Ne voit pas données niveau 2

**Exemple conforme** :
```yaml
# Config avec agrégation explicite
hierarchy:
  levels:
    - id: 2
      name: organization
      aggregation:
        allowed_to_children: false  # Enfants ne voient pas parent
        allowed_from_children: true # Parent voit enfants
```

**Exemple violation** :
```python
# User site essaie de voir données organisation
user = User(level=3, tenant_id="site-x")
org_data = db.query(Organization).filter_by(id=user.org_id).first()
# VIOLATION: Doit être bloqué par RLS
```

**LOT** : LOT 2 (Isolation)

---

### RUN_004 : Contexte tenant obligatoire

**Règle** : Toute requête SQL DOIT passer par le contexte tenant injecté. Aucun bypass possible.

**Justification** : Empêcher les requêtes "admin" qui contournent l'isolation.

**Vérification** :
- Test compliance : Toute connexion DB → Contexte défini avant requête
- Audit : Log si tentative requête sans contexte

**Exemple conforme** :
```python
# Middleware obligatoire
@app.middleware("http")
async def inject_tenant_context(request, call_next):
    tenant_id = extract_tenant_from_jwt(request)
    async with db.connection() as conn:
        await conn.execute(f"SET app.tenant_id = '{tenant_id}'")
        response = await call_next(request)
    return response
```

**Exemple violation** :
```python
# Connexion directe sans contexte
conn = psycopg2.connect(DATABASE_URL)
cursor = conn.cursor()
cursor.execute("SELECT * FROM events")  # VIOLATION: Pas de contexte
```

**LOT** : LOT 2 (Isolation)

---

## 3. AUTHENTIFICATION (RUN_010-014)

**Objectif** : Chaque requête provient d'une identité vérifiée.

---

### RUN_010 : Keycloak obligatoire

**Règle** : Authentification via Keycloak OBLIGATOIRE. Pas de système de login custom.

**Justification** : Keycloak est éprouvé, audité, maintenu. Un login custom = surface d'attaque.

**Vérification** :
- Test compliance : Aucun endpoint /login custom
- Test intégration : Auth uniquement via Keycloak

**Exemple conforme** :
```python
# Validation JWT Keycloak
from keycloak import KeycloakOpenID

keycloak = KeycloakOpenID(
    server_url="https://keycloak.zynaxia.io",
    realm_name="zynaxia-prod",
    client_id="zynaxia-api"
)

def validate_token(token: str) -> dict:
    return keycloak.decode_token(token, validate=True)
```

**Exemple violation** :
```python
# Login custom = VIOLATION
@app.post("/login")
def login(username: str, password: str):
    user = db.query(User).filter_by(username=username).first()
    if verify_password(password, user.password_hash):
        return {"token": create_jwt(user)}  # INTERDIT
```

**LOT** : LOT 3 (Auth)

---

### RUN_011 : JWT expiration max 15 minutes

**Règle** : Access token JWT DOIT expirer en 15 minutes maximum.

**Justification** : Limiter la fenêtre d'exploitation si token compromis.

**Vérification** :
- Test compliance : Keycloak config → access_token_lifespan ≤ 900s
- Test unitaire : Token > 15min → Rejeté

**Exemple conforme** :
```json
// Keycloak realm config
{
  "accessTokenLifespan": 900,
  "accessTokenLifespanForImplicitFlow": 900
}
```

**Exemple violation** :
```json
{
  "accessTokenLifespan": 3600  // 1 heure = VIOLATION
}
```

**LOT** : LOT 3 (Auth)

---

### RUN_012 : Refresh token max 24 heures

**Règle** : Refresh token DOIT expirer en 24 heures maximum.

**Justification** : Forcer ré-authentification quotidienne.

**Vérification** :
- Test compliance : Keycloak config → refresh_token_max_reuse_count, lifespan

**Exemple conforme** :
```json
{
  "ssoSessionMaxLifespan": 86400,
  "offlineSessionMaxLifespan": 86400
}
```

**LOT** : LOT 3 (Auth)

---

### RUN_013 : MFA pour permissions élevées

**Règle** : MFA OBLIGATOIRE pour tout rôle ayant des permissions élevées.

**Justification** : Actions critiques nécessitent double vérification.

**Vérification** :
- Test compliance : Config rôles → elevated_permissions → MFA requis
- Test intégration : User sans MFA → Accès refusé aux actions élevées

**Exemple conforme** :
```yaml
# Config rôles
roles:
  - id: site_admin
    level: 3
    mfa_required: true  # Car permissions élevées
    permissions:
      - "events:write"
      - "config:read"
```

**Exemple violation** :
```yaml
roles:
  - id: platform_admin
    level: 0
    mfa_required: false  # VIOLATION: Admin sans MFA
    permissions:
      - "*"
```

**LOT** : LOT 3 (Auth)

---

### RUN_014 : Session révocable à distance

**Règle** : Toute session DOIT pouvoir être révoquée immédiatement à distance.

**Justification** : Compromission détectée → Révoquer sans attendre expiration.

**Vérification** :
- Test intégration : Révoquer session → Requête suivante = 401

**Exemple conforme** :
```python
# Révocation immédiate
async def revoke_session(session_id: str):
    await keycloak.admin.revoke_session(session_id)
    await redis.delete(f"session:{session_id}")
    await audit.emit("session_revoked", session_id=session_id)
```

**LOT** : LOT 3 (Auth)

---

## 4. PERMISSIONS (RUN_020-023)

**Objectif** : Moindre privilège, pas d'escalade.

---

### RUN_020 : Pas de permissions niveau supérieur

**Règle** : Un rôle niveau N ne peut JAMAIS avoir des permissions de niveau N-1.

**Justification** : Un admin de site ne peut pas avoir des permissions d'organisation.

**Vérification** :
- Test compliance : Valider chaque rôle → permissions cohérentes avec level

**Exemple conforme** :
```yaml
roles:
  - id: site_admin
    level: 3
    permissions:
      - "site:events:write"   # OK: permission niveau 3
      - "site:config:read"    # OK: permission niveau 3
```

**Exemple violation** :
```yaml
roles:
  - id: site_admin
    level: 3
    permissions:
      - "organization:config:write"  # VIOLATION: niveau 2
```

**LOT** : LOT 3 (Auth)

---

### RUN_021 : Wildcard interdit sauf Platform

**Règle** : Permissions wildcard (`*`) INTERDITES sauf pour niveau Platform (0).

**Justification** : Wildcard = tous les droits = dangereux. Réservé au niveau le plus élevé.

**Vérification** :
- Test compliance : Scan config → Wildcard uniquement si level=0

**Exemple conforme** :
```yaml
roles:
  - id: platform_admin
    level: 0  # Platform = OK pour wildcard
    permissions:
      - "*"
```

**Exemple violation** :
```yaml
roles:
  - id: org_admin
    level: 2  # Organisation
    permissions:
      - "organization:*"  # VIOLATION: Wildcard niveau < 0
```

**LOT** : LOT 3 (Auth)

---

### RUN_022 : Quorum pour permissions élevées

**Règle** : Permissions élevées (remote_takeover, config:delete, etc.) REQUIÈRENT quorum minimum 2 signatures.

**Justification** : Actions critiques = validation par plusieurs personnes.

**Vérification** :
- Test compliance : elevated_permissions → quorum_threshold ≥ 2
- Test intégration : Action élevée avec 1 signature → Refusé

**Exemple conforme** :
```yaml
elevated_permissions:
  - id: remote_takeover
    requires_quorum: true
    quorum_threshold: 2
    quorum_roles:
      - platform_admin
      - partner_admin
      - org_director
    max_duration_hours: 2
    audit: blockchain
```

**Exemple violation** :
```yaml
elevated_permissions:
  - id: remote_takeover
    requires_quorum: false  # VIOLATION: Pas de quorum
```

**LOT** : LOT 3 (Auth), LOT 4 (Audit)

---

### RUN_023 : Durée permissions élevées limitée

**Règle** : Permissions élevées temporaires DOIVENT avoir une durée maximale (défaut 2h).

**Justification** : Éviter qu'une élévation de privilège reste active indéfiniment.

**Vérification** :
- Test compliance : max_duration_hours défini
- Test intégration : Après expiration → Permission révoquée automatiquement

**Exemple conforme** :
```yaml
elevated_permissions:
  - id: emergency_access
    max_duration_hours: 2
    auto_revoke: true
```

**LOT** : LOT 3 (Auth)

---

## 5. CRYPTOGRAPHIE (RUN_030-034)

**Objectif** : Conformité RGS 3★ (ANSSI).

---

### RUN_030 : ECDSA-P384 minimum

**Règle** : Signatures cryptographiques DOIVENT utiliser ECDSA-P384 minimum. P-256 INTERDIT.

**Justification** : RGS 3★ exige courbes 384 bits minimum pour signatures.

**Vérification** :
- Test compliance : Scan code → Pas de P-256, secp256r1
- Test unitaire : CryptoProvider utilise P-384

**Exemple conforme** :
```python
from cryptography.hazmat.primitives.asymmetric import ec

# P-384 = secp384r1
private_key = ec.generate_private_key(ec.SECP384R1())
```

**Exemple violation** :
```python
# P-256 = INTERDIT
private_key = ec.generate_private_key(ec.SECP256R1())
```

**LOT** : LOT 1 (Core)

---

### RUN_031 : SHA-384 minimum

**Règle** : Hash pour signatures DOIT être SHA-384 minimum. SHA-256 INTERDIT pour signatures.

**Justification** : RGS 3★ cohérence avec courbe P-384.

**Vérification** :
- Test unitaire : CryptoProvider.hash() retourne 96 chars (384 bits / 4)

**Exemple conforme** :
```python
import hashlib

def hash_data(data: bytes) -> str:
    return hashlib.sha384(data).hexdigest()  # 96 caractères
```

**Exemple violation** :
```python
def hash_data(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()  # INTERDIT pour signatures
```

**LOT** : LOT 1 (Core)

---

### RUN_032 : TLS 1.3 obligatoire

**Règle** : Communications DOIVENT utiliser TLS 1.3. TLS 1.2 et inférieur INTERDITS.

**Justification** : TLS 1.3 corrige vulnérabilités 1.2, plus performant.

**Vérification** :
- Test compliance : Config Traefik/nginx → TLS 1.3 only
- Test intégration : Connexion TLS 1.2 → Refusée

**Exemple conforme** :
```yaml
# Traefik config
tls:
  options:
    default:
      minVersion: VersionTLS13
```

**Exemple violation** :
```yaml
tls:
  options:
    default:
      minVersion: VersionTLS12  # INTERDIT
```

**LOT** : LOT 6 (HA), LOT 7 (Deployment)

---

### RUN_033 : Secrets jamais en clair

**Règle** : Secrets (mots de passe, clés, tokens) JAMAIS en clair. Vault OBLIGATOIRE.

**Justification** : Secret en clair = compromission inévitable.

**Vérification** :
- Test compliance : Scan code → Pas de hardcoded secrets
- Test compliance : Variables env → Références Vault uniquement

**Exemple conforme** :
```python
import hvac

vault = hvac.Client(url=os.environ["VAULT_ADDR"])
db_password = vault.secrets.kv.v2.read_secret("database")["password"]
```

**Exemple violation** :
```python
# INTERDIT
DB_PASSWORD = "super_secret_123"

# INTERDIT aussi
DB_PASSWORD = os.environ["DB_PASSWORD"]  # Si pas chiffré
```

**LOT** : LOT 1 (Core)

---

### RUN_034 : Rotation clés annuelle

**Règle** : Clés de signature DOIVENT être renouvelées annuellement.

**Justification** : Limiter impact si clé compromise sans détection.

**Vérification** :
- Test compliance : Metadata clé → created_at < 1 an
- Alerte MAINT : 30 jours avant expiration

**Exemple conforme** :
```yaml
# Vault key metadata
signing_key:
  id: "zynaxia-signing-2024"
  algorithm: "ECDSA-P384"
  created_at: "2024-01-15"
  expires_at: "2025-01-15"
  rotation_reminder_days: 30
```

**LOT** : LOT 1 (Core), MAINT_020

---

## 6. AUDIT (RUN_040-044)

**Objectif** : Traçabilité complète, non-répudiable.

---

### RUN_040 : Événement audit pour toute action

**Règle** : Toute action utilisateur DOIT générer un événement audit.

**Justification** : Traçabilité complète pour compliance et forensics.

**Vérification** :
- Test intégration : Action → Événement audit créé
- Test compliance : Tous endpoints → Decorator @audit

**Exemple conforme** :
```python
@audit(action="event.create", level="info")
async def create_event(request: Request, event: EventCreate):
    # ... logique
    return created_event
```

**Exemple violation** :
```python
# Pas de décorateur audit = VIOLATION
async def create_event(request: Request, event: EventCreate):
    return created_event
```

**LOT** : LOT 4 (Audit)

---

### RUN_041 : Actions critiques vers blockchain

**Règle** : Actions critiques DOIVENT être ancrées blockchain.

**Justification** : Non-répudiation, preuve légale horodatée.

**Actions critiques** :
- Provisioning site
- Émission/révocation licence
- Kill switch
- Modification config
- Incident sécurité
- Décommissionnement

**Vérification** :
- Test intégration : Action critique → tx_hash blockchain retourné

**Exemple conforme** :
```python
async def revoke_license(site_id: str, reason: str):
    # ... logique révocation
    
    # Ancrage blockchain OBLIGATOIRE
    receipt = await blockchain.anchor(
        event_type="license.revoked",
        data_hash=hash_event(event),
        metadata={"site_id": site_id, "reason": reason}
    )
    
    return {"revoked": True, "blockchain_tx": receipt.tx_hash}
```

**LOT** : LOT 4 (Audit)

---

### RUN_042 : Événements audit immuables

**Règle** : Événements audit IMMUABLES. Append-only, pas de modification ni suppression.

**Justification** : Intégrité audit = confiance compliance.

**Vérification** :
- Test compliance : Table audit → Pas de UPDATE/DELETE
- Test intégration : Tentative DELETE → Erreur

**Exemple conforme** :
```sql
-- Table audit append-only
CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    -- ... autres colonnes
);

-- Bloquer modifications
REVOKE UPDATE, DELETE ON audit_events FROM ALL;

-- Trigger protection
CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit events are immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_immutable
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();
```

**LOT** : LOT 4 (Audit)

---

### RUN_043 : Rétention audit 10 ans

**Règle** : Logs audit conservés 10 ans MINIMUM.

**Justification** : Exigences légales, délais prescription.

**Vérification** :
- Test compliance : Config rétention → 10 ans
- Archivage automatique vers S3 Glacier

**Exemple conforme** :
```yaml
audit:
  retention:
    online: 90d      # Loki/PostgreSQL
    archive: 10y     # S3 Glacier
  archival:
    schedule: "0 2 * * *"  # Quotidien 2h
    destination: "s3://zynaxia-audit-archive"
    storage_class: "GLACIER"
```

**LOT** : LOT 4 (Audit), MAINT_041

---

### RUN_044 : Logs signés cryptographiquement

**Règle** : Logs audit DOIVENT être signés pour garantir intégrité.

**Justification** : Détection falsification, preuve non altérée.

**Vérification** :
- Test unitaire : Log créé → Signature attachée
- Test intégration : Vérification chaîne signatures

**Exemple conforme** :
```python
class AuditEvent:
    id: UUID
    timestamp: datetime
    action: str
    data: dict
    previous_hash: str  # Chaînage
    signature: str      # ECDSA-P384
    
def sign_event(event: AuditEvent, key: PrivateKey) -> str:
    payload = f"{event.id}|{event.timestamp}|{event.action}|{event.previous_hash}"
    return crypto.sign(payload.encode(), key)
```

**LOT** : LOT 4 (Audit)

---

## 7. HAUTE DISPONIBILITÉ (RUN_050-053)

**Objectif** : Continuité de service, résilience.

---

### RUN_050 : Cluster minimum 2 nœuds

**Règle** : Cluster Edge DOIT avoir minimum 2 nœuds.

**Justification** : Failover impossible avec 1 seul nœud.

**Vérification** :
- Test compliance : Config cluster → min_nodes ≥ 2
- Test intégration : Healthcheck retourne node_count

**Exemple conforme** :
```yaml
cluster:
  min_nodes: 2
  max_nodes: 4
  quorum: 2
```

**Exemple violation** :
```yaml
cluster:
  min_nodes: 1  # VIOLATION: Pas de HA possible
```

**LOT** : LOT 6 (HA)

---

### RUN_051 : Failover automatique < 10 secondes

**Règle** : Bascule primary → standby DOIT s'effectuer en moins de 10 secondes.

**Justification** : Interruption minimale, transparent pour utilisateurs.

**Vérification** :
- Test E2E : Kill primary → Mesurer temps reprise
- Métrique : failover_duration_seconds

**Exemple conforme** :
```python
class FailoverManager:
    DETECTION_TIMEOUT = 3  # secondes
    PROMOTION_TIMEOUT = 5  # secondes
    # Total max: 8 secondes < 10
    
    async def trigger_failover(self):
        start = time.time()
        await self.detect_primary_failure()  # 3s max
        await self.promote_standby()          # 5s max
        duration = time.time() - start
        assert duration < 10, f"Failover too slow: {duration}s"
```

**LOT** : LOT 6 (HA)

---

### RUN_052 : Mode dégradé si Cloud offline

**Règle** : Edge DOIT fonctionner en mode dégradé si Cloud Ministry inaccessible.

**Justification** : Prison ne peut pas s'arrêter si internet tombe.

**Fonctionnalités mode dégradé** :
- Lecture données locales : ✅
- Écriture événements locaux : ✅
- Sync vers Cloud : ❌ (file d'attente)
- Nouvelles configs : ❌ (cache local)

**Vérification** :
- Test E2E : Couper Cloud → Edge continue de fonctionner
- Test intégration : Events queued pour sync ultérieur

**Exemple conforme** :
```python
class DegradedModeController:
    def enter_degraded_mode(self, reason: str):
        self.is_degraded = True
        self.degraded_since = datetime.utcnow()
        self.available_features = [
            "events:read",
            "events:write:local",
            "config:read:cached"
        ]
        audit.emit("degraded_mode.entered", reason=reason)
```

**LOT** : LOT 6 (HA)

---

### RUN_053 : Cache config local TTL 7 jours

**Règle** : Configuration cachée localement avec TTL maximum 7 jours.

**Justification** : Permettre fonctionnement offline, mais forcer sync régulier.

**Vérification** :
- Test compliance : Cache TTL ≤ 7 jours
- Test intégration : Cache expiré + Cloud offline → Alerte

**Exemple conforme** :
```python
class ConfigCache:
    MAX_TTL_DAYS = 7
    
    def get_config(self, tenant_id: str) -> Optional[Config]:
        cached = self.cache.get(tenant_id)
        if cached and cached.age_days <= self.MAX_TTL_DAYS:
            return cached.config
        return None  # Force refresh from Cloud
```

**LOT** : LOT 6 (HA)

---

## 8. Récapitulatif

| Section | Règles | LOT principal |
|---------|--------|---------------|
| Isolation | RUN_001-004 | LOT 2 |
| Authentification | RUN_010-014 | LOT 3 |
| Permissions | RUN_020-023 | LOT 3 |
| Cryptographie | RUN_030-034 | LOT 1 |
| Audit | RUN_040-044 | LOT 4 |
| Haute Disponibilité | RUN_050-053 | LOT 6 |

---

## 9. Tests compliance

Fichier : `tests/compliance/test_run_rules.py`
```python
class TestIsolation:
    def test_RUN_001_rls_policy_exists(self): ...
    def test_RUN_002_cross_tenant_blocked(self): ...
    def test_RUN_003_child_parent_blocked(self): ...
    def test_RUN_004_context_required(self): ...

class TestAuth:
    def test_RUN_010_keycloak_only(self): ...
    def test_RUN_011_jwt_expiration_max_15min(self): ...
    def test_RUN_012_refresh_token_max_24h(self): ...
    def test_RUN_013_mfa_for_elevated(self): ...
    def test_RUN_014_session_revocable(self): ...

class TestPermissions:
    def test_RUN_020_no_upper_level_permissions(self): ...
    def test_RUN_021_wildcard_platform_only(self): ...
    def test_RUN_022_quorum_required(self): ...
    def test_RUN_023_elevated_duration_limited(self): ...

class TestCrypto:
    def test_RUN_030_ecdsa_p384(self): ...
    def test_RUN_031_sha384(self): ...
    def test_RUN_032_tls_1_3(self): ...
    def test_RUN_033_no_cleartext_secrets(self): ...
    def test_RUN_034_key_rotation_annual(self): ...

class TestAudit:
    def test_RUN_040_all_actions_audited(self): ...
    def test_RUN_041_critical_to_blockchain(self): ...
    def test_RUN_042_audit_immutable(self): ...
    def test_RUN_043_retention_10_years(self): ...
    def test_RUN_044_logs_signed(self): ...

class TestHA:
    def test_RUN_050_min_2_nodes(self): ...
    def test_RUN_051_failover_under_10s(self): ...
    def test_RUN_052_degraded_mode_works(self): ...
    def test_RUN_053_config_cache_7_days(self): ...
```

---

## 10. Références

| Norme | Règles couvertes |
|-------|------------------|
| RGS 3★ | RUN_030-034 |
| ANSSI | RUN_001-004, RUN_040-044 |
| IEC 62443 | RUN_050-053 |
| RGPD | RUN_040-044 |