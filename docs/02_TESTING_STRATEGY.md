# ZYNAXIA FRAMEWORK - STRATÉGIE DE TESTS

> Version: 1.0 | Date: 2024-12-04 | Status: VALIDÉ
> Approche pragmatique pour équipe de 3

---

## 1. Principes

### 1.1 Pas de mock, vrais services
```
❌ ON NE FAIT PAS                    ✅ ON FAIT
─────────────────                    ─────────
Mock Vault                           Vrai Vault (namespace test)
Mock PostgreSQL                      Vraie DB (zynaxia_test)
Mock Keycloak                        Vrai Keycloak (realm test)
Containers dans CI                   SSH tunnel vers OVH
```

**Pourquoi ?** On est 3, on a l'infra, les mocks ajoutent de la complexité et masquent les vrais bugs.

### 1.2 Une seule infra, namespaces séparés
```
┌─────────────────────────────────────────────────────────────┐
│                        VM OVH                                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  POSTGRESQL                                                 │
│  ├── zynaxia_prod     (données réelles)                     │
│  └── zynaxia_test     (tests, purgeable)                    │
│                                                             │
│  VAULT                                                      │
│  ├── secret/prod/*    (secrets réels)                       │
│  └── secret/test/*    (secrets test)                        │
│                                                             │
│  KEYCLOAK                                                   │
│  ├── zynaxia-prod     (realm production)                    │
│  └── zynaxia-test     (realm test)                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Pyramide de tests
```
                         ┌───────┐
                         │  E2E  │        5%
                         │       │        Scénarios complets
                        ─┴───────┴─
                       ┌───────────┐
                       │INTÉGRATION│      15%
                       │           │      Inter-lots
                      ─┴───────────┴─
                     ┌───────────────┐
                     │  COMPLIANCE   │    30%
                     │               │    Invariants
                    ─┴───────────────┴─
                   ┌───────────────────┐
                   │    UNITAIRES      │  50%
                   │                   │  Fonctions isolées
                  ─┴───────────────────┴─
```

---

## 3. Types de tests

### 3.1 Tests unitaires

**Objectif** : Chaque fonction fait ce qu'elle doit.

**Caractéristiques** :
- Rapides (< 1ms par test)
- Pas de dépendance externe
- Exécutés localement

**Exemple** :
```python
# tests/unit/core/test_crypto_provider.py

def test_hash_sha384_returns_correct_length():
    """SHA-384 doit retourner 96 caractères hex."""
    crypto = CryptoProvider()
    result = crypto.hash(b"test data")
    assert len(result) == 96

def test_hash_sha384_deterministic():
    """Même input = même hash."""
    crypto = CryptoProvider()
    hash1 = crypto.hash(b"test")
    hash2 = crypto.hash(b"test")
    assert hash1 == hash2
```

---

### 3.2 Tests compliance

**Objectif** : Vérifier que les 392 invariants sont respectés.

**Caractéristiques** :
- Un test par invariant (ou groupe logique)
- Générés depuis la liste des invariants
- TOUS doivent passer (0 skip, 0 fail)

**Exemple** :
```python
# tests/compliance/test_run_rules.py

class TestRuntimeInvariants:
    """Tests pour RUN_001 à RUN_062."""
    
    def test_RUN_001_rls_policy_per_level(self, valid_config):
        """RUN_001: Chaque niveau hiérarchique DOIT avoir policy RLS."""
        validator = ConfigValidator()
        result = validator.validate_rule("RUN_001", valid_config)
        assert result is None  # None = pas d'erreur
    
    def test_RUN_001_violation_missing_policy(self, config_missing_rls):
        """RUN_001: Config sans RLS doit être rejetée."""
        validator = ConfigValidator()
        result = validator.validate_rule("RUN_001", config_missing_rls)
        assert result is not None
        assert result.rule_id == "RUN_001"
        assert result.severity == "BLOCKING"
    
    def test_RUN_021_wildcard_forbidden_site_level(self):
        """RUN_021: Wildcard interdit sauf niveau Platform."""
        config = {
            "roles": [{
                "id": "site_admin",
                "level": 3,
                "permissions": ["tenant:*"]  # Violation!
            }]
        }
        validator = ConfigValidator()
        result = validator.validate_rule("RUN_021", config)
        assert result is not None
        assert "wildcard" in result.message.lower()
```

---

### 3.3 Tests intégration

**Objectif** : Vérifier que les lots fonctionnent ensemble.

**Caractéristiques** :
- Requièrent connexion OVH (via SSH tunnel)
- Testent les vraies interactions
- Plus lents (secondes)

**Exemple** :
```python
# tests/integration/test_core_isolation.py

class TestCoreIsolation:
    """Tests LOT1 (Core) + LOT2 (Isolation)."""
    
    @pytest.fixture
    def db_connection(self):
        """Connexion à zynaxia_test via tunnel."""
        return psycopg2.connect(os.environ["TEST_DB_URL"])
    
    def test_rls_blocks_cross_tenant_access(self, db_connection):
        """Un tenant ne peut pas voir les données d'un autre."""
        # Setup : créer 2 tenants avec données
        cursor = db_connection.cursor()
        
        # Agir en tant que tenant_a
        cursor.execute("SET app.tenant_id = 'tenant_a'")
        cursor.execute("SELECT * FROM events")
        events_a = cursor.fetchall()
        
        # Agir en tant que tenant_b
        cursor.execute("SET app.tenant_id = 'tenant_b'")
        cursor.execute("SELECT * FROM events")
        events_b = cursor.fetchall()
        
        # Vérifier isolation
        ids_a = {e[0] for e in events_a}
        ids_b = {e[0] for e in events_b}
        assert ids_a.isdisjoint(ids_b), "RLS violation: tenants see each other's data"
```

---

### 3.4 Tests E2E

**Objectif** : Scénarios métier complets.

**Caractéristiques** :
- Simulent un workflow réel
- De bout en bout
- Les plus longs (minutes)

**Exemple** :
```python
# tests/e2e/test_full_lifecycle.py

class TestSiteLifecycle:
    """Cycle de vie complet d'un site."""
    
    def test_provision_to_kill_switch(self):
        """
        Scénario complet :
        1. Provision nouveau site
        2. Déployer config
        3. Vérifier fonctionnement
        4. Expirer licence
        5. Vérifier kill switch
        6. Renouveler licence
        7. Vérifier reprise
        """
        # 1. Provision
        site = provision_site("test-site-e2e")
        assert site.status == "provisioned"
        
        # 2. Deploy config
        config = load_test_config("valid_config.yaml")
        deploy_result = deploy_config(site.id, config)
        assert deploy_result.status == "deployed"
        
        # 3. Verify working
        health = check_health(site.id)
        assert health.status == "healthy"
        
        # 4. Expire license
        expire_license(site.id)
        time.sleep(5)
        
        # 5. Verify kill switch
        health = check_health(site.id)
        assert health.status == "killed"
        
        # 6. Renew license
        new_license = issue_license(site.id, days=30)
        inject_license(site.id, new_license)
        time.sleep(5)
        
        # 7. Verify recovery
        health = check_health(site.id)
        assert health.status == "healthy"
```

---

## 4. Responsabilités
```
┌─────────────────────────────────────────────────────────────┐
│                    QUI ÉCRIT QUOI                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  CLAUDE (Architecte)                                        │
│  ──────────────────                                         │
│  ├── Tests COMPLIANCE                                       │
│  │   └── Générés depuis invariants                         │
│  │   └── Stables, changent rarement                        │
│  │                                                         │
│  └── Specs tests INTÉGRATION                               │
│      └── Définis dans interfaces                           │
│                                                             │
│  CLAUDE CODE (Développeur)                                  │
│  ─────────────────────────                                  │
│  ├── Tests UNITAIRES                                        │
│  │   └── Écrits avec le code (TDD)                         │
│  │                                                         │
│  └── Implémentation tests INTÉGRATION et E2E               │
│      └── Selon specs Claude                                │
│                                                             │
│  STÉPHANE (CEO)                                             │
│  ─────────────                                              │
│  └── Définit scénarios E2E                                 │
│      └── "Je veux tester : provision → kill switch"        │
│      └── Valide que ça correspond au besoin métier         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. Structure des tests
```
tests/
├── conftest.py                    # Fixtures partagées
│
├── unit/                          # Tests unitaires
│   ├── core/
│   │   ├── test_config_loader.py
│   │   ├── test_config_validator.py
│   │   └── test_crypto_provider.py
│   ├── isolation/
│   │   └── test_rls_engine.py
│   ├── auth/
│   │   └── test_jwt_validator.py
│   └── ...
│
├── compliance/                    # Tests invariants
│   ├── test_prov_rules.py         # PROV_001-023
│   ├── test_depl_rules.py         # DEPL_001-033
│   ├── test_run_rules.py          # RUN_001-062
│   ├── test_maint_rules.py        # MAINT_001-063
│   ├── test_lic_rules.py          # LIC_001-104
│   ├── test_decom_rules.py        # DECOM_001-033
│   ├── test_migr_rules.py         # MIGR_001-010
│   ├── test_api_rules.py          # API_001-008
│   ├── test_incid_rules.py        # INCID_001-011
│   ├── test_obs_rules.py          # OBS_001-007
│   ├── test_net_rules.py          # NET_001-008
│   ├── test_rate_rules.py         # RATE_001-007
│   ├── test_log_rules.py          # LOG_001-007
│   ├── test_health_rules.py       # HEALTH_001-008
│   └── test_time_rules.py         # TIME_001-008
│
├── integration/                   # Tests inter-lots
│   ├── test_core_isolation.py     # LOT1 + LOT2
│   ├── test_auth_audit.py         # LOT3 + LOT4
│   ├── test_licensing_ha.py       # LOT5 + LOT6
│   └── ...
│
└── e2e/                           # Scénarios complets
    ├── test_provision_site.py
    ├── test_failover.py
    ├── test_kill_switch.py
    └── test_full_lifecycle.py
```

---

## 6. CI/CD avec GitHub Actions

### 6.1 Workflow
```yaml
# .github/workflows/framework.yml
name: ZYNAXIA Framework

on:
  push:
    branches: [main, develop, 'feature/**']
  pull_request:
    branches: [main]

env:
  OVH_HOST: ${{ secrets.OVH_HOST }}
  OVH_SSH_KEY: ${{ secrets.OVH_SSH_KEY }}
  TEST_VAULT_ADDR: ${{ secrets.TEST_VAULT_ADDR }}
  TEST_VAULT_TOKEN: ${{ secrets.TEST_VAULT_TOKEN }}
  TEST_DB_URL: ${{ secrets.TEST_DB_URL }}

jobs:
  # ══════════════════════════════════════════════════════
  # FAST TESTS (pas besoin OVH)
  # ══════════════════════════════════════════════════════
  fast-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: pip install -r requirements-dev.txt
      
      - name: Unit tests
        run: pytest tests/unit/ -v --cov=src --cov-fail-under=80
      
      - name: Compliance tests
        run: pytest tests/compliance/ -v
      
      - name: Security scan (Bandit)
        run: bandit -r src/ -ll

  # ══════════════════════════════════════════════════════
  # INTEGRATION TESTS (connexion OVH)
  # ══════════════════════════════════════════════════════
  integration-tests:
    needs: fast-tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Setup SSH tunnel
        run: |
          mkdir -p ~/.ssh
          echo "${{ secrets.OVH_SSH_KEY }}" > ~/.ssh/ovh_key
          chmod 600 ~/.ssh/ovh_key
          ssh-keyscan -H ${{ secrets.OVH_HOST }} >> ~/.ssh/known_hosts
          
          # Tunnels : Vault (8200), PostgreSQL (5432), Keycloak (8080)
          ssh -f -N \
            -L 8200:localhost:8200 \
            -L 5432:localhost:5432 \
            -L 8080:localhost:8080 \
            -i ~/.ssh/ovh_key \
            github-ci@${{ secrets.OVH_HOST }}
      
      - name: Wait for tunnels
        run: sleep 5
      
      - name: Install dependencies
        run: pip install -r requirements-dev.txt
      
      - name: Reset test database
        run: python scripts/reset_test_db.py
      
      - name: Integration tests
        run: pytest tests/integration/ -v
      
      - name: Cleanup tunnels
        if: always()
        run: pkill -f "ssh -f -N -L" || true

  # ══════════════════════════════════════════════════════
  # E2E TESTS (seulement sur main)
  # ══════════════════════════════════════════════════════
  e2e-tests:
    if: github.ref == 'refs/heads/main'
    needs: integration-tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Setup SSH tunnel
        run: |
          mkdir -p ~/.ssh
          echo "${{ secrets.OVH_SSH_KEY }}" > ~/.ssh/ovh_key
          chmod 600 ~/.ssh/ovh_key
          ssh-keyscan -H ${{ secrets.OVH_HOST }} >> ~/.ssh/known_hosts
          ssh -f -N \
            -L 8200:localhost:8200 \
            -L 5432:localhost:5432 \
            -L 8080:localhost:8080 \
            -i ~/.ssh/ovh_key \
            github-ci@${{ secrets.OVH_HOST }}
      
      - name: Install dependencies
        run: pip install -r requirements-dev.txt
      
      - name: E2E tests
        run: pytest tests/e2e/ -v --timeout=300
      
      - name: Cleanup
        if: always()
        run: pkill -f "ssh -f -N -L" || true
```

### 6.2 Secrets GitHub à configurer

| Secret | Valeur | Description |
|--------|--------|-------------|
| `OVH_HOST` | IP ou hostname | Adresse VM OVH |
| `OVH_SSH_KEY` | Clé privée | SSH key dédiée CI |
| `TEST_VAULT_ADDR` | `http://localhost:8200` | Via tunnel |
| `TEST_VAULT_TOKEN` | Token limité | Accès secret/test/* |
| `TEST_DB_URL` | `postgresql://...` | Connexion zynaxia_test |
| `TEST_KEYCLOAK_URL` | `http://localhost:8080` | Via tunnel |

---

## 7. Règles de merge

### 7.1 Pour merger dans `develop`
```
✅ Unit tests passent (coverage ≥ 80%)
✅ Compliance tests passent (100%, 0 skip)
✅ Security scan OK (0 critique/high)
✅ Au moins 1 review
```

### 7.2 Pour merger dans `main`
```
✅ Tout ci-dessus
✅ Integration tests passent
✅ E2E tests passent
✅ Approval Stéphane obligatoire
```

---

## 8. Fixtures et données de test
```
fixtures/
├── configs/
│   ├── valid_config.yaml          # Config complète valide
│   ├── minimal_config.yaml        # Config minimale valide
│   ├── invalid_wildcard.yaml      # Viole RUN_021
│   ├── invalid_no_rls.yaml        # Viole RUN_001
│   └── ...
│
├── licenses/
│   ├── valid_license.yaml         # Licence valide 30 jours
│   ├── expired_license.yaml       # Licence expirée
│   ├── revoked_license.yaml       # Licence révoquée
│   └── ...
│
└── events/
    ├── audit_events.json          # Événements audit sample
    └── ...
```

---

## 9. Commandes utiles
```bash
# Tous les tests
pytest

# Tests unitaires seulement
pytest tests/unit/

# Tests compliance seulement
pytest tests/compliance/

# Un invariant spécifique
pytest tests/compliance/test_run_rules.py -k "RUN_021"

# Avec coverage
pytest tests/unit/ --cov=src --cov-report=html

# Tests intégration (nécessite tunnel OVH)
pytest tests/integration/

# Tests E2E
pytest tests/e2e/ --timeout=300

# Reset DB test
python scripts/reset_test_db.py
```

---

## 10. Checklist avant PR
```
□ Tests unitaires écrits pour nouveau code
□ Tests compliance mis à jour si nouvel invariant
□ pytest tests/unit/ passe
□ pytest tests/compliance/ passe
□ Coverage ≥ 80%
□ bandit -r src/ -ll passe
□ Commit message conventionnel
```