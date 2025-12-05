# ZYNAXIA FRAMEWORK - GUIDE DE CONTRIBUTION

> Version: 1.0 | Date: 2024-12-04 | Status: VALIDÉ
> Règles pour modifier le framework

---

## 1. L'équipe

| Membre | Rôle | Responsabilités |
|--------|------|-----------------|
| **Stéphane** | CEO | Vision, validation finale, arbitrage |
| **Claude** | Architecte | Specs, interfaces, review, invariants |
| **Claude Code** | Développeur | Implémentation, tests unitaires |

---

## 2. Branches
```
main              Production, stable, protégé
  │
  └── develop     Intégration, tests passent
        │
        └── feature/lot-X-description    Développement
```

**Règles** :
- `main` : Merge uniquement depuis `develop`, approval Stéphane obligatoire
- `develop` : Merge depuis features, CI doit passer
- `feature/*` : Travail en cours, commits libres

---

## 3. Commits

### 3.1 Format conventionnel
```
<type>(<scope>): <description>

[body optionnel]

[footer optionnel]
```

### 3.2 Types

| Type | Usage |
|------|-------|
| `feat` | Nouvelle fonctionnalité |
| `fix` | Correction bug |
| `docs` | Documentation |
| `test` | Ajout/modification tests |
| `refactor` | Refactoring sans changement fonctionnel |
| `chore` | Maintenance, dépendances |
| `security` | Correction sécurité |
| `invariant` | Modification invariant (⚠️ spécial) |

### 3.3 Scopes

| Scope | LOT |
|-------|-----|
| `core` | LOT 1 |
| `isolation` | LOT 2 |
| `auth` | LOT 3 |
| `audit` | LOT 4 |
| `licensing` | LOT 5 |
| `ha` | LOT 6 |
| `deployment` | LOT 7 |
| `incident` | LOT 8 |
| `ci` | CI/CD |
| `docs` | Documentation |

### 3.4 Exemples
```bash
# Nouvelle fonctionnalité
feat(licensing): add kill switch controller

# Bug fix
fix(auth): fix JWT expiration check off-by-one

# Documentation
docs(core): update ConfigValidator interface

# Test
test(isolation): add RLS cross-tenant test

# Modification invariant (ATTENTION)
invariant(licensing): change LIC_021 TTL from 7 to 14 days

BREAKING CHANGE: Sites must update their cache configuration
Reviewed-by: Stéphane
RFC: #12
```

---

## 4. Pull Requests

### 4.1 Template PR
```markdown
## Description

[Qu'est-ce que cette PR fait ?]

## Type de changement

- [ ] Nouvelle fonctionnalité (feat)
- [ ] Bug fix (fix)
- [ ] Documentation (docs)
- [ ] Refactoring (refactor)
- [ ] Modification invariant (invariant) ⚠️

## LOT concerné

- [ ] LOT 1 - Core
- [ ] LOT 2 - Isolation
- [ ] LOT 3 - Auth
- [ ] LOT 4 - Audit
- [ ] LOT 5 - Licensing
- [ ] LOT 6 - HA
- [ ] LOT 7 - Deployment
- [ ] LOT 8 - Incident

## Checklist

- [ ] Tests unitaires ajoutés/modifiés
- [ ] Tests compliance passent
- [ ] Documentation mise à jour
- [ ] Pas de régression (autres tests passent)

## Si modification invariant

- [ ] RFC créée et approuvée
- [ ] Justification documentée
- [ ] Tests compliance mis à jour
- [ ] Migration documentée si nécessaire
```

### 4.2 Labels

| Label | Signification |
|-------|---------------|
| `lot-1` à `lot-8` | LOT concerné |
| `invariant-change` | ⚠️ Modification règle |
| `breaking-change` | Changement non rétrocompatible |
| `security` | Impact sécurité |
| `needs-review` | En attente review |
| `approved` | Validé, prêt à merger |

---

## 5. Modifier un invariant

### 5.1 Processus obligatoire
```
┌─────────────────────────────────────────────────────────────┐
│          PROCESSUS MODIFICATION INVARIANT                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. CRÉER UNE RFC (Request For Comments)                    │
│     └── Issue GitHub avec template RFC                      │
│                                                             │
│  2. DOCUMENTER                                              │
│     ├── Quel invariant ?                                    │
│     ├── Pourquoi le changer ?                               │
│     ├── Impact sur sites existants ?                        │
│     ├── Migration nécessaire ?                              │
│     └── Alternatives considérées ?                          │
│                                                             │
│  3. REVIEW                                                  │
│     ├── Claude analyse cohérence                            │
│     └── Stéphane valide business/sécurité                   │
│                                                             │
│  4. IMPLÉMENTER                                             │
│     ├── Modifier code invariant                             │
│     ├── Modifier test compliance                            │
│     └── PR avec label `invariant-change`                    │
│                                                             │
│  5. MERGER                                                  │
│     └── Approval Stéphane OBLIGATOIRE                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 Template RFC
```markdown
# RFC: [Titre]

## Invariant concerné

`[CODE]` : [Description actuelle]

## Changement proposé

**Avant** : [Règle actuelle]
**Après** : [Nouvelle règle]

## Justification

[Pourquoi ce changement est nécessaire ?]

## Impact

### Sites existants
[Comment les sites déployés sont-ils affectés ?]

### Migration
[Étapes de migration si nécessaire]

### Compatibilité
[Backward compatible ? Breaking change ?]

## Alternatives considérées

1. [Alternative 1] - [Pourquoi rejetée]
2. [Alternative 2] - [Pourquoi rejetée]

## Checklist

- [ ] Impact analysé
- [ ] Migration documentée
- [ ] Tests compliance prévus
- [ ] Review Claude
- [ ] Validation Stéphane
```

### 5.3 Ce qui nécessite une RFC

| Changement | RFC obligatoire ? |
|------------|-------------------|
| Nouvelle règle | Oui |
| Modifier seuil/valeur | Oui |
| Supprimer règle | Oui + justification forte |
| Clarifier formulation | Non (PR directe) |
| Corriger typo | Non (PR directe) |

---

## 6. Review

### 6.1 Qui review quoi ?

| Type de changement | Reviewer |
|--------------------|----------|
| Code standard | Claude |
| Tests | Claude |
| Documentation | Claude |
| Invariant | Claude + Stéphane |
| Merge dans main | Stéphane |

### 6.2 Critères de review

**Claude vérifie** :
- Cohérence avec architecture
- Respect des interfaces
- Qualité du code
- Tests suffisants
- Pas de régression

**Stéphane vérifie** :
- Alignement vision produit
- Impact business
- Sécurité
- Go/No-go final

---

## 7. Workflow quotidien

### 7.1 Développer une feature
```bash
# 1. Créer branche
git checkout develop
git pull
git checkout -b feature/lot-5-kill-switch

# 2. Développer + tester
# ... code ...
pytest tests/unit/licensing/

# 3. Commit
git add .
git commit -m "feat(licensing): implement kill switch controller"

# 4. Push
git push -u origin feature/lot-5-kill-switch

# 5. Créer PR sur GitHub
# 6. Attendre review
# 7. Merger après approval
```

### 7.2 Hotfix sécurité
```bash
# 1. Branche depuis main
git checkout main
git pull
git checkout -b hotfix/security-jwt-validation

# 2. Fix + test
# ... code ...

# 3. Commit avec type security
git commit -m "security(auth): fix JWT signature bypass"

# 4. PR directe vers main
# 5. Review urgente Stéphane
# 6. Merge + deploy immédiat
# 7. Backport vers develop
```

---

## 8. Règles de merge

### 8.1 Vers `develop`
```
✅ CI passe (unit + compliance)
✅ Review Claude OK
✅ Pas de conflit
```

### 8.2 Vers `main`
```
✅ Tout ci-dessus
✅ Tests intégration passent
✅ Tests E2E passent
✅ Approval Stéphane
✅ CHANGELOG mis à jour
```

---

## 9. CHANGELOG

### 9.1 Format
```markdown
# Changelog

## [1.2.0] - 2024-12-15

### Added
- feat(licensing): Kill switch controller (#45)
- feat(ha): Automatic failover (#42)

### Changed
- invariant(licensing): LIC_021 TTL 7→14 days (#48)

### Fixed
- fix(auth): JWT expiration off-by-one (#44)

### Security
- security(auth): Fix signature bypass (#50)

## [1.1.0] - 2024-12-01
...
```

### 9.2 Quand mettre à jour

- À chaque merge dans `main`
- Avant release/tag

---

## 10. Versioning
```
vX.Y.Z

X = MAJOR : Breaking change, modification invariant majeure
Y = MINOR : Nouvelle fonctionnalité, compatible
Z = PATCH : Bug fix, compatible
```

### Exemples

| Changement | Version |
|------------|---------|
| Nouveau lot ajouté | MINOR |
| Bug fix | PATCH |
| Nouvel invariant | MINOR |
| Modifier invariant existant | MAJOR |
| Supprimer invariant | MAJOR |
| Refactoring interne | PATCH |

---

## 11. Checklist contributeur

Avant de soumettre une PR :
```
□ Tests unitaires écrits (coverage ≥ 80%)
□ pytest tests/unit/ passe
□ pytest tests/compliance/ passe
□ bandit -r src/ -ll passe (sécurité)
□ Code formaté (black, isort)
□ Commit message conventionnel
□ Documentation mise à jour si nécessaire
□ CHANGELOG mis à jour si merge vers main
□ Si invariant : RFC créée et approuvée
```

---

## 12. Contacts

| Sujet | Contact |
|-------|---------|
| Vision, arbitrage | Stéphane |
| Architecture, specs | Claude (conversation) |
| Implémentation | Claude Code (terminal) |
| Bug urgent | Issue GitHub + mention @stephane |