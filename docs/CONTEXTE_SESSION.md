# CONTEXTE PROJET ZYNAXIA - ÉTAT AU 5 DÉCEMBRE 2024

## RÉSUMÉ EXÉCUTIF

Framework ZYNAXIA : 252 invariants de sécurité, 8 lots de développement.
LOT 1 (Core) : TERMINÉ avec 62 tests passés.

## ÉTAT DES LOTS

| LOT | Nom | Status | Tests |
|-----|-----|--------|-------|
| 1 | Core | ✅ TERMINÉ | 62 |
| 2 | Isolation | ⏳ À faire | - |
| 3 | Auth | ⏳ À faire | - |
| 4 | Audit | ⏳ À faire | - |
| 5 | Licensing | 🔒 Dépend 1,4 | - |
| 6 | HA | 🔒 Dépend 1,4,5 | - |
| 7 | Deployment | 🔒 Dépend tous | - |
| 8 | Incident | 🔒 Dépend 3,4,5 | - |

## LOT 1 DÉTAIL (TERMINÉ)

Composants implémentés :
- `src/core/crypto_provider.py` : ECDSA-P384, SHA-384
- `src/core/config_validator.py` : RUN_020, RUN_021, LIC_003
- `src/core/config_loader.py` : YAML, validation structure

Tests :
- 22 tests unitaires
- 6 tests intégration
- 34 tests compliance

## PROCHAINE ÉTAPE

LOT 2 (Isolation) ou LOT 5 (Licensing) selon priorité business.

## WORKFLOW CLAUDE CODE

Toujours commencer les prompts par :
```
AVANT D'IMPLÉMENTER, LIS CES FICHIERS :
1. docs/03_LOTS_OVERVIEW.md - section du LOT concerné
2. docs/invariants/INV_*.md - invariants concernés
```

## RÈGLES STRICTES

- NE PAS modifier src/invariants/rules.py
- NE PAS créer de .env
- NE PAS hardcoder secrets/tokens/URLs
- Commits conventionnels uniquement
