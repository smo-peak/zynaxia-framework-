# ZYNAXIA Framework

Framework de sécurité multi-tenant pour applications Defense-grade.

## Status

🚧 **En développement** - Version 0.1.0

## Architecture

- **392 invariants** de sécurité immuables
- **8 lots** de développement indépendants
- Conformité **RGS 3★**, **IEC 62443**, **RGPD**

## Structure
```
src/
├── invariants/    # Règles de sécurité immuables
├── core/          # LOT 1 - Fondations
├── isolation/     # LOT 2 - Multi-tenant
├── auth/          # LOT 3 - Authentification
├── audit/         # LOT 4 - Traçabilité
├── licensing/     # LOT 5 - Licences
├── ha/            # LOT 6 - Haute disponibilité
├── deployment/    # LOT 7 - Déploiement
└── incident/      # LOT 8 - Réponse incidents
```

## Installation (dev)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

## Tests
```bash
# Tests unitaires
pytest tests/unit/

# Tests compliance
pytest tests/compliance/

# Tous les tests
pytest
```

## Documentation

Voir le dossier `docs/` et la base de connaissances du projet.

## Licence

Propriétaire - ZYNAXIA SAS
