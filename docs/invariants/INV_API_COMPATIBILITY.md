# INVARIANTS API COMPATIBILITY (API_001-008)

> Version: 1.0 | Date: 2024-12-04 | Status: VALIDÉ
> 8 règles | Phase: Versioning des APIs

---

## 1. Règles

### API_001 : Version dans URL

**Règle** : API versionnée dans URL (/api/v1/, /api/v2/).

---

### API_002 : Support N-1

**Règle** : Version N supporte N-1 (backward compatible 1 version).

---

### API_003 : Dépréciation 6 mois

**Règle** : Dépréciation API = 6 mois minimum avant suppression.

---

### API_004 : Header X-API-Version

**Règle** : Header X-API-Version dans toutes les réponses.
```http
HTTP/1.1 200 OK
X-API-Version: 1.2.0
Content-Type: application/json
```

---

### API_005 : Changelog documenté

**Règle** : Changelog API documenté pour chaque release.

---

### API_006 : Breaking change = version majeure

**Règle** : Breaking change = version majeure obligatoire.

---

### API_007 : Edge compatible Cloud N±1

**Règle** : Edge peut fonctionner avec Cloud N+1 ou N-1.

---

### API_008 : Incompatibilité = alerte pas crash

**Règle** : Incompatibilité version = alerte (pas crash).

---

## 2. LOT

Invariants API_* implémentés dans **LOT 7 (Deployment)** et tous les LOTs exposant des APIs.