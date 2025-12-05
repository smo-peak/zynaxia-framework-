# INVARIANTS NETWORK (NET_001-008)

> Version: 1.0 | Date: 2024-12-04 | Status: VALIDÉ
> 8 règles | Phase: Connectivité et résilience réseau

---

## 1. Règles

### NET_001 : Timeout connexion 10s

**Règle** : Timeout connexion : 10 secondes max.

---

### NET_002 : Timeout requête 30s

**Règle** : Timeout requête : 30 secondes max (configurable par endpoint).

---

### NET_003 : Retry 3x avec backoff

**Règle** : Retry automatique : 3 tentatives avec backoff exponentiel.
```python
@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10)
)
async def call_external_service():
    ...
```

---

### NET_004 : Circuit breaker après 5 échecs

**Règle** : Circuit breaker : ouvert après 5 échecs consécutifs.

---

### NET_005 : Half-open après 30s

**Règle** : Circuit breaker : half-open après 30 secondes.

---

### NET_006 : Cloud perdu = mode dégradé

**Règle** : Connexion Cloud perdue = mode dégradé (pas crash).

---

### NET_007 : Reconnexion auto

**Règle** : Reconnexion automatique avec backoff.

---

### NET_008 : Keep-alive TCP

**Règle** : Keep-alive TCP activé (détection connexion morte).

---

## 2. LOT

Invariants NET_* implémentés dans **LOT 6 (HA)**.