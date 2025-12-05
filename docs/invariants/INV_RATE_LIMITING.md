# INVARIANTS RATE LIMITING (RATE_001-007)

> Version: 1.0 | Date: 2024-12-04 | Status: VALIDÉ
> 7 règles | Phase: Protection contre abus

---

## 1. Règles

### RATE_001 : Rate limit par tenant

**Règle** : Rate limit par tenant (pas global).

---

### RATE_002 : Configurable par endpoint

**Règle** : Rate limit configurable par endpoint.

---

### RATE_003 : Dépassement = 429

**Règle** : Dépassement rate limit = 429 Too Many Requests (pas crash).
```http
HTTP/1.1 429 Too Many Requests
Retry-After: 60
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1701705600
```

---

### RATE_004 : Rate limit loggé

**Règle** : Rate limit logged pour analyse.

---

### RATE_005 : Burst autorisé

**Règle** : Burst autorisé : 2x limite pendant 10 secondes.

---

### RATE_006 : Auth 10 req/min/IP

**Règle** : Rate limit critique (auth) : 10 req/min par IP.

---

### RATE_007 : Standard 100 req/min/tenant

**Règle** : Rate limit standard : 100 req/min par tenant.

---

## 2. LOT

Invariants RATE_* implémentés dans **LOT 8 (Incident)** et middleware API.