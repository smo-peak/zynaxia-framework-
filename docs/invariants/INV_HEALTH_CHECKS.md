# INVARIANTS HEALTH CHECKS (HEALTH_001-008)

> Version: 1.0 | Date: 2024-12-04 | Status: VALIDÉ
> 8 règles | Phase: Endpoints de santé

---

## 1. Règles

### HEALTH_001 : /health obligatoire

**Règle** : Endpoint /health OBLIGATOIRE sur chaque service.

---

### HEALTH_002 : /health/live (liveness)

**Règle** : Endpoint /health/live : service répond (liveness).

---

### HEALTH_003 : /health/ready (readiness)

**Règle** : Endpoint /health/ready : service opérationnel (readiness).

---

### HEALTH_004 : Format JSON standard

**Règle** : Format réponse JSON : {status, checks[], timestamp}.
```json
{
  "status": "healthy",
  "timestamp": "2024-12-04T14:30:00Z",
  "checks": [
    {"name": "database", "status": "healthy", "latency_ms": 5},
    {"name": "vault", "status": "healthy", "latency_ms": 12},
    {"name": "keycloak", "status": "healthy", "latency_ms": 45},
    {"name": "disk", "status": "healthy", "usage_percent": 42},
    {"name": "memory", "status": "healthy", "usage_percent": 65}
  ]
}
```

---

### HEALTH_005 : Checks standards

**Règle** : Checks incluent : db, vault, keycloak, disk, memory.

---

### HEALTH_006 : Status standardisés

**Règle** : Status : healthy, degraded, unhealthy.

---

### HEALTH_007 : Unhealthy = plus de trafic

**Règle** : Unhealthy = ne reçoit plus de trafic (load balancer).

---

### HEALTH_008 : Health check < 5s

**Règle** : Health check < 5 secondes (timeout).

---

## 2. LOT

Invariants HEALTH_* implémentés dans **LOT 6 (HA)**.