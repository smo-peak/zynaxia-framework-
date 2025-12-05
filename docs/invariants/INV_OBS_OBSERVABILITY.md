# INVARIANTS OBSERVABILITY (OBS_001-007)

> Version: 1.0 | Date: 2024-12-04 | Status: VALIDÉ
> 7 règles | Phase: Tracing distribué

---

## 1. Règles

### OBS_001 : correlation_id unique

**Règle** : Chaque requête DOIT avoir un correlation_id unique (UUID).

---

### OBS_002 : correlation_id propagé

**Règle** : correlation_id propagé dans TOUS les appels (Edge→Cloud→DB→Blockchain).
```python
# Middleware propagation
@app.middleware("http")
async def add_correlation_id(request, call_next):
    correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    request.state.correlation_id = correlation_id
    response = await call_next(request)
    response.headers["X-Correlation-ID"] = correlation_id
    return response
```

---

### OBS_003 : correlation_id dans logs

**Règle** : correlation_id présent dans TOUS les logs liés à la requête.

---

### OBS_004 : Format OpenTelemetry

**Règle** : Traces exportées format OpenTelemetry.

---

### OBS_005 : Retention traces 30 jours

**Règle** : Retention traces 30 jours minimum.

---

### OBS_006 : Latence spans mesurée

**Règle** : Latence chaque span mesurée et stockée.

---

### OBS_007 : Erreurs avec stack trace

**Règle** : Erreurs tracées avec stack trace complet.

---

## 2. LOT

Invariants OBS_* implémentés dans **LOT 4 (Audit)** et tous les LOTs.