# INVARIANTS LOGGING (LOG_001-007)

> Version: 1.0 | Date: 2024-12-04 | Status: VALIDÉ
> 7 règles | Phase: Format des logs

---

## 1. Règles

### LOG_001 : JSON structuré

**Règle** : Format JSON structuré obligatoire.

---

### LOG_002 : Champs obligatoires

**Règle** : Champs obligatoires : timestamp, level, correlation_id, tenant_id, message.
```json
{
  "timestamp": "2024-12-04T14:30:00.123Z",
  "level": "INFO",
  "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
  "tenant_id": "site-fleury-001",
  "message": "Event created successfully",
  "event_id": "evt-123",
  "user_id": "usr-456"
}
```

---

### LOG_003 : Timestamp ISO 8601 UTC

**Règle** : Timestamp format ISO 8601 avec timezone UTC.

---

### LOG_004 : Niveaux standard

**Règle** : Niveaux : DEBUG, INFO, WARN, ERROR, CRITICAL.

---

### LOG_005 : Données sensibles masquées

**Règle** : Données sensibles JAMAIS en clair dans logs (masquées).
```python
# Masquage automatique
def mask_sensitive(data: dict) -> dict:
    sensitive_keys = ["password", "token", "secret", "key"]
    return {
        k: "***MASKED***" if any(s in k.lower() for s in sensitive_keys) else v
        for k, v in data.items()
    }
```

---

### LOG_006 : Rotation automatique

**Règle** : Log rotation automatique (taille ou temps).

---

### LOG_007 : ERROR/CRITICAL = alerte auto

**Règle** : Logs ERROR et CRITICAL → alerte automatique.

---

## 2. LOT

Invariants LOG_* implémentés dans **LOT 4 (Audit)** et tous les LOTs.