# INVARIANTS TIME SYNC (TIME_001-008)

> Version: 1.0 | Date: 2024-12-04 | Status: VALIDÉ
> 8 règles | Phase: Synchronisation horloge

---

## 1. Règles

### TIME_001 : NTP obligatoire

**Règle** : NTP synchronisation OBLIGATOIRE.

---

### TIME_002 : Serveurs NTP FR/EU

**Règle** : Serveurs NTP : pool français ou européen.
```
server 0.fr.pool.ntp.org
server 1.europe.pool.ntp.org
server 2.europe.pool.ntp.org
```

---

### TIME_003 : Drift max 1 seconde

**Règle** : Drift max autorisé : 1 seconde.

---

### TIME_004 : Drift > 1s = WARNING

**Règle** : Drift > 1 seconde = alerte WARNING.

**Criticité** : WARNING

---

### TIME_005 : Drift > 5s = CRITICAL

**Règle** : Drift > 5 secondes = alerte CRITICAL + mode dégradé.

---

### TIME_006 : Timestamps UTC

**Règle** : Tous timestamps stockés en UTC.

---

### TIME_007 : Vérification au démarrage

**Règle** : Vérification drift au démarrage service.

---

### TIME_008 : Vérification horaire

**Règle** : Vérification drift périodique (toutes les heures).

---

## 2. LOT

Invariants TIME_* implémentés dans **LOT 6 (HA)**.