# INVARIANTS INCIDENT RESPONSE (INCID_001-011)

> Version: 1.0 | Date: 2024-12-04 | Status: VALIDÉ
> 11 règles | Phase: Réponse aux incidents sécurité

---

## 1. Règles

### INCID_001 : Intrusion = alerte immédiate

**Règle** : Détection intrusion = alerte immédiate multi-canal.

---

### INCID_002 : Accès non autorisé = log + alerte

**Règle** : Tentative accès non autorisé = log + alerte.

---

### INCID_003 : 3 échecs auth = verrouillage

**Règle** : 3 échecs auth = compte verrouillé temporaire (15 min).

---

### INCID_004 : Activité DB anormale = alerte

**Règle** : Activité anormale DB = alerte (queries inhabituelles).

---

### INCID_005 : Breach = isolation tenant

**Règle** : Breach confirmée = isolation automatique du tenant.

---

### INCID_006 : Breach = notification RSSI < 1h

**Règle** : Breach = notification RSSI < 1 heure.

---

### INCID_007 : Breach = révocation tokens

**Règle** : Breach = révocation tous tokens/sessions du tenant.

---

### INCID_008 : Breach = snapshot forensics

**Règle** : Breach = snapshot données pour forensics.

---

### INCID_009 : Post-incident < 72h

**Règle** : Post-incident = rapport obligatoire < 72h (RGPD).

---

### INCID_010 : Incident ancré blockchain

**Règle** : Incident ancré blockchain (preuve horodatée).

---

### INCID_011 : Procédure testée trimestriellement

**Règle** : Procédure incident testée trimestriellement.

---

## 2. LOT

Invariants INCID_* implémentés dans **LOT 8 (Incident)**.