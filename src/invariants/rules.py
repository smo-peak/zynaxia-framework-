"""
ZYNAXIA Framework - Security Invariants
Ces règles sont IMMUABLES et ne peuvent être modifiées par configuration.
Total: 392 règles
"""

from enum import Enum
from typing import Final


class Severity(Enum):
    """Criticité d'un invariant."""

    BLOCKING = "blocking"
    WARNING = "warning"


class Invariant:
    """Définition d'un invariant de sécurité."""

    def __init__(self, id: str, rule: str, severity: Severity = Severity.BLOCKING):
        self.id = id
        self.rule = rule
        self.severity = severity

    def __repr__(self) -> str:
        return f"Invariant({self.id})"


# ══════════════════════════════════════════════════════════════════════════════
# PROVISIONING (PROV_001-023) - 13 règles
# ══════════════════════════════════════════════════════════════════════════════

PROV_001 = Invariant("PROV_001", "Chaque site DOIT avoir un IAM User dédié")
PROV_002 = Invariant("PROV_002", "Credentials générés automatiquement")
PROV_003 = Invariant("PROV_003", "Credentials JAMAIS transmis en clair")
PROV_004 = Invariant("PROV_004", "Recovery keys dans AWS Secrets Manager")
PROV_005 = Invariant("PROV_005", "Première connexion force changement credentials")
PROV_010 = Invariant("PROV_010", "Vault avec KMS auto-unseal")
PROV_011 = Invariant("PROV_011", "Recovery keys threshold 3/5 minimum")
PROV_012 = Invariant("PROV_012", "Root token révoqué après setup")
PROV_013 = Invariant("PROV_013", "Policies Vault depuis config")
PROV_020 = Invariant("PROV_020", "Provisioning ancré blockchain")
PROV_021 = Invariant("PROV_021", "Auto-enregistrement Fleet Manager")
PROV_022 = Invariant("PROV_022", "Healthcheck avant activation licence")
PROV_023 = Invariant("PROV_023", "Package déploiement signé")

# ══════════════════════════════════════════════════════════════════════════════
# DEPLOYMENT (DEPL_001-033) - 33 règles
# ══════════════════════════════════════════════════════════════════════════════

DEPL_001 = Invariant("DEPL_001", "Images Docker signées Cosign")
DEPL_002 = Invariant("DEPL_002", "Vérification signature avant exécution")
DEPL_003 = Invariant("DEPL_003", "Registry privé uniquement")
DEPL_004 = Invariant("DEPL_004", "Scan CVE avant déploiement")
DEPL_005 = Invariant("DEPL_005", "CVE critique bloque déploiement")
DEPL_010 = Invariant("DEPL_010", "Déploiement standby-first obligatoire")
DEPL_011 = Invariant("DEPL_011", "Healthcheck avant bascule")
DEPL_012 = Invariant("DEPL_012", "Rollback auto si healthcheck échoue < 60s")
DEPL_013 = Invariant("DEPL_013", "Zero-downtime obligatoire")
DEPL_014 = Invariant("DEPL_014", "Déploiement progressif")
DEPL_020 = Invariant("DEPL_020", "Config validée avant déploiement")
DEPL_021 = Invariant("DEPL_021", "Config signée quorum atteint")
DEPL_022 = Invariant("DEPL_022", "Config ancrée blockchain")
DEPL_023 = Invariant("DEPL_023", "Hash config vérifié chaque noeud")
DEPL_024 = Invariant("DEPL_024", "Ancienne config archivée jamais supprimée")
DEPL_030 = Invariant("DEPL_030", "Fenêtre maintenance respectée", Severity.WARNING)
DEPL_031 = Invariant("DEPL_031", "Bloqué si licence invalide")
DEPL_032 = Invariant("DEPL_032", "Bloqué si cluster non-healthy")
DEPL_033 = Invariant("DEPL_033", "Notification Fleet Manager")

# ══════════════════════════════════════════════════════════════════════════════
# RUNTIME (RUN_001-062) - 62 règles
# ══════════════════════════════════════════════════════════════════════════════

# Isolation
RUN_001 = Invariant("RUN_001", "Chaque niveau hiérarchique DOIT avoir policy RLS")
RUN_002 = Invariant("RUN_002", "Tenant ne voit JAMAIS données autre tenant")
RUN_003 = Invariant("RUN_003", "Enfant ne voit pas données parent")
RUN_004 = Invariant("RUN_004", "Toute requête passe par contexte tenant")

# Authentification
RUN_010 = Invariant("RUN_010", "Authentification Keycloak OBLIGATOIRE")
RUN_011 = Invariant("RUN_011", "JWT expiration MAX 15 minutes")
RUN_012 = Invariant("RUN_012", "Refresh token MAX 24 heures")
RUN_013 = Invariant("RUN_013", "MFA pour permissions élevées")
RUN_014 = Invariant("RUN_014", "Session révocable à distance")

# Permissions
RUN_020 = Invariant("RUN_020", "Rôle niveau N ne peut avoir permissions N-1")
RUN_021 = Invariant("RUN_021", "Wildcard interdit sauf Platform")
RUN_022 = Invariant("RUN_022", "Permissions élevées requièrent quorum")
RUN_023 = Invariant("RUN_023", "Durée permissions élevées limitée")

# Cryptographie
RUN_030 = Invariant("RUN_030", "ECDSA-P384 minimum")
RUN_031 = Invariant("RUN_031", "SHA-384 minimum")
RUN_032 = Invariant("RUN_032", "TLS 1.3 obligatoire")
RUN_033 = Invariant("RUN_033", "Secrets JAMAIS en clair")
RUN_034 = Invariant("RUN_034", "Rotation clés annuelle")

# Audit
RUN_040 = Invariant("RUN_040", "Toute action génère événement audit")
RUN_041 = Invariant("RUN_041", "Actions critiques vers blockchain")
RUN_042 = Invariant("RUN_042", "Événements audit immuables")
RUN_043 = Invariant("RUN_043", "Rétention audit 10 ans")
RUN_044 = Invariant("RUN_044", "Logs signés cryptographiquement")

# Haute Disponibilité
RUN_050 = Invariant("RUN_050", "Cluster minimum 2 noeuds")
RUN_051 = Invariant("RUN_051", "Failover < 10 secondes")
RUN_052 = Invariant("RUN_052", "Mode dégradé si Cloud offline")
RUN_053 = Invariant("RUN_053", "Cache config local TTL 7 jours")

# ══════════════════════════════════════════════════════════════════════════════
# MAINTENANCE (MAINT_001-063) - 63 règles
# ══════════════════════════════════════════════════════════════════════════════

# Monitoring
MAINT_001 = Invariant("MAINT_001", "Heartbeat vers Fleet Manager 60s")
MAINT_002 = Invariant("MAINT_002", "Alerte si heartbeat manquant > 2min")
MAINT_003 = Invariant("MAINT_003", "Métriques Prometheus exposées")
MAINT_004 = Invariant("MAINT_004", "Dashboards Grafana accessibles")
MAINT_005 = Invariant("MAINT_005", "Alertes multi-canal")

# Backup
MAINT_010 = Invariant("MAINT_010", "Backup quotidien automatique")
MAINT_011 = Invariant("MAINT_011", "Backup chiffré GPG")
MAINT_012 = Invariant("MAINT_012", "Backup stocké hors-site")
MAINT_013 = Invariant("MAINT_013", "Rétention backup 90 jours")
MAINT_014 = Invariant("MAINT_014", "Test restore mensuel")
MAINT_015 = Invariant("MAINT_015", "RPO < 1 heure")
MAINT_016 = Invariant("MAINT_016", "RTO < 10 minutes")

# Rotation secrets
MAINT_020 = Invariant("MAINT_020", "Rotation KMS annuelle")
MAINT_021 = Invariant("MAINT_021", "Rotation credentials DB trimestrielle")
MAINT_022 = Invariant("MAINT_022", "Rotation TLS avant expiration")
MAINT_023 = Invariant("MAINT_023", "Rotation API keys sur incident")
MAINT_024 = Invariant("MAINT_024", "Ancienne clé conservée 30 jours")

# Patch sécurité
MAINT_030 = Invariant("MAINT_030", "Scan CVE quotidien")
MAINT_031 = Invariant("MAINT_031", "CVE critique patch < 24h")
MAINT_032 = Invariant("MAINT_032", "CVE haute patch < 7 jours")
MAINT_033 = Invariant("MAINT_033", "CVE moyenne patch < 30 jours")
MAINT_034 = Invariant("MAINT_034", "OS updates auto sécurité")
MAINT_035 = Invariant("MAINT_035", "Audit dépendances Dependabot")

# Logs
MAINT_040 = Invariant("MAINT_040", "Logs centralisés 90 jours")
MAINT_041 = Invariant("MAINT_041", "Logs archivés 10 ans")
MAINT_042 = Invariant("MAINT_042", "Logs compressés après 7 jours")
MAINT_043 = Invariant("MAINT_043", "Intégrité logs vérifiable")

# Capacité
MAINT_050 = Invariant("MAINT_050", "Alerte disque > 80%", Severity.WARNING)
MAINT_051 = Invariant("MAINT_051", "Alerte RAM > 90%", Severity.WARNING)
MAINT_052 = Invariant("MAINT_052", "Alerte CPU > 80% 5min", Severity.WARNING)
MAINT_053 = Invariant("MAINT_053", "Alerte latence API > 500ms", Severity.WARNING)
MAINT_054 = Invariant("MAINT_054", "Auto-scaling si supporté", Severity.WARNING)

# Documentation
MAINT_060 = Invariant("MAINT_060", "Runbook opérationnel obligatoire")
MAINT_061 = Invariant("MAINT_061", "DR testé trimestriellement")
MAINT_062 = Invariant("MAINT_062", "Changelog automatique")
MAINT_063 = Invariant("MAINT_063", "Post-mortem incidents majeurs")

# ══════════════════════════════════════════════════════════════════════════════
# LICENSING (LIC_001-104) - 104 règles
# ══════════════════════════════════════════════════════════════════════════════

# Structure
LIC_001 = Invariant("LIC_001", "Licence signée ECDSA-P384")
LIC_002 = Invariant("LIC_002", "Contenu obligatoire site_id org_id dates modules")
LIC_003 = Invariant("LIC_003", "Durée maximale 366 jours")
LIC_004 = Invariant("LIC_004", "Émission ancrée blockchain")
LIC_005 = Invariant("LIC_005", "Une licence = un site")
LIC_006 = Invariant("LIC_006", "Émission par License Manager Cloud uniquement")

# Validation
LIC_010 = Invariant("LIC_010", "Validation signature au démarrage")
LIC_011 = Invariant("LIC_011", "Validation toutes les 60 secondes")
LIC_012 = Invariant("LIC_012", "Invalide = kill switch immédiat")
LIC_013 = Invariant("LIC_013", "Altérée = alerte CRITICAL + kill switch")
LIC_014 = Invariant("LIC_014", "Vérification online toutes les 6h")
LIC_015 = Invariant("LIC_015", "Réponse License Manager signée")

# Cache
LIC_020 = Invariant("LIC_020", "Cache local obligatoire")
LIC_021 = Invariant("LIC_021", "Cache TTL max 7 jours")
LIC_022 = Invariant("LIC_022", "Cache chiffré Vault")
LIC_023 = Invariant("LIC_023", "Hash vérifié chaque lecture")
LIC_024 = Invariant("LIC_024", "Cloud offline > 7j = kill switch")

# Alertes
LIC_030 = Invariant("LIC_030", "Alerte J-60")
LIC_031 = Invariant("LIC_031", "Alerte J-30")
LIC_032 = Invariant("LIC_032", "Alerte J-14")
LIC_033 = Invariant("LIC_033", "Alerte J-7")
LIC_034 = Invariant("LIC_034", "Alerte J-1")
LIC_035 = Invariant("LIC_035", "Alertes non désactivables")

# Expiration
LIC_040 = Invariant("LIC_040", "Expirée = mode dégradé")
LIC_041 = Invariant("LIC_041", "Mode dégradé = lecture seule")
LIC_042 = Invariant("LIC_042", "Écritures bloquées")
LIC_043 = Invariant("LIC_043", "Alerte permanente dashboard")
LIC_044 = Invariant("LIC_044", "Grace period expirée = kill switch")
LIC_045 = Invariant("LIC_045", "Expiration ancrée blockchain")

# Renouvellement
LIC_050 = Invariant("LIC_050", "Renouvellement = nouvelle licence")
LIC_051 = Invariant("LIC_051", "Nouvelle licence signée + blockchain")
LIC_052 = Invariant("LIC_052", "Injection via Sync License")
LIC_053 = Invariant("LIC_053", "Ancienne archivée")
LIC_054 = Invariant("LIC_054", "Renouvellement après expiration OK")
LIC_055 = Invariant("LIC_055", "Réactivation healthcheck d'abord")

# Révocation
LIC_060 = Invariant("LIC_060", "Révocation explicite")
LIC_061 = Invariant("LIC_061", "Révocation requiert quorum")
LIC_062 = Invariant("LIC_062", "Push < 60 secondes")
LIC_063 = Invariant("LIC_063", "Kill switch immédiat")
LIC_064 = Invariant("LIC_064", "Révocation ancrée blockchain")
LIC_065 = Invariant("LIC_065", "Notification tous canaux")
LIC_066 = Invariant("LIC_066", "Raison obligatoire")

# Kill Switch
LIC_070 = Invariant("LIC_070", "Arrêt contrôlé tous services")
LIC_071 = Invariant("LIC_071", "Données préservées")
LIC_072 = Invariant("LIC_072", "Logs audit préservés")
LIC_073 = Invariant("LIC_073", "Monitoring maintenu")
LIC_074 = Invariant("LIC_074", "Message explicite dashboard")
LIC_075 = Invariant("LIC_075", "Réversible par nouvelle licence")
LIC_076 = Invariant("LIC_076", "Kill switch ancré blockchain")
LIC_077 = Invariant("LIC_077", "Contournement = alerte CRITICAL")

# Modules
LIC_080 = Invariant("LIC_080", "Modules en liste blanche")
LIC_081 = Invariant("LIC_081", "Module non licencié = 403")
LIC_082 = Invariant("LIC_082", "UI masque fonctionnalité")
LIC_083 = Invariant("LIC_083", "Tentative accès = audit")
LIC_084 = Invariant("LIC_084", "Upgrade = nouvelle licence")
LIC_085 = Invariant("LIC_085", "Downgrade = nouvelle licence")

# Audit
LIC_090 = Invariant("LIC_090", "Tout événement licence = audit")
LIC_091 = Invariant("LIC_091", "Critiques = blockchain")
LIC_092 = Invariant("LIC_092", "Historique jamais purgé")
LIC_093 = Invariant("LIC_093", "Dashboard temps réel")
LIC_094 = Invariant("LIC_094", "Export audit compliance")

# Anti-fraude
LIC_100 = Invariant("LIC_100", "Licence liée site_id unique")
LIC_101 = Invariant("LIC_101", "Hardware fingerprint H2+", Severity.WARNING)
LIC_102 = Invariant("LIC_102", "Clonage = révocation + alerte")
LIC_103 = Invariant("LIC_103", "Horloge vérifiée")
LIC_104 = Invariant("LIC_104", "Drift horloge > 5min = dégradé")

# ══════════════════════════════════════════════════════════════════════════════
# DECOMMISSIONING (DECOM_001-033) - 33 règles
# ══════════════════════════════════════════════════════════════════════════════

DECOM_001 = Invariant("DECOM_001", "Révocation licence avant décom")
DECOM_002 = Invariant("DECOM_002", "Kill switch activé")
DECOM_003 = Invariant("DECOM_003", "IAM révoqués")
DECOM_004 = Invariant("DECOM_004", "Sessions Keycloak révoquées")
DECOM_005 = Invariant("DECOM_005", "Certificats révoqués CRL")
DECOM_010 = Invariant("DECOM_010", "Backup final obligatoire")
DECOM_011 = Invariant("DECOM_011", "Données exportées si demandé")
DECOM_012 = Invariant("DECOM_012", "Logs archivés 10 ans")
DECOM_013 = Invariant("DECOM_013", "Décom ancré blockchain")
DECOM_020 = Invariant("DECOM_020", "Suppression sécurisée")
DECOM_021 = Invariant("DECOM_021", "Secrets Vault purgés")
DECOM_022 = Invariant("DECOM_022", "Destruction clé = inaccessible")
DECOM_023 = Invariant("DECOM_023", "Certificat destruction")
DECOM_030 = Invariant("DECOM_030", "IAM User supprimé")
DECOM_031 = Invariant("DECOM_031", "Ressources cloud nettoyées")
DECOM_032 = Invariant("DECOM_032", "DNS supprimés")
DECOM_033 = Invariant("DECOM_033", "Retrait Fleet Manager")

# ══════════════════════════════════════════════════════════════════════════════
# MIGRATION (MIGR_001-010) - 10 règles
# ══════════════════════════════════════════════════════════════════════════════

MIGR_001 = Invariant("MIGR_001", "Migration réversible")
MIGR_002 = Invariant("MIGR_002", "Backup avant migration")
MIGR_003 = Invariant("MIGR_003", "Migration sur standby d'abord")
MIGR_004 = Invariant("MIGR_004", "Validation post-migration")
MIGR_005 = Invariant("MIGR_005", "Échec = rollback auto")
MIGR_006 = Invariant("MIGR_006", "Scripts versionnés")
MIGR_007 = Invariant("MIGR_007", "Migration ancrée blockchain")
MIGR_008 = Invariant("MIGR_008", "Downtime documenté")
MIGR_009 = Invariant("MIGR_009", "Test sur zynaxia_test d'abord")
MIGR_010 = Invariant("MIGR_010", "Anciennes données archivées")

# ══════════════════════════════════════════════════════════════════════════════
# API COMPATIBILITY (API_001-008) - 8 règles
# ══════════════════════════════════════════════════════════════════════════════

API_001 = Invariant("API_001", "Version dans URL /api/vN/")
API_002 = Invariant("API_002", "Support N-1 backward compatible")
API_003 = Invariant("API_003", "Dépréciation 6 mois minimum")
API_004 = Invariant("API_004", "Header X-API-Version")
API_005 = Invariant("API_005", "Changelog documenté")
API_006 = Invariant("API_006", "Breaking change = version majeure")
API_007 = Invariant("API_007", "Edge compatible Cloud N+-1")
API_008 = Invariant("API_008", "Incompatibilité = alerte pas crash")

# ══════════════════════════════════════════════════════════════════════════════
# INCIDENT RESPONSE (INCID_001-011) - 11 règles
# ══════════════════════════════════════════════════════════════════════════════

INCID_001 = Invariant("INCID_001", "Intrusion = alerte immédiate")
INCID_002 = Invariant("INCID_002", "Accès non autorisé = log + alerte")
INCID_003 = Invariant("INCID_003", "3 échecs auth = verrouillage 15min")
INCID_004 = Invariant("INCID_004", "Activité DB anormale = alerte")
INCID_005 = Invariant("INCID_005", "Breach = isolation tenant")
INCID_006 = Invariant("INCID_006", "Breach = notification RSSI < 1h")
INCID_007 = Invariant("INCID_007", "Breach = révocation tokens")
INCID_008 = Invariant("INCID_008", "Breach = snapshot forensics")
INCID_009 = Invariant("INCID_009", "Post-incident < 72h RGPD")
INCID_010 = Invariant("INCID_010", "Incident ancré blockchain")
INCID_011 = Invariant("INCID_011", "Procédure testée trimestriellement")

# ══════════════════════════════════════════════════════════════════════════════
# OBSERVABILITY (OBS_001-007) - 7 règles
# ══════════════════════════════════════════════════════════════════════════════

OBS_001 = Invariant("OBS_001", "correlation_id unique par requête")
OBS_002 = Invariant("OBS_002", "correlation_id propagé partout")
OBS_003 = Invariant("OBS_003", "correlation_id dans tous logs")
OBS_004 = Invariant("OBS_004", "Format OpenTelemetry")
OBS_005 = Invariant("OBS_005", "Retention traces 30 jours")
OBS_006 = Invariant("OBS_006", "Latence spans mesurée")
OBS_007 = Invariant("OBS_007", "Erreurs avec stack trace")

# ══════════════════════════════════════════════════════════════════════════════
# NETWORK (NET_001-008) - 8 règles
# ══════════════════════════════════════════════════════════════════════════════

NET_001 = Invariant("NET_001", "Timeout connexion 10s")
NET_002 = Invariant("NET_002", "Timeout requête 30s")
NET_003 = Invariant("NET_003", "Retry 3x backoff exponentiel")
NET_004 = Invariant("NET_004", "Circuit breaker après 5 échecs")
NET_005 = Invariant("NET_005", "Half-open après 30s")
NET_006 = Invariant("NET_006", "Cloud perdu = mode dégradé")
NET_007 = Invariant("NET_007", "Reconnexion auto backoff")
NET_008 = Invariant("NET_008", "Keep-alive TCP activé")

# ══════════════════════════════════════════════════════════════════════════════
# RATE LIMITING (RATE_001-007) - 7 règles
# ══════════════════════════════════════════════════════════════════════════════

RATE_001 = Invariant("RATE_001", "Rate limit par tenant")
RATE_002 = Invariant("RATE_002", "Configurable par endpoint")
RATE_003 = Invariant("RATE_003", "Dépassement = 429")
RATE_004 = Invariant("RATE_004", "Rate limit loggé")
RATE_005 = Invariant("RATE_005", "Burst 2x 10 secondes")
RATE_006 = Invariant("RATE_006", "Auth 10 req/min/IP")
RATE_007 = Invariant("RATE_007", "Standard 100 req/min/tenant")

# ══════════════════════════════════════════════════════════════════════════════
# LOGGING (LOG_001-007) - 7 règles
# ══════════════════════════════════════════════════════════════════════════════

LOG_001 = Invariant("LOG_001", "Format JSON structuré")
LOG_002 = Invariant("LOG_002", "Champs timestamp level correlation_id tenant_id message")
LOG_003 = Invariant("LOG_003", "Timestamp ISO 8601 UTC")
LOG_004 = Invariant("LOG_004", "Niveaux DEBUG INFO WARN ERROR CRITICAL")
LOG_005 = Invariant("LOG_005", "Données sensibles masquées")
LOG_006 = Invariant("LOG_006", "Rotation automatique")
LOG_007 = Invariant("LOG_007", "ERROR CRITICAL = alerte auto")

# ══════════════════════════════════════════════════════════════════════════════
# HEALTH CHECKS (HEALTH_001-008) - 8 règles
# ══════════════════════════════════════════════════════════════════════════════

HEALTH_001 = Invariant("HEALTH_001", "/health obligatoire")
HEALTH_002 = Invariant("HEALTH_002", "/health/live liveness")
HEALTH_003 = Invariant("HEALTH_003", "/health/ready readiness")
HEALTH_004 = Invariant("HEALTH_004", "Format JSON status checks timestamp")
HEALTH_005 = Invariant("HEALTH_005", "Checks db vault keycloak disk memory")
HEALTH_006 = Invariant("HEALTH_006", "Status healthy degraded unhealthy")
HEALTH_007 = Invariant("HEALTH_007", "Unhealthy = plus de trafic")
HEALTH_008 = Invariant("HEALTH_008", "Health check < 5s timeout")

# ══════════════════════════════════════════════════════════════════════════════
# TIME SYNC (TIME_001-008) - 8 règles
# ══════════════════════════════════════════════════════════════════════════════

TIME_001 = Invariant("TIME_001", "NTP obligatoire")
TIME_002 = Invariant("TIME_002", "Serveurs NTP FR/EU")
TIME_003 = Invariant("TIME_003", "Drift max 1 seconde")
TIME_004 = Invariant("TIME_004", "Drift > 1s = WARNING", Severity.WARNING)
TIME_005 = Invariant("TIME_005", "Drift > 5s = CRITICAL + dégradé")
TIME_006 = Invariant("TIME_006", "Timestamps UTC")
TIME_007 = Invariant("TIME_007", "Vérification au démarrage")
TIME_008 = Invariant("TIME_008", "Vérification horaire")


# ══════════════════════════════════════════════════════════════════════════════
# COLLECTION COMPLÈTE
# ══════════════════════════════════════════════════════════════════════════════

ALL_INVARIANTS: Final[dict[str, Invariant]] = {
    # PROV (13)
    "PROV_001": PROV_001,
    "PROV_002": PROV_002,
    "PROV_003": PROV_003,
    "PROV_004": PROV_004,
    "PROV_005": PROV_005,
    "PROV_010": PROV_010,
    "PROV_011": PROV_011,
    "PROV_012": PROV_012,
    "PROV_013": PROV_013,
    "PROV_020": PROV_020,
    "PROV_021": PROV_021,
    "PROV_022": PROV_022,
    "PROV_023": PROV_023,
    # DEPL (19)
    "DEPL_001": DEPL_001,
    "DEPL_002": DEPL_002,
    "DEPL_003": DEPL_003,
    "DEPL_004": DEPL_004,
    "DEPL_005": DEPL_005,
    "DEPL_010": DEPL_010,
    "DEPL_011": DEPL_011,
    "DEPL_012": DEPL_012,
    "DEPL_013": DEPL_013,
    "DEPL_014": DEPL_014,
    "DEPL_020": DEPL_020,
    "DEPL_021": DEPL_021,
    "DEPL_022": DEPL_022,
    "DEPL_023": DEPL_023,
    "DEPL_024": DEPL_024,
    "DEPL_030": DEPL_030,
    "DEPL_031": DEPL_031,
    "DEPL_032": DEPL_032,
    "DEPL_033": DEPL_033,
    # RUN (27)
    "RUN_001": RUN_001,
    "RUN_002": RUN_002,
    "RUN_003": RUN_003,
    "RUN_004": RUN_004,
    "RUN_010": RUN_010,
    "RUN_011": RUN_011,
    "RUN_012": RUN_012,
    "RUN_013": RUN_013,
    "RUN_014": RUN_014,
    "RUN_020": RUN_020,
    "RUN_021": RUN_021,
    "RUN_022": RUN_022,
    "RUN_023": RUN_023,
    "RUN_030": RUN_030,
    "RUN_031": RUN_031,
    "RUN_032": RUN_032,
    "RUN_033": RUN_033,
    "RUN_034": RUN_034,
    "RUN_040": RUN_040,
    "RUN_041": RUN_041,
    "RUN_042": RUN_042,
    "RUN_043": RUN_043,
    "RUN_044": RUN_044,
    "RUN_050": RUN_050,
    "RUN_051": RUN_051,
    "RUN_052": RUN_052,
    "RUN_053": RUN_053,
    # MAINT (38)
    "MAINT_001": MAINT_001,
    "MAINT_002": MAINT_002,
    "MAINT_003": MAINT_003,
    "MAINT_004": MAINT_004,
    "MAINT_005": MAINT_005,
    "MAINT_010": MAINT_010,
    "MAINT_011": MAINT_011,
    "MAINT_012": MAINT_012,
    "MAINT_013": MAINT_013,
    "MAINT_014": MAINT_014,
    "MAINT_015": MAINT_015,
    "MAINT_016": MAINT_016,
    "MAINT_020": MAINT_020,
    "MAINT_021": MAINT_021,
    "MAINT_022": MAINT_022,
    "MAINT_023": MAINT_023,
    "MAINT_024": MAINT_024,
    "MAINT_030": MAINT_030,
    "MAINT_031": MAINT_031,
    "MAINT_032": MAINT_032,
    "MAINT_033": MAINT_033,
    "MAINT_034": MAINT_034,
    "MAINT_035": MAINT_035,
    "MAINT_040": MAINT_040,
    "MAINT_041": MAINT_041,
    "MAINT_042": MAINT_042,
    "MAINT_043": MAINT_043,
    "MAINT_050": MAINT_050,
    "MAINT_051": MAINT_051,
    "MAINT_052": MAINT_052,
    "MAINT_053": MAINT_053,
    "MAINT_054": MAINT_054,
    "MAINT_060": MAINT_060,
    "MAINT_061": MAINT_061,
    "MAINT_062": MAINT_062,
    "MAINT_063": MAINT_063,
    # LIC (66)
    "LIC_001": LIC_001,
    "LIC_002": LIC_002,
    "LIC_003": LIC_003,
    "LIC_004": LIC_004,
    "LIC_005": LIC_005,
    "LIC_006": LIC_006,
    "LIC_010": LIC_010,
    "LIC_011": LIC_011,
    "LIC_012": LIC_012,
    "LIC_013": LIC_013,
    "LIC_014": LIC_014,
    "LIC_015": LIC_015,
    "LIC_020": LIC_020,
    "LIC_021": LIC_021,
    "LIC_022": LIC_022,
    "LIC_023": LIC_023,
    "LIC_024": LIC_024,
    "LIC_030": LIC_030,
    "LIC_031": LIC_031,
    "LIC_032": LIC_032,
    "LIC_033": LIC_033,
    "LIC_034": LIC_034,
    "LIC_035": LIC_035,
    "LIC_040": LIC_040,
    "LIC_041": LIC_041,
    "LIC_042": LIC_042,
    "LIC_043": LIC_043,
    "LIC_044": LIC_044,
    "LIC_045": LIC_045,
    "LIC_050": LIC_050,
    "LIC_051": LIC_051,
    "LIC_052": LIC_052,
    "LIC_053": LIC_053,
    "LIC_054": LIC_054,
    "LIC_055": LIC_055,
    "LIC_060": LIC_060,
    "LIC_061": LIC_061,
    "LIC_062": LIC_062,
    "LIC_063": LIC_063,
    "LIC_064": LIC_064,
    "LIC_065": LIC_065,
    "LIC_066": LIC_066,
    "LIC_070": LIC_070,
    "LIC_071": LIC_071,
    "LIC_072": LIC_072,
    "LIC_073": LIC_073,
    "LIC_074": LIC_074,
    "LIC_075": LIC_075,
    "LIC_076": LIC_076,
    "LIC_077": LIC_077,
    "LIC_080": LIC_080,
    "LIC_081": LIC_081,
    "LIC_082": LIC_082,
    "LIC_083": LIC_083,
    "LIC_084": LIC_084,
    "LIC_085": LIC_085,
    "LIC_090": LIC_090,
    "LIC_091": LIC_091,
    "LIC_092": LIC_092,
    "LIC_093": LIC_093,
    "LIC_094": LIC_094,
    "LIC_100": LIC_100,
    "LIC_101": LIC_101,
    "LIC_102": LIC_102,
    "LIC_103": LIC_103,
    "LIC_104": LIC_104,
    # DECOM (17)
    "DECOM_001": DECOM_001,
    "DECOM_002": DECOM_002,
    "DECOM_003": DECOM_003,
    "DECOM_004": DECOM_004,
    "DECOM_005": DECOM_005,
    "DECOM_010": DECOM_010,
    "DECOM_011": DECOM_011,
    "DECOM_012": DECOM_012,
    "DECOM_013": DECOM_013,
    "DECOM_020": DECOM_020,
    "DECOM_021": DECOM_021,
    "DECOM_022": DECOM_022,
    "DECOM_023": DECOM_023,
    "DECOM_030": DECOM_030,
    "DECOM_031": DECOM_031,
    "DECOM_032": DECOM_032,
    "DECOM_033": DECOM_033,
    # MIGR (10)
    "MIGR_001": MIGR_001,
    "MIGR_002": MIGR_002,
    "MIGR_003": MIGR_003,
    "MIGR_004": MIGR_004,
    "MIGR_005": MIGR_005,
    "MIGR_006": MIGR_006,
    "MIGR_007": MIGR_007,
    "MIGR_008": MIGR_008,
    "MIGR_009": MIGR_009,
    "MIGR_010": MIGR_010,
    # API (8)
    "API_001": API_001,
    "API_002": API_002,
    "API_003": API_003,
    "API_004": API_004,
    "API_005": API_005,
    "API_006": API_006,
    "API_007": API_007,
    "API_008": API_008,
    # INCID (11)
    "INCID_001": INCID_001,
    "INCID_002": INCID_002,
    "INCID_003": INCID_003,
    "INCID_004": INCID_004,
    "INCID_005": INCID_005,
    "INCID_006": INCID_006,
    "INCID_007": INCID_007,
    "INCID_008": INCID_008,
    "INCID_009": INCID_009,
    "INCID_010": INCID_010,
    "INCID_011": INCID_011,
    # OBS (7)
    "OBS_001": OBS_001,
    "OBS_002": OBS_002,
    "OBS_003": OBS_003,
    "OBS_004": OBS_004,
    "OBS_005": OBS_005,
    "OBS_006": OBS_006,
    "OBS_007": OBS_007,
    # NET (8)
    "NET_001": NET_001,
    "NET_002": NET_002,
    "NET_003": NET_003,
    "NET_004": NET_004,
    "NET_005": NET_005,
    "NET_006": NET_006,
    "NET_007": NET_007,
    "NET_008": NET_008,
    # RATE (7)
    "RATE_001": RATE_001,
    "RATE_002": RATE_002,
    "RATE_003": RATE_003,
    "RATE_004": RATE_004,
    "RATE_005": RATE_005,
    "RATE_006": RATE_006,
    "RATE_007": RATE_007,
    # LOG (7)
    "LOG_001": LOG_001,
    "LOG_002": LOG_002,
    "LOG_003": LOG_003,
    "LOG_004": LOG_004,
    "LOG_005": LOG_005,
    "LOG_006": LOG_006,
    "LOG_007": LOG_007,
    # HEALTH (8)
    "HEALTH_001": HEALTH_001,
    "HEALTH_002": HEALTH_002,
    "HEALTH_003": HEALTH_003,
    "HEALTH_004": HEALTH_004,
    "HEALTH_005": HEALTH_005,
    "HEALTH_006": HEALTH_006,
    "HEALTH_007": HEALTH_007,
    "HEALTH_008": HEALTH_008,
    # TIME (8)
    "TIME_001": TIME_001,
    "TIME_002": TIME_002,
    "TIME_003": TIME_003,
    "TIME_004": TIME_004,
    "TIME_005": TIME_005,
    "TIME_006": TIME_006,
    "TIME_007": TIME_007,
    "TIME_008": TIME_008,
}

# Comptage attendu par section
EXPECTED_COUNTS: Final[dict[str, int]] = {
    "PROV": 13,
    "DEPL": 19,
    "RUN": 27,
    "MAINT": 36,
    "LIC": 66,
    "DECOM": 17,
    "MIGR": 10,
    "API": 8,
    "INCID": 11,
    "OBS": 7,
    "NET": 8,
    "RATE": 7,
    "LOG": 7,
    "HEALTH": 8,
    "TIME": 8,
}

TOTAL_INVARIANTS: Final[int] = len(ALL_INVARIANTS)
