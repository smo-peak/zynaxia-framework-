#!/bin/bash
# ============================================================================
# ZYNAXIA - Migration Secrets vers Vault Edge (Industriel)
# ============================================================================
# Conformité : RUN_033, ANSSI, RGS 2★/3★
# Usage : ./migrate_secrets_to_vault.sh
# ============================================================================

set -e

echo "=== MIGRATION SECRETS VERS VAULT EDGE ==="
echo ""
echo -n "VAULT_TOKEN: "
read -s VAULT_TOKEN
echo ""
export VAULT_TOKEN

# Charger .env existant (source des secrets actuels)
source ~/agentic-ai-platform/.env

# Fonction pour stocker dans Vault
store_secret() {
    local path=$1
    shift
    docker exec -e VAULT_ADDR="http://127.0.0.1:8200" -e VAULT_TOKEN="$VAULT_TOKEN" \
      zynaxia-edge-vault vault kv put "$path" "$@" > /dev/null 2>&1
    echo "✓ $path"
}

echo ""
echo "--- Migration des secrets ---"

# 1. PostgreSQL Admin (superuser - DevOps only)
store_secret secret/edge/postgres-admin \
  username="$POSTGRES_USER" \
  password="$POSTGRES_PASSWORD" \
  database="$POSTGRES_DB" \
  host="zynaxia-edge-postgres" \
  port="5432" \
  usage="admin-devops-only"

# 2. Keycloak DB
store_secret secret/edge/keycloak-db \
  username="$KEYCLOAK_DB_USER" \
  password="$KEYCLOAK_DB_PASSWORD" \
  database="keycloak" \
  host="zynaxia-edge-postgres" \
  port="5432"

# 3. Keycloak Admin
store_secret secret/edge/keycloak-admin \
  username="$KEYCLOAK_ADMIN" \
  password="$KEYCLOAK_ADMIN_PASSWORD" \
  hostname="$KEYCLOAK_HOSTNAME"

# 4. Grafana Admin
store_secret secret/edge/grafana \
  username="$GRAFANA_ADMIN_USER" \
  password="$GRAFANA_ADMIN_PASSWORD"

# Nettoyage
unset VAULT_TOKEN POSTGRES_PASSWORD KEYCLOAK_DB_PASSWORD KEYCLOAK_ADMIN_PASSWORD GRAFANA_ADMIN_PASSWORD

echo ""
echo "=== MIGRATION TERMINÉE ==="
echo ""
echo "Secrets stockés dans Vault Edge :"
echo "  - secret/edge/postgres        (user applicatif)"
echo "  - secret/edge/postgres-admin  (superuser DevOps)"
echo "  - secret/edge/keycloak-db     (DB Keycloak)"
echo "  - secret/edge/keycloak-admin  (Admin Keycloak)"
echo "  - secret/edge/grafana         (Admin Grafana)"
echo ""
echo "⚠️  PROCHAINE ÉTAPE : Supprimer les secrets de .env"
