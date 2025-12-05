#!/bin/bash
set -e

echo "=== ROTATION CREDENTIALS POSTGRESQL ==="
echo ""
echo -n "VAULT_TOKEN: "
read -s VAULT_TOKEN
echo ""
export VAULT_TOKEN

NEW_PASSWORD=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32)

source ~/agentic-ai-platform/.env
docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" zynaxia-edge-postgres \
  psql -U zynaxia -d zynaxia -c "ALTER ROLE zynaxia_app WITH PASSWORD '$NEW_PASSWORD';" > /dev/null 2>&1

echo "✓ PostgreSQL mis à jour"

docker exec -e VAULT_ADDR="http://127.0.0.1:8200" -e VAULT_TOKEN="$VAULT_TOKEN" \
  zynaxia-edge-vault vault kv put secret/edge/postgres \
  username='zynaxia_app' \
  password="$NEW_PASSWORD" \
  database='zynaxia' \
  host='zynaxia-edge-postgres' \
  port='5432' > /dev/null 2>&1

echo "✓ Vault mis à jour"

unset NEW_PASSWORD VAULT_TOKEN POSTGRES_PASSWORD

echo ""
echo "=== ROTATION TERMINÉE ==="
