#!/bin/bash
# ============================================================================
# ZYNAXIA FRAMEWORK - Test Intégration RLS (LOT 2)
# Conformité : RUN_001, RUN_002, RUN_004, ANSSI
# ============================================================================

set -e

echo "=== TEST RLS INTEGRATION (LOT 2) ==="
echo ""
echo -n "VAULT_TOKEN: "
read -s VAULT_TOKEN
echo ""

# Récupérer credentials depuis Vault
CREDS=$(docker exec -e VAULT_ADDR="http://127.0.0.1:8200" -e VAULT_TOKEN="$VAULT_TOKEN" \
  zynaxia-edge-vault vault kv get -format=json secret/edge/postgres)

PGUSER=$(echo "$CREDS" | jq -r '.data.data.username')
PGPASSWORD=$(echo "$CREDS" | jq -r '.data.data.password')

echo "✓ Credentials récupérés (user: $PGUSER)"

# Vérifier non-superuser
IS_SUPER=$(docker exec -e PGPASSWORD="$PGPASSWORD" zynaxia-edge-postgres \
  psql -U "$PGUSER" -d zynaxia -t -c "SELECT usesuper FROM pg_user WHERE usename = '$PGUSER';")

if [[ "$IS_SUPER" == *"t"* ]]; then
  echo "✗ ERREUR: $PGUSER est superuser - RLS contourné!"
  exit 1
fi
echo "✓ User non-superuser (RLS actif)"

# Test RLS
echo ""
echo "--- Test Tenant A ---"
docker exec -e PGPASSWORD="$PGPASSWORD" zynaxia-edge-postgres \
  psql -U "$PGUSER" -d zynaxia -c "
SET app.tenant_id = '11111111-1111-1111-1111-111111111111';
SELECT * FROM test_rls;
"

echo "--- Test Tenant B ---"
docker exec -e PGPASSWORD="$PGPASSWORD" zynaxia-edge-postgres \
  psql -U "$PGUSER" -d zynaxia -c "
SET app.tenant_id = '22222222-2222-2222-2222-222222222222';
SELECT * FROM test_rls;
"

echo "--- Test Sans Contexte ---"
docker exec -e PGPASSWORD="$PGPASSWORD" zynaxia-edge-postgres \
  psql -U "$PGUSER" -d zynaxia -c "
RESET app.tenant_id;
SELECT * FROM test_rls;
" 2>&1 || echo "✓ Erreur attendue (contexte obligatoire)"

unset VAULT_TOKEN PGPASSWORD
echo ""
echo "=== TEST TERMINÉ ==="
