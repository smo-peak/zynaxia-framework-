#!/usr/bin/env python3
"""
ZYNAXIA Framework - Reset Test Database
Conformité: Isolation tests/prod, RUN_033
"""

import subprocess
import json
import os
import sys

VAULT_ADDR = "http://127.0.0.1:8200"

def get_vault_secret(path: str, vault_token: str) -> dict:
    """Récupère un secret depuis Vault Edge."""
    result = subprocess.run([
        "docker", "exec",
        "-e", f"VAULT_ADDR={VAULT_ADDR}",
        "-e", f"VAULT_TOKEN={vault_token}",
        "zynaxia-edge-vault",
        "vault", "kv", "get", "-format=json", path
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        raise Exception(f"Vault error: {result.stderr}")
    
    return json.loads(result.stdout)["data"]["data"]

def run_sql(sql: str, creds: dict) -> str:
    """Exécute SQL sur PostgreSQL Edge."""
    result = subprocess.run([
        "docker", "exec",
        "-e", f"PGPASSWORD={creds['password']}",
        "zynaxia-edge-postgres",
        "psql", "-U", creds["username"], "-d", creds["database"], "-c", sql
    ], capture_output=True, text=True)
    
    return result.stdout + result.stderr

def main():
    print("=== RESET TEST DATABASE ===\n")
    
    # Token depuis env ou input
    vault_token = os.environ.get("VAULT_TOKEN")
    if not vault_token:
        vault_token = input("VAULT_TOKEN: ").strip()
    
    # Récupérer credentials test
    print("Récupération credentials depuis Vault...")
    creds = get_vault_secret("secret/edge/postgres-test", vault_token)
    print(f"✓ User: {creds['username']}, DB: {creds['database']}")
    
    # Reset tables
    print("\nReset tables...")
    
    sql = """
    -- Drop all tables in public schema
    DO $$ 
    DECLARE r RECORD;
    BEGIN
        FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public') 
        LOOP
            EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE';
        END LOOP;
    END $$;
    
    SELECT 'Database reset complete' AS status;
    """
    
    output = run_sql(sql, creds)
    print(output)
    
    print("=== RESET TERMINÉ ===")

if __name__ == "__main__":
    main()
