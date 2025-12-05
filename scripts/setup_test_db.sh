#!/usr/bin/env python3
"""ZYNAXIA Framework - Reset Test Database"""

import subprocess
import json
import os

VAULT_ADDR = "http://127.0.0.1:8200"

def get_vault_secret(path, vault_token):
    result = subprocess.run([
        "docker", "exec",
        "-e", "VAULT_ADDR=" + VAULT_ADDR,
        "-e", "VAULT_TOKEN=" + vault_token,
        "zynaxia-edge-vault",
        "vault", "kv", "get", "-format=json", path
    ], capture_output=True, text=True)
    if result.returncode != 0:
        raise Exception("Vault error: " + result.stderr)
    return json.loads(result.stdout)["data"]["data"]

def run_sql(sql, creds):
    result = subprocess.run([
        "docker", "exec",
        "-e", "PGPASSWORD=" + creds["password"],
        "zynaxia-edge-postgres",
        "psql", "-U", creds["username"], "-d", creds["database"], "-c", sql
    ], capture_output=True, text=True)
    return result.stdout + result.stderr

def main():
    print("=== RESET TEST DATABASE ===")
    vault_token = os.environ.get("VAULT_TOKEN") or input("VAULT_TOKEN: ").strip()
    
    print("Récupération credentials...")
    creds = get_vault_secret("secret/edge/postgres-test", vault_token)
    print("✓ User:", creds["username"])
    
    print("Reset tables...")
    sql = "DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO zynaxia_test;"
    print(run_sql(sql, creds))
    print("=== RESET TERMINÉ ===")

if __name__ == "__main__":
    main()
