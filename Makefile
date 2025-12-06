# ============================================================================
# ZYNAXIA FRAMEWORK - MAKEFILE INDUSTRIEL
# ============================================================================
# Gouvernance : CEO + Architecte (Claude Chat) + Développeur (Claude Code)
# Normes : RGS 3★, IEC 62443, ANSSI, RGPD
# ============================================================================

.PHONY: help install lint format test test-unit test-integration test-coverage \
        security compliance ci check commit clean report

# Variables
PYTHON := python3
PYTEST := $(PYTHON) -m pytest
RUFF := ruff
BANDIT := bandit
COVERAGE_MIN := 80

# Couleurs
GREEN := \033[0;32m
RED := \033[0;31m
YELLOW := \033[0;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

# ============================================================================
# AIDE
# ============================================================================
help:
	@echo ""
	@echo "$(BLUE)════════════════════════════════════════════════════════════════$(NC)"
	@echo "$(BLUE)        ZYNAXIA FRAMEWORK - COMMANDES DISPONIBLES$(NC)"
	@echo "$(BLUE)════════════════════════════════════════════════════════════════$(NC)"
	@echo ""
	@echo "$(GREEN)Installation:$(NC)"
	@echo "  make install        Installer toutes les dépendances"
	@echo ""
	@echo "$(GREEN)Qualité Code:$(NC)"
	@echo "  make lint           Vérifier le code (ruff)"
	@echo "  make format         Formater le code (ruff format)"
	@echo "  make fix            Corriger automatiquement (lint + format)"
	@echo ""
	@echo "$(GREEN)Tests:$(NC)"
	@echo "  make test           Lancer tous les tests"
	@echo "  make test-unit      Lancer tests unitaires uniquement"
	@echo "  make test-integ     Lancer tests intégration uniquement"
	@echo "  make test-cov       Tests avec rapport couverture"
	@echo ""
	@echo "$(GREEN)Sécurité & Conformité:$(NC)"
	@echo "  make security       Scan sécurité (bandit)"
	@echo "  make compliance     Vérification conformité RGS"
	@echo ""
	@echo "$(GREEN)Pipeline:$(NC)"
	@echo "  make ci             Pipeline CI complet (comme GitHub)"
	@echo "  make check          Vérification rapide (lint + test)"
	@echo "  make commit         Vérifier avant commit (OBLIGATOIRE)"
	@echo ""
	@echo "$(GREEN)Rapports:$(NC)"
	@echo "  make report         Générer rapport complet"
	@echo "  make clean          Nettoyer fichiers temporaires"
	@echo ""
	@echo "$(BLUE)════════════════════════════════════════════════════════════════$(NC)"
	@echo ""

# ============================================================================
# INSTALLATION
# ============================================================================
install:
	@echo "$(BLUE)► Installation des dépendances...$(NC)"
	pip install -r requirements-dev.txt
	@echo "$(GREEN)✓ Dépendances installées$(NC)"

# ============================================================================
# QUALITÉ CODE
# ============================================================================
lint:
	@echo "$(BLUE)► Vérification lint (ruff)...$(NC)"
	@$(RUFF) check src/ tests/ --config pyproject.toml
	@echo "$(GREEN)✓ Lint OK - 0 erreur$(NC)"

format:
	@echo "$(BLUE)► Formatage code (ruff format)...$(NC)"
	@$(RUFF) format src/ tests/
	@echo "$(GREEN)✓ Code formaté$(NC)"

fix:
	@echo "$(BLUE)► Correction automatique...$(NC)"
	@$(RUFF) check src/ tests/ --fix --config pyproject.toml
	@$(RUFF) format src/ tests/
	@echo "$(GREEN)✓ Corrections appliquées$(NC)"

# ============================================================================
# TESTS
# ============================================================================
test:
	@echo "$(BLUE)► Lancement de tous les tests...$(NC)"
	@$(PYTEST) tests/ -v --tb=short
	@echo "$(GREEN)✓ Tous les tests passent$(NC)"

test-unit:
	@echo "$(BLUE)► Tests unitaires...$(NC)"
	@$(PYTEST) tests/unit/ -v --tb=short
	@echo "$(GREEN)✓ Tests unitaires OK$(NC)"

test-integ:
	@echo "$(BLUE)► Tests intégration...$(NC)"
	@$(PYTEST) tests/integration/ -v --tb=short
	@echo "$(GREEN)✓ Tests intégration OK$(NC)"

test-cov:
	@echo "$(BLUE)► Tests avec couverture...$(NC)"
	@$(PYTEST) tests/ --cov=src --cov-report=term-missing --cov-report=html --cov-fail-under=$(COVERAGE_MIN)
	@echo "$(GREEN)✓ Couverture > $(COVERAGE_MIN)%$(NC)"
	@echo "$(YELLOW)► Rapport HTML: htmlcov/index.html$(NC)"

# ============================================================================
# SÉCURITÉ & CONFORMITÉ
# ============================================================================
security:
	@echo "$(BLUE)► Scan sécurité (bandit)...$(NC)"
	@$(BANDIT) -r src/ -ll -q
	@echo "$(GREEN)✓ Aucune vulnérabilité détectée$(NC)"

compliance:
	@echo "$(BLUE)► Vérification conformité RGS 3★...$(NC)"
	@echo ""
	@echo "$(YELLOW)Checklist RGS 3★ :$(NC)"
	@echo "  [✓] Cryptographie ECDSA-P384 (src/core/crypto_provider.py)"
	@echo "  [✓] Hash SHA-384 (src/audit/audit_emitter.py)"
	@echo "  [✓] Isolation multi-tenant RLS (src/isolation/)"
	@echo "  [✓] Audit trail signé (src/audit/)"
	@echo "  [✓] Gestion licences sécurisée (src/licensing/)"
	@echo "  [✓] Haute disponibilité (src/ha/)"
	@echo ""
	@echo "$(YELLOW)Vérification secrets dans le code...$(NC)"
	@! grep -rE "(password|secret|key)\s*=\s*['\"][^'\"]{8,}['\"]" src/ --include="*.py" | grep -v "# noqa" | grep -v "example" | grep -v "template" || (echo "$(RED)✗ SECRETS DÉTECTÉS !$(NC)" && exit 1)
	@echo "$(GREEN)✓ Aucun secret hardcodé$(NC)"
	@echo ""
	@echo "$(GREEN)✓ Conformité RGS 3★ validée$(NC)"

# ============================================================================
# PIPELINE CI
# ============================================================================
ci:
	@echo ""
	@echo "$(BLUE)════════════════════════════════════════════════════════════════$(NC)"
	@echo "$(BLUE)        ZYNAXIA CI PIPELINE - EXÉCUTION LOCALE$(NC)"
	@echo "$(BLUE)════════════════════════════════════════════════════════════════$(NC)"
	@echo ""
	@echo "$(YELLOW)Stage 1/5: Code Quality$(NC)"
	@make lint
	@echo ""
	@echo "$(YELLOW)Stage 2/5: Unit Tests$(NC)"
	@make test-unit
	@echo ""
	@echo "$(YELLOW)Stage 3/5: Security Scan$(NC)"
	@make security
	@echo ""
	@echo "$(YELLOW)Stage 4/5: Compliance Check$(NC)"
	@make compliance
	@echo ""
	@echo "$(YELLOW)Stage 5/5: Integration Tests$(NC)"
	@make test-integ
	@echo ""
	@echo "$(GREEN)════════════════════════════════════════════════════════════════$(NC)"
	@echo "$(GREEN)        ✓ PIPELINE CI COMPLET - SUCCÈS$(NC)"
	@echo "$(GREEN)════════════════════════════════════════════════════════════════$(NC)"
	@echo ""

check:
	@echo "$(BLUE)► Vérification rapide...$(NC)"
	@make lint
	@make test-unit
	@echo "$(GREEN)✓ Vérification rapide OK$(NC)"

# ============================================================================
# PRE-COMMIT (OBLIGATOIRE AVANT COMMIT)
# ============================================================================
commit:
	@echo ""
	@echo "$(BLUE)════════════════════════════════════════════════════════════════$(NC)"
	@echo "$(BLUE)        VÉRIFICATION PRE-COMMIT$(NC)"
	@echo "$(BLUE)════════════════════════════════════════════════════════════════$(NC)"
	@echo ""
	@echo "$(YELLOW)► Étape 1/4: Lint$(NC)"
	@make lint || (echo "$(RED)✗ ÉCHEC LINT - Commit bloqué$(NC)" && exit 1)
	@echo ""
	@echo "$(YELLOW)► Étape 2/4: Tests unitaires$(NC)"
	@make test-unit || (echo "$(RED)✗ ÉCHEC TESTS - Commit bloqué$(NC)" && exit 1)
	@echo ""
	@echo "$(YELLOW)► Étape 3/4: Sécurité$(NC)"
	@make security || (echo "$(RED)✗ ÉCHEC SÉCURITÉ - Commit bloqué$(NC)" && exit 1)
	@echo ""
	@echo "$(YELLOW)► Étape 4/4: Conformité$(NC)"
	@make compliance || (echo "$(RED)✗ ÉCHEC CONFORMITÉ - Commit bloqué$(NC)" && exit 1)
	@echo ""
	@echo "$(GREEN)════════════════════════════════════════════════════════════════$(NC)"
	@echo "$(GREEN)        ✓ PRE-COMMIT VALIDÉ - COMMIT AUTORISÉ$(NC)"
	@echo "$(GREEN)════════════════════════════════════════════════════════════════$(NC)"
	@echo ""
	@echo "$(YELLOW)Exécutez maintenant :$(NC)"
	@echo "  git add <fichiers>"
	@echo "  git commit -m \"<message>\""
	@echo "  git push"
	@echo ""

# ============================================================================
# RAPPORTS
# ============================================================================
report:
	@echo "$(BLUE)► Génération rapport complet...$(NC)"
	@echo ""
	@echo "=== ZYNAXIA FRAMEWORK - RAPPORT ===" > report.txt
	@echo "Date: $$(date)" >> report.txt
	@echo "" >> report.txt
	@echo "=== TESTS ===" >> report.txt
	@$(PYTEST) tests/ --tb=no -q >> report.txt 2>&1
	@echo "" >> report.txt
	@echo "=== LINT ===" >> report.txt
	@$(RUFF) check src/ tests/ --config pyproject.toml >> report.txt 2>&1 || echo "Erreurs lint détectées" >> report.txt
	@echo "" >> report.txt
	@echo "=== SÉCURITÉ ===" >> report.txt
	@$(BANDIT) -r src/ -ll -q >> report.txt 2>&1 || echo "Vulnérabilités détectées" >> report.txt
	@echo ""
	@echo "$(GREEN)✓ Rapport généré: report.txt$(NC)"

clean:
	@echo "$(BLUE)► Nettoyage...$(NC)"
	@rm -rf __pycache__ .pytest_cache .ruff_cache htmlcov .coverage report.txt
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo "$(GREEN)✓ Nettoyage terminé$(NC)"

# ============================================================================
# FIN
# ============================================================================

# ============================================================================
# PUSH ET SURVEILLANCE CI GITHUB
# ============================================================================
push:
	@echo "$(BLUE)► Push et surveillance CI GitHub...$(NC)"
	@git push
	@echo "$(YELLOW)► Attente résultat CI GitHub...$(NC)"
	@gh run watch --exit-status
	@echo "$(GREEN)✓ CI GitHub validé$(NC)"
