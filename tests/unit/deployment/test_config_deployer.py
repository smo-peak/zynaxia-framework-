"""
Tests unitaires pour ConfigDeployer.

LOT 7: Déploiement de configuration sécurisé

Invariants testés:
    DEPL_020: Config validée par ConfigValidator AVANT déploiement
    DEPL_021: Config signée (quorum atteint) AVANT déploiement
    DEPL_022: Config ancrée blockchain AVANT déploiement
    DEPL_023: Hash config vérifié sur chaque nœud après réception
    DEPL_024: Ancienne config archivée (JAMAIS supprimée)
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, AsyncMock

import pytest

from src.audit.interfaces import AuditEventType, IAuditEmitter
from src.core.interfaces import (
    ICryptoProvider,
    IConfigValidator,
    ValidationResult,
    ValidationError,
    ValidationSeverity,
)
from src.deployment.config_deployer import (
    BlockchainAnchorError,
    ConfigDeployer,
    ConfigDeployerError,
    ConfigHashMismatchError,
    ConfigNotValidError,
    ConfigVersion,
    QuorumNotReachedError,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mock_config_validator() -> MagicMock:
    """Crée un mock de IConfigValidator."""
    validator = MagicMock(spec=IConfigValidator)
    # Par défaut, validation réussie
    validator.validate = MagicMock(
        return_value=ValidationResult(
            valid=True,
            errors=[],
            warnings=[],
            checked_at=datetime.now(),
        )
    )
    return validator


@pytest.fixture
def mock_crypto_provider() -> MagicMock:
    """Crée un mock de ICryptoProvider."""
    provider = MagicMock(spec=ICryptoProvider)
    provider.hash = MagicMock(return_value="a" * 96)  # SHA-384 = 96 chars
    provider.verify_signature = MagicMock(return_value=True)
    return provider


@pytest.fixture
def mock_audit_emitter() -> AsyncMock:
    """Crée un mock de IAuditEmitter."""
    emitter = AsyncMock(spec=IAuditEmitter)
    emitter.emit_event = AsyncMock()
    return emitter


@pytest.fixture
def config_deployer(
    mock_config_validator: MagicMock,
    mock_crypto_provider: MagicMock,
    mock_audit_emitter: AsyncMock,
) -> ConfigDeployer:
    """Crée un ConfigDeployer pour les tests."""
    return ConfigDeployer(
        config_validator=mock_config_validator,
        crypto_provider=mock_crypto_provider,
        audit_emitter=mock_audit_emitter,
        min_quorum=2,
    )


@pytest.fixture
def valid_config_with_signatures() -> Dict[str, Any]:
    """Configuration valide avec signatures quorum."""
    return {
        "version": "1.0.0",
        "tenant_id": "tenant-123",
        "hierarchy": {"level": "site"},
        "roles": {"admin": {"permissions": ["read", "write"]}},
        "_signatures": ["sig1_base64", "sig2_base64"],
        "_signer_ids": ["admin-1", "admin-2"],
    }


@pytest.fixture
def config_without_signatures() -> Dict[str, Any]:
    """Configuration sans signatures."""
    return {
        "version": "1.0.0",
        "tenant_id": "tenant-123",
        "hierarchy": {"level": "site"},
    }


# ============================================================================
# Tests DEPL_020: Config validée avant déploiement
# ============================================================================


class TestDEPL020ConfigValidation:
    """Tests pour DEPL_020: Config validée avant déploiement."""

    @pytest.mark.asyncio
    async def test_valid_config_accepted(
        self,
        config_deployer: ConfigDeployer,
        valid_config_with_signatures: Dict[str, Any],
    ) -> None:
        """DEPL_020: Config valide acceptée."""
        result = await config_deployer.deploy_config(
            valid_config_with_signatures,
            "site-001",
            validate=True,
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_invalid_config_rejected(
        self,
        config_deployer: ConfigDeployer,
        mock_config_validator: MagicMock,
        valid_config_with_signatures: Dict[str, Any],
    ) -> None:
        """DEPL_020: Config invalide rejetée."""
        # Simuler une erreur de validation
        mock_config_validator.validate = MagicMock(
            return_value=ValidationResult(
                valid=False,
                errors=[
                    ValidationError(
                        rule_id="RUN_020",
                        message="Niveau hiérarchique invalide",
                        location="hierarchy.level",
                        severity=ValidationSeverity.BLOCKING,
                    )
                ],
                warnings=[],
                checked_at=datetime.now(),
            )
        )

        with pytest.raises(ConfigNotValidError, match="DEPL_020"):
            await config_deployer.deploy_config(
                valid_config_with_signatures,
                "site-001",
                validate=True,
            )

    @pytest.mark.asyncio
    async def test_validation_called_before_deployment(
        self,
        config_deployer: ConfigDeployer,
        mock_config_validator: MagicMock,
        valid_config_with_signatures: Dict[str, Any],
    ) -> None:
        """DEPL_020: Validation appelée avant déploiement."""
        await config_deployer.deploy_config(
            valid_config_with_signatures,
            "site-001",
            validate=True,
        )

        mock_config_validator.validate.assert_called_once()

    @pytest.mark.asyncio
    async def test_validation_can_be_skipped(
        self,
        config_deployer: ConfigDeployer,
        mock_config_validator: MagicMock,
        valid_config_with_signatures: Dict[str, Any],
    ) -> None:
        """DEPL_020: Validation peut être désactivée."""
        await config_deployer.deploy_config(
            valid_config_with_signatures,
            "site-001",
            validate=False,
        )

        mock_config_validator.validate.assert_not_called()

    @pytest.mark.asyncio
    async def test_validate_config_returns_errors(
        self,
        config_deployer: ConfigDeployer,
        mock_config_validator: MagicMock,
    ) -> None:
        """DEPL_020: validate_config retourne la liste d'erreurs."""
        mock_config_validator.validate = MagicMock(
            return_value=ValidationResult(
                valid=False,
                errors=[
                    ValidationError(
                        rule_id="RUN_001",
                        message="Erreur 1",
                        location="field1",
                        severity=ValidationSeverity.BLOCKING,
                    ),
                    ValidationError(
                        rule_id="RUN_002",
                        message="Erreur 2",
                        location="field2",
                        severity=ValidationSeverity.BLOCKING,
                    ),
                ],
                warnings=[],
                checked_at=datetime.now(),
            )
        )

        errors = await config_deployer.validate_config({"test": "data"})

        assert len(errors) == 2
        assert "RUN_001" in errors[0]
        assert "RUN_002" in errors[1]

    @pytest.mark.asyncio
    async def test_validate_config_empty_on_success(
        self,
        config_deployer: ConfigDeployer,
    ) -> None:
        """DEPL_020: validate_config retourne liste vide si valide."""
        errors = await config_deployer.validate_config({"test": "data"})

        assert errors == []


# ============================================================================
# Tests DEPL_021: Quorum signatures
# ============================================================================


class TestDEPL021QuorumSignatures:
    """Tests pour DEPL_021: Quorum signatures."""

    @pytest.mark.asyncio
    async def test_quorum_reached_accepted(
        self,
        config_deployer: ConfigDeployer,
        valid_config_with_signatures: Dict[str, Any],
    ) -> None:
        """DEPL_021: Config avec quorum acceptée."""
        result = await config_deployer.deploy_config(
            valid_config_with_signatures,
            "site-001",
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_quorum_not_reached_rejected(
        self,
        config_deployer: ConfigDeployer,
    ) -> None:
        """DEPL_021: Config sans quorum rejetée."""
        config = {
            "version": "1.0.0",
            "_signatures": ["sig1"],  # Seulement 1 signature
            "_signer_ids": ["admin-1"],
        }

        with pytest.raises(QuorumNotReachedError, match="DEPL_021"):
            await config_deployer.deploy_config(config, "site-001")

    @pytest.mark.asyncio
    async def test_no_signatures_rejected(
        self,
        config_deployer: ConfigDeployer,
        config_without_signatures: Dict[str, Any],
    ) -> None:
        """DEPL_021: Config sans signatures rejetée."""
        with pytest.raises(QuorumNotReachedError, match="DEPL_021"):
            await config_deployer.deploy_config(config_without_signatures, "site-001")

    @pytest.mark.asyncio
    async def test_invalid_signature_rejected(
        self,
        config_deployer: ConfigDeployer,
        mock_crypto_provider: MagicMock,
        valid_config_with_signatures: Dict[str, Any],
    ) -> None:
        """DEPL_021: Signature invalide rejetée."""
        mock_crypto_provider.verify_signature = MagicMock(return_value=False)

        with pytest.raises(QuorumNotReachedError, match="Signature invalide"):
            await config_deployer.deploy_config(
                valid_config_with_signatures,
                "site-001",
            )

    @pytest.mark.asyncio
    async def test_custom_quorum_respected(
        self,
        mock_config_validator: MagicMock,
        mock_crypto_provider: MagicMock,
        mock_audit_emitter: AsyncMock,
    ) -> None:
        """DEPL_021: Quorum personnalisé respecté."""
        deployer = ConfigDeployer(
            config_validator=mock_config_validator,
            crypto_provider=mock_crypto_provider,
            audit_emitter=mock_audit_emitter,
            min_quorum=3,
        )

        config = {
            "version": "1.0.0",
            "_signatures": ["sig1", "sig2"],  # 2 signatures, quorum = 3
            "_signer_ids": ["admin-1", "admin-2"],
        }

        with pytest.raises(QuorumNotReachedError, match="2/3"):
            await deployer.deploy_config(config, "site-001")

    @pytest.mark.asyncio
    async def test_set_min_quorum(
        self,
        config_deployer: ConfigDeployer,
    ) -> None:
        """DEPL_021: set_min_quorum modifie le quorum."""
        assert config_deployer.get_min_quorum() == 2

        config_deployer.set_min_quorum(3)

        assert config_deployer.get_min_quorum() == 3

    @pytest.mark.asyncio
    async def test_set_min_quorum_invalid_rejected(
        self,
        config_deployer: ConfigDeployer,
    ) -> None:
        """DEPL_021: Quorum < 1 rejeté."""
        with pytest.raises(ValueError):
            config_deployer.set_min_quorum(0)


# ============================================================================
# Tests DEPL_022: Ancrage blockchain
# ============================================================================


class TestDEPL022BlockchainAnchor:
    """Tests pour DEPL_022: Ancrage blockchain."""

    @pytest.mark.asyncio
    async def test_blockchain_anchor_created(
        self,
        config_deployer: ConfigDeployer,
        valid_config_with_signatures: Dict[str, Any],
    ) -> None:
        """DEPL_022: Ancrage blockchain créé."""
        await config_deployer.deploy_config(
            valid_config_with_signatures,
            "site-001",
        )

        current = config_deployer.get_current_config("site-001")
        assert current is not None
        assert current.blockchain_anchor is not None
        assert current.is_anchored()

    @pytest.mark.asyncio
    async def test_blockchain_anchor_contains_hash(
        self,
        config_deployer: ConfigDeployer,
        valid_config_with_signatures: Dict[str, Any],
    ) -> None:
        """DEPL_022: Ancrage contient le hash."""
        await config_deployer.deploy_config(
            valid_config_with_signatures,
            "site-001",
        )

        current = config_deployer.get_current_config("site-001")
        assert current is not None
        assert "anchor:" in current.blockchain_anchor

    @pytest.mark.asyncio
    async def test_blockchain_failure_raises_error(
        self,
        mock_config_validator: MagicMock,
        mock_crypto_provider: MagicMock,
        mock_audit_emitter: AsyncMock,
        valid_config_with_signatures: Dict[str, Any],
    ) -> None:
        """DEPL_022: Échec blockchain lève erreur."""

        async def failing_blockchain(config_hash: str) -> str:
            raise Exception("Blockchain unavailable")

        deployer = ConfigDeployer(
            config_validator=mock_config_validator,
            crypto_provider=mock_crypto_provider,
            audit_emitter=mock_audit_emitter,
            blockchain_client=failing_blockchain,
        )

        with pytest.raises(BlockchainAnchorError, match="DEPL_022"):
            await deployer.deploy_config(
                valid_config_with_signatures,
                "site-001",
            )

    @pytest.mark.asyncio
    async def test_custom_blockchain_client_used(
        self,
        mock_config_validator: MagicMock,
        mock_crypto_provider: MagicMock,
        mock_audit_emitter: AsyncMock,
        valid_config_with_signatures: Dict[str, Any],
    ) -> None:
        """DEPL_022: Client blockchain personnalisé utilisé."""
        blockchain_called = False

        async def custom_blockchain(config_hash: str) -> str:
            nonlocal blockchain_called
            blockchain_called = True
            return f"custom_anchor:{config_hash[:8]}"

        deployer = ConfigDeployer(
            config_validator=mock_config_validator,
            crypto_provider=mock_crypto_provider,
            audit_emitter=mock_audit_emitter,
            blockchain_client=custom_blockchain,
        )

        await deployer.deploy_config(valid_config_with_signatures, "site-001")

        assert blockchain_called

    @pytest.mark.asyncio
    async def test_anchor_called_after_validation(
        self,
        config_deployer: ConfigDeployer,
        mock_config_validator: MagicMock,
        valid_config_with_signatures: Dict[str, Any],
    ) -> None:
        """DEPL_022: Ancrage appelé après validation."""
        call_order: List[str] = []

        original_validate = mock_config_validator.validate

        def track_validate(config: Dict[str, Any]) -> ValidationResult:
            call_order.append("validate")
            return original_validate(config)

        mock_config_validator.validate = track_validate

        async def track_blockchain(config_hash: str) -> str:
            call_order.append("blockchain")
            return f"anchor:{config_hash[:8]}"

        config_deployer._blockchain_client = track_blockchain

        await config_deployer.deploy_config(
            valid_config_with_signatures,
            "site-001",
        )

        assert call_order.index("validate") < call_order.index("blockchain")


# ============================================================================
# Tests DEPL_023: Vérification hash sur nœuds
# ============================================================================


class TestDEPL023HashVerification:
    """Tests pour DEPL_023: Vérification hash sur nœuds."""

    @pytest.mark.asyncio
    async def test_hash_match_returns_true(
        self,
        mock_config_validator: MagicMock,
        mock_crypto_provider: MagicMock,
        mock_audit_emitter: AsyncMock,
    ) -> None:
        """DEPL_023: Hash correspondant retourne True."""
        expected_hash = "abc123" * 16

        async def matching_fetcher(node_id: str) -> str:
            return expected_hash

        deployer = ConfigDeployer(
            config_validator=mock_config_validator,
            crypto_provider=mock_crypto_provider,
            audit_emitter=mock_audit_emitter,
            remote_hash_fetcher=matching_fetcher,
        )

        result = await deployer.verify_config_on_node(expected_hash, "node-1")

        assert result is True

    @pytest.mark.asyncio
    async def test_hash_mismatch_raises_error(
        self,
        mock_config_validator: MagicMock,
        mock_crypto_provider: MagicMock,
        mock_audit_emitter: AsyncMock,
    ) -> None:
        """DEPL_023: Hash différent lève erreur."""
        expected_hash = "abc123" * 16
        wrong_hash = "xyz789" * 16

        async def wrong_fetcher(node_id: str) -> str:
            return wrong_hash

        deployer = ConfigDeployer(
            config_validator=mock_config_validator,
            crypto_provider=mock_crypto_provider,
            audit_emitter=mock_audit_emitter,
            remote_hash_fetcher=wrong_fetcher,
        )

        with pytest.raises(ConfigHashMismatchError, match="DEPL_023"):
            await deployer.verify_config_on_node(expected_hash, "node-1")

    @pytest.mark.asyncio
    async def test_verify_on_multiple_nodes(
        self,
        mock_config_validator: MagicMock,
        mock_crypto_provider: MagicMock,
        mock_audit_emitter: AsyncMock,
    ) -> None:
        """DEPL_023: Vérification sur plusieurs nœuds."""
        expected_hash = "abc123" * 16

        async def matching_fetcher(node_id: str) -> str:
            if node_id == "node-2":
                return "wrong_hash"
            return expected_hash

        deployer = ConfigDeployer(
            config_validator=mock_config_validator,
            crypto_provider=mock_crypto_provider,
            audit_emitter=mock_audit_emitter,
            remote_hash_fetcher=matching_fetcher,
        )

        results = await deployer.verify_config_on_nodes(
            expected_hash,
            ["node-1", "node-2", "node-3"],
        )

        assert results["node-1"] is True
        assert results["node-2"] is False
        assert results["node-3"] is True

    @pytest.mark.asyncio
    async def test_fetch_error_raises_mismatch(
        self,
        mock_config_validator: MagicMock,
        mock_crypto_provider: MagicMock,
        mock_audit_emitter: AsyncMock,
    ) -> None:
        """DEPL_023: Erreur de récupération lève mismatch."""

        async def failing_fetcher(node_id: str) -> str:
            raise Exception("Network error")

        deployer = ConfigDeployer(
            config_validator=mock_config_validator,
            crypto_provider=mock_crypto_provider,
            audit_emitter=mock_audit_emitter,
            remote_hash_fetcher=failing_fetcher,
        )

        with pytest.raises(ConfigHashMismatchError, match="Erreur vérification"):
            await deployer.verify_config_on_node("abc123", "node-1")

    @pytest.mark.asyncio
    async def test_audit_event_on_mismatch(
        self,
        mock_config_validator: MagicMock,
        mock_crypto_provider: MagicMock,
        mock_audit_emitter: AsyncMock,
    ) -> None:
        """DEPL_023: Événement audit émis sur mismatch."""

        async def wrong_fetcher(node_id: str) -> str:
            return "wrong_hash"

        deployer = ConfigDeployer(
            config_validator=mock_config_validator,
            crypto_provider=mock_crypto_provider,
            audit_emitter=mock_audit_emitter,
            remote_hash_fetcher=wrong_fetcher,
        )

        try:
            await deployer.verify_config_on_node("expected_hash", "node-1")
        except ConfigHashMismatchError:
            pass

        mock_audit_emitter.emit_event.assert_called()
        call_args = mock_audit_emitter.emit_event.call_args
        assert call_args.kwargs["action"] == "config_hash_mismatch"

    @pytest.mark.asyncio
    async def test_empty_remote_hash_is_mismatch(
        self,
        mock_config_validator: MagicMock,
        mock_crypto_provider: MagicMock,
        mock_audit_emitter: AsyncMock,
    ) -> None:
        """DEPL_023: Hash vide distant = mismatch."""

        async def empty_fetcher(node_id: str) -> str:
            return ""

        deployer = ConfigDeployer(
            config_validator=mock_config_validator,
            crypto_provider=mock_crypto_provider,
            audit_emitter=mock_audit_emitter,
            remote_hash_fetcher=empty_fetcher,
        )

        with pytest.raises(ConfigHashMismatchError):
            await deployer.verify_config_on_node("abc123", "node-1")


# ============================================================================
# Tests DEPL_024: Archivage configs
# ============================================================================


class TestDEPL024ConfigArchive:
    """Tests pour DEPL_024: Archivage configs."""

    @pytest.mark.asyncio
    async def test_old_config_archived_on_new_deploy(
        self,
        config_deployer: ConfigDeployer,
        valid_config_with_signatures: Dict[str, Any],
    ) -> None:
        """DEPL_024: Ancienne config archivée lors de nouveau déploiement."""
        # Premier déploiement
        await config_deployer.deploy_config(
            valid_config_with_signatures,
            "site-001",
        )
        first_version = config_deployer.get_current_config("site-001")

        # Deuxième déploiement
        new_config = valid_config_with_signatures.copy()
        new_config["version"] = "2.0.0"
        await config_deployer.deploy_config(new_config, "site-001")

        # Vérifier archivage
        archived = config_deployer.get_archived_configs()
        assert len(archived) == 1
        assert archived[0].version_id == first_version.version_id
        assert archived[0].archived is True

    @pytest.mark.asyncio
    async def test_archived_config_never_deleted(
        self,
        config_deployer: ConfigDeployer,
        valid_config_with_signatures: Dict[str, Any],
    ) -> None:
        """DEPL_024: Config archivée jamais supprimée."""
        # Déployer plusieurs configs
        for i in range(5):
            config = valid_config_with_signatures.copy()
            config["version"] = f"{i}.0.0"
            await config_deployer.deploy_config(config, "site-001")

        # Toutes les versions doivent exister
        all_configs = config_deployer.get_all_configs()
        assert len(all_configs) == 5

        # 4 archivées, 1 active
        archived = config_deployer.get_archived_configs()
        assert len(archived) == 4

    @pytest.mark.asyncio
    async def test_archived_config_has_timestamp(
        self,
        config_deployer: ConfigDeployer,
        valid_config_with_signatures: Dict[str, Any],
    ) -> None:
        """DEPL_024: Config archivée a timestamp."""
        # Premier déploiement
        await config_deployer.deploy_config(
            valid_config_with_signatures,
            "site-001",
        )

        # Deuxième déploiement
        new_config = valid_config_with_signatures.copy()
        new_config["version"] = "2.0.0"
        await config_deployer.deploy_config(new_config, "site-001")

        archived = config_deployer.get_archived_configs()
        assert archived[0].archived_at is not None

    @pytest.mark.asyncio
    async def test_archived_config_has_replacement_link(
        self,
        config_deployer: ConfigDeployer,
        valid_config_with_signatures: Dict[str, Any],
    ) -> None:
        """DEPL_024: Config archivée a lien vers remplaçant."""
        # Premier déploiement
        await config_deployer.deploy_config(
            valid_config_with_signatures,
            "site-001",
        )
        first = config_deployer.get_current_config("site-001")

        # Deuxième déploiement
        new_config = valid_config_with_signatures.copy()
        new_config["version"] = "2.0.0"
        await config_deployer.deploy_config(new_config, "site-001")
        second = config_deployer.get_current_config("site-001")

        # Vérifier lien
        archived_first = config_deployer.get_config_by_version(first.version_id)
        assert archived_first.replaced_by == second.version_id

    @pytest.mark.asyncio
    async def test_get_config_history(
        self,
        config_deployer: ConfigDeployer,
        valid_config_with_signatures: Dict[str, Any],
    ) -> None:
        """DEPL_024: Historique configs récupérable."""
        # Déployer plusieurs configs
        for i in range(3):
            config = valid_config_with_signatures.copy()
            config["version"] = f"{i}.0.0"
            await config_deployer.deploy_config(config, "site-001")

        history = config_deployer.get_config_history("site-001")

        assert len(history) == 3
        # Plus récent en premier
        assert history[0].archived is False  # Current
        assert history[1].archived is True
        assert history[2].archived is True

    @pytest.mark.asyncio
    async def test_backup_config_returns_version_id(
        self,
        config_deployer: ConfigDeployer,
        valid_config_with_signatures: Dict[str, Any],
    ) -> None:
        """DEPL_024: backup_config retourne version_id."""
        await config_deployer.deploy_config(
            valid_config_with_signatures,
            "site-001",
        )

        backup_id = config_deployer.backup_config("site-001")

        assert backup_id is not None
        assert config_deployer.get_config_by_version(backup_id) is not None

    @pytest.mark.asyncio
    async def test_restore_config_works(
        self,
        config_deployer: ConfigDeployer,
        valid_config_with_signatures: Dict[str, Any],
    ) -> None:
        """DEPL_024: restore_config restaure une version."""
        # Déployer v1
        config_v1 = valid_config_with_signatures.copy()
        config_v1["version"] = "1.0.0"
        await config_deployer.deploy_config(config_v1, "site-001")
        v1_id = config_deployer.get_current_config("site-001").version_id

        # Déployer v2
        config_v2 = valid_config_with_signatures.copy()
        config_v2["version"] = "2.0.0"
        await config_deployer.deploy_config(config_v2, "site-001")

        # Restaurer v1
        result = config_deployer.restore_config(v1_id, "site-001")

        assert result is True
        current = config_deployer.get_current_config("site-001")
        assert current.version_id == v1_id


# ============================================================================
# Tests utilitaires
# ============================================================================


class TestUtilities:
    """Tests pour les méthodes utilitaires."""

    @pytest.mark.asyncio
    async def test_get_deployment_stats(
        self,
        config_deployer: ConfigDeployer,
        valid_config_with_signatures: Dict[str, Any],
    ) -> None:
        """Statistiques de déploiement correctes."""
        # Déployer sur plusieurs sites
        await config_deployer.deploy_config(valid_config_with_signatures, "site-001")
        await config_deployer.deploy_config(valid_config_with_signatures, "site-002")

        # Nouvelle version sur site-001
        new_config = valid_config_with_signatures.copy()
        new_config["version"] = "2.0.0"
        await config_deployer.deploy_config(new_config, "site-001")

        stats = config_deployer.get_deployment_stats()

        assert stats["total_versions"] == 3
        assert stats["active_configs"] == 2
        assert stats["archived_configs"] == 1
        assert "site-001" in stats["sites_configured"]
        assert "site-002" in stats["sites_configured"]

    @pytest.mark.asyncio
    async def test_clear_state(
        self,
        config_deployer: ConfigDeployer,
        valid_config_with_signatures: Dict[str, Any],
    ) -> None:
        """clear_state nettoie tout."""
        await config_deployer.deploy_config(valid_config_with_signatures, "site-001")

        config_deployer.clear_state()

        assert len(config_deployer.get_all_configs()) == 0
        assert config_deployer.get_current_config("site-001") is None

    @pytest.mark.asyncio
    async def test_audit_events_emitted(
        self,
        config_deployer: ConfigDeployer,
        mock_audit_emitter: AsyncMock,
        valid_config_with_signatures: Dict[str, Any],
    ) -> None:
        """Événements audit émis."""
        await config_deployer.deploy_config(valid_config_with_signatures, "site-001")

        mock_audit_emitter.emit_event.assert_called()


# ============================================================================
# Tests dataclasses
# ============================================================================


class TestDataClasses:
    """Tests pour les dataclasses."""

    def test_config_version_is_fully_signed(self) -> None:
        """ConfigVersion.is_fully_signed fonctionne."""
        version = ConfigVersion(
            version_id="v1",
            config_hash="hash",
            config_data={},
            created_at=datetime.now(),
            signatures=["sig1", "sig2"],
        )

        assert version.is_fully_signed(2) is True
        assert version.is_fully_signed(3) is False

    def test_config_version_is_anchored(self) -> None:
        """ConfigVersion.is_anchored fonctionne."""
        not_anchored = ConfigVersion(
            version_id="v1",
            config_hash="hash",
            config_data={},
            created_at=datetime.now(),
        )

        assert not_anchored.is_anchored() is False

        anchored = ConfigVersion(
            version_id="v2",
            config_hash="hash",
            config_data={},
            created_at=datetime.now(),
            blockchain_anchor="anchor:123",
        )

        assert anchored.is_anchored() is True

    def test_config_version_archived_fields(self) -> None:
        """ConfigVersion champs archivage."""
        version = ConfigVersion(
            version_id="v1",
            config_hash="hash",
            config_data={},
            created_at=datetime.now(),
        )

        assert version.archived is False
        assert version.archived_at is None
        assert version.replaced_by is None

        version.archived = True
        version.archived_at = datetime.now()
        version.replaced_by = "v2"

        assert version.archived is True
        assert version.archived_at is not None
        assert version.replaced_by == "v2"
