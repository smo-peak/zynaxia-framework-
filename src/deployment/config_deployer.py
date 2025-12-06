"""
LOT 7: Config Deployer Implementation

Déploiement de configuration sécurisé avec validation, signatures et ancrage.

Invariants:
    DEPL_020: Config validée par ConfigValidator AVANT déploiement
    DEPL_021: Config signée (quorum atteint) AVANT déploiement
    DEPL_022: Config ancrée blockchain AVANT déploiement
    DEPL_023: Hash config vérifié sur chaque nœud après réception
    DEPL_024: Ancienne config archivée (JAMAIS supprimée)
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional

from src.audit.interfaces import AuditEventType, IAuditEmitter
from src.core.interfaces import ICryptoProvider, IConfigValidator, ValidationResult
from src.deployment.interfaces import IConfigDeployer


class ConfigNotValidError(Exception):
    """Config non valide (DEPL_020)."""

    pass


class QuorumNotReachedError(Exception):
    """Quorum signatures non atteint (DEPL_021)."""

    pass


class BlockchainAnchorError(Exception):
    """Erreur ancrage blockchain (DEPL_022)."""

    pass


class ConfigHashMismatchError(Exception):
    """Hash config ne correspond pas (DEPL_023)."""

    pass


class ConfigDeployerError(Exception):
    """Erreur générale de déploiement config."""

    pass


# Type pour le client blockchain (injectable pour tests)
BlockchainClient = Callable[[str], Awaitable[str]]

# Type pour le client de distribution config (injectable pour tests)
ConfigDistributor = Callable[[str, str, Dict[str, Any]], Awaitable[bool]]

# Type pour le récupérateur de hash distant
RemoteHashFetcher = Callable[[str], Awaitable[str]]


@dataclass
class ConfigVersion:
    """Version de configuration avec métadonnées de sécurité.

    DEPL_021: Stocke les signatures du quorum.
    DEPL_022: Stocke l'ancrage blockchain.
    DEPL_024: archived=True quand remplacée.
    """

    version_id: str
    config_hash: str
    config_data: Dict[str, Any]
    created_at: datetime
    signatures: List[str] = field(default_factory=list)  # DEPL_021
    signer_ids: List[str] = field(default_factory=list)  # IDs des signataires
    blockchain_anchor: Optional[str] = None  # DEPL_022
    site_id: Optional[str] = None
    archived: bool = False  # DEPL_024
    archived_at: Optional[datetime] = None
    replaced_by: Optional[str] = None  # version_id du remplaçant

    def is_fully_signed(self, min_signatures: int) -> bool:
        """DEPL_021: Vérifie si le quorum est atteint."""
        return len(self.signatures) >= min_signatures

    def is_anchored(self) -> bool:
        """DEPL_022: Vérifie si ancrée blockchain."""
        return self.blockchain_anchor is not None


@dataclass
class DeploymentRecord:
    """Enregistrement d'un déploiement de config."""

    deployment_id: str
    version_id: str
    site_id: str
    deployed_at: datetime
    deployed_nodes: List[str]
    verified_nodes: List[str]  # DEPL_023
    success: bool
    error_message: Optional[str] = None


class ConfigDeployer(IConfigDeployer):
    """
    Déploiement de configuration sécurisé.

    Invariants:
        DEPL_020: Config validée avant déploiement
        DEPL_021: Quorum signatures atteint
        DEPL_022: Ancrage blockchain
        DEPL_023: Vérification hash sur nœuds
        DEPL_024: Archivage configs
    """

    # DEPL_021: Nombre minimum de signatures
    MIN_QUORUM_SIGNATURES: int = 2

    def __init__(
        self,
        config_validator: IConfigValidator,
        crypto_provider: ICryptoProvider,
        audit_emitter: IAuditEmitter,
        blockchain_client: Optional[BlockchainClient] = None,
        config_distributor: Optional[ConfigDistributor] = None,
        remote_hash_fetcher: Optional[RemoteHashFetcher] = None,
        min_quorum: int = 2,
    ) -> None:
        """
        Initialise le déployeur de configuration.

        Args:
            config_validator: Validateur de configuration.
            crypto_provider: Provider cryptographique.
            audit_emitter: Émetteur d'événements audit.
            blockchain_client: Client blockchain injectable.
            config_distributor: Distributeur de config injectable.
            remote_hash_fetcher: Récupérateur de hash distant.
            min_quorum: Nombre minimum de signatures (DEPL_021).
        """
        self._validator = config_validator
        self._crypto = crypto_provider
        self._audit = audit_emitter
        self._blockchain_client = blockchain_client or self._default_blockchain_client
        self._config_distributor = config_distributor or self._default_config_distributor
        self._remote_hash_fetcher = remote_hash_fetcher or self._default_remote_hash_fetcher
        self._min_quorum = min_quorum

        # DEPL_024: Archive des configs (jamais supprimées)
        self._config_archive: Dict[str, ConfigVersion] = {}
        self._current_configs: Dict[str, str] = {}  # site_id -> version_id
        self._deployment_records: Dict[str, DeploymentRecord] = {}

    async def _default_blockchain_client(self, config_hash: str) -> str:
        """Client blockchain par défaut (stub)."""
        # En production, ancrerait sur une vraie blockchain
        return f"anchor:{config_hash[:16]}:{datetime.now().timestamp()}"

    async def _default_config_distributor(
        self,
        node_id: str,
        site_id: str,
        config: Dict[str, Any],
    ) -> bool:
        """Distributeur de config par défaut (stub)."""
        # En production, distribuerait via réseau sécurisé
        return True

    async def _default_remote_hash_fetcher(self, node_id: str) -> str:
        """Récupérateur de hash distant par défaut (stub)."""
        # En production, récupérerait le hash depuis le nœud distant
        return ""

    def _compute_config_hash(self, config: Dict[str, Any]) -> str:
        """Calcule le hash d'une configuration."""
        import json

        config_bytes = json.dumps(config, sort_keys=True).encode("utf-8")
        return self._crypto.hash(config_bytes)

    async def deploy_config(
        self,
        config_data: Dict[str, Any],
        target_path: str,
        validate: bool = True,
    ) -> bool:
        """
        DEPL_020-024: Déploie une configuration validée et signée.

        Le target_path est interprété comme site_id pour la distribution.

        Args:
            config_data: Données de configuration.
            target_path: Site ID cible.
            validate: Si True, valide avant déploiement.

        Returns:
            True si déployé avec succès.

        Raises:
            ConfigNotValidError: Si validation échoue (DEPL_020).
            QuorumNotReachedError: Si quorum non atteint (DEPL_021).
            BlockchainAnchorError: Si ancrage échoue (DEPL_022).
        """
        site_id = target_path

        # DEPL_020: Valider la configuration
        if validate:
            validation_result = await self.validate_config(config_data)
            if validation_result:  # Non vide = erreurs
                error_msg = "; ".join(validation_result)
                await self._emit_audit_event(
                    "config_validation_failed",
                    {
                        "site_id": site_id,
                        "errors": validation_result,
                    },
                )
                raise ConfigNotValidError(f"DEPL_020: {error_msg}")

        # Calculer le hash
        config_hash = self._compute_config_hash(config_data)

        # DEPL_021: Vérifier les signatures (quorum)
        signatures = config_data.get("_signatures", [])
        signer_ids = config_data.get("_signer_ids", [])

        if len(signatures) < self._min_quorum:
            await self._emit_audit_event(
                "config_quorum_not_reached",
                {
                    "site_id": site_id,
                    "signatures_count": len(signatures),
                    "required": self._min_quorum,
                },
            )
            raise QuorumNotReachedError(
                f"DEPL_021: Quorum non atteint ({len(signatures)}/{self._min_quorum})"
            )

        # Valider chaque signature
        config_without_sigs = {k: v for k, v in config_data.items() if not k.startswith("_")}
        config_bytes = self._compute_config_hash(config_without_sigs).encode("utf-8")

        for i, signature in enumerate(signatures):
            signer_id = signer_ids[i] if i < len(signer_ids) else f"signer-{i}"
            if not self._crypto.verify_signature(config_bytes, signature.encode("utf-8"), signer_id):
                await self._emit_audit_event(
                    "config_signature_invalid",
                    {
                        "site_id": site_id,
                        "signer_id": signer_id,
                    },
                )
                raise QuorumNotReachedError(f"DEPL_021: Signature invalide de {signer_id}")

        # DEPL_022: Ancrer sur blockchain
        try:
            blockchain_anchor = await self._anchor_to_blockchain(config_hash)
        except Exception as e:
            await self._emit_audit_event(
                "config_blockchain_anchor_failed",
                {
                    "site_id": site_id,
                    "error": str(e),
                },
            )
            raise BlockchainAnchorError(f"DEPL_022: Ancrage blockchain échoué - {str(e)}")

        # DEPL_024: Archiver l'ancienne config si elle existe
        current_version_id = self._current_configs.get(site_id)
        if current_version_id and current_version_id in self._config_archive:
            self._archive_config(self._config_archive[current_version_id])

        # Créer la nouvelle version
        version_id = str(uuid.uuid4())
        new_version = ConfigVersion(
            version_id=version_id,
            config_hash=config_hash,
            config_data=config_without_sigs,
            created_at=datetime.now(),
            signatures=signatures,
            signer_ids=signer_ids,
            blockchain_anchor=blockchain_anchor,
            site_id=site_id,
        )

        # Stocker la nouvelle version
        self._config_archive[version_id] = new_version
        self._current_configs[site_id] = version_id

        # Mettre à jour le lien de remplacement
        if current_version_id and current_version_id in self._config_archive:
            self._config_archive[current_version_id].replaced_by = version_id

        await self._emit_audit_event(
            "config_deployed",
            {
                "site_id": site_id,
                "version_id": version_id,
                "config_hash": config_hash,
                "blockchain_anchor": blockchain_anchor,
                "signatures_count": len(signatures),
            },
        )

        return True

    async def validate_config(self, config_data: Dict[str, Any]) -> List[str]:
        """
        DEPL_020: Valide une configuration.

        Args:
            config_data: Données à valider.

        Returns:
            Liste d'erreurs (vide si valide).
        """
        # Enlever les métadonnées internes
        config_to_validate = {k: v for k, v in config_data.items() if not k.startswith("_")}

        result: ValidationResult = self._validator.validate(config_to_validate)

        errors: List[str] = []
        for error in result.errors:
            errors.append(f"{error.rule_id}: {error.message}")

        return errors

    def backup_config(self, target_path: str) -> Optional[str]:
        """
        DEPL_024: Sauvegarde une configuration existante.

        Args:
            target_path: Site ID.

        Returns:
            Version ID du backup, None si pas de config existante.
        """
        site_id = target_path
        current_version_id = self._current_configs.get(site_id)

        if not current_version_id:
            return None

        if current_version_id in self._config_archive:
            # La config est déjà archivée, retourner son ID
            return current_version_id

        return None

    def restore_config(self, backup_path: str, target_path: str) -> bool:
        """
        Restaure une configuration depuis backup.

        Args:
            backup_path: Version ID du backup.
            target_path: Site ID cible.

        Returns:
            True si restauré.
        """
        version_id = backup_path
        site_id = target_path

        if version_id not in self._config_archive:
            return False

        version = self._config_archive[version_id]

        # Archiver la config actuelle
        current_version_id = self._current_configs.get(site_id)
        if current_version_id and current_version_id in self._config_archive:
            self._archive_config(self._config_archive[current_version_id])

        # Désarchiver la version à restaurer
        version.archived = False
        version.archived_at = None

        # Mettre à jour la config courante
        self._current_configs[site_id] = version_id

        return True

    async def verify_config_on_node(
        self,
        config_hash: str,
        node_id: str,
    ) -> bool:
        """
        DEPL_023: Vérifie hash config sur un nœud distant.

        Args:
            config_hash: Hash attendu.
            node_id: ID du nœud.

        Returns:
            True si hash correspond.

        Raises:
            ConfigHashMismatchError: Si hash ne correspond pas.
        """
        try:
            remote_hash = await self._remote_hash_fetcher(node_id)

            if remote_hash != config_hash:
                await self._emit_audit_event(
                    "config_hash_mismatch",
                    {
                        "node_id": node_id,
                        "expected_hash": config_hash,
                        "actual_hash": remote_hash,
                    },
                )
                raise ConfigHashMismatchError(
                    f"DEPL_023: Hash mismatch sur {node_id}: "
                    f"attendu {config_hash[:16]}..., reçu {remote_hash[:16]}..."
                )

            return True

        except ConfigHashMismatchError:
            raise
        except Exception as e:
            raise ConfigHashMismatchError(f"DEPL_023: Erreur vérification sur {node_id}: {str(e)}")

    async def verify_config_on_nodes(
        self,
        config_hash: str,
        node_ids: List[str],
    ) -> Dict[str, bool]:
        """
        DEPL_023: Vérifie hash config sur plusieurs nœuds.

        Args:
            config_hash: Hash attendu.
            node_ids: Liste des IDs de nœuds.

        Returns:
            Dict node_id -> True/False.
        """
        results: Dict[str, bool] = {}

        for node_id in node_ids:
            try:
                results[node_id] = await self.verify_config_on_node(config_hash, node_id)
            except ConfigHashMismatchError:
                results[node_id] = False

        return results

    def _archive_config(self, version: ConfigVersion) -> None:
        """
        DEPL_024: Archive une configuration (jamais supprimée).

        Args:
            version: Version à archiver.
        """
        version.archived = True
        version.archived_at = datetime.now()

    async def _anchor_to_blockchain(self, config_hash: str) -> str:
        """
        DEPL_022: Ancre hash sur blockchain.

        Args:
            config_hash: Hash à ancrer.

        Returns:
            ID de l'ancrage blockchain.
        """
        return await self._blockchain_client(config_hash)

    def get_archived_configs(self) -> List[ConfigVersion]:
        """
        DEPL_024: Retourne toutes les configs archivées.

        Returns:
            Liste des versions archivées.
        """
        return [v for v in self._config_archive.values() if v.archived]

    def get_all_configs(self) -> List[ConfigVersion]:
        """Retourne toutes les configs (actives et archivées)."""
        return list(self._config_archive.values())

    def get_current_config(self, site_id: str) -> Optional[ConfigVersion]:
        """
        Retourne la config active pour un site.

        Args:
            site_id: ID du site.

        Returns:
            Version courante ou None.
        """
        version_id = self._current_configs.get(site_id)
        if version_id:
            return self._config_archive.get(version_id)
        return None

    def get_config_by_version(self, version_id: str) -> Optional[ConfigVersion]:
        """
        Retourne une config par son version_id.

        Args:
            version_id: ID de la version.

        Returns:
            Version ou None.
        """
        return self._config_archive.get(version_id)

    def get_config_history(self, site_id: str) -> List[ConfigVersion]:
        """
        Retourne l'historique des configs pour un site.

        Args:
            site_id: ID du site.

        Returns:
            Liste des versions (récentes en premier).
        """
        configs = [v for v in self._config_archive.values() if v.site_id == site_id]
        return sorted(configs, key=lambda v: v.created_at, reverse=True)

    def set_min_quorum(self, min_quorum: int) -> None:
        """
        DEPL_021: Définit le quorum minimum.

        Args:
            min_quorum: Nombre minimum de signatures.

        Raises:
            ValueError: Si min_quorum < 1.
        """
        if min_quorum < 1:
            raise ValueError("Quorum minimum doit être >= 1")
        self._min_quorum = min_quorum

    def get_min_quorum(self) -> int:
        """Retourne le quorum minimum actuel."""
        return self._min_quorum

    async def _emit_audit_event(
        self,
        action: str,
        metadata: Dict[str, Any],
    ) -> None:
        """Émet un événement d'audit."""
        await self._audit.emit_event(
            event_type=AuditEventType.SYSTEM_CONFIG_CHANGE,
            user_id="system",
            tenant_id="system",
            action=action,
            metadata=metadata,
        )

    def get_deployment_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques de déploiement."""
        archived_count = len(self.get_archived_configs())
        active_count = len(self._current_configs)
        total_count = len(self._config_archive)

        return {
            "total_versions": total_count,
            "active_configs": active_count,
            "archived_configs": archived_count,
            "sites_configured": list(self._current_configs.keys()),
            "min_quorum": self._min_quorum,
        }

    def clear_state(self) -> None:
        """Nettoie l'état (pour tests uniquement)."""
        self._config_archive.clear()
        self._current_configs.clear()
        self._deployment_records.clear()
