"""
LOT 11: Logging - Sensitive Masker

Masquage automatique des données sensibles.

Invariant:
    LOG_005: Données sensibles JAMAIS en clair (masquées)
"""

from typing import Any, Dict, List, Optional

from .interfaces import ISensitiveMasker


class SensitiveMasker(ISensitiveMasker):
    """
    Masquage automatique des données sensibles.

    Implémente le masquage récursif pour protéger les données
    sensibles dans les logs.

    Invariant:
        LOG_005: Données sensibles JAMAIS en clair

    Example:
        masker = SensitiveMasker()
        safe_data = masker.mask({"password": "secret123"})
        # {"password": "***MASKED***"}
    """

    def __init__(self, additional_patterns: Optional[List[str]] = None) -> None:
        """
        Initialise le masker avec patterns sensibles.

        Args:
            additional_patterns: Patterns supplémentaires à masquer
        """
        self._patterns: List[str] = list(self.SENSITIVE_PATTERNS)
        if additional_patterns:
            for pattern in additional_patterns:
                if pattern and pattern.lower() not in [p.lower() for p in self._patterns]:
                    self._patterns.append(pattern.lower())

    @property
    def patterns(self) -> List[str]:
        """Retourne les patterns sensibles configurés."""
        return list(self._patterns)

    def mask(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        LOG_005: Masque récursivement toutes les données sensibles.

        Comportement:
            - Clés contenant patterns sensibles → valeur masquée
            - Valeurs dict → récursion
            - Valeurs list → masque chaque élément

        Args:
            data: Dictionnaire à masquer

        Returns:
            Copie avec données sensibles masquées
        """
        if not isinstance(data, dict):
            return data

        result: Dict[str, Any] = {}

        for key, value in data.items():
            if self.is_sensitive_key(key):
                # Clé sensible → masquer la valeur
                result[key] = self.MASK_VALUE
            elif isinstance(value, dict):
                # Récursion pour dictionnaires imbriqués
                result[key] = self.mask(value)
            elif isinstance(value, list):
                # Masquer chaque élément de la liste
                result[key] = self._mask_list(value, key)
            else:
                result[key] = value

        return result

    def _mask_list(self, items: List[Any], parent_key: str = "") -> List[Any]:
        """
        Masque les éléments sensibles d'une liste.

        Args:
            items: Liste à traiter
            parent_key: Clé parente (pour contexte)

        Returns:
            Liste avec éléments masqués
        """
        result = []
        for item in items:
            if isinstance(item, dict):
                result.append(self.mask(item))
            elif isinstance(item, list):
                result.append(self._mask_list(item, parent_key))
            else:
                result.append(item)
        return result

    def mask_string(self, value: str) -> str:
        """
        Masque valeur string sensible.

        Args:
            value: Valeur à masquer

        Returns:
            MASK_VALUE constant
        """
        return self.MASK_VALUE

    def is_sensitive_key(self, key: str) -> bool:
        """
        Vérifie si clé contient un pattern sensible.

        La vérification est case-insensitive.

        Args:
            key: Nom de la clé à vérifier

        Returns:
            True si clé contient pattern sensible
        """
        if not key:
            return False

        key_lower = key.lower()

        for pattern in self._patterns:
            if pattern.lower() in key_lower:
                return True

        return False

    def add_pattern(self, pattern: str) -> None:
        """
        Ajoute pattern sensible personnalisé.

        Args:
            pattern: Pattern à ajouter (case-insensitive)

        Raises:
            ValueError: Si pattern vide
        """
        if not pattern or not pattern.strip():
            raise ValueError("Pattern cannot be empty")

        pattern_lower = pattern.lower().strip()
        if pattern_lower not in [p.lower() for p in self._patterns]:
            self._patterns.append(pattern_lower)

    def remove_pattern(self, pattern: str) -> bool:
        """
        Retire un pattern de la liste.

        Args:
            pattern: Pattern à retirer

        Returns:
            True si pattern retiré, False si non trouvé
        """
        pattern_lower = pattern.lower().strip()
        for i, p in enumerate(self._patterns):
            if p.lower() == pattern_lower:
                self._patterns.pop(i)
                return True
        return False

    def mask_value_if_sensitive(self, key: str, value: Any) -> Any:
        """
        Masque une valeur si la clé est sensible.

        Args:
            key: Nom de la clé
            value: Valeur associée

        Returns:
            Valeur masquée ou originale
        """
        if self.is_sensitive_key(key):
            return self.MASK_VALUE
        return value
