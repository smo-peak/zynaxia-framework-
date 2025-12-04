"""
Tests unitaires pour CryptoProvider.
"""

import pytest

from src.core.crypto_provider import CryptoProvider


class TestCryptoProvider:
    """Tests pour CryptoProvider."""
    
    def setup_method(self):
        """Setup avant chaque test."""
        self.crypto = CryptoProvider()
    
    def test_hash_returns_96_chars(self):
        """Le hash SHA-384 doit retourner exactement 96 caractères."""
        data = b"test data"
        hash_result = self.crypto.hash(data)
        
        assert len(hash_result) == 96
        assert all(c in "0123456789abcdef" for c in hash_result)
    
    def test_hash_deterministic(self):
        """Le hash doit être déterministe."""
        data = b"test data for deterministic check"
        
        hash1 = self.crypto.hash(data)
        hash2 = self.crypto.hash(data)
        
        assert hash1 == hash2
    
    def test_sign_and_verify(self):
        """Signature et vérification doivent fonctionner ensemble."""
        data = b"message to sign"
        key_id = "test_key_1"
        
        signature = self.crypto.sign(data, key_id)
        is_valid = self.crypto.verify_signature(data, signature, key_id)
        
        assert signature is not None
        assert len(signature) > 0
        assert is_valid is True
    
    def test_verify_fails_with_wrong_signature(self):
        """La vérification doit échouer avec une mauvaise signature."""
        data = b"original message"
        wrong_data = b"tampered message"
        key_id = "test_key_2"
        
        signature = self.crypto.sign(data, key_id)
        is_valid = self.crypto.verify_signature(wrong_data, signature, key_id)
        
        assert is_valid is False
    
    def test_verify_fails_with_wrong_key(self):
        """La vérification doit échouer avec une mauvaise clé."""
        data = b"message to sign"
        key_id1 = "key_1"
        key_id2 = "key_2"
        
        signature = self.crypto.sign(data, key_id1)
        is_valid = self.crypto.verify_signature(data, signature, key_id2)
        
        assert is_valid is False
    
    def test_hash_different_data_different_hash(self):
        """Des données différentes doivent donner des hash différents."""
        data1 = b"first message"
        data2 = b"second message"
        
        hash1 = self.crypto.hash(data1)
        hash2 = self.crypto.hash(data2)
        
        assert hash1 != hash2
        assert len(hash1) == 96
        assert len(hash2) == 96