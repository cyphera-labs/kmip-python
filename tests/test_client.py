"""Client-level tests (no network required)."""

from cyphera_kmip.client import resolve_algorithm
from cyphera_kmip.tags import Algorithm


class TestResolveAlgorithm:
    def test_aes(self):
        assert resolve_algorithm("AES") == Algorithm.AES

    def test_aes_lowercase(self):
        assert resolve_algorithm("aes") == Algorithm.AES

    def test_des(self):
        assert resolve_algorithm("DES") == Algorithm.DES

    def test_triple_des(self):
        assert resolve_algorithm("TripleDES") == Algorithm.TripleDES

    def test_3des(self):
        assert resolve_algorithm("3DES") == Algorithm.TripleDES

    def test_rsa(self):
        assert resolve_algorithm("RSA") == Algorithm.RSA

    def test_dsa(self):
        assert resolve_algorithm("DSA") == Algorithm.DSA

    def test_ecdsa(self):
        assert resolve_algorithm("ECDSA") == Algorithm.ECDSA

    def test_hmacsha1(self):
        assert resolve_algorithm("HMACSHA1") == Algorithm.HMACSHA1

    def test_hmacsha256(self):
        assert resolve_algorithm("HMACSHA256") == Algorithm.HMACSHA256

    def test_hmacsha384(self):
        assert resolve_algorithm("HMACSHA384") == Algorithm.HMACSHA384

    def test_hmacsha512(self):
        assert resolve_algorithm("HMACSHA512") == Algorithm.HMACSHA512

    def test_unknown_returns_zero(self):
        assert resolve_algorithm("BLOWFISH") == 0
