from typing import Tuple, Any, Optional

from asn1crypto import keys, algos


class CryptoBackend:

    def load_private_key(self, key_bytes: bytes, password: Optional[str]) \
            -> Tuple[Any, keys.PrivateKeyInfo, keys.PublicKeyInfo]:
        raise NotImplementedError

    def load_public_key(self, key_bytes: bytes) -> keys.PublicKeyInfo:
        raise NotImplementedError

    def generic_sign(self, private_key: keys.PrivateKeyInfo, tbs_bytes: bytes,
                     signature_algo: algos.SignedDigestAlgorithm) -> bytes:
        raise NotImplementedError


class OscryptoBackend(CryptoBackend):

    def load_private_key(self, key_bytes: bytes, password: Optional[str]) \
            -> Tuple[Any, keys.PrivateKeyInfo, keys.PublicKeyInfo]:
        from oscrypto import asymmetric, keys as oskeys
        private = oskeys.parse_private(
            key_bytes, password=password
        )
        if private.algorithm == 'rsassa_pss':
            loaded, public = _oscrypto_hacky_load_pss_exclusive_key(private)
        else:
            loaded = asymmetric.load_private_key(private)
            public = loaded.public_key.asn1
        return loaded, private, public

    def load_public_key(self, key_bytes: bytes) -> keys.PublicKeyInfo:
        from oscrypto import keys as oskeys
        return oskeys.parse_public(key_bytes)

    def generic_sign(self, private_key: keys.PrivateKeyInfo, tbs_bytes: bytes,
                     signature_algo: algos.SignedDigestAlgorithm) -> bytes:
        from oscrypto import asymmetric

        pk_algo = private_key.algorithm
        loaded_key = None
        if pk_algo == 'rsa':
            if signature_algo.signature_algo == 'rsassa_pss':
                sign_fun = asymmetric.rsa_pss_sign
            else:
                sign_fun = asymmetric.rsa_pkcs1v15_sign
        elif pk_algo == 'rsassa_pss':
            loaded_key = _oscrypto_hacky_load_pss_exclusive_key(private_key)[0]
            sign_fun = asymmetric.rsa_pss_sign
        elif pk_algo == 'ec':
            sign_fun = asymmetric.ecdsa_sign
        elif pk_algo == 'dsa':
            sign_fun = asymmetric.dsa_sign
        else:
            raise NotImplementedError(
                f"The signing mechanism '{pk_algo}' is not supported."
            )
        if loaded_key is None:
            loaded_key = asymmetric.load_private_key(private_key)
        return sign_fun(
            loaded_key, tbs_bytes, signature_algo.hash_algo
        )


def pyca_cryptography_present() -> bool:
    try:
        import cryptography
        return True
    except ImportError:  # pragma: nocover
        return False


def _oscrypto_hacky_load_pss_exclusive_key(private: keys.PrivateKeyInfo):
    from oscrypto import asymmetric
    # HACK to load PSS-exclusive RSA keys in oscrypto
    #  Don't ever do this in production code!
    algo_copy = private['private_key_algorithm'].native
    private_copy = keys.PrivateKeyInfo.load(private.dump())
    # set the algorithm to "generic RSA"
    private_copy['private_key_algorithm'] = {'algorithm': 'rsa'}
    loaded_key = asymmetric.load_private_key(private_copy)
    public = loaded_key.public_key.asn1
    public['algorithm'] = algo_copy
    return loaded_key, public


def _select_default_crypto_backend() -> CryptoBackend:
    return OscryptoBackend()


CRYPTO_BACKEND: CryptoBackend = _select_default_crypto_backend()


def generic_sign(private_key: keys.PrivateKeyInfo, tbs_bytes: bytes,
                 signature_algo: algos.SignedDigestAlgorithm) -> bytes:
    return CRYPTO_BACKEND.generic_sign(private_key, tbs_bytes, signature_algo)


def load_private_key(key_bytes: bytes, password: Optional[str]) \
        -> Tuple[Any, keys.PrivateKeyInfo, keys.PublicKeyInfo]:
    return CRYPTO_BACKEND.load_private_key(key_bytes, password)


def load_public_key(key_bytes: bytes) -> keys.PublicKeyInfo:
    return CRYPTO_BACKEND.load_public_key(key_bytes)
