import hashlib
import logging
from typing import Tuple, Optional

from asn1crypto import keys, algos, pem, x509
from asn1crypto.keys import PublicKeyInfo

logger = logging.getLogger(__name__)


class CryptoBackend:

    def load_private_key(self, key_bytes: bytes, password: Optional[str]) \
            -> Tuple[keys.PrivateKeyInfo, keys.PublicKeyInfo]:
        raise NotImplementedError

    def load_public_key(self, key_bytes: bytes) -> keys.PublicKeyInfo:
        raise NotImplementedError

    def generic_sign(self, private_key: keys.PrivateKeyInfo, tbs_bytes: bytes,
                     sd_algo: algos.SignedDigestAlgorithm) -> bytes:
        raise NotImplementedError

    def optimal_pss_params(self, key: PublicKeyInfo, digest_algo: str) \
            -> algos.RSASSAPSSParams:
        raise NotImplementedError


class OscryptoBackend(CryptoBackend):

    def load_private_key(self, key_bytes: bytes, password: Optional[str]) \
            -> Tuple[keys.PrivateKeyInfo, keys.PublicKeyInfo]:
        from oscrypto import asymmetric, keys as oskeys
        private = oskeys.parse_private(
            key_bytes, password=password
        )
        if private.algorithm == 'rsassa_pss':
            loaded, public = _oscrypto_hacky_load_pss_exclusive_key(private)
        else:
            loaded = asymmetric.load_private_key(private)
            public = loaded.public_key.asn1
        return private, public

    def load_public_key(self, key_bytes: bytes) -> keys.PublicKeyInfo:
        from oscrypto import keys as oskeys
        return oskeys.parse_public(key_bytes)

    def generic_sign(self, private_key: keys.PrivateKeyInfo, tbs_bytes: bytes,
                     sd_algo: algos.SignedDigestAlgorithm) -> bytes:
        from oscrypto import asymmetric

        pk_algo = private_key.algorithm
        loaded_key = None
        if pk_algo == 'rsa':
            if sd_algo.signature_algo == 'rsassa_pss':
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
            loaded_key, tbs_bytes, sd_algo.hash_algo
        )

    def optimal_pss_params(self, key: PublicKeyInfo, digest_algo: str):
        key_algo = key.algorithm
        if key_algo == 'rsassa_pss':
            logger.warning(
                "You seem to be using an RSA key that has been marked as "
                "RSASSA-PSS exclusive. If it has non-null parameters, these "
                "WILL be disregarded by the signer, since oscrypto doesn't "
                "currently support RSASSA-PSS with arbitrary parameters."
            )
        # replicate default oscrypto PSS settings
        salt_len = len(getattr(hashlib, digest_algo)().digest())
        return algos.RSASSAPSSParams({
            'hash_algorithm': algos.DigestAlgorithm({
                'algorithm': digest_algo
            }),
            'mask_gen_algorithm': algos.MaskGenAlgorithm({
                'algorithm': 'mgf1',
                'parameters': algos.DigestAlgorithm(
                    {'algorithm': digest_algo}
                )
            }),
            'salt_length': salt_len
        })


class PycaCryptographyBackend(CryptoBackend):

    def load_private_key(self, key_bytes: bytes, password: Optional[str]) \
            -> Tuple[keys.PrivateKeyInfo, keys.PublicKeyInfo]:
        from cryptography.hazmat.primitives import serialization
        from oscrypto import keys as oskeys

        # use oscrypto parser here to parse the key to a PrivateKeyInfo object
        # (It handles unarmoring/decryption/... without worrying about the
        # key type, while load_der/pem_private_key would fail to process
        # PSS-exclusive keys)
        priv_key_info = oskeys.parse_private(key_bytes, password)
        assert isinstance(priv_key_info, keys.PrivateKeyInfo)
        if priv_key_info.algorithm == 'rsassa_pss':
            # these keys can't be loaded directly in pyca/cryptography,
            # so we have to give it a nudge
            priv_key_copy = priv_key_info.copy()
            priv_key_copy['private_key_algorithm'] = {'algorithm': 'rsa'}
            key_bytes = priv_key_copy.dump()
        else:
            key_bytes = priv_key_info.dump()

        priv_key = serialization.load_der_private_key(key_bytes, password=None)
        pub_key_bytes = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pub_key_info = keys.PublicKeyInfo.load(pub_key_bytes)
        if priv_key_info.algorithm == 'rsassa_pss':
            # if the private key was a PSS-exclusive one, copy the parameters
            # back from the original (since we stripped them going in)
            # We use .native to get around asn1crypto's type checking
            pub_key_info['algorithm'] = \
                priv_key_info['private_key_algorithm'].native
        return priv_key_info, pub_key_info

    def load_public_key(self, key_bytes: bytes) -> keys.PublicKeyInfo:
        if key_bytes.startswith(b'----'):
            key_bytes = pem.unarmor(key_bytes)[2]
        return keys.PublicKeyInfo.load(key_bytes)

    def generic_sign(self, private_key: keys.PrivateKeyInfo, tbs_bytes: bytes,
                     sd_algo: algos.SignedDigestAlgorithm) -> bytes:
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.asymmetric import (
            padding, rsa, dsa, ec, ed25519, ed448
        )

        if private_key.algorithm == 'rsassa_pss':
            # as usual, we need to pretend it's a normal RSA key
            # for pyca_cryptography to be able to load it
            private_key_copy = private_key.copy()
            private_key_copy['private_key_algorithm'] = {'algorithm': 'rsa'}
            priv_key_bytes = private_key_copy.dump()
        else:
            priv_key_bytes = private_key.dump()

        priv_key = serialization.load_der_private_key(
            priv_key_bytes, password=None
        )
        digest_algorithm = sd_algo.hash_algo
        sig_algo = sd_algo.signature_algo
        if sig_algo == 'rsassa_pkcs1v15':
            padding = padding.PKCS1v15()
            hash_algo = getattr(hashes, digest_algorithm.upper())()
            assert isinstance(priv_key, rsa.RSAPrivateKey)
            return priv_key.sign(tbs_bytes, padding, hash_algo)
        elif sig_algo == 'rsassa_pss':
            parameters = None
            if private_key.algorithm == 'rsassa_pss':
                key_params = \
                    private_key['private_key_algorithm']['parameters']
                # if the key is parameterised, we must use those params
                if key_params.native is not None:
                    parameters = key_params
            if parameters is None:
                parameters = sd_algo['parameters']

            mga: algos.MaskGenAlgorithm = parameters['mask_gen_algorithm']
            if not mga['algorithm'].native == 'mgf1':
                raise NotImplementedError("Only MFG1 is supported")

            mgf_md_name = mga['parameters']['algorithm'].native

            salt_len: int = parameters['salt_length'].native

            mgf_md = getattr(hashes, mgf_md_name.upper())()
            pss_padding = padding.PSS(
                mgf=padding.MGF1(algorithm=mgf_md),
                salt_length=salt_len
            )
            hash_algo = getattr(hashes, digest_algorithm.upper())()
            assert isinstance(priv_key, rsa.RSAPrivateKey)
            return priv_key.sign(tbs_bytes, pss_padding, hash_algo)
        elif sig_algo == 'dsa':
            assert isinstance(priv_key, dsa.DSAPrivateKey)
            hash_algo = getattr(hashes, digest_algorithm.upper())()
            return priv_key.sign(tbs_bytes, hash_algo)
        elif sig_algo == 'ecdsa':
            hash_algo = getattr(hashes, digest_algorithm.upper())()
            assert isinstance(priv_key, ec.EllipticCurvePrivateKey)
            return priv_key.sign(
                tbs_bytes, signature_algorithm=ec.ECDSA(hash_algo)
            )
        elif sig_algo == 'ed25519':
            assert isinstance(priv_key, ed25519.Ed25519PrivateKey)
            return priv_key.sign(tbs_bytes)
        elif sig_algo == 'ed448':
            assert isinstance(priv_key, ed448.Ed448PrivateKey)
            return priv_key.sign(tbs_bytes)
        else:  # pragma: nocover
            raise NotImplementedError(
                f"The signature signature_algo {sig_algo} "
                f"is unsupported"
            )

    def optimal_pss_params(self, key: keys.PublicKeyInfo,
                           digest_algo: str) -> algos.RSASSAPSSParams:
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import serialization, hashes
        digest_algo = digest_algo.lower()

        if key.algorithm == 'rsassa_pss':
            # again, pretend that we're working with a normal RSA key
            key = key.copy()
            key['algorithm'] = {'algorithm': 'rsa'}

        loaded_key: rsa.RSAPublicKey \
            = serialization.load_der_public_key(key.dump())
        md = getattr(hashes, digest_algo.upper())
        # the PSS salt calculation function is not in the .pyi file, apparently.
        # noinspection PyUnresolvedReferences
        optimal_salt_len = padding.calculate_max_pss_salt_length(
            loaded_key, md()
        )
        return algos.RSASSAPSSParams({
            'hash_algorithm': algos.DigestAlgorithm({
                'algorithm': digest_algo
            }),
            'mask_gen_algorithm': algos.MaskGenAlgorithm({
                'algorithm': 'mgf1',
                'parameters': algos.DigestAlgorithm({
                    'algorithm': digest_algo
                }),
            }),
            'salt_length': optimal_salt_len
        })


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
    from ._asn1crypto_patches import register_attr_cert_patches
    register_attr_cert_patches()
    # pyca/cryptography required for EdDSA certs
    if pyca_cryptography_present():
        # Patch EdDSA support into asn1crypto
        from ._asn1crypto_patches import register_eddsa_oids
        register_eddsa_oids()
        return PycaCryptographyBackend()
    else:
        return OscryptoBackend()


CRYPTO_BACKEND: CryptoBackend = _select_default_crypto_backend()


def generic_sign(private_key: keys.PrivateKeyInfo, tbs_bytes: bytes,
                 signature_algo: algos.SignedDigestAlgorithm) -> bytes:
    return CRYPTO_BACKEND.generic_sign(private_key, tbs_bytes, signature_algo)


def load_private_key(key_bytes: bytes, password: Optional[str]) \
        -> Tuple[keys.PrivateKeyInfo, keys.PublicKeyInfo]:
    return CRYPTO_BACKEND.load_private_key(key_bytes, password)


def load_public_key(key_bytes: bytes) -> keys.PublicKeyInfo:
    return CRYPTO_BACKEND.load_public_key(key_bytes)


def optimal_pss_params(key_algo: keys.PublicKeyInfo, digest_algo: str) \
        -> algos.RSASSAPSSParams:
    return CRYPTO_BACKEND.optimal_pss_params(key_algo, digest_algo)


def load_certs_from_pemder(cert_files):
    """
    A convenience function to load PEM/DER-encoded certificates from files.

    :param cert_files:
        An iterable of file names.
    :return:
        A generator producing :class:`.asn1crypto.x509.Certificate` objects.
    """

    for cert_file in cert_files:
        with open(cert_file, 'rb') as f:
            ca_chain_bytes = f.read()
        # use the pattern from the asn1crypto docs
        # to distinguish PEM/DER and read multiple certs
        # from one PEM file (if necessary)
        if pem.detect(ca_chain_bytes):
            pems = pem.unarmor(ca_chain_bytes, multiple=True)
            for type_name, _, der in pems:
                if type_name is None or type_name.lower() == 'certificate':
                    yield x509.Certificate.load(der)
                else:  # pragma: nocover
                    logger.debug(
                        f'Skipping PEM block of type {type_name} in '
                        f'certificate file.'
                    )
        else:
            # no need to unarmor, just try to load it immediately
            yield x509.Certificate.load(ca_chain_bytes)


def load_cert_from_pemder(cert_file):
    """
    A convenience function to load a single PEM/DER-encoded certificate
    from a file.

    :param cert_file:
        A file name.
    :return:
        An :class:`.asn1crypto.x509.Certificate` object.
    """
    certs = list(load_certs_from_pemder([cert_file]))
    if len(certs) != 1:
        raise ValueError(
            f"Number of certs in {cert_file} should be exactly 1"
        )
    return certs[0]
