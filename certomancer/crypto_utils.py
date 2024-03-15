import logging
from typing import Optional, Tuple

from asn1crypto import algos, keys, pem, x509
from asn1crypto.keys import PublicKeyInfo
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)


class CryptoBackend:
    def load_private_key(
        self, key_bytes: bytes, password: Optional[bytes]
    ) -> Tuple[keys.PrivateKeyInfo, keys.PublicKeyInfo]:
        raise NotImplementedError

    def load_public_key(self, key_bytes: bytes) -> keys.PublicKeyInfo:
        raise NotImplementedError

    def generic_sign(
        self,
        private_key: keys.PrivateKeyInfo,
        tbs_bytes: bytes,
        sd_algo: algos.SignedDigestAlgorithm,
    ) -> bytes:
        raise NotImplementedError

    def optimal_pss_params(
        self, key: PublicKeyInfo, digest_algo: str
    ) -> algos.RSASSAPSSParams:
        raise NotImplementedError


def _load_private_key_from_pemder_data(
    key_bytes: bytes, passphrase: Optional[bytes]
) -> keys.PrivateKeyInfo:
    load_fun = (
        serialization.load_pem_private_key
        if pem.detect(key_bytes)
        else serialization.load_der_private_key
    )

    private_key = load_fun(key_bytes, password=passphrase)
    return keys.PrivateKeyInfo.load(
        private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


class PycaCryptographyBackend(CryptoBackend):
    def load_private_key(
        self, key_bytes: bytes, password: Optional[bytes]
    ) -> Tuple[keys.PrivateKeyInfo, keys.PublicKeyInfo]:
        from cryptography.hazmat.primitives import serialization

        priv_key_info = _load_private_key_from_pemder_data(key_bytes, password)
        assert isinstance(priv_key_info, keys.PrivateKeyInfo)
        key_bytes = priv_key_info.dump()

        priv_key = serialization.load_der_private_key(key_bytes, password=None)
        pub_key_bytes = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_key_info = keys.PublicKeyInfo.load(pub_key_bytes)
        return priv_key_info, pub_key_info

    def load_public_key(self, key_bytes: bytes) -> keys.PublicKeyInfo:
        if key_bytes.startswith(b'----'):
            key_bytes = pem.unarmor(key_bytes)[2]
        return keys.PublicKeyInfo.load(key_bytes)

    def generic_sign(
        self,
        private_key: keys.PrivateKeyInfo,
        tbs_bytes: bytes,
        sd_algo: algos.SignedDigestAlgorithm,
    ) -> bytes:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import (
            dsa,
            ec,
            ed448,
            ed25519,
            padding,
            rsa,
        )

        priv_key_bytes = private_key.dump()

        priv_key = serialization.load_der_private_key(
            priv_key_bytes, password=None
        )
        digest_algorithm = sd_algo.hash_algo
        sig_algo = sd_algo.signature_algo
        if sig_algo == 'rsassa_pkcs1v15':
            asym_padding = padding.PKCS1v15()
            hash_algo = getattr(hashes, digest_algorithm.upper())()
            assert isinstance(priv_key, rsa.RSAPrivateKey)
            return priv_key.sign(tbs_bytes, asym_padding, hash_algo)
        elif sig_algo == 'rsassa_pss':
            parameters = None
            if parameters is None:
                parameters = sd_algo['parameters']

            mga: algos.MaskGenAlgorithm = parameters['mask_gen_algorithm']
            if not mga['algorithm'].native == 'mgf1':
                raise NotImplementedError("Only MFG1 is supported")

            mgf_md_name = mga['parameters']['algorithm'].native

            salt_len: int = parameters['salt_length'].native

            mgf_md = getattr(hashes, mgf_md_name.upper())()
            pss_padding = padding.PSS(
                mgf=padding.MGF1(algorithm=mgf_md), salt_length=salt_len
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
                f"The signature signature_algo {sig_algo} " f"is unsupported"
            )

    def optimal_pss_params(
        self, key: keys.PublicKeyInfo, digest_algo: str
    ) -> algos.RSASSAPSSParams:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa

        digest_algo = digest_algo.lower()

        loaded_key = serialization.load_der_public_key(key.dump())
        assert isinstance(loaded_key, rsa.RSAPublicKey)
        md = getattr(hashes, digest_algo.upper())
        # the PSS salt calculation function is not in the .pyi file, apparently.
        # noinspection PyUnresolvedReferences
        optimal_salt_len = padding.calculate_max_pss_salt_length(
            loaded_key, md()
        )
        return algos.RSASSAPSSParams(
            {
                'hash_algorithm': algos.DigestAlgorithm(
                    {'algorithm': digest_algo}
                ),
                'mask_gen_algorithm': algos.MaskGenAlgorithm(
                    {
                        'algorithm': 'mgf1',
                        'parameters': algos.DigestAlgorithm(
                            {'algorithm': digest_algo}
                        ),
                    }
                ),
                'salt_length': optimal_salt_len,
            }
        )


def pyca_cryptography_present() -> bool:
    try:
        import cryptography

        return True
    except ImportError:
        return False


CRYPTO_BACKEND: CryptoBackend = PycaCryptographyBackend()


def generic_sign(
    private_key: keys.PrivateKeyInfo,
    tbs_bytes: bytes,
    signature_algo: algos.SignedDigestAlgorithm,
) -> bytes:
    return CRYPTO_BACKEND.generic_sign(private_key, tbs_bytes, signature_algo)


def load_private_key(
    key_bytes: bytes, password: Optional[bytes]
) -> Tuple[keys.PrivateKeyInfo, keys.PublicKeyInfo]:
    return CRYPTO_BACKEND.load_private_key(key_bytes, password)


def load_public_key(key_bytes: bytes) -> keys.PublicKeyInfo:
    return CRYPTO_BACKEND.load_public_key(key_bytes)


def optimal_pss_params(
    key_algo: keys.PublicKeyInfo, digest_algo: str
) -> algos.RSASSAPSSParams:
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
        raise ValueError(f"Number of certs in {cert_file} should be exactly 1")
    return certs[0]
