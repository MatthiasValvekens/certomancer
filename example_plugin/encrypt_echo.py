"""
A Certomancer service plugin example.

It's a simple echo service that encrypts whatever it receives
using AES-256-CBC and replies with an EnvelopedData
addressed to the recipient specified in the configuration.
"""
import logging
import secrets
from datetime import datetime
from typing import Optional

from asn1crypto import cms, algos
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from certomancer import registry
from certomancer.registry import plugin_api

logger = logging.getLogger(__name__)


@registry.service_plugin_registry.register
class EncryptEcho(plugin_api.ServicePlugin):
    content_type = 'application/cms'
    plugin_label = 'encrypt-echo'

    def process_plugin_config(self, params):
        recpt = params['recipient']
        logger.info(f"Found endpoint for recipient {recpt}")
        return registry.CertLabel(recpt)

    def invoke(self, arch: registry.PKIArchitecture,
               info: plugin_api.PluginServiceInfo, request: bytes,
               at_time: Optional[datetime] = None) -> bytes:

        cfg = info.plugin_config
        assert isinstance(cfg, registry.CertLabel)
        cert = arch.get_cert(cfg)
        if cert.public_key.algorithm != 'rsa':
            raise plugin_api.CertomancerServiceError(
                "This test plugin only works with RSA with PKCS #1 v1.5 padding"
            )

        # generate a 256-bit key
        envelope_key = secrets.token_bytes(32)

        # encrypt the envelope key with the recipient's public key

        key: RSAPublicKey = serialization.load_der_public_key(cert.public_key.dump())
        encrypted_data = key.encrypt(envelope_key, padding.PKCS1v15())

        rid = cms.RecipientIdentifier({
            'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                'issuer': cert.issuer, 'serial_number': cert.serial_number
            })
        })

        algo = cms.KeyEncryptionAlgorithm({
            'algorithm': cms.KeyEncryptionAlgorithmId('rsaes_pkcs1v15')
        })

        rec_info = cms.RecipientInfo({
            'ktri': cms.KeyTransRecipientInfo({
                'version': 0, 'rid': rid, 'key_encryption_algorithm': algo,
                'encrypted_key': encrypted_data
            })
        })

        # encrypt the request body
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(envelope_key), modes.CBC(iv))
        padder = PKCS7(128).padder()
        padded = padder.update(request) + padder.finalize()
        enc = cipher.encryptor()
        encrypted_envelope_content = enc.update(padded) + enc.finalize()

        algo = cms.EncryptionAlgorithm({
            'algorithm': algos.EncryptionAlgorithmId('aes256_cbc'),
            'parameters': iv
        })
        encrypted_content_info = cms.EncryptedContentInfo({
            'content_type': cms.ContentType('data'),
            'content_encryption_algorithm': algo,
            'encrypted_content': encrypted_envelope_content
        })
        enveloped_data = cms.EnvelopedData({
            'version': 0, 'recipient_infos': [rec_info],
            'encrypted_content_info': encrypted_content_info
        })

        return cms.ContentInfo({
            'content_type': cms.ContentType('enveloped_data'),
            'content': enveloped_data
        }).dump()
