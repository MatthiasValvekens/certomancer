import hashlib
import importlib

import pytest
from asn1crypto import algos, cms, core, ocsp, tsp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from freezegun import freeze_time

from certomancer._asn1_types import register_extensions
from certomancer.integrations.aiohttp_illusionist import AsyncIllusionist
from certomancer.registry import ArchLabel, CertomancerConfig, KeyLabel

register_extensions()
importlib.import_module('certomancer.default_plugins')


def _get_arch(cfgfile='tests/data/with-services.yml'):
    cfg = CertomancerConfig.from_file(cfgfile, 'tests/data')
    return cfg.get_pki_arch(ArchLabel('testing-ca'))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'time, expected',
    [('2020-11-05', 'good'), ('2020-12-05', 'revoked')],
)
async def test_ocsp(time, expected):
    arch = _get_arch()
    with open('tests/data/signer2-ocsp-req.der', 'rb') as f:
        req_data = f.read()

    with freeze_time(time):
        async with AsyncIllusionist(arch).serving_session() as session:
            async with session.post(
                'http://test.test/testing-ca/ocsp/interm', data=req_data
            ) as r:
                body = await r.read()

    resp: ocsp.OCSPResponse = ocsp.OCSPResponse.load(body)
    assert resp['response_status'].native == 'successful'

    rdata = resp['response_bytes']['response'].parsed['tbs_response_data']
    status = rdata['responses'][0]['cert_status'].name
    assert status == expected


@pytest.mark.asyncio
@freeze_time('2020-11-01')
@pytest.mark.parametrize('include_nonce', [True, False])
async def test_timestamp(include_nonce):
    from datetime import datetime, timezone

    arch = _get_arch()
    hashed_bytes = hashlib.sha256(b'test').digest()
    req_data = {
        'version': 'v2',
        'message_imprint': tsp.MessageImprint(
            {
                'hash_algorithm': algos.DigestAlgorithm(
                    {'algorithm': 'sha256'}
                ),
                'hashed_message': hashed_bytes,
            }
        ),
        'cert_req': True,
    }
    if include_nonce:
        req_data['nonce'] = core.Integer(0x1337)
    req = tsp.TimeStampReq(req_data)

    async with AsyncIllusionist(arch).serving_session() as session:
        async with session.post(
            'http://test.test/testing-ca/tsa/tsa', data=req.dump()
        ) as r:
            body = await r.read()

    resp: tsp.TimeStampResp = tsp.TimeStampResp.load(body)
    sd = resp['time_stamp_token']['content']
    tst_info: tsp.TSTInfo = sd['encap_content_info']['content'].parsed
    if include_nonce:
        assert tst_info['nonce'].native == 0x1337
    assert tst_info['gen_time'].native == datetime.now().replace(
        tzinfo=timezone.utc
    )


@pytest.mark.asyncio
@freeze_time('2020-11-01')
async def test_crl():
    arch = _get_arch()

    async with AsyncIllusionist(arch).serving_session() as session:
        async with session.get(
            'http://test.test/testing-ca/crls/interm/latest.crl'
        ) as r:
            body = await r.read()
            assert r.status == 200

    from asn1crypto import crl as asn1_crl

    loaded = asn1_crl.CertificateList.load(body)
    # At 2020-11-01, signer2 is not yet revoked
    revoked = loaded['tbs_cert_list']['revoked_certificates']
    assert len(revoked) == 0


@pytest.mark.asyncio
@freeze_time('2020-12-29')
async def test_crl_with_revocation():
    arch = _get_arch()

    async with AsyncIllusionist(arch).serving_session() as session:
        async with session.get(
            'http://test.test/testing-ca/crls/interm/latest.crl'
        ) as r:
            body = await r.read()
            assert r.status == 200

    from asn1crypto import crl as asn1_crl

    loaded = asn1_crl.CertificateList.load(body)
    revoked = loaded['tbs_cert_list']['revoked_certificates']
    assert len(revoked) == 1


@pytest.mark.asyncio
async def test_demo_plugin():
    importlib.import_module('example_plugin.encrypt_echo')
    cfg = CertomancerConfig.from_file(
        'tests/data/with-plugin.yml', 'tests/data'
    )
    arch = cfg.get_pki_arch(ArchLabel('testing-ca'))

    endpoint = 'http://test.test/testing-ca/plugin/encrypt-echo/test-endpoint'
    payload = b'test test test'

    async with AsyncIllusionist(arch).serving_session() as session:
        async with session.post(endpoint, data=payload) as r:
            body = await r.read()
            assert r.status == 200

    # Decrypt the response to verify correctness
    env_data = cms.ContentInfo.load(body)['content']
    key_info = arch.key_set.get_private_key(KeyLabel('signer1'))
    ktri = env_data['recipient_infos'][0].chosen
    encrypted_key = ktri['encrypted_key'].native

    key: RSAPrivateKey = serialization.load_der_private_key(
        key_info.dump(), password=None
    )
    decrypted_key = key.decrypt(encrypted_key, padding.PKCS1v15())

    eci = env_data['encrypted_content_info']
    cea = eci['content_encryption_algorithm']
    assert cea['algorithm'].native == 'aes256_cbc'
    iv = cea['parameters'].native
    encrypted_content_bytes = eci['encrypted_content'].native

    cipher = Cipher(algorithms.AES(decrypted_key), modes.CBC(iv))
    dec = cipher.decryptor()
    decrypted_payload = dec.update(encrypted_content_bytes) + dec.finalize()
    unpadder = PKCS7(128).unpadder()
    result = unpadder.update(decrypted_payload) + unpadder.finalize()
    assert result == payload
