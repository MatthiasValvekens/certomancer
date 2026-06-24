"""
Async integration tests for aiohttp_animator.

Mirrors tests/test_animator.py, adapted for aiohttp's test utilities.
"""

import hashlib
from datetime import datetime, timezone
from io import BytesIO
from zipfile import ZipFile

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from asn1crypto import algos, cms, core, crl, ocsp, tsp, x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from freezegun import freeze_time

from certomancer import CertomancerConfig
from certomancer.integrations._animator_shared import FAKE_TIME_HEADER
from certomancer.integrations.aiohttp_animator import build_animator_app
from certomancer.registry import ArchLabel, KeyLabel

CFG = CertomancerConfig.from_file('tests/data/with-services.yml', 'tests/data')


@pytest_asyncio.fixture
async def client():
    app = build_animator_app(CFG.pki_archs)
    async with TestClient(TestServer(app)) as c:
        yield c


@pytest_asyncio.fixture
async def client_no_ui():
    app = build_animator_app(CFG.pki_archs, with_web_ui=False)
    async with TestClient(TestServer(app)) as c:
        yield c


@pytest.mark.asyncio
@freeze_time('2020-11-01')
async def test_timestamp(client):
    hashed_bytes = hashlib.sha256(b'test').digest()
    req = tsp.TimeStampReq(
        {
            'version': 'v2',
            'message_imprint': tsp.MessageImprint(
                {
                    'hash_algorithm': algos.DigestAlgorithm(
                        {'algorithm': 'sha256'}
                    ),
                    'hashed_message': hashed_bytes,
                }
            ),
            'nonce': core.Integer(0x1337),
            'cert_req': True,
        }
    )
    resp = await client.post(
        '/testing-ca/tsa/tsa',
        data=req.dump(),
        headers={'Content-Type': 'application/timestamp-query'},
    )
    assert resp.status == 200
    body = await resp.read()
    ts_resp: tsp.TimeStampResp = tsp.TimeStampResp.load(body)
    sd = ts_resp['time_stamp_token']['content']
    tst_info: tsp.TSTInfo = sd['encap_content_info']['content'].parsed
    assert tst_info['nonce'].native == 0x1337
    assert tst_info['gen_time'].native == datetime.now().replace(
        tzinfo=timezone.utc
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "time, expected",
    [('2020-11-05', 'good'), ('2020-12-05', 'revoked')],
)
async def test_ocsp(client, time, expected):
    with open('tests/data/signer2-ocsp-req.der', 'rb') as req_in:
        req_data = req_in.read()
    with freeze_time(time):
        resp = await client.post(
            '/testing-ca/ocsp/interm',
            data=req_data,
            headers={'Content-Type': 'application/ocsp-request'},
        )
        assert resp.status == 200
        body = await resp.read()
        ocsp_resp: ocsp.OCSPResponse = ocsp.OCSPResponse.load(body)
        assert ocsp_resp['response_status'].native == 'successful'
        rdata = ocsp_resp['response_bytes']['response'].parsed[
            'tbs_response_data'
        ]
        status = rdata['responses'][0]['cert_status'].name
        assert status == expected


@pytest.mark.asyncio
async def test_no_plugins_loaded(client):
    endpoint = '/testing-ca/plugin/encrypt-echo/test-endpoint'
    resp = await client.post(endpoint, data=b'bleh')
    assert resp.status == 404


@pytest.mark.asyncio
async def test_demo_plugin():
    with_plugin_cfg = CertomancerConfig.from_file(
        'tests/data/with-plugin.yml', 'tests/data'
    )
    app = build_animator_app(with_plugin_cfg.pki_archs, with_web_ui=False)
    async with TestClient(TestServer(app)) as c:
        endpoint = '/testing-ca/plugin/encrypt-echo/test-endpoint'
        payload = b'test test test'
        resp = await c.post(endpoint, data=payload)
        assert resp.status == 200
        body = await resp.read()

    # decrypt it
    env_data = cms.ContentInfo.load(body)['content']
    arch = with_plugin_cfg.get_pki_arch(ArchLabel('testing-ca'))
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


@pytest.mark.asyncio
async def test_crl(client):
    from tests.test_services import _check_crl_cardinality

    resp = await client.get(
        '/testing-ca/crls/interm/latest.crl',
        headers={FAKE_TIME_HEADER: "2020-11-01T00:00:00+0000"},
    )
    assert resp.status == 200
    body = await resp.read()
    _check_crl_cardinality(crl.CertificateList.load(body), expected_revoked=0)

    resp = await client.get(
        '/testing-ca/crls/interm/latest.crl',
        headers={FAKE_TIME_HEADER: "2020-12-02T00:00:00+0000"},
    )
    assert resp.status == 200
    body = await resp.read()
    _check_crl_cardinality(crl.CertificateList.load(body), expected_revoked=0)

    resp = await client.get(
        '/testing-ca/crls/interm/latest.crl',
        headers={FAKE_TIME_HEADER: "2020-12-29T00:00:00+0000"},
    )
    assert resp.status == 200
    body = await resp.read()
    some_crl3 = crl.CertificateList.load(body)
    _check_crl_cardinality(some_crl3, expected_revoked=1)
    revo = some_crl3['tbs_cert_list']['revoked_certificates'][0]
    rev_time = datetime(2020, 12, 1, tzinfo=timezone.utc)
    assert revo['revocation_date'].native == rev_time

    reason = next(
        ext['extn_value'].native
        for ext in revo['crl_entry_extensions']
        if ext['extn_id'].native == 'crl_reason'
    )
    assert reason == 'key_compromise'

    invalidity_date = next(
        ext['extn_value'].native
        for ext in revo['crl_entry_extensions']
        if ext['extn_id'].native == 'invalidity_date'
    )
    assert invalidity_date == datetime(2020, 11, 30, tzinfo=timezone.utc)


@pytest.mark.asyncio
async def test_crl_archive(client):
    from tests.test_services import _check_crl_cardinality

    resp = await client.get('/testing-ca/crls/interm/archive-1.crl')
    assert resp.status == 200
    body = await resp.read()
    _check_crl_cardinality(crl.CertificateList.load(body), expected_revoked=0)

    resp = await client.get('/testing-ca/crls/interm/archive-1000.crl')
    assert resp.status == 200
    body = await resp.read()
    _check_crl_cardinality(crl.CertificateList.load(body), expected_revoked=1)


@pytest.mark.asyncio
async def test_cert_repo(client):
    resp = await client.get('/testing-ca/certs/root/issued/interm.crt')
    assert resp.status == 200
    body1 = await resp.read()
    cert1 = x509.Certificate.load(body1)

    resp = await client.get('/testing-ca/certs/interm/ca.crt')
    assert resp.status == 200
    body2 = await resp.read()
    cert2 = x509.Certificate.load(body2)

    resp = await client.get('/_certomancer/any-cert/testing-ca/interm.crt')
    assert resp.status == 200
    body3 = await resp.read()
    cert3 = x509.Certificate.load(body3)

    assert cert1.dump() == cert2.dump() == cert3.dump()


@pytest.mark.asyncio
async def test_zip(client):
    resp = await client.get('/_certomancer/cert-bundle/testing-ca')
    assert resp.status == 200
    body = await resp.read()
    z = ZipFile(BytesIO(body))
    dumped = set(z.namelist())
    assert dumped == set(
        map(
            lambda n: 'testing-ca/' + n,
            {
                'interm/signer1-long.cert.pem',
                'interm/signer1.cert.pem',
                'interm/signer2.cert.pem',
                'interm/interm-ocsp.cert.pem',
                'root/interm.cert.pem',
                'root/tsa.cert.pem',
                'root/tsa2.cert.pem',
                'root/root.cert.pem',
            },
        )
    )


@pytest.mark.asyncio
@pytest.mark.parametrize('pw', [None, b'', b'secret'])
async def test_pkcs12(client, pw):
    data = {'cert': 'signer1'}
    if pw is not None:
        data['passphrase'] = pw.decode('ascii')
    resp = await client.post('/_certomancer/pfx-download/testing-ca', data=data)
    assert resp.status == 200
    package = await resp.read()
    from cryptography.hazmat.primitives.serialization import pkcs12

    key, cert, chain = pkcs12.load_key_and_certificates(package, password=pw)
    assert key is not None
    assert len(chain) == 2


@pytest.mark.asyncio
async def test_index(client):
    resp = await client.get('/')
    assert resp.status == 200
    body = await resp.read()
    assert b'testing-ca' in body


@pytest.mark.asyncio
async def test_fake_time_override(client):
    """X-Certomancer-Fake-Time header should influence CRL generation."""
    from tests.test_services import _check_crl_cardinality

    resp = await client.get(
        '/testing-ca/crls/interm/latest.crl',
        headers={FAKE_TIME_HEADER: "2020-12-29T00:00:00+0000"},
    )
    assert resp.status == 200
    body = await resp.read()
    # After revocation date of signer2, CRL should have 1 revoked entry
    _check_crl_cardinality(crl.CertificateList.load(body), expected_revoked=1)


@pytest.mark.asyncio
async def test_unknown_arch(client):
    resp = await client.get('/nonexistent-arch/certs/root/ca.crt')
    assert resp.status == 404


@pytest.mark.asyncio
async def test_no_web_ui(client_no_ui):
    resp = await client_no_ui.get('/')
    assert resp.status == 404

    resp = await client_no_ui.get(
        '/_certomancer/any-cert/testing-ca/interm.crt'
    )
    assert resp.status == 404


@pytest.mark.asyncio
async def test_attr_cert_repo_aa(client):
    resp = await client.get('/testing-ca-with-aa/attr-certs/role-aa/aa.crt')
    assert resp.status == 200
    body = await resp.read()
    cert = x509.Certificate.load(body)
    assert cert is not None


@pytest.mark.asyncio
async def test_attr_cert_repo_issued(client):
    resp = await client.get(
        '/testing-ca-with-aa/attr-certs/role-aa/issued/test-ac.attr.crt'
    )
    assert resp.status == 200
    body = await resp.read()
    ac = cms.AttributeCertificateV2.load(body)
    assert ac is not None


@pytest.mark.asyncio
async def test_attr_cert_repo_by_holder(client):
    resp = await client.get(
        '/testing-ca-with-aa/attr-certs/role-aa/by-holder/signer2-all.attr.cert.pem'
    )
    assert resp.status == 200
    body = await resp.read()
    assert b'ATTRIBUTE CERTIFICATE' in body


@pytest.mark.asyncio
async def test_any_attr_cert(client):
    resp = await client.get(
        '/_certomancer/any-attr-cert/testing-ca-with-aa/test-ac.attr.crt'
    )
    assert resp.status == 200
    body = await resp.read()
    ac = cms.AttributeCertificateV2.load(body)
    assert ac is not None


@pytest.mark.asyncio
async def test_attr_certs_of(client):
    resp = await client.get(
        '/_certomancer/attr-certs-of/testing-ca-with-aa/signer2-all.attr.cert.pem'
    )
    assert resp.status == 200
    body = await resp.read()
    assert b'ATTRIBUTE CERTIFICATE' in body


@pytest.mark.asyncio
async def test_attr_cert_not_found(client):
    resp = await client.get(
        '/testing-ca-with-aa/attr-certs/role-aa/issued/nonexistent.attr.crt'
    )
    assert resp.status == 404


@pytest.mark.asyncio
async def test_attr_cert_wrong_arch(client):
    resp = await client.get(
        '/nonexistent-arch/attr-certs/role-aa/issued/test-ac.attr.crt'
    )
    assert resp.status == 404
