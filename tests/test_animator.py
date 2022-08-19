import hashlib
import os
from datetime import datetime
from io import BytesIO
from zipfile import ZipFile

import pytest
import pytz
from asn1crypto import algos, cms, core, crl, ocsp, tsp, x509
from freezegun import freeze_time
from oscrypto import asymmetric
from oscrypto import keys as oskeys
from oscrypto import symmetric
from werkzeug.test import Client
from werkzeug.wrappers import Response

from certomancer import CertomancerConfig
from certomancer.integrations.animator import (
    FAKE_TIME_HEADER,
    Animator,
    AnimatorArchStore,
    app,
)
from certomancer.registry import ArchLabel, KeyLabel

os.environ['CERTOMANCER_CONFIG'] = 'tests/data/with-services.yml'
os.environ['CERTOMANCER_KEY_DIR'] = 'tests/data'
CLIENT = Client(app, Response)


@freeze_time('2020-11-01')
def test_timestamp():
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
    response = CLIENT.post("/testing-ca/tsa/tsa", data=req.dump())
    resp: tsp.TimeStampResp = tsp.TimeStampResp.load(response.data)
    sd = resp['time_stamp_token']['content']
    tst_info: tsp.TSTInfo = sd['encap_content_info']['content'].parsed
    assert tst_info['nonce'].native == 0x1337
    assert tst_info['gen_time'].native == datetime.now().replace(
        tzinfo=pytz.utc
    )


@pytest.mark.parametrize(
    "time, expected", [('2020-11-05', 'good'), ('2020-12-05', 'revoked')]
)
def test_ocsp(time, expected):
    with open('tests/data/signer2-ocsp-req.der', 'rb') as req_in:
        req_data = req_in.read()
    with freeze_time(time):
        response = CLIENT.post("/testing-ca/ocsp/interm", data=req_data)
        resp: ocsp.OCSPResponse = ocsp.OCSPResponse.load(response.data)
        assert resp['response_status'].native == 'successful'

        rdata = resp['response_bytes']['response'].parsed['tbs_response_data']
        status = rdata['responses'][0]['cert_status'].name
        assert status == expected


def test_no_plugins_loaded():
    # make the endpoint encrypt something
    endpoint = '/testing-ca/plugin/encrypt-echo/test-endpoint'
    response = CLIENT.post(endpoint, data=b'bleh')
    assert response.status_code == 404


def test_demo_plugin():

    with_plugin_cfg = CertomancerConfig.from_file(
        'tests/data/with-plugin.yml', 'tests/data'
    )

    with_plugin_app = Animator(
        AnimatorArchStore(with_plugin_cfg.pki_archs), with_web_ui=False
    )
    client = Client(with_plugin_app, Response)

    # make the endpoint encrypt something
    endpoint = '/testing-ca/plugin/encrypt-echo/test-endpoint'
    payload = b'test test test'
    response = client.post(endpoint, data=payload)

    # decrypt it
    env_data = cms.ContentInfo.load(response.data)['content']
    arch = with_plugin_cfg.get_pki_arch(ArchLabel('testing-ca'))
    key = arch.key_set.get_private_key(KeyLabel('signer1'))
    ktri = env_data['recipient_infos'][0].chosen
    encrypted_key = ktri['encrypted_key'].native

    decrypted_key = asymmetric.rsa_pkcs1v15_decrypt(
        asymmetric.load_private_key(key.dump()), encrypted_key
    )

    eci = env_data['encrypted_content_info']
    cea = eci['content_encryption_algorithm']
    assert cea['algorithm'].native == 'aes256_cbc'
    iv = cea['parameters'].native
    encrypted_content_bytes = eci['encrypted_content'].native
    decrypted_payload = symmetric.aes_cbc_pkcs7_decrypt(
        decrypted_key, encrypted_content_bytes, iv
    )
    assert decrypted_payload == payload


def test_crl():
    from tests.test_services import _check_crl_cardinality

    response = CLIENT.get(
        '/testing-ca/crls/interm/latest.crl',
        headers={FAKE_TIME_HEADER: "2020-11-01T00:00:00+0000"},
    )
    _check_crl_cardinality(
        crl.CertificateList.load(response.data), expected_revoked=0
    )
    response = CLIENT.get(
        '/testing-ca/crls/interm/latest.crl',
        headers={FAKE_TIME_HEADER: "2020-12-02T00:00:00+0000"},
    )
    _check_crl_cardinality(
        crl.CertificateList.load(response.data), expected_revoked=0
    )
    response = CLIENT.get(
        '/testing-ca/crls/interm/latest.crl',
        headers={FAKE_TIME_HEADER: "2020-12-29T00:00:00+0000"},
    )
    some_crl3 = crl.CertificateList.load(response.data)
    _check_crl_cardinality(some_crl3, expected_revoked=1)
    revo = some_crl3['tbs_cert_list']['revoked_certificates'][0]
    rev_time = datetime(2020, 12, 1, tzinfo=pytz.utc)
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
    assert invalidity_date == datetime(2020, 11, 30, tzinfo=pytz.utc)


def test_crl_archive():
    from tests.test_services import _check_crl_cardinality

    response = CLIENT.get('/testing-ca/crls/interm/archive-1.crl')
    _check_crl_cardinality(
        crl.CertificateList.load(response.data), expected_revoked=0
    )
    from tests.test_services import _check_crl_cardinality

    response = CLIENT.get('/testing-ca/crls/interm/archive-1000.crl')
    _check_crl_cardinality(
        crl.CertificateList.load(response.data), expected_revoked=1
    )


def test_cert_repo():
    response = CLIENT.get('/testing-ca/certs/root/issued/interm.crt')
    assert response.status_code == 200
    cert1 = x509.Certificate.load(response.data)
    response = CLIENT.get('/testing-ca/certs/interm/ca.crt')
    assert response.status_code == 200
    cert2 = x509.Certificate.load(response.data)

    assert app.animator.with_web_ui
    response = CLIENT.get('/_certomancer/any-cert/testing-ca/interm.crt')
    assert response.status_code == 200
    cert3 = x509.Certificate.load(response.data)
    assert cert1.dump() == cert2.dump() == cert3.dump()


def test_zip():
    response = CLIENT.get('/_certomancer/cert-bundle/testing-ca')
    z = ZipFile(BytesIO(response.data))
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


@pytest.mark.parametrize('pw', [None, b'', b'secret'])
def test_pkcs12(pw):
    data = {'cert': 'signer1'}
    if pw is not None:
        data['passphrase'] = pw.decode('ascii')
    response = CLIENT.post('/_certomancer/pfx-download/testing-ca', data=data)
    package = response.data
    if pw:
        # there's something about passwordless PKCS#12 files that doesn't quite
        # jive between oscrypto and pyca/cryptography
        key, cert, chain = oskeys.parse_pkcs12(package, password=pw)
        assert 'Alice' in cert.subject.human_friendly
        assert len(chain) == 2
        assert key is not None

    from cryptography.hazmat.primitives.serialization import pkcs12

    key, cert, chain = pkcs12.load_key_and_certificates(package, password=pw)
    assert key is not None
    assert len(chain) == 2


def test_index():
    response = CLIENT.get('/')
    assert b'testing-ca' in response.data
