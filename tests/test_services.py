import hashlib
import importlib
import itertools
from collections import namedtuple
from datetime import datetime

import pytest
import pytz
import requests
from asn1crypto import algos, cms, core, ocsp, tsp
from freezegun import freeze_time
from oscrypto import asymmetric, symmetric
from pyhanko_certvalidator import CertificateValidator, ValidationContext

from certomancer.integrations import illusionist
from certomancer.registry import (
    ArchLabel,
    CertLabel,
    CertomancerConfig,
    KeyLabel,
    ServiceLabel,
)

importlib.import_module('certomancer.default_plugins')


ServiceSetup = namedtuple('ServiceSetup', ('config', 'arch', 'illusionist'))


def _setup(cfgfile) -> ServiceSetup:

    cfg = CertomancerConfig.from_file(cfgfile, 'tests/data')

    arch = cfg.get_pki_arch(ArchLabel('testing-ca'))

    return ServiceSetup(cfg, arch, illusionist.Illusionist(pki_arch=arch))


RSA_SETUP = _setup('tests/data/with-services.yml')
DSA_SETUP = _setup('tests/data/with-services-dsa.yml')
ECDSA_SETUP = _setup('tests/data/with-services-ecdsa.yml')


def _check_crl_cardinality(crl, expected_revoked):
    assert len(crl['tbs_cert_list']['revoked_certificates']) == expected_revoked


@pytest.mark.parametrize('setup', [RSA_SETUP, DSA_SETUP, ECDSA_SETUP])
def test_crl(setup):
    some_crl = setup.arch.service_registry.get_crl(
        ServiceLabel('interm'),
        at_time=datetime.fromisoformat('2020-11-01 00:00:00+00:00'),
    )
    _check_crl_cardinality(some_crl, expected_revoked=0)
    some_crl2 = setup.arch.service_registry.get_crl(
        ServiceLabel('interm'),
        at_time=datetime.fromisoformat('2020-12-02 00:00:00+00:00'),
    )
    _check_crl_cardinality(some_crl2, expected_revoked=0)
    some_crl3 = setup.arch.service_registry.get_crl(
        ServiceLabel('interm'),
        at_time=datetime.fromisoformat('2020-12-29 00:00:00+00:00'),
    )
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


def test_aa_crl():

    cfg = CertomancerConfig.from_file(
        'tests/data/with-services.yml', 'tests/data'
    )

    arch = cfg.get_pki_arch(ArchLabel('testing-ca-with-aa'))

    setup = ServiceSetup(cfg, arch, illusionist.Illusionist(pki_arch=arch))
    some_crl = setup.arch.service_registry.get_crl(
        ServiceLabel('role-aa'),
        at_time=datetime.fromisoformat('2020-11-01 00:00:00+00:00'),
    )
    _check_crl_cardinality(some_crl, expected_revoked=0)
    some_crl2 = setup.arch.service_registry.get_crl(
        ServiceLabel('role-aa'),
        at_time=datetime.fromisoformat('2020-12-02 00:00:00+00:00'),
    )
    _check_crl_cardinality(some_crl2, expected_revoked=0)
    some_crl3 = setup.arch.service_registry.get_crl(
        ServiceLabel('role-aa'),
        at_time=datetime.fromisoformat('2020-12-29 00:00:00+00:00'),
    )
    _check_crl_cardinality(some_crl3, expected_revoked=1)

    idp = next(
        ext['extn_value'].native
        for ext in some_crl3['tbs_cert_list']['crl_extensions']
        if ext['extn_id'].native == 'issuing_distribution_point'
    )
    assert bool(idp['only_contains_attribute_certs'])


@pytest.mark.parametrize('setup', [RSA_SETUP, DSA_SETUP, ECDSA_SETUP])
def test_aia_ca_issuers(setup):
    signer1 = setup.arch.get_cert(CertLabel('signer1'))
    ca_issuer_urls = {
        aia_entry['access_location']
        for aia_entry in signer1.authority_information_access_value.native
        if aia_entry['access_method'] == 'ca_issuers'
    }
    assert ca_issuer_urls == {
        'http://test.test/testing-ca/certs/interm/ca.crt',
        'http://test.test/testing-ca/certs/root/issued/interm.crt',
    }


@freeze_time('2020-11-01')
@pytest.mark.asyncio
@pytest.mark.parametrize('setup', [RSA_SETUP, DSA_SETUP, ECDSA_SETUP])
async def test_validate(requests_mock, setup):
    setup.illusionist.register(requests_mock)
    signer_cert = setup.arch.get_cert(CertLabel('signer1'))
    root = setup.arch.get_cert(CertLabel('root'))
    interm = setup.arch.get_cert(CertLabel('interm'))
    vc = ValidationContext(
        trust_roots=[root],
        allow_fetching=True,
        revocation_mode='hard-fail',
        other_certs=[interm],
    )

    validator = CertificateValidator(
        signer_cert, intermediate_certs=[], validation_context=vc
    )
    await validator.async_validate_usage({'digital_signature'})

    assert len(vc.ocsps)
    assert len(vc.crls)


@freeze_time('2020-11-01')
@pytest.mark.parametrize(
    'setup,include_nonce',
    list(itertools.product([RSA_SETUP, DSA_SETUP, ECDSA_SETUP], (True, False))),
)
def test_timestamp(requests_mock, setup, include_nonce):
    setup.illusionist.register(requests_mock)
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
    response = requests.post(
        "http://test.test/testing-ca/tsa/tsa", data=req.dump()
    )
    resp: tsp.TimeStampResp = tsp.TimeStampResp.load(response.content)
    sd = resp['time_stamp_token']['content']
    tst_info: tsp.TSTInfo = sd['encap_content_info']['content'].parsed
    if include_nonce:
        assert tst_info['nonce'].native == 0x1337
    assert tst_info['gen_time'].native == datetime.now().replace(
        tzinfo=pytz.utc
    )


@pytest.mark.parametrize(
    "time, expected", [('2020-11-05', 'good'), ('2020-12-05', 'revoked')]
)
def test_ocsp(requests_mock, time, expected):
    setup = RSA_SETUP
    setup.illusionist.register(requests_mock)
    with open('tests/data/signer2-ocsp-req.der', 'rb') as req_in:
        req_data = req_in.read()
    with freeze_time(time):
        response = requests.post(
            "http://test.test/testing-ca/ocsp/interm", data=req_data
        )
        resp: ocsp.OCSPResponse = ocsp.OCSPResponse.load(response.content)
        assert resp['response_status'].native == 'successful'

        rdata = resp['response_bytes']['response'].parsed['tbs_response_data']
        status = rdata['responses'][0]['cert_status'].name
        assert status == expected


@pytest.mark.parametrize(
    "time, expected", [('2020-11-05', 'good'), ('2020-12-05', 'revoked')]
)
def test_aa_ocsp(requests_mock, time, expected):
    cfg = CertomancerConfig.from_file(
        'tests/data/with-services.yml', 'tests/data'
    )

    arch = cfg.get_pki_arch(ArchLabel('testing-ca-with-aa'))

    setup = ServiceSetup(cfg, arch, illusionist.Illusionist(pki_arch=arch))
    setup.illusionist.register(requests_mock)

    with open('tests/data/test-ac-ocsp-req.der', 'rb') as req_in:
        req_data = req_in.read()

    with freeze_time(time):
        response = requests.post(
            "http://test.test/testing-ca-with-aa/ocsp/role-aa", data=req_data
        )
        resp: ocsp.OCSPResponse = ocsp.OCSPResponse.load(response.content)
        assert resp['response_status'].native == 'successful'

        rdata = resp['response_bytes']['response'].parsed['tbs_response_data']
        status = rdata['responses'][0]['cert_status'].name
        assert status == expected


@freeze_time('2020-11-01')
@pytest.mark.parametrize(
    'fname', ['tests/data/tsa-ocsp-req.der', 'tests/data/tsa-bad-ocsp-req.der']
)
def test_ocsp_unauthorized(requests_mock, fname):
    setup = RSA_SETUP
    setup.illusionist.register(requests_mock)
    # 1st file: request OK, but this responder can't answer for the issuer
    # in question
    # 2nd file: actual issuer of the cert and issuer in the OCSP req are not
    # the same => the certid won't be found in the (simulated) database, so
    # we should also get 'unauthorized'
    with open(fname, 'rb') as req_in:
        req_data = req_in.read()
    response = requests.post(
        "http://test.test/testing-ca/ocsp/interm", data=req_data
    )
    resp: ocsp.OCSPResponse = ocsp.OCSPResponse.load(response.content)
    assert resp['response_status'].native == 'unauthorized'


def test_demo_plugin(requests_mock):

    with_plugin_cfg = CertomancerConfig.from_file(
        'tests/data/with-plugin.yml', 'tests/data'
    )

    arch = with_plugin_cfg.get_pki_arch(ArchLabel('testing-ca'))

    illusionist.Illusionist(pki_arch=arch).register(requests_mock)

    importlib.import_module('example_plugin.encrypt_echo')

    # make the endpoint encrypt something
    endpoint = 'http://test.test/testing-ca/plugin/encrypt-echo/test-endpoint'
    payload = b'test test test'
    response = requests.post(endpoint, data=payload)

    # decrypt it
    env_data = cms.ContentInfo.load(response.content)['content']
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


def test_svc_template_result():
    cfg = CertomancerConfig.from_file(
        'tests/data/with-services.yml', 'tests/data'
    )

    arch = cfg.get_pki_arch(ArchLabel('testing-ca-with-aa'))
    # new OCSP responder
    arch.service_registry.get_ocsp_info(ServiceLabel('role-aa'))
    # inherited OCSP responder
    arch.service_registry.get_ocsp_info(ServiceLabel('interm'))
    # no new TSAs, but this should still work
    arch.service_registry.get_tsa_info(ServiceLabel('tsa'))
