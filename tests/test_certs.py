import hashlib
import importlib
import os
import re
from datetime import datetime
from io import BytesIO
from typing import Any
from zipfile import ZipFile

import pyhanko_certvalidator
import pytest
import pytz
import yaml
from asn1crypto import cms, core, x509
from oscrypto import keys as oskeys
from pyhanko_certvalidator import ValidationContext

from certomancer import CertProfilePlugin
from certomancer.config_utils import ConfigurationError, SearchDir
from certomancer.crypto_utils import load_cert_from_pemder
from certomancer.registry import (
    ArchLabel,
    CertLabel,
    CertomancerConfig,
    EntityLabel,
    PKIArchitecture,
)
from certomancer.registry.entities import EntityRegistry
from certomancer.registry.issued.attr_cert import HolderSpec
from certomancer.registry.issued.general import ExtensionSpec
from certomancer.registry.keys import KeySet
from certomancer.registry.plugin_api import CertProfilePluginRegistry

importlib.import_module('certomancer.default_plugins')

DUMMY_PASSWORD = b'secret'


KEY_NAME_REGEX = re.compile(r'([a-zA-Z0-9-]+)\.key\.pem')

TEST_DATA_DIR = 'tests/data'

CONFIG = CertomancerConfig.from_file(
    'tests/data/with-services.yml', 'tests/data'
)


def dir_to_keyset_cfg(dirpath):
    def _keys():
        for fname in os.listdir(os.path.join(TEST_DATA_DIR, dirpath)):
            m = KEY_NAME_REGEX.fullmatch(fname)
            if not m:
                continue
            cfg = {'path': fname}

            # identify public keys in test set by whether 'pub' occurs
            # in the file name
            if 'pub' in fname:
                cfg['public-only'] = True
            else:
                cfg['password'] = DUMMY_PASSWORD.decode('ascii')
            yield m.group(1), cfg

    return {'path-prefix': dirpath, 'keys': {k: v for k, v in _keys()}}


def dir_to_keyset(dirpath):
    return KeySet(
        dir_to_keyset_cfg(dirpath), search_dir=SearchDir(TEST_DATA_DIR)
    )


RSA_KEYS = dir_to_keyset('keys-rsa')
ECDSA_KEYS = dir_to_keyset('keys-ecdsa')

ENTITIES = EntityRegistry(
    yaml.safe_load(
        '''
root:
    common-name: Root CA
interm:
    common-name: Intermediate CA
tsa:
    common-name: Time Stamping Authority
interm-ocsp:
    common-name: OCSP responder
signer1:
    organizational-unit-name: Signers
    common-name: Alice
signer2:
    organizational-unit-name: Signers
    common-name: Bob
pub-only:
    organizational-unit-name: Signers
    common-name: Priv Key Unknown
'''
    ),
    defaults=yaml.safe_load(
        '''
country-name: BE
organization-name: Testing Authority
'''
    ),
)


@pytest.mark.parametrize('label', ['root', 'root-ca'])
def test_self_signed(label):
    cfg = f'''
      {label}:
        subject: root
        subject-key: root
        issuer: root
        authority-key: root
        validity:
          valid-from: "2000-01-01T00:00:00+0000"
          valid-to: "2500-01-01T00:00:00+0000"
        extensions:
          - id: basic_constraints
            critical: true
            value:
              ca: true
          - id: key_usage
            critical: true
            smart-value:
              schema: key-usage
              params: [digital_signature, key_cert_sign, crl_sign]
    '''

    arch = PKIArchitecture(
        arch_label=ArchLabel('test'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config=yaml.safe_load(cfg),
        service_config={},
        external_url_prefix='http://test.test',
    )
    root_cert = arch.get_cert(CertLabel(label))
    assert root_cert.subject == ENTITIES[EntityLabel('root')]
    assert root_cert.issuer == ENTITIES[EntityLabel('root')]
    assert root_cert.not_valid_before == datetime(2000, 1, 1, tzinfo=pytz.utc)


def test_detect_self_reference():
    cfg = '''
      root:
        subject: root
        subject-key: root
        issuer: root
        authority-key: root
        validity:
          valid-from: "2000-01-01T00:00:00+0000"
          valid-to: "2500-01-01T00:00:00+0000"
      other:
        subject: root
        subject-key: root
        issuer: root
        authority-key: interm
        issuer-cert: other
        validity:
          valid-from: "2000-01-01T00:00:00+0000"
          valid-to: "2500-01-01T00:00:00+0000"
    '''

    arch = PKIArchitecture(
        arch_label=ArchLabel('test'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config=yaml.safe_load(cfg),
        service_config={},
        external_url_prefix='http://test.test',
    )
    with pytest.raises(ConfigurationError, match='Self-reference'):
        arch.get_cert(CertLabel('other'))


def test_template_does_not_copy_inferred_authority_key():
    cfg = '''
      root:
        subject: root
        issuer: root
        validity:
          valid-from: "2000-01-01T00:00:00+0000"
          valid-to: "2500-01-01T00:00:00+0000"
      tsa:
        template: root
        subject: tsa
        issuer: tsa
    '''

    arch = PKIArchitecture(
        arch_label=ArchLabel('test'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config=yaml.safe_load(cfg),
        service_config={},
        external_url_prefix='http://test.test',
    )
    root_cert = arch.get_cert(CertLabel('root'))
    assert root_cert.subject == ENTITIES[EntityLabel('root')]
    assert root_cert.issuer == ENTITIES[EntityLabel('root')]
    assert root_cert.not_valid_before == datetime(2000, 1, 1, tzinfo=pytz.utc)
    other_cert = arch.get_cert(CertLabel('tsa'))
    assert other_cert.subject == ENTITIES[EntityLabel('tsa')]
    assert other_cert.issuer == ENTITIES[EntityLabel('tsa')]
    # check whether this was copied
    assert other_cert.not_valid_before == datetime(2000, 1, 1, tzinfo=pytz.utc)


BASIC_AC_ISSUER_SETUP = '''
  ac-issuer:
    subject: root
    subject-key: root
    issuer: root
    authority-key: root
    validity:
      valid-from: "2000-01-01T00:00:00+0000"
      valid-to: "2500-01-01T00:00:00+0000"
    extensions:
      - id: key_usage
        critical: true
        smart-value:
          schema: key-usage
          params: [digital_signature, key_cert_sign, crl_sign]
      - id: aa_controls
        critical: true
        value:
          path_len_constraint: 0
          permitted_attrs: ['role']
  signer:
    subject: signer1
    subject-key: signer
    issuer: root
    validity:
      valid-from: "2000-01-01T00:00:00+0000"
      valid-to: "2100-01-01T00:00:00+0000"
    extensions:
      - id: key_usage
        critical: true
        smart-value:
          schema: key-usage
          params: [digital_signature]
'''


def test_attr_cert_spec():
    attr_cert_cfg = '''
    test-ac:
      holder:
          name: signer
          cert: signer
      issuer: root
      attributes:
          - id: role
            smart-value:
              schema: role-syntax
              params:
                  name: {type: email, value: blah@example.com}
          - id: group
            smart-value:
                schema: ietf-attribute
                params:
                    - type: string
                      value: "Big Corp Inc. Employees"
                    - type: octets
                      value: deadbeef
                    - type: oid
                      value: "2.999"
          - id: charging_identity
            smart-value:
                schema: ietf-attribute
                params: ["Big Corp Inc."]
          - id: authentication_info
            smart-value:
                schema: service-auth-info
                params:
                    service: {type: dns_name, value: admin.example.com}
                    ident: {type: email, value: blah@example.com}
                    auth-info: deadbeef
          - id: access_identity
            smart-value:
                schema: service-auth-info
                params:
                    service: {type: dns_name, value: admin.example.com}
                    ident: {type: email, value: blah@example.com}
      validity:
        valid-from: "2010-01-01T00:00:00+0000"
        valid-to: "2011-01-01T00:00:00+0000"
    '''

    arch = PKIArchitecture(
        arch_label=ArchLabel('test'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config=yaml.safe_load(BASIC_AC_ISSUER_SETUP),
        ac_spec_config=yaml.safe_load(attr_cert_cfg),
        service_config={},
        external_url_prefix='http://test.test',
    )
    test_ac_spec = arch.get_attr_cert_spec(CertLabel('test-ac'))
    assert test_ac_spec.attributes[0].id == 'role'
    assert test_ac_spec.attributes[1].id == 'group'
    assert test_ac_spec.attributes[2].id == 'charging_identity'
    assert test_ac_spec.attributes[3].id == 'authentication_info'
    assert test_ac_spec.attributes[4].id == 'access_identity'
    test_ac = arch.get_attr_cert(CertLabel('test-ac'))
    attrs = test_ac['ac_info']['attributes']
    assert attrs[0]['type'].native == 'role'
    assert attrs[1]['type'].native == 'group'
    group_attr_syntax = attrs[1]['values'][0]
    assert group_attr_syntax['values'][0].native == "Big Corp Inc. Employees"
    assert group_attr_syntax['values'][1].native == b"\xde\xad\xbe\xef"
    assert group_attr_syntax['values'][2].chosen == core.ObjectIdentifier(
        "2.999"
    )

    assert attrs[2]['type'].native == 'charging_identity'
    assert attrs[2]['values'][0]['values'][0].native == "Big Corp Inc."
    ac_iss = arch.get_cert(CertLabel('ac-issuer'))
    assert len(ac_iss['tbs_certificate']['extensions']) == 4

    assert attrs[3]['type'].native == 'authentication_info'
    assert attrs[3]['values'][0]['service'].native == 'admin.example.com'
    assert attrs[3]['values'][0]['ident'].native == 'blah@example.com'
    assert attrs[3]['values'][0]['auth_info'].native == b'\xde\xad\xbe\xef'

    assert attrs[4]['type'].native == 'access_identity'
    assert attrs[4]['values'][0]['service'].native == 'admin.example.com'
    assert attrs[4]['values'][0]['ident'].native == 'blah@example.com'


def test_attr_cert_targets():
    attr_cert_cfg = '''
    test-ac:
      holder:
          name: signer
          cert: signer
      issuer: root
      attributes:
          - id: role
            smart-value:
              schema: role-syntax
              params:
                  name: {type: email, value: blah@example.com}
      validity:
        valid-from: "2010-01-01T00:00:00+0000"
        valid-to: "2011-01-01T00:00:00+0000"
      extensions:
          - id: target_information
            critical: true
            smart-value:
              schema: ac-targets
              params:
                  - signer2
                  - type: dns_name
                    value: example.com
                    is-group: true
    '''

    arch = PKIArchitecture(
        arch_label=ArchLabel('test'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config=yaml.safe_load(BASIC_AC_ISSUER_SETUP),
        ac_spec_config=yaml.safe_load(attr_cert_cfg),
        service_config={},
        external_url_prefix='http://test.test',
    )
    test_ac = arch.get_attr_cert(CertLabel('test-ac'))

    targets_ext = next(
        ext['extn_value'].parsed
        for ext in test_ac['ac_info']['extensions']
        if ext['extn_id'].native == 'target_information'
    )
    targets_obj = targets_ext[0]
    assert len(targets_obj) == 2
    assert targets_obj[0].name == 'target_name'
    assert 'Bob' in targets_obj[0].chosen.chosen.human_friendly
    assert targets_obj[1].name == 'target_group'
    assert 'example.com' == targets_obj[1].chosen.native


def test_issue_intermediate():
    cfg = '''
      root-ca:
        subject: root
        subject-key: root
        issuer: root
        authority-key: root
        validity:
          valid-from: "2000-01-01T00:00:00+0000"
          valid-to: "2500-01-01T00:00:00+0000"
        extensions:
          - id: basic_constraints
            critical: true
            value:
              ca: true
          - id: key_usage
            critical: true
            smart-value:
              schema: key-usage
              params: [digital_signature, key_cert_sign, crl_sign]
      intermediate-ca:
        subject: interm
        issuer: root
        validity:
          valid-from: "2000-01-01T00:00:00+0000"
          valid-to: "2100-01-01T00:00:00+0000"
        extensions:
          - id: basic_constraints
            critical: true
            value:
              ca: true
              path-len-constraint: 0
          - id: key_usage
            critical: true
            smart-value:
              schema: key-usage
              params: [digital_signature, key_cert_sign, crl_sign]
    '''

    arch = PKIArchitecture(
        arch_label=ArchLabel('test'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config=yaml.safe_load(cfg),
        service_config={},
        external_url_prefix='http://test.test',
    )
    root_cert = arch.get_cert(CertLabel('root-ca'))
    assert root_cert.subject == ENTITIES[EntityLabel('root')]
    assert root_cert.issuer == ENTITIES[EntityLabel('root')]
    assert root_cert.not_valid_before == datetime(2000, 1, 1, tzinfo=pytz.utc)
    interm_cert = arch.get_cert(CertLabel('intermediate-ca'))
    assert interm_cert.subject == ENTITIES[EntityLabel('interm')]
    assert root_cert.issuer == ENTITIES[EntityLabel('root')]
    assert root_cert.not_valid_before == datetime(2000, 1, 1, tzinfo=pytz.utc)


def test_template_override_issuer():
    cfg = '''
      root-ca:
        subject: root
        subject-key: root
        issuer: root
        authority-key: root
        validity:
          valid-from: "2000-01-01T00:00:00+0000"
          valid-to: "2500-01-01T00:00:00+0000"
        extensions:
          - id: basic_constraints
            critical: true
            value:
              ca: true
          - id: key_usage
            critical: true
            smart-value:
              schema: key-usage
              params: [digital_signature, key_cert_sign, crl_sign]
      intermediate-ca:
        subject: interm
        issuer: root
        validity:
          valid-from: "2000-01-01T00:00:00+0000"
          valid-to: "2100-01-01T00:00:00+0000"
        extensions:
          - id: basic_constraints
            critical: true
            value:
              ca: true
              path-len-constraint: 0
          - id: key_usage
            critical: true
            smart-value:
              schema: key-usage
              params: [digital_signature, key_cert_sign, crl_sign]
      leaf:
        issuer: interm
        subject: signer1
        subject-key: signer
        validity:
          valid-from: "2020-01-01T00:00:00+0000"
          valid-to: "2022-01-01T00:00:00+0000"
        extensions:
          - id: key_usage
            critical: true
            smart-value:
              schema: key-usage
              params: [digital_signature, non_repudiation]
      leaf-copy:
        subject: signer1
        subject-key: signer
        template: leaf
        issuer: root
    '''

    arch = PKIArchitecture(
        arch_label=ArchLabel('test'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config=yaml.safe_load(cfg),
        service_config={},
        external_url_prefix='http://test.test',
    )
    root_cert = arch.get_cert(CertLabel('root-ca'))
    interm_cert = arch.get_cert(CertLabel('intermediate-ca'))
    leaf = arch.get_cert(CertLabel('leaf'))
    leaf_copy = arch.get_cert(CertLabel('leaf-copy'))
    assert leaf.issuer == interm_cert.subject
    assert leaf_copy.issuer == root_cert.subject
    assert leaf.key_usage_value == leaf_copy.key_usage_value
    assert leaf.subject == leaf_copy.subject
    assert leaf.public_key == leaf_copy.public_key


def test_sign_public_only():
    cfg = '''
      root-ca:
        subject: root
        subject-key: root
        issuer: root
        authority-key: root
        validity:
          valid-from: "2000-01-01T00:00:00+0000"
          valid-to: "2500-01-01T00:00:00+0000"
        extensions:
          - id: basic_constraints
            critical: true
            value:
              ca: true
          - id: key_usage
            critical: true
            smart-value:
              schema: key-usage
              params: [digital_signature, key_cert_sign, crl_sign]
      leaf:
          subject: pub-only
          subject-key: split-key-pub
          issuer: root
          authority-key: root
          validity:
            valid-from: "2020-01-01T00:00:00+0000"
            valid-to: "2050-01-01T00:00:00+0000"
          extensions:
            - id: key_usage
              critical: true
              smart-value:
                schema: key-usage
                params: [digital_signature]
    '''

    arch = PKIArchitecture(
        arch_label=ArchLabel('test'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config=yaml.safe_load(cfg),
        service_config={},
        external_url_prefix='http://test.test',
    )
    pubkey = arch.get_cert(CertLabel('leaf')).public_key
    with open('tests/data/keys-rsa/split-key-pub.key.pem', 'rb') as inf:
        pubkey_actual = oskeys.parse_public(inf.read())
    assert pubkey.native == pubkey_actual.native


@pytest.mark.parametrize(
    'order',
    [
        ('interm', 'root', 'signer1'),
        ('signer1', 'root', 'interm'),
        ('root', 'signer1', 'interm'),
    ],
)
def test_serial_order_indep(order):
    arch = CONFIG.get_pki_arch(ArchLabel('testing-ca'))
    for lbl in order:
        arch.get_cert(CertLabel(lbl))

    assert arch.get_cert(CertLabel('root')).serial_number == 4096
    assert arch.get_cert(CertLabel('interm')).serial_number == 4097
    assert arch.get_cert(CertLabel('signer1')).serial_number == 4097


def _collect_files(path):
    for cur, dirs, files in os.walk(path):
        for file in files:
            yield os.path.relpath(os.path.join(cur, file), path)


def test_dump_no_pfx(tmp_path):
    arch = CONFIG.get_pki_arch(ArchLabel('testing-ca'))
    arch.dump_certs(str(tmp_path), include_pkcs12=False)
    dumped = set(_collect_files(str(tmp_path)))
    assert dumped == {
        'interm/signer1-long.cert.pem',
        'interm/signer1.cert.pem',
        'interm/signer2.cert.pem',
        'interm/interm-ocsp.cert.pem',
        'root/interm.cert.pem',
        'root/tsa.cert.pem',
        'root/tsa2.cert.pem',
        'root/root.cert.pem',
    }


def test_dump_with_pfx(tmp_path):
    arch = CONFIG.get_pki_arch(ArchLabel('testing-ca'))
    arch.dump_certs(str(tmp_path), include_pkcs12=True)
    dumped = set(_collect_files(str(tmp_path)))
    assert dumped == {
        'interm/signer1-long.cert.pem',
        'interm/signer1-long.pfx',
        'interm/signer1.cert.pem',
        'interm/signer1.pfx',
        'interm/signer2.cert.pem',
        'interm/signer2.pfx',
        'interm/interm-ocsp.cert.pem',
        'interm/interm-ocsp.pfx',
        'root/interm.cert.pem',
        'root/interm.pfx',
        'root/tsa.cert.pem',
        'root/tsa.pfx',
        'root/tsa2.cert.pem',
        'root/tsa2.pfx',
        'root/root.cert.pem',
        'root/root.pfx',
    }


def test_dump_flat_no_pfx(tmp_path):
    arch = CONFIG.get_pki_arch(ArchLabel('testing-ca'))
    arch.dump_certs(str(tmp_path), include_pkcs12=False, flat=True)
    dumped = set(_collect_files(str(tmp_path)))
    assert dumped == {
        'signer1-long.cert.pem',
        'signer1.cert.pem',
        'signer2.cert.pem',
        'interm-ocsp.cert.pem',
        'interm.cert.pem',
        'tsa.cert.pem',
        'tsa2.cert.pem',
        'root.cert.pem',
    }


def test_dump_zip():
    out = BytesIO()
    arch = CONFIG.get_pki_arch(ArchLabel('testing-ca'))
    arch.zip_certs(out)
    out.seek(0)
    z = ZipFile(out)
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


def test_subject_alt_names():
    # test whether SAN extensions are reassigned properly when using
    # cert specs as templates for other cert specs
    arch = CONFIG.get_pki_arch(ArchLabel('testing-ca'))
    signer1 = arch.get_cert(CertLabel('signer1'))
    signer2 = arch.get_cert(CertLabel('signer2'))
    signer1_long = arch.get_cert(CertLabel('signer1-long'))

    assert signer1.subject_alt_name_value[0].chosen.native == 'test@example.com'
    assert (
        signer2.subject_alt_name_value[0].chosen.native == 'test2@example.com'
    )
    assert signer1_long.subject_alt_name_value is None


def test_pss():
    cfg = CertomancerConfig.from_file(
        'tests/data/with-external-config.yml', 'tests/data'
    )
    arch = cfg.get_pki_arch(ArchLabel('testing-ca-pss'))
    assert arch.get_cert(CertLabel('root')).signature_algo == 'rsassa_pkcs1v15'
    assert arch.get_cert(CertLabel('root')).public_key.algorithm == 'rsa'

    certs = ['interm', 'signer1', 'signer2']
    for c in certs:
        assert arch.get_cert(CertLabel(c)).signature_algo == 'rsassa_pss'
        assert arch.get_cert(CertLabel(c)).public_key.algorithm == 'rsa'


def test_pss_exclusive():
    cfg = CertomancerConfig.from_file(
        'tests/data/with-external-config.yml', 'tests/data'
    )
    arch = cfg.get_pki_arch(ArchLabel('testing-ca-pss-exclusive'))
    certs = ['root', 'interm', 'signer1', 'signer2']
    for c in certs:
        assert arch.get_cert(CertLabel(c)).signature_algo == 'rsassa_pss'
        assert arch.get_cert(CertLabel(c)).public_key.algorithm == 'rsassa_pss'


@pytest.mark.parametrize('pw', [None, b'', b'secret'])
def test_pkcs12(pw):
    arch = CONFIG.get_pki_arch(ArchLabel('testing-ca'))
    package = arch.package_pkcs12(CertLabel('signer1'), password=pw)
    if pw:
        # there's something about passwordless PKCS#12 files that doesn't quite
        # jive between oscrypto and pyca/cryptography
        key, cert, chain = oskeys.parse_pkcs12(package, password=pw)
        assert cert.dump() == arch.get_cert(CertLabel('signer1')).dump()
        assert len(chain) == 2
        assert key is not None

    from cryptography.hazmat.primitives.serialization import pkcs12

    key, cert, chain = pkcs12.load_key_and_certificates(package, password=pw)
    assert key is not None
    assert len(chain) == 2


def test_raw_extension():
    cfg = '''
      root:
        subject: root
        subject-key: root
        issuer: root
        authority-key: root
        validity:
          valid-from: "2000-01-01T00:00:00+0000"
          valid-to: "2500-01-01T00:00:00+0000"
        extensions:
          - id: basic_constraints
            critical: true
            value:
              ca: true
          - id: key_usage
            critical: true
            smart-value:
              schema: key-usage
              params: [digital_signature, key_cert_sign, crl_sign]
          - id: "2.16.840.1.113730.1.1"  # this is netscape_certificate_type
            smart-value:
                schema: der-bytes
                params: "03020520"
    '''

    arch = PKIArchitecture(
        arch_label=ArchLabel('test'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config=yaml.safe_load(cfg),
        service_config={},
        external_url_prefix='http://test.test',
    )
    ext: x509.Extension = next(
        filter(
            lambda x: x['extn_id'].native == 'netscape_certificate_type',
            arch.get_cert(CertLabel('root'))['tbs_certificate']['extensions'],
        )
    )
    assert ext['extn_value'].parsed.native == {'email'}


@pytest.mark.parametrize('wrong_value', ['"xlkjd"', '[]', 'null'])
def test_raw_extension_error(wrong_value):
    cfg = f'''
      root:
        subject: root
        subject-key: root
        issuer: root
        authority-key: root
        validity:
          valid-from: "2000-01-01T00:00:00+0000"
          valid-to: "2500-01-01T00:00:00+0000"
        extensions:
          - id: basic_constraints
            critical: true
            value:
              ca: true
          - id: key_usage
            critical: true
            smart-value:
              schema: key-usage
              params: [digital_signature, key_cert_sign, crl_sign]
          - id: "2.16.840.1.113730.1.1"  # this is netscape_certificate_type
            smart-value:
                schema: der-bytes
                params: {wrong_value}
    '''

    arch = PKIArchitecture(
        arch_label=ArchLabel('test'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config=yaml.safe_load(cfg),
        service_config={},
        external_url_prefix='http://test.test',
    )
    with pytest.raises(ConfigurationError):
        arch.get_cert(CertLabel('root'))


def test_arch_templates():

    cfg = CertomancerConfig.from_file(
        'tests/data/with-arch-templates.yml', 'tests/data'
    )
    old_arch = cfg.get_pki_arch(ArchLabel('testing-ca'))
    root_name = old_arch.entities[EntityLabel('root')].human_friendly
    assert 'Country: BE' in root_name
    assert 'Test OU' not in root_name
    assert 'Organization: Testing Authority' in root_name

    new_arch = cfg.get_pki_arch(ArchLabel('testing-ca-2'))
    root_name = new_arch.entities[EntityLabel('root')].human_friendly
    assert 'Country: BE' in root_name
    assert 'Organizational Unit: Test OU' in root_name
    assert 'Organization: Testing Authority' in root_name

    newer_arch = cfg.get_pki_arch(ArchLabel('testing-ca-3'))
    root_name = newer_arch.entities[EntityLabel('root')].human_friendly
    assert 'Country: FR' in root_name
    assert 'Organizational Unit: Test OU' in root_name
    assert 'Organization: Testing Authority' in root_name


def test_keyset_templates():
    cfg = CertomancerConfig.from_file(
        'tests/data/with-arch-templates.yml', 'tests/data'
    )
    algo = cfg.key_sets['testing-ca'].get_public_key('root').algorithm
    assert algo == 'rsa'

    algo = cfg.key_sets['other-keyset'].get_public_key('root').algorithm
    assert algo == 'ed25519'


def test_keyset_templates_in_arch():

    cfg = CertomancerConfig.from_file(
        'tests/data/with-arch-templates.yml', 'tests/data'
    )
    old_arch = cfg.get_pki_arch(ArchLabel('testing-ca'))
    algo = old_arch.get_cert(CertLabel('root')).public_key.algorithm
    assert algo == 'rsa'

    new_arch = cfg.get_pki_arch(ArchLabel('testing-ca-2'))
    algo = new_arch.get_cert(CertLabel('root')).public_key.algorithm
    assert algo == 'rsa'

    newer_arch = cfg.get_pki_arch(ArchLabel('testing-ca-3'))
    algo = newer_arch.get_cert(CertLabel('root')).public_key.algorithm
    assert algo == 'ed25519'


@pytest.mark.asyncio
async def test_pregenerated_cert():
    cfg = CertomancerConfig.from_file(
        'tests/data/with-pregenerated-cert.yml', 'tests/data'
    )
    arch = cfg.get_pki_arch(ArchLabel('testing-ca'))
    ca = arch.get_cert(CertLabel('ca'))

    # ECDSA involves randomness, so this is an OK check to see if the file
    # content was actually used for the CA cert
    ca_from_disk = load_cert_from_pemder('tests/data/pregenerated-ca-cert.crt')
    assert ca.dump() == ca_from_disk.dump()

    moment = datetime(2021, 5, 10, tzinfo=pytz.utc)
    await pyhanko_certvalidator.CertificateValidator(
        end_entity_cert=arch.get_cert(CertLabel('signer')),
        validation_context=ValidationContext(trust_roots=[ca], moment=moment),
    ).async_validate_usage({'digital_signature'})


def test_holder_config1():
    holder_cfg_str = 'name: signer2'
    holder_cfg = yaml.safe_load(holder_cfg_str)
    arch = CONFIG.get_pki_arch(ArchLabel('testing-ca'))
    holder_obj = HolderSpec.from_config(holder_cfg).to_asn1(arch)
    holder_cert = arch.get_cert(CertLabel('signer2'))
    assert (
        holder_obj['base_certificate_id']['serial'].native
        == holder_cert.serial_number
    )
    assert (
        holder_obj['base_certificate_id']['issuer'][0].chosen
        == holder_cert.issuer
    )


def test_holder_config2():
    holder_cfg_str = '''
    name: signer1
    cert: signer1-long
    include-entity-name: true
    '''
    holder_cfg = yaml.safe_load(holder_cfg_str)
    arch = CONFIG.get_pki_arch(ArchLabel('testing-ca'))
    holder_obj = HolderSpec.from_config(holder_cfg).to_asn1(arch)
    holder_cert = arch.get_cert(CertLabel('signer1-long'))
    assert (
        holder_obj['base_certificate_id']['serial'].native
        == holder_cert.serial_number
    )
    assert (
        holder_obj['base_certificate_id']['issuer'][0].chosen
        == holder_cert.issuer
    )
    assert holder_obj['entity_name'][0].chosen == holder_cert.subject


def test_holder_config_digest1():
    holder_cfg_str = '''
    name: signer1
    cert: signer1-long
    include-base-cert-id: false
    include-object-digest-info: true
    '''
    holder_cfg = yaml.safe_load(holder_cfg_str)
    arch = CONFIG.get_pki_arch(ArchLabel('testing-ca'))
    holder_obj = HolderSpec.from_config(holder_cfg).to_asn1(arch)
    holder_cert = arch.get_cert(CertLabel('signer1-long'))
    odi: cms.ObjectDigestInfo = holder_obj['object_digest_info']

    assert odi['digested_object_type'].native == 'public_key_cert'
    assert odi['digest_algorithm']['algorithm'].native == 'sha256'
    assert (
        odi['object_digest'].native
        == hashlib.sha256(holder_cert.dump()).digest()
    )


@pytest.mark.parametrize('dot_str_spec', ['public_key', '0'])
def test_holder_config_digest2(dot_str_spec):
    holder_cfg_str = f'''
    name: signer1
    cert: signer1-long
    include-base-cert-id: false
    include-object-digest-info: true
    digested-object-type: {dot_str_spec}
    '''
    holder_cfg = yaml.safe_load(holder_cfg_str)
    arch = CONFIG.get_pki_arch(ArchLabel('testing-ca'))
    holder_obj = HolderSpec.from_config(holder_cfg).to_asn1(arch)
    holder_cert = arch.get_cert(CertLabel('signer1-long'))
    odi: cms.ObjectDigestInfo = holder_obj['object_digest_info']

    assert odi['digested_object_type'].native == 'public_key'
    assert odi['digest_algorithm']['algorithm'].native == 'sha256'
    assert (
        odi['object_digest'].native
        == hashlib.sha256(holder_cert.public_key.dump()).digest()
    )


def _parse_ietf_syntax(params_str):

    from certomancer.default_plugins import IetfAttrSyntaxPlugin

    params = yaml.safe_load(params_str)['params']
    arch = PKIArchitecture(
        arch_label=ArchLabel('test'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config={},
        service_config={},
        external_url_prefix='http://test.test',
    )
    return IetfAttrSyntaxPlugin().provision(None, arch, params)


@pytest.mark.parametrize(
    'params_str',
    [
        """
    params:
         - type: string
           value: "Big Corp Inc. Employees"
         - type: octets
           value: deadbeef
         - type: oid
           value: "2.999"
    """,
        """
    params:
        values:
             - type: string
               value: "Big Corp Inc. Employees"
             - type: octets
               value: deadbeef
             - type: oid
               value: "2.999"
    """,
        """
    params:
         - "Big Corp Inc. Employees"
         - type: octets
           value: deadbeef
         - type: oid
           value: "2.999"
    """,
    ],
)
def test_ietf_attr_value(params_str):
    result = _parse_ietf_syntax(params_str)

    assert result['policy_authority'].native is None
    assert result['values'][0].native == "Big Corp Inc. Employees"
    assert result['values'][1].native == b"\xde\xad\xbe\xef"
    assert result['values'][2].chosen == core.ObjectIdentifier("2.999")


def test_ietf_attr_value_with_authority():
    params_str = """
    params:
        authority:
             - type: dns_name
               value: admin.example.com
        values:
             - type: string
               value: "Big Corp Inc. Employees"
             - type: octets
               value: deadbeef
             - type: oid
               value: "2.999"
    """
    result = _parse_ietf_syntax(params_str)

    assert result['policy_authority'].native == ['admin.example.com']
    assert result['values'][0].native == "Big Corp Inc. Employees"
    assert result['values'][1].native == b"\xde\xad\xbe\xef"
    assert result['values'][2].chosen == core.ObjectIdentifier("2.999")


@pytest.mark.parametrize(
    'params_str,err_msg',
    [
        (
            """
     params:
         - type: string
           value: "Big Corp Inc. Employees"
         - type: octets
           value: deadbeefz
         - type: oid
           value: "2.999"
     """,
            "hex string",
        ),
        (
            """
     params:
         - type: string
           value: "Big Corp Inc. Employees"
         - type: octets
           value: deadbeef
         - type: oid
           value: "2.999z"
     """,
            "dotted OID string",
        ),
        (
            """
     params:
         - type: string
           value: "Big Corp Inc. Employees"
         - type: octets
           value: deadbeef
         - type: oid
           value: 2.999
     """,
            "must be a string",
        ),
        (
            """
     params:
         - type: string
           value: "Big Corp Inc. Employees"
         - type: octets
           value: 0
         - type: oid
           value: "2.999"
     """,
            "must be a string",
        ),
        (
            """
     params:
         - type: string
           value: 0
         - type: octets
           value: deadbeef
         - type: oid
           value: "2.999"
     """,
            "must be a string",
        ),
        (
            """
     params:
         - type: string
         - type: octets
           value: deadbeef
         - type: oid
           value: "2.999"
     """,
            "'value'.*required",
        ),
        (
            """
     params:
         - value: "Big Corp Inc. Employees"
         - type: octets
           value: deadbeef
         - type: oid
           value: "2.999"
     """,
            "'type'.*required",
        ),
        (
            """
     params:
         - type: foobar
           value: "Big Corp Inc. Employees"
     """,
            "'type'.*one of",
        ),
        (
            """
     params:
        foo: bar
        values:
             - type: string
               value: "Big Corp Inc. Employees"
             - type: octets
               value: deadbeef
             - type: oid
               value: "2.999"
     """,
            "Unexpected.*foo",
        ),
        (
            """
     params:
         - 0
         - type: octets
           value: deadbeef
         - type: oid
           value: "2.999"
     """,
            "string or a dict",
        ),
        (
            """
     params:
        values: 0
     """,
            "'values'.*list",
        ),
        (
            """
     params: {}
     """,
            "requires.*values",
        ),
        (
            """
     params: 0
     """,
            "dict or a list",
        ),
        (
            """
     params:
        authority: bar
        values:
             - type: string
               value: "Big Corp Inc. Employees"
             - type: octets
               value: deadbeef
             - type: oid
               value: "2.999"
     """,
            "authority.*list",
        ),
    ],
)
def test_ietf_attr_value_syntax_errors(err_msg, params_str):
    from certomancer.default_plugins import IetfAttrSyntaxPlugin

    params = yaml.safe_load(params_str)['params']
    arch = PKIArchitecture(
        arch_label=ArchLabel('test'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config={},
        service_config={},
        external_url_prefix='http://test.test',
    )
    with pytest.raises(ConfigurationError, match=err_msg):
        IetfAttrSyntaxPlugin().provision(None, arch, params)


def test_role_syntax_with_authority():
    params_str = """
    params:
       authority:
        - type: email
          value: admin@example.com
       name:
          type: email
          value: blah@example.com
    """
    from certomancer.default_plugins import RoleSyntaxPlugin

    params = yaml.safe_load(params_str)['params']
    arch = PKIArchitecture(
        arch_label=ArchLabel('test'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config={},
        service_config={},
        external_url_prefix='http://test.test',
    )
    result = RoleSyntaxPlugin().provision(None, arch, params)
    assert result['role_name'].native == 'blah@example.com'
    assert result['role_authority'].native == ['admin@example.com']


@pytest.mark.parametrize(
    'params_str,err_msg',
    [
        (
            """
     params:
        authority: 0
        name: {type: email, value: blah@example.com}
     """,
            "authority.*list",
        ),
        (
            """
     params:
        authority: []
     """,
            "requires.*name",
        ),
        (
            """
     params: foo
     """,
            "should be specified as a dict",
        ),
    ],
)
def test_role_syntax_attr_errors(err_msg, params_str):
    from certomancer.default_plugins import RoleSyntaxPlugin

    params = yaml.safe_load(params_str)['params']
    arch = PKIArchitecture(
        arch_label=ArchLabel('test'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config={},
        service_config={},
        external_url_prefix='http://test.test',
    )
    with pytest.raises(ConfigurationError, match=err_msg):
        RoleSyntaxPlugin().provision(None, arch, params)


@pytest.mark.parametrize(
    'params_str,err_msg',
    [
        (
            """
    params:
        service: {type: dns_name, value: admin.example.com}
        ident: {type: email, value: blah@example.com}
        auth-info: deadbeefz
    """,
            "hex string",
        ),
        (
            """
    params:
        service: {type: dns_name, value: admin.example.com}
        ident: {type: email, value: blah@example.com}
        auth-info: 0
    """,
            "hex string",
        ),
        (
            """
     params: foo
     """,
            "should be specified as a dict",
        ),
        (
            """
    params:
        service: {type: dns_name, value: admin.example.com}
    """,
            "'ident'.*required",
        ),
        (
            """
    params:
        ident: {type: email, value: blah@example.com}
        auth-info: deadbeef
    """,
            "'service'.*required",
        ),
        (
            """
    params:
        foo: bar
        service: {type: dns_name, value: admin.example.com}
        ident: {type: email, value: blah@example.com}
        auth-info: deadbeef
    """,
            "Unexpected.*foo",
        ),
    ],
)
def test_svce_auth_info_errors(err_msg, params_str):
    from certomancer.default_plugins import ServiceAuthInfoPlugin

    params = yaml.safe_load(params_str)['params']
    arch = PKIArchitecture(
        arch_label=ArchLabel('test'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config={},
        service_config={},
        external_url_prefix='http://test.test',
    )
    with pytest.raises(ConfigurationError, match=err_msg):
        ServiceAuthInfoPlugin().provision(None, arch, params)


def test_template_extension_uniqueness():
    cfg = '''
      root-ca:
        subject: root
        subject-key: root
        issuer: root
        authority-key: root
        validity:
          valid-from: "2000-01-01T00:00:00+0000"
          valid-to: "2500-01-01T00:00:00+0000"
        extensions:
          - id: basic_constraints
            critical: true
            value:
              ca: true
          - id: key_usage
            critical: true
            smart-value:
              schema: key-usage
              params: [digital_signature, key_cert_sign, crl_sign]
      intermediate-ca:
        template: root-ca
        subject: interm
        issuer: root
        extensions:
          - id: basic_constraints
            critical: true
            value:
              ca: true
              path-len-constraint: 0
    '''

    arch = PKIArchitecture(
        arch_label=ArchLabel('test'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config=yaml.safe_load(cfg),
        service_config={},
        external_url_prefix='http://test.test',
    )
    root_cert = arch.get_cert(CertLabel('root-ca'))
    interm_cert = arch.get_cert(CertLabel('intermediate-ca'))
    assert (
        root_cert.basic_constraints_value['path_len_constraint'].native is None
    )
    assert (
        interm_cert.basic_constraints_value['path_len_constraint'].native == 0
    )
    assert (
        root_cert.key_usage_value.dump() == interm_cert.key_usage_value.dump()
    )


def test_duplicate_exts():
    cfg = '''
      root-ca:
        subject: root
        subject-key: root
        issuer: root
        authority-key: root
        validity:
          valid-from: "2000-01-01T00:00:00+0000"
          valid-to: "2500-01-01T00:00:00+0000"
        unique-extensions: false
        extensions:
          - id: basic_constraints
            critical: true
            value:
              ca: true
          - id: key_usage
            critical: true
            smart-value:
              schema: key-usage
              params: [digital_signature, key_cert_sign, crl_sign]
          - id: '2.999'
            smart-value:
                schema: der-bytes
                params: "0404deadbeef"
          - id: '2.999'
            smart-value:
                schema: der-bytes
                params: "0404cafebabe"
    '''

    arch = PKIArchitecture(
        arch_label=ArchLabel('test'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config=yaml.safe_load(cfg),
        service_config={},
        external_url_prefix='http://test.test',
    )
    cert = arch.get_cert(CertLabel('root-ca'))
    values_seen = []
    for ext in cert['tbs_certificate']['extensions']:
        if ext['extn_id'].native == '2.999':
            values_seen.append(ext['extn_value'].parsed.native)
    assert values_seen == [b'\xde\xad\xbe\xef', b'\xca\xfe\xba\xbe']


def test_apply_profiles():
    cfg = """
      root:
        subject: root
        subject-key: root
        issuer: root
        authority-key: root
        validity:
          valid-from: "2000-01-01T00:00:00+0000"
          valid-to: "2500-01-01T00:00:00+0000"
        profiles:
          - id: simple-ca
            params:
              crl-repo: root
      interm:
        issuer: root
        validity:
          valid-from: "2000-01-01T00:00:00+0000"
          valid-to: "2100-01-01T00:00:00+0000"
        profiles:
          - id: simple-ca
            params:
              ocsp-service: interm
      interm-ocsp:
        issuer: interm
        validity:
          valid-from: "2000-01-01T00:00:00+0000"
          valid-to: "2100-01-01T00:00:00+0000"
        profiles:
          - ocsp-responder
      leaf:
        subject: signer1
        subject-key: signer
        issuer: interm
        validity:
          valid-from: "2020-01-01T00:00:00+0000"
          valid-to: "2022-01-01T00:00:00+0000"
        profiles:
          - digsig-commitment
    """

    srv_cfg = """
    ocsp:
        interm:
          for-issuer: interm
          responder-cert: interm-ocsp
          signing-key: interm-ocsp
    crl-repo:
        root:
          for-issuer: root
          signing-key: root
          simulated-update-schedule: "P90D"
    """
    arch = PKIArchitecture(
        arch_label=ArchLabel('test'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config=yaml.safe_load(cfg),
        service_config=yaml.safe_load(srv_cfg),
        external_url_prefix='http://test.test',
    )
    cert = arch.get_cert(CertLabel('leaf'))
    assert cert.ocsp_urls == ['http://test.test/test/ocsp/interm']
    assert cert.key_usage_value.native == {
        "digital_signature",
        "non_repudiation",
    }

    cert = arch.get_cert(CertLabel('interm'))
    assert cert.ocsp_urls == []
    crl_urls = [
        dp['distribution_point'].native[0]
        for dp in cert.crl_distribution_points
    ]
    assert crl_urls == ['http://test.test/test/crls/root/latest.crl']
    assert cert.key_usage_value.native == {
        "digital_signature",
        "crl_sign",
        "key_cert_sign",
    }


def test_apply_simple_ca_skip_ocsp():
    cfg = """
      root:
        subject: root
        subject-key: root
        issuer: root
        authority-key: root
        validity:
          valid-from: "2000-01-01T00:00:00+0000"
          valid-to: "2500-01-01T00:00:00+0000"
        profiles:
          - id: simple-ca
            params:
                ocsp-service: root
      ocsp:
        issuer: root
        subject: interm-ocsp
        validity:
          valid-from: "2000-01-01T00:00:00+0000"
          valid-to: "2100-01-01T00:00:00+0000"
        profiles:
          - ocsp-responder
    """

    srv_cfg = """
    ocsp:
        root:
          for-issuer: root
          responder-cert: ocsp
          signing-key: interm-ocsp
    """

    arch = PKIArchitecture(
        arch_label=ArchLabel('test'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config=yaml.safe_load(cfg),
        service_config=yaml.safe_load(srv_cfg),
        external_url_prefix='http://test.test',
    )
    cert = arch.get_cert(CertLabel('ocsp'))
    assert cert.ocsp_urls == []
    assert cert.ocsp_no_check_value == core.Null()


class SampleACProfile(CertProfilePlugin):
    profile_label = 'test-profile'

    def extensions_for_self(
        self, arch: 'PKIArchitecture', profile_params: Any, spec
    ):
        return [ExtensionSpec(id='no_rev_avail')]


def test_ac_profiles():
    attr_cert_cfg = '''
    test-ac:
      holder:
          name: signer
          cert: signer
      issuer: root
      profiles:
        - test-profile
      attributes:
          - id: role
            smart-value:
              schema: role-syntax
              params:
                  name: {type: email, value: blah@example.com}
      validity:
        valid-from: "2010-01-01T00:00:00+0000"
        valid-to: "2011-01-01T00:00:00+0000"
    '''
    test_registry = CertProfilePluginRegistry()
    test_registry.register(SampleACProfile)

    arch = PKIArchitecture(
        arch_label=ArchLabel('test'),
        key_set=RSA_KEYS,
        entities=ENTITIES,
        cert_spec_config=yaml.safe_load(BASIC_AC_ISSUER_SETUP),
        ac_spec_config=yaml.safe_load(attr_cert_cfg),
        service_config={},
        external_url_prefix='http://test.test',
        profile_plugins=test_registry,
    )
    test_ac = arch.get_attr_cert(CertLabel('test-ac'))

    ext_value = next(
        ext['extn_value'].parsed
        for ext in test_ac['ac_info']['extensions']
        if ext['extn_id'].native == 'no_rev_avail'
    )
    assert ext_value == core.Null()
