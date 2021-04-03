import importlib
import os
import re
from datetime import datetime

import pytest
import pytz
import yaml
from oscrypto import keys as oskeys

from certomancer.config_utils import SearchDir
from certomancer.registry import KeySet, EntityRegistry, PKIArchitecture, \
    CertLabel, EntityLabel, ArchLabel

importlib.import_module('certomancer.default_plugins')

DUMMY_PASSWORD = b'secret'


KEY_NAME_REGEX = re.compile(r'([a-zA-Z0-9-]+)\.key\.pem')

TEST_DATA_DIR = 'tests/data'


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

    return {
        'path-prefix': dirpath,
        'keys': {k: v for k, v in _keys()}
    }


def dir_to_keyset(dirpath):
    return KeySet(
        dir_to_keyset_cfg(dirpath),
        search_dir=SearchDir(TEST_DATA_DIR)
    )


RSA_KEYS = dir_to_keyset('keys-rsa')
ECDSA_KEYS = dir_to_keyset('keys-ecdsa')

ENTITIES = EntityRegistry(
    yaml.safe_load('''
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
'''),
    defaults=yaml.safe_load('''
country-name: BE
organization-name: Testing Authority
''')
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
        arch_label=ArchLabel('test'), key_set=RSA_KEYS, entities=ENTITIES,
        cert_spec_config=yaml.safe_load(cfg), service_config={},
        external_url_prefix='http://test.test', service_base_url='/test'
    )
    root_cert = arch.get_cert(CertLabel(label))
    assert root_cert.subject == ENTITIES[EntityLabel('root')]
    assert root_cert.issuer == ENTITIES[EntityLabel('root')]
    assert root_cert.not_valid_before == datetime(2000, 1, 1, tzinfo=pytz.utc)


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
        arch_label=ArchLabel('test'), key_set=RSA_KEYS, entities=ENTITIES,
        cert_spec_config=yaml.safe_load(cfg), service_config={},
        external_url_prefix='http://test.test', service_base_url='/test'
    )
    root_cert = arch.get_cert(CertLabel('root-ca'))
    assert root_cert.subject == ENTITIES[EntityLabel('root')]
    assert root_cert.issuer == ENTITIES[EntityLabel('root')]
    assert root_cert.not_valid_before == datetime(2000, 1, 1, tzinfo=pytz.utc)
    interm_cert = arch.get_cert(CertLabel('intermediate-ca'))
    assert interm_cert.subject == ENTITIES[EntityLabel('interm')]
    assert root_cert.issuer == ENTITIES[EntityLabel('root')]
    assert root_cert.not_valid_before == datetime(2000, 1, 1, tzinfo=pytz.utc)


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
        arch_label=ArchLabel('test'), key_set=RSA_KEYS, entities=ENTITIES,
        cert_spec_config=yaml.safe_load(cfg), service_config={},
        external_url_prefix='http://test.test', service_base_url='/test'
    )
    pubkey = arch.get_cert(CertLabel('leaf')).public_key
    with open('tests/data/keys-rsa/split-key-pub.key.pem', 'rb') as inf:
        pubkey_actual = oskeys.parse_public(inf.read())
    assert pubkey.native == pubkey_actual.native
