import hashlib
import importlib
import os
import re
from datetime import datetime
from io import BytesIO
from zipfile import ZipFile

import pyhanko_certvalidator
import pytest
import pytz
import yaml
from oscrypto import keys as oskeys
from asn1crypto import x509, cms
from pyhanko_certvalidator import ValidationContext

from certomancer.config_utils import SearchDir, ConfigurationError
from certomancer.crypto_utils import load_cert_from_pemder
from certomancer.registry import KeySet, EntityRegistry, PKIArchitecture, \
    CertLabel, EntityLabel, ArchLabel, CertomancerConfig, HolderSpec

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
        external_url_prefix='http://test.test',
    )
    root_cert = arch.get_cert(CertLabel(label))
    assert root_cert.subject == ENTITIES[EntityLabel('root')]
    assert root_cert.issuer == ENTITIES[EntityLabel('root')]
    assert root_cert.not_valid_before == datetime(2000, 1, 1, tzinfo=pytz.utc)


def test_attr_cert_spec():
    cert_cfg = '''
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
      signer1:
        subject: signer1
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

    attr_cert_cfg = '''
      test-ac:
        holder: signer1
        # not allowed in RFC 5755, but it doesn't matter for this test
        issuer: root
        attributes:
            - id: role
              value:
                role_name:
                    rfc822_name: signer1@example.com
        validity:
          valid-from: "2010-01-01T00:00:00+0000"
          valid-to: "2011-01-01T00:00:00+0000"
    '''

    arch = PKIArchitecture(
        arch_label=ArchLabel('test'), key_set=RSA_KEYS, entities=ENTITIES,
        cert_spec_config=yaml.safe_load(cert_cfg),
        ac_spec_config=yaml.safe_load(attr_cert_cfg),
        service_config={},
        external_url_prefix='http://test.test',
    )
    test_ac = arch.get_attr_cert_spec(CertLabel('test-ac'))
    assert test_ac.attributes[0].id == 'role'


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
        arch_label=ArchLabel('test'), key_set=RSA_KEYS, entities=ENTITIES,
        cert_spec_config=yaml.safe_load(cfg), service_config={},
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
        arch_label=ArchLabel('test'), key_set=RSA_KEYS, entities=ENTITIES,
        cert_spec_config=yaml.safe_load(cfg), service_config={},
        external_url_prefix='http://test.test',
    )
    pubkey = arch.get_cert(CertLabel('leaf')).public_key
    with open('tests/data/keys-rsa/split-key-pub.key.pem', 'rb') as inf:
        pubkey_actual = oskeys.parse_public(inf.read())
    assert pubkey.native == pubkey_actual.native


@pytest.mark.parametrize('order',
                         [('interm', 'root', 'signer1'),
                          ('signer1', 'root', 'interm'),
                          ('root', 'signer1', 'interm')])
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
        'interm/signer1-long.cert.pem', 'interm/signer1.cert.pem',
        'interm/signer2.cert.pem', 'interm/interm-ocsp.cert.pem',
        'root/interm.cert.pem', 'root/tsa.cert.pem',
        'root/tsa2.cert.pem', 'root/root.cert.pem',
    }


def test_dump_with_pfx(tmp_path):
    arch = CONFIG.get_pki_arch(ArchLabel('testing-ca'))
    arch.dump_certs(str(tmp_path), include_pkcs12=True)
    dumped = set(_collect_files(str(tmp_path)))
    assert dumped == {
        'interm/signer1-long.cert.pem', 'interm/signer1-long.pfx',
        'interm/signer1.cert.pem', 'interm/signer1.pfx',
        'interm/signer2.cert.pem', 'interm/signer2.pfx',
        'interm/interm-ocsp.cert.pem', 'interm/interm-ocsp.pfx',
        'root/interm.cert.pem', 'root/interm.pfx',
        'root/tsa.cert.pem', 'root/tsa.pfx',
        'root/tsa2.cert.pem', 'root/tsa2.pfx',
        'root/root.cert.pem', 'root/root.pfx',
    }


def test_dump_flat_no_pfx(tmp_path):
    arch = CONFIG.get_pki_arch(ArchLabel('testing-ca'))
    arch.dump_certs(str(tmp_path), include_pkcs12=False, flat=True)
    dumped = set(_collect_files(str(tmp_path)))
    assert dumped == {
        'signer1-long.cert.pem', 'signer1.cert.pem',
        'signer2.cert.pem', 'interm-ocsp.cert.pem',
        'interm.cert.pem', 'tsa.cert.pem',
        'tsa2.cert.pem', 'root.cert.pem',
    }


def test_dump_zip():
    out = BytesIO()
    arch = CONFIG.get_pki_arch(ArchLabel('testing-ca'))
    arch.zip_certs(out)
    out.seek(0)
    z = ZipFile(out)
    dumped = set(z.namelist())
    assert dumped == set(map(lambda n: 'testing-ca/' + n, {
        'interm/signer1-long.cert.pem', 'interm/signer1.cert.pem',
        'interm/signer2.cert.pem', 'interm/interm-ocsp.cert.pem',
        'root/interm.cert.pem', 'root/tsa.cert.pem',
        'root/tsa2.cert.pem', 'root/root.cert.pem',
    }))


def test_subject_alt_names():
    # test whether SAN extensions are reassigned properly when using
    # cert specs as templates for other cert specs
    arch = CONFIG.get_pki_arch(ArchLabel('testing-ca'))
    signer1 = arch.get_cert(CertLabel('signer1'))
    signer2 = arch.get_cert(CertLabel('signer2'))
    signer1_long = arch.get_cert(CertLabel('signer1-long'))

    assert signer1.subject_alt_name_value[0].chosen.native == 'test@example.com'
    assert signer2.subject_alt_name_value[0].chosen.native \
           == 'test2@example.com'
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
        arch_label=ArchLabel('test'), key_set=RSA_KEYS, entities=ENTITIES,
        cert_spec_config=yaml.safe_load(cfg), service_config={},
        external_url_prefix='http://test.test',
    )
    ext: x509.Extension = next(filter(
        lambda x: x['extn_id'].native == 'netscape_certificate_type',
        arch.get_cert(CertLabel('root'))['tbs_certificate']['extensions']
    ))
    assert ext['extn_value'].parsed.native == {'email'}


@pytest.mark.parametrize('wrong_value', ['"xlkjd"', '[]', 'null'])
def test_raw_extension(wrong_value):
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
        arch_label=ArchLabel('test'), key_set=RSA_KEYS, entities=ENTITIES,
        cert_spec_config=yaml.safe_load(cfg), service_config={},
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

    await pyhanko_certvalidator.CertificateValidator(
        end_entity_cert=arch.get_cert(CertLabel('signer')),
        validation_context=ValidationContext(trust_roots=[ca]),
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
    assert odi['object_digest'].native \
           == hashlib.sha256(holder_cert.dump()).digest()


@pytest.mark.parametrize('dot_str_spec', [
    'public_key', '0'
])
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
    assert odi['object_digest'].native \
           == hashlib.sha256(holder_cert.public_key.dump()).digest()
