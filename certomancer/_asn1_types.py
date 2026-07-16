"""
ASN.1 types for internal Certomancer use. All of these are for encoding only.
"""

from asn1crypto import algos, cms, core, keys, x509


class Target(core.Choice):
    # NOTE: we don't declare target_cert here because Certomancer never encodes
    # it (it's not in RFC 5755), and we don't use these ASN.1 types for anything
    # other than encoding values.
    _alternatives = [
        ('target_name', x509.GeneralName, {'explicit': 0}),
        ('target_group', x509.GeneralName, {'explicit': 1}),
    ]


class Targets(core.SequenceOf):
    _child_spec = Target


# Blame X.509...
class SequenceOfTargets(core.SequenceOf):
    _child_spec = Targets


class AttrSpec(core.SequenceOf):
    _child_spec = cms.AttCertAttributeType


class AAControls(core.Sequence):
    _fields = [
        ('path_len_constraint', core.Integer, {'optional': True}),
        ('permitted_attrs', AttrSpec, {'optional': True, 'implicit': 0}),
        ('excluded_attrs', AttrSpec, {'optional': True, 'implicit': 1}),
        ('permit_unspecified', core.Boolean, {'default': True}),
    ]


class MLDSAPrivateKey(core.Choice):
    _alternatives = [('seed', core.OctetString, {'implicit': 0})]


def _pqc_setup():
    sd_algo_map = algos.SignedDigestAlgorithmId._map
    sd_algo_map['2.16.840.1.101.3.4.3.17'] = 'mldsa44'
    sd_algo_map['2.16.840.1.101.3.4.3.18'] = 'mldsa65'
    sd_algo_map['2.16.840.1.101.3.4.3.19'] = 'mldsa87'

    sd_algo_reverse_map = algos.SignedDigestAlgorithmId._reverse_map
    if sd_algo_reverse_map is not None:
        sd_algo_reverse_map['mldsa44'] = '2.16.840.1.101.3.4.3.17'
        sd_algo_reverse_map['mldsa65'] = '2.16.840.1.101.3.4.3.18'
        sd_algo_reverse_map['mldsa87'] = '2.16.840.1.101.3.4.3.19'

    key_algo_map = keys.PublicKeyAlgorithmId._map
    key_algo_map['2.16.840.1.101.3.4.3.17'] = 'mldsa44'
    key_algo_map['2.16.840.1.101.3.4.3.18'] = 'mldsa65'
    key_algo_map['2.16.840.1.101.3.4.3.19'] = 'mldsa87'

    priv_key_algo_map = keys.PrivateKeyAlgorithmId._map
    priv_key_algo_map['2.16.840.1.101.3.4.3.17'] = 'mldsa44'
    priv_key_algo_map['2.16.840.1.101.3.4.3.18'] = 'mldsa65'
    priv_key_algo_map['2.16.840.1.101.3.4.3.19'] = 'mldsa87'

    key_algo_reverse_map = keys.PublicKeyAlgorithmId._reverse_map

    if key_algo_reverse_map is not None:  # pragma: nocover
        key_algo_reverse_map['mldsa44'] = '2.16.840.1.101.3.4.3.17'
        key_algo_reverse_map['mldsa65'] = '2.16.840.1.101.3.4.3.18'
        key_algo_reverse_map['mldsa87'] = '2.16.840.1.101.3.4.3.19'

    priv_key_algo_reverse_map = keys.PrivateKeyAlgorithmId._reverse_map

    if priv_key_algo_reverse_map is not None:  # pragma: nocover
        priv_key_algo_reverse_map['mldsa44'] = '2.16.840.1.101.3.4.3.17'
        priv_key_algo_reverse_map['mldsa65'] = '2.16.840.1.101.3.4.3.18'
        priv_key_algo_reverse_map['mldsa87'] = '2.16.840.1.101.3.4.3.19'

    def _public_key_spec_wrapped(public_key_info: keys.PublicKeyInfo):
        try:
            return public_key_info._public_key_spec()
        except KeyError:
            return core.OctetBitString, None

    keys.PublicKeyInfo._spec_callbacks['public_key'] = _public_key_spec_wrapped

    def _private_key_spec_wrapped(private_key_info: keys.PrivateKeyInfo):
        algo = private_key_info['private_key_algorithm']['algorithm'].native
        if algo.startswith('mldsa'):
            return MLDSAPrivateKey
        try:
            return private_key_info._private_key_spec()
        except KeyError:
            return core.OctetString

    keys.PrivateKeyInfo._spec_callbacks['private_key'] = (
        _private_key_spec_wrapped
    )


def register_extensions():
    # patch in attribute certificate extensions
    # Note: we only make these patches so that we can reliably produce the
    # relevant values, and don't insist on supplying Certomancer's internal
    # definitions at the Python level if some other library already supplied
    # them
    ext_map = x509.ExtensionId._map
    ext_specs = x509.Extension._oid_specs
    if '2.5.29.55' not in ext_map:
        ext_map['2.5.29.55'] = 'target_information'
        ext_specs['target_information'] = SequenceOfTargets
    if '2.5.29.56' not in ext_map:
        ext_map['2.5.29.56'] = 'no_rev_avail'
        ext_specs['no_rev_avail'] = core.Null
    if '1.3.6.1.5.5.7.1.6' not in ext_map:
        ext_map['1.3.6.1.5.5.7.1.6'] = 'aa_controls'
        ext_specs['aa_controls'] = AAControls

    # patch in PQ algorithm OIDs
    _pqc_setup()


register_extensions()
