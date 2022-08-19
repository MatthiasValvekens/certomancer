"""
ASN.1 types for internal Certomancer use. All of these are for encoding only.
"""

from asn1crypto import cms, core, x509


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


register_extensions()
