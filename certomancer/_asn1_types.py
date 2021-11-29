"""
ASN.1 types for internal Certomancer use. All of these are for encoding only.
"""

from asn1crypto import core, x509, cms


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
        ('permit_unspecified', core.Boolean, {'default': True})
    ]
