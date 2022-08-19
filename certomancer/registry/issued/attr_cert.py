import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from asn1crypto import cms, keys, x509

from ...config_utils import ConfigurableMixin, ConfigurationError
from ..common import CertLabel, EntityLabel, KeyLabel
from ..entities import as_general_name
from ..plugin_api import SmartValueSpec, process_config_with_smart_value
from .general import IssuedItemSpec

if TYPE_CHECKING:
    from ..pki_arch import PKIArchitecture

__all__ = ['HolderSpec', 'AttrSpec', 'AttributeCertificateSpec']


@dataclass(frozen=True)
class HolderSpec(ConfigurableMixin):
    """Describes the holder of an attribute certificate."""

    name: EntityLabel
    """The name of the holding entity."""

    cert: Optional[CertLabel] = None
    """
    The label of the entity certificate to use when encoding the holder, 
    if the entity has more than one certificate.
    """

    key: Optional[KeyLabel] = None
    """
    The label of the public key to use when encoding the holder, 
    if the entity has more than one certificate.
    """

    include_base_cert_id: bool = True
    """
    Include the ``baseCertificateID`` field in the holder value.
    This is recommended by RFC 5755 and the default.
    """

    include_entity_name: bool = False
    """
    Include the ``entityName`` field in the holder value.
    ``False`` by default.
    """

    include_object_digest_info: bool = False
    """
    Include the ``objectDigestInfo`` field in the holder value.
    ``False`` by default, and further controlled by :attr:`digested_object_type`
    and :attr:`obj_digest_algorithm`.
    """

    digested_object_type: cms.DigestedObjectType = cms.DigestedObjectType(
        'public_key_cert'
    )
    """
    The type of data to digest when computing the ``objectDigestInfo``
    field (see :class:`cms.DigestedObjectType`).
    """

    obj_digest_algorithm: str = 'sha256'
    """
    Name of the digest algorithm to use when producing holder identifiers
    of type ``objectDigestInfo``. Defaults to SHA-256.
    """

    @classmethod
    def process_entries(cls, config_dict):
        try:
            dot_setting = config_dict['digested_object_type']
            if isinstance(dot_setting, (int, str)):
                config_dict['digested_object_type'] = cms.DigestedObjectType(
                    dot_setting
                )
            elif not isinstance(dot_setting, cms.DigestedObjectType):
                raise ConfigurationError(
                    f"Digested object type setting type must be 'str' "
                    f"or 'int', not {type(dot_setting)}"
                )
        except KeyError:
            pass

    def to_asn1(self, arch: 'PKIArchitecture') -> cms.Holder:
        result: Dict[str, Any] = {}
        holder_cert_label = self.cert or arch.get_unique_cert_for_entity(
            self.name
        )
        holder_cert: x509.Certificate = arch.get_cert(holder_cert_label)
        if self.include_base_cert_id:
            result['base_certificate_id'] = {
                'issuer': [as_general_name(holder_cert.issuer)],
                'serial': holder_cert.serial_number,
            }
        if self.include_entity_name:
            result['entity_name'] = [as_general_name(holder_cert.subject)]
        if self.include_object_digest_info:
            type_desc = self.digested_object_type.native
            data_to_digest: bytes
            if type_desc == 'public_key':
                pk_info: keys.PublicKeyInfo = holder_cert.public_key
                # RFC 5755 § 7.3 requires that the entire PublicKeyInfo be
                # hashed
                # (Warning: this is _not_ what pk_info.sha256 does in
                #  asn1crypto!)
                if (
                    pk_info.algorithm == 'dsa'
                    and not pk_info['algorithm']['parameters'].native
                ):
                    raise NotImplementedError(
                        "DSA parameter inheritance is not supported"
                    )
                data_to_digest = pk_info.dump()
            elif type_desc == 'public_key_cert':
                data_to_digest = holder_cert.dump()
            else:
                raise NotImplementedError(
                    "Only 'public_key' and 'public_key_cert' are implemented"
                )

            digest_f = getattr(hashlib, self.obj_digest_algorithm)
            obj_digest = digest_f(data_to_digest).digest()

            result['object_digest_info'] = {
                'digested_object_type': self.digested_object_type,
                'digest_algorithm': {'algorithm': self.obj_digest_algorithm},
                'object_digest': obj_digest,
            }
        return cms.Holder(result)


@dataclass(frozen=True)
class AttrSpec(ConfigurableMixin):
    """Specifies the value of an attribute."""

    id: str
    """ID of the attribute, as a string (see :module:`asn1crypto.cms`)."""

    value: object = None
    """Provides the value of the attribute, in a form that the ``asn1crypto``
    value class for the attribute accepts."""

    multivalued: bool = False
    """
    If ``True``, the :attr:`value` field will be interpreted as a set of
    values instead of a singular one.
    """

    smart_value: Optional[SmartValueSpec] = None
    """
    Provides instructions for the dynamic calculation of an attribute value
    through a plugin. Must be omitted if :attr:`value` is present.
    """

    @classmethod
    def process_entries(cls, config_dict):
        process_config_with_smart_value(config_dict, "attribute")
        super().process_entries(config_dict)

    def to_asn1(self, arch: 'PKIArchitecture'):
        value = self.value
        if value is None and self.smart_value is not None:
            values = arch.attr_plugin_registry.process_value(
                self.id, arch, self.smart_value, self.multivalued
            )
        else:
            values = value if self.multivalued else [value]

        return cms.AttCertAttribute(
            {'type': cms.AttCertAttributeType(self.id), 'values': values}
        )


@dataclass(frozen=True)
class AttributeCertificateSpec(IssuedItemSpec):
    """Attribute certificate specification."""

    label: CertLabel
    """Internal name of the attribute certificate spec."""

    holder: HolderSpec
    """Description of the holder."""

    attributes: List[AttrSpec]
    """List of certified attributes."""

    @classmethod
    def process_entries(cls, config_dict):
        try:
            holder_raw = config_dict['holder']
        except KeyError:
            raise ConfigurationError(
                "Attribute certificates must specify a holder"
            )
        if isinstance(holder_raw, dict):
            config_dict['holder'] = HolderSpec.from_config(holder_raw)
        elif isinstance(holder_raw, str):
            config_dict['holder'] = HolderSpec(name=EntityLabel(holder_raw))
        else:
            raise ConfigurationError(
                f"'holder' entry must be a string or a dictionary, not "
                f"{type(holder_raw)}."
            )

        attr_spec = config_dict.get('attributes', ())
        if not isinstance(attr_spec, (list, tuple)):
            raise ConfigurationError(
                "Applicable attributes must be specified as a list."
            )
        config_dict['attributes'] = [
            AttrSpec.from_config(sett) for sett in attr_spec
        ]
        super().process_entries(config_dict)
