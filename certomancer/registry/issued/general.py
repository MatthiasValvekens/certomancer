from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, TYPE_CHECKING

from asn1crypto import x509, core, ocsp, crl, cms
from dateutil.parser import parse as parse_dt

from ..common import CertLabel, EntityLabel, KeyLabel
from ..plugin_api import process_config_with_smart_value, SmartValueSpec
from ...config_utils import (
    ConfigurationError, ConfigurableMixin
)
from ...services import CRLBuilder


if TYPE_CHECKING:
    from ..pki_arch import PKIArchitecture


__all__ = [
    'Validity', 'ExtensionSpec', 'RevocationStatus', 'IssuedItemSpec',
    'parse_extension_settings'
]


def _x509_dt_asn1(dt: datetime) -> x509.Time:
    return x509.Time({'utc_time' if dt.year < 2050 else 'general_time': dt})


@dataclass(frozen=True)
class Validity(ConfigurableMixin):
    """Validity period of a certificate."""

    valid_from: datetime
    """
    Start of validity period. To be specified as an ISO 8601 datetime string
    (with timezone offset) in the configuration.
    """

    valid_to: datetime
    """
    End of validity period. To be specified as an ISO 8601 datetime string
    (with timezone offset) in the configuration.
    """

    @classmethod
    def process_entries(cls, config_dict):
        super().process_entries(config_dict)
        try:
            valid_from_str = config_dict['valid_from']
            valid_to_str = config_dict['valid_to']
        except KeyError:
            return  # constructor will error later
        try:
            config_dict['valid_from'] = parse_dt(valid_from_str)
            config_dict['valid_to'] = parse_dt(valid_to_str)
        except ValueError as e:
            raise ConfigurationError(
                "Illegal date-time string in validity specification"
            ) from e

    @property
    def asn1(self) -> x509.Validity:
        return x509.Validity({
            'not_before': _x509_dt_asn1(self.valid_from),
            'not_after': _x509_dt_asn1(self.valid_to)
        })

    @property
    def att_asn1(self) -> cms.AttCertValidityPeriod:
        return cms.AttCertValidityPeriod({
            'not_before_time': core.GeneralizedTime(self.valid_from),
            'not_after_time': core.GeneralizedTime(self.valid_to),
        })


@dataclass(frozen=True)
class ExtensionSpec(ConfigurableMixin):
    """Specifies the value of an extension."""

    id: str
    """ID of the extension, as a string (see :module:`asn1crypto.x509`)."""

    critical: bool = False
    """Indicates whether the extension is critical or not."""

    value: object = None
    """Provides the value of the extension, in a form that the ``asn1crypto``
    value class for the extension accepts."""

    smart_value: Optional[SmartValueSpec] = None
    """
    Provides instructions for the dynamic calculation of an extension value
    through a plugin. Must be omitted if :attr:`value` is present.
    """

    @classmethod
    def process_entries(cls, config_dict):
        process_config_with_smart_value(config_dict, "certificate extension")
        super().process_entries(config_dict)

    def to_asn1(self, arch: 'PKIArchitecture', extension_class):
        value = self.value
        if value is None and self.smart_value is not None:
            value = arch.extn_plugin_registry.process_value(
                self.id, arch, self.smart_value
            )

        return extension_class({
            'extn_id': self.id, 'critical': self.critical, 'extn_value': value
        })


def parse_extension_settings(sett_dict, sett_key):
    try:
        ext_spec = sett_dict.get(sett_key, ())
        if not isinstance(ext_spec, (list, tuple)):
            raise ConfigurationError(
                "Applicable extensions must be specified as a list."
            )
        sett_dict[sett_key] = result = [
            ExtensionSpec.from_config(sett) for sett in ext_spec
        ]
        return result
    except KeyError:
        return []


@dataclass(frozen=True)
class RevocationStatus(ConfigurableMixin):
    """
    Models the revocation status of a certificate.

    .. warning::
        Currently, "temporary" revocations (a.k.a. certificate holds) cannot be
        represented properly.
    """

    revoked_since: datetime
    """
    Time of revocation.
    """

    reason: crl.CRLReason = None
    """
    Revocation reason.
    """

    crl_entry_extensions: List[ExtensionSpec] = field(default_factory=list)
    """
    CRL entry extensions to add when adding this revocation information to
    a CRL.
    """

    ocsp_response_extensions: List[ExtensionSpec] = field(default_factory=list)
    """
    Response extensions to add when reporting this revocation information
    via OCSP.
    """

    @classmethod
    def process_entries(cls, config_dict):
        super().process_entries(config_dict)
        try:
            revoked_since = config_dict['revoked_since']
        except KeyError:
            return
        config_dict['revoked_since'] = parse_dt(revoked_since)

        try:
            reason_spec = config_dict['reason']
            config_dict['reason'] = crl.CRLReason(reason_spec)
        except KeyError:
            pass

        parse_extension_settings(config_dict, 'crl_entry_extensions')
        parse_extension_settings(config_dict, 'ocsp_response_extensions')

    def to_crl_entry_asn1(self, serial_number: int,
                          extensions: List[crl.CRLEntryExtension]) \
            -> crl.RevokedCertificate:
        return CRLBuilder.format_revoked_cert(
            serial_number, reason=self.reason,
            revocation_date=self.revoked_since,
            extensions=extensions
        )

    def to_ocsp_asn1(self) -> ocsp.CertStatus:
        return ocsp.CertStatus(
            name='revoked', value={
                'revocation_time': self.revoked_since,
                'revocation_reason': self.reason
            }
        )


@dataclass(frozen=True)
class IssuedItemSpec(ConfigurableMixin):
    """Specification of a generic issued item."""

    serial: int
    """Serial number"""

    issuer: EntityLabel
    """Certificate issuer"""

    authority_key: KeyLabel
    """Key of the authority issuing the certificate.
    Private key must be available. Defaults to the value of :attr:`issuer`."""

    validity: Validity
    """Validity period of the certificate."""

    signature_algo: Optional[str]
    """Signature algorithm designation. Certomancer will try to figure out
    something sensible if none is given."""

    issuer_cert: Optional[CertLabel]
    """
    Label of the issuer certificate to use. If the issuer only has one
    certificate, it is not necessary to provide a value for this field.

    The certificate is only used to make sure the authority key identifier
    in the generated certificate matches up with the issuer's subject key
    identifier. Certomancer calculates these by hashing the public key (as
    recommended by :rfc:`5280`, but in principle CAs can do whatever they want.
    """

    digest_algo: str
    """Digest algorithm to use in the signing process. Defaults to SHA-256."""

    revocation: Optional[RevocationStatus]
    """Revocation status of the certificate, if relevant."""

    @classmethod
    def process_entries(cls, config_dict):
        # we can't set these at the dataclass level because of dataclass
        # inheritance rules
        # (solvable in Python 3.10 by making all arguments keyword-only, but
        #  that's not an option right now)
        config_dict.setdefault('signature_algo', None)
        config_dict.setdefault('issuer_cert', None)
        config_dict.setdefault('revocation', None)
        config_dict.setdefault('digest_algo', 'sha256')

        try:
            val_spec = config_dict['validity']
            config_dict['validity'] = Validity.from_config(val_spec)
        except KeyError:
            pass

        revocation = config_dict.get('revocation', None)
        if revocation is not None:
            config_dict['revocation'] = RevocationStatus.from_config(revocation)

        super().process_entries(config_dict)

    def resolve_issuer_cert(self, arch: 'PKIArchitecture') -> CertLabel:
        return self.issuer_cert or arch.get_unique_cert_for_entity(self.issuer)