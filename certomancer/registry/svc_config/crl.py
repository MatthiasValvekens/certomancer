import enum
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from asn1crypto import x509

from ...config_utils import (
    ConfigurableMixin,
    key_dashes_to_underscores,
    parse_duration,
)
from ...services import urls_as_names
from ..common import CertLabel, EntityLabel, KeyLabel
from ..entities import EntityRegistry
from ..issued.general import ExtensionSpec, parse_extension_settings
from .api import ServiceInfo

if TYPE_CHECKING:
    from ..pki_arch import PKIArchitecture

__all__ = ['CRLType', 'CRLRepoServiceInfo']


@enum.unique
class CRLType(enum.Enum):
    """
    Type of CRL. Determines flags in the issuing distribution point extension.

    Note: Certomancer internally does not distinguish between user certs and
    CA certs, so these will be treated uniformly.

    Note: RFC 5755 bans AAs from acting as CAs, so in principle AA-backed CRLs
    should not intersect with CA-backed ones in a well-managed PKI/PMI
    infrastructure (unless CRLs are delegated).
    However, Certomancer will still allow you to mix and match.
    """

    USER_ONLY = 'user-only'
    """
    Include only user certs.
    """

    CA_ONLY = 'ca-only'
    """
    Include only CA certs.
    """

    AC_ONLY = 'ac-only'
    """
    Include only attribute certs.
    """

    MIXED = 'mixed'
    """
    Unspecified.
    """


@dataclass(frozen=True)
class DistributionPointNameInfo(ConfigurableMixin):
    include_distribution_point_name_in_crl: bool = True
    """
    Include the distribution point's name in the CRL's IssuingDistributionPoint extension.
    """

    include_url_in_distribution_point_name: bool = True
    """
    Include the distribution point's URL in the CRL's IssuingDistributionPoint extension.

    Can be combined with :attr:`full_directory_name`, but not :attr:`relative_name`.
    """

    extra_urls: List[str] = field(default_factory=list)
    """
    Extra URLs to add to the distribution point.

    These don't have any function within Certomancer.
    """

    relative_name: Optional[x509.RelativeDistinguishedName] = None
    """
    Instead of naming the distribution point by URL, name it relative to
    the issuer of the CRL.
    """

    full_directory_name: Optional[EntityLabel] = None
    """
    Manually specify the full name of the distribution point as a directory name.
    """

    name_crl_issuer_in_certificate: Optional[bool] = None
    """
    Name the CRL's issuer in the distribution point extensions of the
    certificates to which the CRL applies.

    The default is to do this for indirect CRLs, but not for direct ones.
    """

    @classmethod
    def process_entries(cls, config_dict):
        super().process_entries(config_dict)
        try:
            relative_name_cfg = key_dashes_to_underscores(
                config_dict['relative_name']
            )
            name = x509.Name.build(relative_name_cfg)
            relative_name = x509.RelativeDistinguishedName(
                [keyval_pair for rdn in name.chosen for keyval_pair in rdn]
            )
            config_dict['relative_name'] = relative_name
        except KeyError:
            pass


@dataclass(frozen=True)
class CRLRepoServiceInfo(ServiceInfo):
    """
    Configuration describing a CRL repository/distribution points.

    The main purpose of this service is to model a distribution location
    that makes the "freshest" CRL available for download, but it can also
    serve CRL archives.

    .. note::
        There is currently no support for delta CRLs, but in principle
        indirect CRLs can be generated if you implement the relevant
        extensions yourself using plugins and the :attr:`crl_extensions`
        parameter.
    """

    base_url = '/crls'

    for_issuer: EntityLabel
    """
    Issuing entity for which the CRLs are issued.
    """

    signing_key: KeyLabel
    """
    Key to sign CRLs with.
    """

    simulated_update_schedule: timedelta
    """
    Time interval for (regular) CRL updates. Used to generate CRL numbers
    and to populate the ``thisUpdate`` and ``nextUpdate`` fields.

    The time origin is taken to be the start of the validity period of
    :attr:`issuer_cert`.
    """

    issuer_cert: Optional[CertLabel] = None
    """CRL issuer's certificate."""

    signature_algo: Optional[str] = None
    """
    Signature algorithm to use. You can use this field to enforce RSASSA-PSS 
    padding, for example.
    """

    digest_algo: str = 'sha256'
    """Digest algorithm to use in the signing process. Defaults to SHA-256."""

    crl_extensions: List[ExtensionSpec] = field(default_factory=list)
    """
    List of additional CRL extensions.
    """

    crl_type: CRLType = CRLType.MIXED
    """
    Type of CRL.
    """

    crl_issuer: Optional[EntityLabel] = None
    """
    CRL issuer. Defaults to the issuing CA (direct CRL).
    """

    covered_reasons: Optional[x509.ReasonFlags] = None
    """
    Set the covered reasons in the IssuingDistributionPoint extension.
    If not specified, the field is omitted from the extension (implying
    that all reasons are covered).
    """

    distribution_point_name: DistributionPointNameInfo = (
        DistributionPointNameInfo()
    )
    """
    Extra settings to control the naming of distribution points.
    """

    @classmethod
    def process_entries(cls, config_dict):
        super().process_entries(config_dict)
        try:
            upd_sched = config_dict['simulated_update_schedule']
            config_dict['simulated_update_schedule'] = parse_duration(upd_sched)
        except KeyError:
            pass
        try:
            config_dict.setdefault('signing_key', config_dict['for_issuer'])
        except KeyError:
            pass
        try:
            config_dict['crl_type'] = CRLType(config_dict['crl_type'])
        except KeyError:
            pass

        try:
            flags = config_dict['covered_reasons']
            config_dict['covered_reasons'] = x509.ReasonFlags(set(flags))
        except KeyError:
            pass

        try:
            config_dict['distribution_point_name'] = (
                DistributionPointNameInfo.from_config(
                    config_dict['distribution_point_name']
                )
            )
        except KeyError:
            pass
        parse_extension_settings(config_dict, 'crl_extensions')

    @property
    def latest_external_url(self):
        return f"{self.url}/latest.crl"

    @property
    def latest_full_relative_url(self):
        return f"{self.full_relative_url}/latest.crl"

    def archive_url(self, for_crl_number):
        return f"{self.internal_url}/archive-{for_crl_number}.crl"

    def format_distribution_point_name(self, entities: EntityRegistry):
        name_info = self.distribution_point_name
        if name_info.relative_name:
            return x509.DistributionPointName(
                name='name_relative_to_crl_issuer',
                value=name_info.relative_name,
            )
        else:
            names = []
            if name_info.include_url_in_distribution_point_name:
                names.extend(
                    urls_as_names(
                        self.latest_external_url,
                        *self.distribution_point_name.extra_urls,
                    )
                )
            if name_info.full_directory_name:
                names.append(
                    x509.GeneralName(
                        name='directory_name',
                        value=entities[name_info.full_directory_name],
                    )
                )
            return x509.DistributionPointName(name='full_name', value=names)

    def format_distpoint(self, entities: EntityRegistry):
        result: Dict[str, Any] = {
            'distribution_point': self.format_distribution_point_name(entities),
        }
        if self.covered_reasons:
            result['reasons'] = self.covered_reasons
        if (
            self.distribution_point_name.name_crl_issuer_in_certificate
            is not None
        ):
            include_issuer = (
                self.distribution_point_name.name_crl_issuer_in_certificate
            )
        else:
            include_issuer = self.indirect
        if include_issuer:
            issuer_name = entities[self.crl_issuer or self.for_issuer]
            result['crl_issuer'] = [
                x509.GeneralName(name='directory_name', value=issuer_name)
            ]
        return result

    def format_idp(self, entities: EntityRegistry):
        result: Dict[str, Any] = {
            'distribution_point': self.format_distribution_point_name(entities),
        }
        if self.crl_type == CRLType.AC_ONLY:
            result['only_contains_attribute_certs'] = True
        elif self.crl_type == CRLType.CA_ONLY:
            result['only_contains_ca_certs'] = True
        elif self.crl_type == CRLType.USER_ONLY:
            result['only_contains_user_certs'] = True

        if self.crl_issuer is not None:
            result['indirect_crl'] = self.indirect
        if self.covered_reasons is not None:
            result['only_some_reasons'] = self.covered_reasons
        return result

    @property
    def indirect(self) -> bool:
        return (
            self.crl_issuer is not None and self.crl_issuer != self.for_issuer
        )

    def resolve_issuer_cert(self, arch: 'PKIArchitecture') -> CertLabel:
        return self.issuer_cert or arch.get_unique_cert_for_entity(
            self.crl_issuer or self.for_issuer
        )
