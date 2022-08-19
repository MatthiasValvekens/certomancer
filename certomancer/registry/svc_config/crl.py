import enum
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, List, Optional

from ...config_utils import parse_duration
from ...services import url_distribution_point
from ..common import CertLabel, EntityLabel, KeyLabel
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
    # TODO mixed CRLs would be interesting for edge case testing
    #  but for that to work well we need to support generating indirect
    #  CRLs properly first (IDP extension management etc.)


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
    """Issuer's certificate."""

    extra_urls: List[str] = field(default_factory=list)
    """
    Extra URLs to add to the distribution point.

    These don't have any function within Certomancer.
    """

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

    @classmethod
    def process_entries(cls, config_dict):
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

        parse_extension_settings(config_dict, 'crl_extensions')

    @property
    def latest_external_url(self):
        return f"{self.url}/latest.crl"

    @property
    def latest_full_relative_url(self):
        return f"{self.full_relative_url}/latest.crl"

    def archive_url(self, for_crl_number):
        return f"{self.internal_url}/archive-{for_crl_number}.crl"

    def format_distpoint(self):
        return url_distribution_point(self.latest_external_url, self.extra_urls)

    def format_idp(self):
        result = url_distribution_point(
            self.latest_external_url, self.extra_urls
        )
        if self.crl_type == CRLType.AC_ONLY:
            result['only_contains_attribute_certs'] = True
        elif self.crl_type == CRLType.CA_ONLY:
            result['only_contains_ca_certs'] = True
        elif self.crl_type == CRLType.USER_ONLY:
            result['only_contains_user_certs'] = True
        return result

    def resolve_issuer_cert(self, arch: 'PKIArchitecture') -> CertLabel:
        return self.issuer_cert or arch.get_unique_cert_for_entity(
            self.for_issuer
        )
