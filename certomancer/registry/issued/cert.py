from dataclasses import dataclass
from typing import Optional

from ..common import CertLabel, EntityLabel, KeyLabel
from .general import IssuedItemSpec

EXCLUDED_FROM_TEMPLATE = frozenset(
    {'subject', 'subject_key', 'serial', 'certificate_file'}
)
EXTNS_EXCLUDED_FROM_TEMPLATE = frozenset({'subject_alt_name'})


@dataclass(frozen=True)
class CertificateSpec(IssuedItemSpec):
    """Certificate specification."""

    label: CertLabel
    """Internal name of the certificate spec."""

    subject: EntityLabel
    """Certificate subject"""

    subject_key: KeyLabel
    """Subject's (public) key. Defaults to the value of :attr:`subject`."""

    templatable_config: dict
    """Configuration that can be reused by other certificate specs."""

    certificate_file: Optional[str] = None
    """
    Path to a file with a pre-generated copy of the certificate in question,
    either in DER or in PEM format.

    When the certificate determined by this certificate spec is requested,
    the certificate in the file will be returned.

    .. warning::
        Certomancer will not attempt to process any information from the
        certificate file, beyond parsing it into an X.509 certificate structure.
        Internally, the certificate spec's entries are used instead.
        It is the config writer's responsibility to make sure that both match
        up.

    .. note::
        This option is unavailable when external configuration is disabled.
        Moreover, it is excluded from templates derived from this certificate
        spec.
    """

    @property
    def self_issued(self) -> bool:
        """
        Check whether the corresponding certificate is self-issued,
        i.e. whether the subject and issuer coincide.

        .. warning::
            Self-issued and self-signed are two related, but very different
            notions. Not all self-issued certificates are self-signed (e.g.
            CA key rollover can be implemented using self-issued certificates),
            and in principle self-signed certificates need not be self-issued
            either (although that usually makes little sense in practice).
        :return:
        """
        return self.subject == self.issuer

    @property
    def self_signed(self) -> bool:
        """
        Check whether the produced certificate is self-signed,
        i.e. whether the signer's (public) key is the same as the subject key.
        """
        return self.subject_key == self.authority_key

    @classmethod
    def extract_templatable_config(cls, config_dict):

        # Do this first for consistency, so we don't put processed values
        # into the template
        for k, v in config_dict.items():
            if k.replace('-', '_') in EXCLUDED_FROM_TEMPLATE:
                continue
            elif k == 'extensions':
                yield k, [
                    ext_dict
                    for ext_dict in v
                    if ext_dict['id'] not in EXTNS_EXCLUDED_FROM_TEMPLATE
                ]
            else:
                yield k, v
