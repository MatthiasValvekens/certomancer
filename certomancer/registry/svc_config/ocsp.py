from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional, Tuple

from asn1crypto import ocsp, x509

from ...services import RevocationInfoInterface
from ..common import CertLabel, EntityLabel, KeyLabel
from ..issued.general import ExtensionSpec, parse_extension_settings
from .api import ServiceInfo

if TYPE_CHECKING:
    from ..pki_arch import PKIArchitecture

__all__ = ['OCSPInterface', 'OCSPResponderServiceInfo']


@dataclass(frozen=True)
class OCSPResponderServiceInfo(ServiceInfo):
    """Configuration describing an OCSP responder."""

    base_url = '/ocsp'

    for_issuer: EntityLabel
    """
    Issuing entity on behalf of which the responder acts.
    """

    responder_cert: CertLabel
    """
    Responder's certificate to use.

    .. note::
        This certificate will be embedded in the response's certificate store,
        and the public key embedded inside will be used to derive the 
        ``responderId`` entry in the OCSP packet.

    """

    signing_key: KeyLabel
    """
    Key to use to sign the OCSP response.

    Will be derived from ``responder_cert`` if not specified in config.
    """

    signature_algo: Optional[str] = None
    """
    Signature algorithm to use. You can use this field to enforce RSASSA-PSS 
    padding, for example.
    """

    issuer_cert: Optional[CertLabel] = None
    """
    Issuer certificate. If the issuing entity has only one certificate, 
    you don't need to supply a value for this field.
    """

    digest_algo: str = 'sha256'
    """Digest algorithm to use in the signing process. Defaults to SHA-256."""

    ocsp_extensions: List[ExtensionSpec] = field(default_factory=list)
    """
    List of additional OCSP response extensions.

    Note: only extensions with a fixed value are allowed here, you cannot
    customise the value based on the request received.

    For this reason, the ``nonce`` extension is handled automatically by
    Certomancer.
    """

    is_aa_responder: bool = False
    """
    Flag indicating whether the OCSP responder queries attribute certificates
    or regular certificates.
    """

    @classmethod
    def process_entries(cls, config_dict):
        try:
            config_dict.setdefault('signing_key', config_dict['responder_cert'])
        except KeyError:
            pass

        parse_extension_settings(config_dict, 'ocsp_extensions')

    def resolve_issuer_cert(self, arch: 'PKIArchitecture') -> CertLabel:
        return self.issuer_cert or arch.get_unique_cert_for_entity(
            self.for_issuer
        )


class OCSPInterface(RevocationInfoInterface):
    def __init__(
        self,
        for_issuer: EntityLabel,
        pki_arch: 'PKIArchitecture',
        issuer_cert_label: CertLabel,
        is_aa_responder: bool = False,
    ):
        self.for_issuer = for_issuer
        self.pki_arch = pki_arch
        self.issuer_cert_label = issuer_cert_label
        self.is_aa_responder = is_aa_responder

    def get_issuer_cert(self) -> x509.Certificate:
        return self.pki_arch.get_cert(self.issuer_cert_label)

    def check_revocation_status(
        self, cid: ocsp.CertId, at_time: datetime
    ) -> Tuple[ocsp.CertStatus, List[ocsp.SingleResponseExtension]]:
        cert_label = self.pki_arch.find_cert_label(
            cid, issuer_label=self.for_issuer, is_ac=self.is_aa_responder
        )
        revo = self.pki_arch.check_revocation_status(
            cert_label, at_time, is_ac=self.is_aa_responder
        )

        if revo is None:
            return ocsp.CertStatus('good'), []
        else:
            exts = [
                ext.to_asn1(self.pki_arch, ocsp.SingleResponseExtension)
                for ext in revo.ocsp_response_extensions
            ]
            return revo.to_ocsp_asn1(), exts
