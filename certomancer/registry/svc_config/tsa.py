from dataclasses import dataclass, field
from typing import List, Optional

from ..common import CertLabel, KeyLabel
from .api import ServiceInfo

__all__ = ['TSAServiceInfo']


@dataclass(frozen=True)
class TSAServiceInfo(ServiceInfo):
    """Configuration describing a time stamping service."""

    base_url = '/tsa'

    signing_cert: CertLabel
    """
    Label of the signer's certificate.
    """

    signing_key: KeyLabel
    """
    Key to sign responses with. Ordinarily derived from :attr:`signing_cert`
    when not specified in config.
    """

    signature_algo: Optional[str] = None
    """
    Signature algorithm to use. You can use this field to enforce RSASSA-PSS 
    padding, for example.
    """

    digest_algo: str = 'sha256'
    """Digest algorithm to use in the signing process. Defaults to SHA-256."""

    certs_to_embed: List[CertLabel] = field(default_factory=list)
    """Extra certificates to embed."""

    @classmethod
    def process_entries(cls, config_dict):
        try:
            config_dict.setdefault('signing_key', config_dict['signing_cert'])
        except KeyError:
            pass
