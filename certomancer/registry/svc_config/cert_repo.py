from dataclasses import dataclass
from typing import Optional

from ...config_utils import ConfigurationError
from ..common import CertLabel, EntityLabel
from .api import ServiceInfo

__all__ = [
    'BaseCertRepoServiceInfo',
    'CertRepoServiceInfo',
    'AttrCertRepoServiceInfo',
]


@dataclass(frozen=True)
class BaseCertRepoServiceInfo(ServiceInfo):
    for_issuer: EntityLabel
    issuer_cert: Optional[CertLabel] = None


@dataclass(frozen=True)
class CertRepoServiceInfo(BaseCertRepoServiceInfo):
    base_url = '/certs'
    publish_issued_certs: bool = True

    @staticmethod
    def issuer_cert_file_name(use_pem=True):
        fname = f"ca.{'cert.pem' if use_pem else 'crt'}"
        return f"{fname}"

    def issued_cert_url_path(self, label: CertLabel, use_pem=True):
        if not self.publish_issued_certs:
            raise ConfigurationError(
                f"Cert repo '{self.label}' does not make issued certs public"
            )
        fname = f"{label}.{'cert.pem' if use_pem else 'crt'}"
        return f"issued/{fname}"

    def issuer_cert_url(self, use_pem=True):
        fname = CertRepoServiceInfo.issuer_cert_file_name(use_pem=use_pem)
        return f"{self.url}/{fname}"

    @property
    def issuer_cert_external_url(self):
        fname = CertRepoServiceInfo.issuer_cert_file_name(use_pem=True)
        return f"{self.url}/{fname}"

    @property
    def issuer_cert_full_relative_url(self):
        fname = CertRepoServiceInfo.issuer_cert_file_name(use_pem=True)
        return f"{self.full_relative_url}/{fname}"

    def issued_cert_url(self, label: CertLabel, use_pem=True):
        path = self.issued_cert_url_path(label=label, use_pem=use_pem)
        return f"{self.url}/{path}"


# TODO Add to Illusionist


@dataclass(frozen=True)
class AttrCertRepoServiceInfo(BaseCertRepoServiceInfo):
    base_url = '/attr-certs'
    publish_by_holder: bool = True

    @staticmethod
    def issuer_cert_file_name(use_pem=True):
        fname = f"aa.{'cert.pem' if use_pem else 'crt'}"
        return f"{fname}"

    @classmethod
    def issued_cert_url_path(cls, label: CertLabel, use_pem=True):
        fname = f"{label}.{'attr.cert.pem' if use_pem else 'attr.crt'}"
        return f"issued/{fname}"

    @classmethod
    def by_holder_url_path(cls, label: EntityLabel, use_pem=True):
        fname = f"{label}-all.{'attr.cert.pem' if use_pem else 'attr.p7b'}"
        return f"by-holder/{fname}"

    def issuer_cert_url(self, use_pem=True):
        fname = AttrCertRepoServiceInfo.issuer_cert_file_name(use_pem=use_pem)
        return f"{self.url}/{fname}"

    @property
    def issuer_cert_external_url(self):
        fname = AttrCertRepoServiceInfo.issuer_cert_file_name(use_pem=True)
        return f"{self.url}/{fname}"

    @property
    def issuer_cert_full_relative_url(self):
        fname = AttrCertRepoServiceInfo.issuer_cert_file_name(use_pem=True)
        return f"{self.full_relative_url}/{fname}"

    def issued_cert_url(self, label: CertLabel, use_pem=True):
        path = AttrCertRepoServiceInfo.issued_cert_url_path(
            label=label, use_pem=use_pem
        )
        return f"{self.url}/{path}"

    def issued_to_holder_url(self, label: EntityLabel, use_pem=True):
        path = AttrCertRepoServiceInfo.by_holder_url_path(
            label=label, use_pem=use_pem
        )
        return f"{self.url}/{path}"
