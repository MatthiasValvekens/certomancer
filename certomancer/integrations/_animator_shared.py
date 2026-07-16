from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List

from certomancer.registry import (
    ArchLabel,
    AttributeCertificateSpec,
    CertificateSpec,
    EntityLabel,
    PKIArchitecture,
)
from certomancer.services import CertomancerServiceError

FAKE_TIME_HEADER = 'X-Certomancer-Fake-Time'
WEB_UI_URL_PREFIX = '_certomancer'


def _now():
    return datetime.now(tz=timezone.utc)


@dataclass(frozen=True)
class AnimatorCertInfo:
    spec: CertificateSpec
    pfx_available: bool
    subject_dn: str

    @staticmethod
    def gather_cert_info(pki_arch: PKIArchitecture):
        def _for_cert(spec: CertificateSpec):
            pfx = pki_arch.is_subject_key_available(spec.label)
            return AnimatorCertInfo(
                spec=spec,
                pfx_available=pfx,
                subject_dn=pki_arch.entities[spec.subject].human_friendly,
            )

        return {
            iss: list(map(_for_cert, issd_certs))
            for iss, issd_certs in pki_arch.enumerate_certs_by_issuer()
        }


@dataclass(frozen=True)
class AnimatorAttrCertInfo:
    spec: AttributeCertificateSpec
    holder_dn: str

    @staticmethod
    def gather_cert_info(pki_arch: PKIArchitecture):
        def _for_attr_cert(spec: AttributeCertificateSpec):
            return AnimatorAttrCertInfo(
                spec=spec,
                holder_dn=pki_arch.entities[spec.holder.name].human_friendly,
            )

        return {
            iss: list(map(_for_attr_cert, issd_certs))
            for iss, issd_certs in pki_arch.enumerate_attr_certs_by_issuer()
        }


@dataclass(frozen=True)
class ArchServicesDescription:
    arch: ArchLabel
    tsa: list
    ocsp: list
    crl: list
    cert_repo: list
    attr_cert_repo: list
    certs_by_issuer: Dict[EntityLabel, List[AnimatorCertInfo]]
    attr_certs_by_issuer: Dict[EntityLabel, List[AnimatorAttrCertInfo]]

    @classmethod
    def compile(cls, pki_arch: PKIArchitecture):
        services = pki_arch.service_registry
        cert_info = AnimatorCertInfo.gather_cert_info(pki_arch)
        attr_cert_info = AnimatorAttrCertInfo.gather_cert_info(pki_arch)
        return ArchServicesDescription(
            pki_arch.arch_label,
            tsa=services.list_time_stamping_services(),
            ocsp=services.list_ocsp_responders(),
            crl=services.list_crl_repos(),
            cert_repo=services.list_cert_repos(),
            attr_cert_repo=services.list_attr_cert_repos(),
            certs_by_issuer=cert_info,
            attr_certs_by_issuer=attr_cert_info,
        )


def gen_index(architectures):
    try:
        from jinja2 import Environment, PackageLoader
    except ImportError as e:  # pragma: nocover
        raise CertomancerServiceError(
            "Web UI requires Jinja2 to be installed"
        ) from e

    # the index is fixed from the moment the server is launched, so
    #  just go ahead and render it
    jinja_env = Environment(
        loader=PackageLoader('certomancer.integrations', 'animator_templates'),
        autoescape=True,
    )
    template = jinja_env.get_template('index.html')
    return template.render(
        pki_archs=[
            ArchServicesDescription.compile(arch) for arch in architectures
        ],
        web_ui_prefix=WEB_UI_URL_PREFIX,
    )
