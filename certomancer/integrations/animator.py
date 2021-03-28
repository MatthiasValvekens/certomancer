import enum
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict

import tzlocal
from asn1crypto import ocsp, tsp, pem
from jinja2 import FileSystemLoader, Environment
from werkzeug.wrappers import Request, Response
from werkzeug.routing import Map, Rule, BaseConverter
from werkzeug.exceptions import HTTPException, NotFound, InternalServerError

from certomancer.registry import (
    PKIArchitecture, ServiceRegistry, ServiceLabel, CertLabel,
    CertomancerObjectNotFoundError, CertomancerConfig, ArchLabel
)
from certomancer.services import CertomancerServiceError


logger = logging.getLogger(__name__)


class LabelConverter(BaseConverter):
    regex = "[^./]+"


class ServiceType(enum.Enum):
    OCSP = 'ocsp'
    CRL_REPO = 'crl'
    TSA = 'tsa'
    CERT_REPO = 'certs'

    def endpoint(self, arch: ArchLabel, label: ServiceLabel):
        return Endpoint(arch, self, label)


@dataclass(frozen=True)
class Endpoint:
    arch: ArchLabel
    service_type: ServiceType
    label: ServiceLabel


def service_rules(services: ServiceRegistry):
    arch = services.pki_arch.arch_label
    srv = ServiceType.OCSP
    for ocsp_info in services.list_ocsp_responders():
        logger.info("OCSP:" + ocsp_info.internal_url)
        yield Rule(
            ocsp_info.internal_url,
            endpoint=srv.endpoint(arch, ocsp_info.label),
            methods=('POST',)
        )
    srv = ServiceType.TSA
    for tsa_info in services.list_time_stamping_services():
        logger.info("TSA:" + tsa_info.internal_url)
        yield Rule(
            tsa_info.internal_url, endpoint=srv.endpoint(
                arch, tsa_info.label
            ), methods=('POST',)
        )
    srv = ServiceType.CRL_REPO
    for crl_repo in services.list_crl_repos():
        logger.info("CRLs:" + crl_repo.internal_url)
        # latest CRL
        endpoint = srv.endpoint(arch, crl_repo.label)
        yield Rule(
            f"{crl_repo.internal_url}/latest.<extension>",
            defaults={'crl_no': None}, endpoint=endpoint,
            methods=('GET',)
        )
        # CRL archive
        yield Rule(
            f"{crl_repo.internal_url}/archive-<int:crl_no>.<extension>",
            endpoint=endpoint, methods=('GET',)
        )
    srv = ServiceType.CERT_REPO
    for cert_repo in services.list_cert_repos():
        publish_issued = cert_repo.publish_issued_certs
        logger.info(
            f"CERT:{cert_repo.internal_url} "
            f"({'all certs' if publish_issued else 'CA only'})"
        )
        endpoint = srv.endpoint(arch, cert_repo.label)
        yield Rule(
            f"{cert_repo.internal_url}/ca.<extension>",
            defaults={'cert_label': None}, endpoint=endpoint, methods=('GET',)
        )
        if publish_issued:
            yield Rule(
                f"{cert_repo.internal_url}/issued/"
                f"<label:cert_label>.<extension>",
                endpoint=endpoint, methods=('GET',)
            )


@dataclass(frozen=True)
class ArchServicesDescription:
    arch: ArchLabel
    tsa: list
    ocsp: list
    crl: list


def gen_index(architectures):
    template_path = os.path.join(
        os.path.dirname(__file__), 'animator_templates'
    )

    def _index_info():
        pki_arch: PKIArchitecture
        for pki_arch in architectures:
            services = pki_arch.service_registry
            yield ArchServicesDescription(
                pki_arch.arch_label,
                tsa=services.list_time_stamping_services(),
                ocsp=services.list_ocsp_responders(),
                crl=services.list_crl_repos()
            )

    # the index is fixed from the moment the server is launched, so
    #  just go ahead and render it
    jinja_env = Environment(
        loader=FileSystemLoader(template_path), autoescape=True
    )
    template = jinja_env.get_template('index.html')
    return template.render(pki_archs=list(_index_info()))


class Animator:

    def __init__(self, architectures: Dict[ArchLabel, PKIArchitecture],
                 at_time: Optional[datetime] = None):
        self.fixed_time = at_time
        self.architectures = architectures

        def _all_rules():
            yield Rule('/', endpoint='index')
            for pki_arch in architectures.values():
                yield from service_rules(pki_arch.service_registry)

        self.url_map = Map(
            list(_all_rules()),
            converters={'label': LabelConverter}
        )
        self.index_html = gen_index(architectures.values())

    @property
    def at_time(self):
        return self.fixed_time or datetime.now(tz=tzlocal.get_localzone())

    def serve_ocsp_response(self, request: Request, *, label: ServiceLabel,
                            arch: ArchLabel):
        pki_arch = self.architectures[arch]
        ocsp_resp = pki_arch.service_registry.summon_responder(
            label, self.at_time
        )
        data = request.stream.read()
        req: ocsp.OCSPRequest = ocsp.OCSPRequest.load(data)
        response = ocsp_resp.build_ocsp_response(req)
        return Response(response.dump(), mimetype='application/ocsp-response')

    def serve_timestamp_response(self, request, *, label: ServiceLabel,
                                 arch: ArchLabel):
        pki_arch = self.architectures[arch]
        tsa = pki_arch.service_registry.summon_timestamper(
            label, self.at_time
        )
        data = request.stream.read()
        req: tsp.TimeStampReq = tsp.TimeStampReq.load(data)
        response = tsa.request_tsa_response(req)
        return Response(response.dump(), mimetype='application/timestamp-reply')

    def serve_crl(self, *, label: ServiceLabel, arch: ArchLabel,
                  crl_no, extension):
        pki_arch = self.architectures[arch]
        if extension == 'crl.pem':
            use_pem = True
            mime = 'application/x-pem-file'
        elif extension == 'crl':
            use_pem = False
            mime = 'application/pkix-crl'
        else:
            raise NotFound()

        if crl_no is not None:
            crl = pki_arch.service_registry.get_crl(label, number=crl_no)
        else:
            crl = pki_arch.service_registry.get_crl(label, self.at_time)

        data = crl.dump()
        if use_pem:
            data = pem.armor('X509 CRL', data)
        return Response(data, mimetype=mime)

    def serve_cert(self, *, label: ServiceLabel, arch: ArchLabel,
                   cert_label: Optional[str], extension):
        if extension == 'cert.pem':
            use_pem = True
            mime = 'application/x-pem-file'
        elif extension == 'crt':
            use_pem = False
            mime = 'application/pkix-cert'
        else:
            raise NotFound()

        pki_arch = self.architectures[arch]
        cert_label = CertLabel(cert_label) if cert_label is not None else None

        cert = pki_arch.service_registry.get_cert_from_repo(
            label, cert_label
        )
        if cert is None:
            raise NotFound()

        data = cert.dump()
        if use_pem:
            data = pem.armor('certificate', data)
        return Response(data, mimetype=mime)

    def dispatch(self, request: Request):
        adapter = self.url_map.bind_to_environ(request.environ)
        # TODO even though this is a testing tool, inserting some safeguards
        #  to check request size etc. might be prudent
        try:
            endpoint, values = adapter.match()
            if endpoint == 'index':
                return Response(self.index_html, mimetype='text/html')
            assert isinstance(endpoint, Endpoint)
            if endpoint.service_type == ServiceType.OCSP:
                return self.serve_ocsp_response(
                    request, label=endpoint.label, arch=endpoint.arch
                )
            if endpoint.service_type == ServiceType.TSA:
                return self.serve_timestamp_response(
                    request, label=endpoint.label, arch=endpoint.arch
                )
            if endpoint.service_type == ServiceType.CRL_REPO:
                return self.serve_crl(
                    label=endpoint.label, arch=endpoint.arch, **values
                )
            if endpoint.service_type == ServiceType.CERT_REPO:
                return self.serve_cert(
                    label=endpoint.label, arch=endpoint.arch, **values
                )
            raise InternalServerError()  # pragma: nocover
        except CertomancerObjectNotFoundError as e:
            logger.info(e)
            return NotFound()
        except CertomancerServiceError as e:
            logger.error(e)
            return InternalServerError()
        except HTTPException as e:
            return e

    def __call__(self, environ, start_response):
        request = Request(environ)
        resp = self.dispatch(request)
        return resp(environ, start_response)


class LazyAnimator:
    def __init__(self):
        self.animator = None

    def _load(self):
        if self.animator is not None:
            return
        env = os.environ
        cfg_file = env['CERTOMANCER_CONFIG']
        key_dir = env['CERTOMANCER_KEY_DIR']
        cfg = CertomancerConfig.from_file(cfg_file, key_dir)
        self.animator = Animator(cfg.pki_archs)

    def __call__(self, environ, start_response):
        self._load()
        return self.animator(environ, start_response)


app = LazyAnimator()
