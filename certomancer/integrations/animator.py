import logging
import os
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from typing import Optional, Dict, List

import tzlocal
from asn1crypto import ocsp, tsp, pem
from werkzeug.wrappers import Request, Response
from werkzeug.routing import Map, Rule, BaseConverter, Submount
from werkzeug.exceptions import HTTPException, NotFound, InternalServerError, \
    BadRequest

from certomancer.config_utils import pyca_cryptography_present, \
    ConfigurationError
from certomancer.registry import (
    PKIArchitecture, ServiceLabel, CertLabel,
    CertomancerObjectNotFoundError, CertomancerConfig, ArchLabel, EntityLabel,
    CertificateSpec, PluginLabel, PluginServiceRequestError
)
from certomancer.services import CertomancerServiceError


logger = logging.getLogger(__name__)

pfx_possible = pyca_cryptography_present()


class PemExtensionConverter(BaseConverter):

    def __init__(self, map, exts=('crt', 'cert', 'cer')):
        if isinstance(exts, str):
            exts = (exts,)
        self.expected_exts = exts
        self.regex = r"(%s)(\.pem)?" % '|'.join(exts)
        super().__init__(map)

    def to_python(self, value):
        return value.endswith('.pem')

    def to_url(self, value):
        return self.expected_exts[0] + ('.pem' if value else '')


@dataclass(frozen=True)
class AnimatorCertInfo:
    spec: CertificateSpec
    pfx_available: bool
    subject_dn: str

    @staticmethod
    def gather_cert_info(pki_arch: PKIArchitecture):

        def _for_cert(spec: CertificateSpec):
            pfx = pfx_possible and pki_arch.is_subject_key_available(spec.label)
            return AnimatorCertInfo(
                spec=spec, pfx_available=pfx,
                subject_dn=pki_arch.entities[spec.subject].human_friendly
            )

        return {
            iss: list(map(_for_cert, issd_certs))
            for iss, issd_certs in pki_arch.enumerate_certs_by_issuer()
        }


@dataclass(frozen=True)
class ArchServicesDescription:
    arch: ArchLabel
    tsa: list
    ocsp: list
    crl: list
    cert_repo: list
    certs_by_issuer: Dict[EntityLabel, List[AnimatorCertInfo]]

    @classmethod
    def compile(cls, pki_arch: PKIArchitecture):
        services = pki_arch.service_registry
        cert_info = AnimatorCertInfo.gather_cert_info(pki_arch)
        return ArchServicesDescription(
            pki_arch.arch_label,
            tsa=services.list_time_stamping_services(),
            ocsp=services.list_ocsp_responders(),
            crl=services.list_crl_repos(),
            cert_repo=services.list_cert_repos(),
            certs_by_issuer=cert_info,
        )


WEB_UI_URL_PREFIX = '/_certomancer'


WEB_UI_URLS = [
    Rule('/', endpoint='index', methods=('GET',)),
    Submount(WEB_UI_URL_PREFIX, [
        # convenience endpoint that serves certs without regard for
        # checking whether they belong to any particular (logical)
        # cert repo (these URLs aren't part of the "PKI API", for lack
        # of a better term)
        Rule('/any-cert/<arch>/<label>.<ext:use_pem>',
             endpoint='any-cert', methods=('GET',)),
        Rule('/cert-bundle/<arch>', endpoint='cert-bundle', methods=('GET',)),
        Rule('/pfx-download/<arch>', endpoint='pfx-download',
             methods=('POST',)),
    ])
]


SERVICE_RULES = [
    # OCSP responder pattern
    Rule('/<arch>/ocsp/<label>', endpoint='ocsp', methods=('POST',)),
    # Time stamping service pattern
    Rule('/<arch>/tsa/<label>', endpoint='tsa', methods=('POST',)),
    # Plugin endpoint pattern
    Rule('/<arch>/plugin/<plugin_label>/<label>', endpoint='plugin',
         methods=('POST',)),
    # latest CRL pattern
    Rule("/<arch>/crls/<label>/latest.<ext(exts='crl'):use_pem>",
         endpoint='crls', methods=('GET',), defaults={'crl_no': None}),
    # CRL archive pattern
    Rule("/<arch>/crls/<label>/archive-<int:crl_no>.<ext(exts='crl'):use_pem>",
         endpoint='crls', methods=('GET',)),
    # Cert repo authority pattern
    Rule('/<arch>/certs/<label>/ca.<ext:use_pem>',
         defaults={'cert_label': None}, endpoint='certs', methods=('GET',)),
    # Cert repo generic pattern
    Rule(f"/<arch>/certs/<label>/issued/<cert_label>.<ext:use_pem>",
         endpoint='certs', methods=('GET',))
]


def gen_index(architectures):
    try:
        from jinja2 import Environment, PackageLoader
    except ImportError as e:
        raise CertomancerServiceError(
            "Web UI requires Jinja2 to be installed"
        ) from e

    # the index is fixed from the moment the server is launched, so
    #  just go ahead and render it
    jinja_env = Environment(
        loader=PackageLoader('certomancer.integrations', 'animator_templates'),
        autoescape=True
    )
    template = jinja_env.get_template('index.html')
    return template.render(
        pki_archs=[
            ArchServicesDescription.compile(arch) for arch in architectures
        ],
        pfx_possible=pfx_possible, web_ui_prefix=WEB_UI_URL_PREFIX
    )


class AnimatorArchStore:

    def __init__(self, architectures: Dict[ArchLabel, PKIArchitecture]):
        self.architectures = architectures

    def __getitem__(self, arch: ArchLabel) -> PKIArchitecture:
        try:
            return self.architectures[arch]
        except KeyError:
            raise NotFound()

    def __iter__(self):
        return iter(self.architectures.values())


class Animator:

    def __init__(self, architectures: AnimatorArchStore,
                 at_time: Optional[datetime] = None, with_web_ui=True):
        self.fixed_time = at_time
        self.architectures = architectures
        self.with_web_ui = with_web_ui
        self.url_map = None

        self.url_map = Map(
            SERVICE_RULES + (WEB_UI_URLS if with_web_ui else []),
            converters={'ext': PemExtensionConverter}
        )
        if with_web_ui:
            self.index_html = gen_index(iter(architectures))

    @property
    def at_time(self):
        return self.fixed_time or datetime.now(tz=tzlocal.get_localzone())

    def serve_ocsp_response(self, request: Request, *, label: str, arch: str):
        pki_arch = self.architectures[ArchLabel(arch)]
        ocsp_resp = pki_arch.service_registry.summon_responder(
            ServiceLabel(label), self.at_time
        )
        data = request.stream.read()
        req: ocsp.OCSPRequest = ocsp.OCSPRequest.load(data)
        response = ocsp_resp.build_ocsp_response(req)
        return Response(response.dump(), mimetype='application/ocsp-response')

    def serve_timestamp_response(self, request, *, label: str, arch: str):
        pki_arch = self.architectures[ArchLabel(arch)]
        tsa = pki_arch.service_registry.summon_timestamper(
            ServiceLabel(label), self.at_time
        )
        data = request.stream.read()
        req: tsp.TimeStampReq = tsp.TimeStampReq.load(data)
        response = tsa.request_tsa_response(req)
        return Response(response.dump(), mimetype='application/timestamp-reply')

    def serve_crl(self, *, label: ServiceLabel, arch: str, crl_no, use_pem):
        pki_arch = self.architectures[ArchLabel(arch)]
        mime = 'application/x-pem-file' if use_pem else 'application/pkix-crl'
        if crl_no is not None:
            crl = pki_arch.service_registry.get_crl(label, number=crl_no)
        else:
            crl = pki_arch.service_registry.get_crl(label, self.at_time)

        data = crl.dump()
        if use_pem:
            data = pem.armor('X509 CRL', data)
        return Response(data, mimetype=mime)

    def serve_any_cert(self, *, arch: str, label: str, use_pem):
        mime = 'application/x-pem-file' if use_pem else 'application/pkix-cert'
        pki_arch = self.architectures[ArchLabel(arch)]
        cert = pki_arch.get_cert(CertLabel(label))

        data = cert.dump()
        if use_pem:
            data = pem.armor('certificate', data)
        return Response(data, mimetype=mime)

    def serve_cert(self, *, label: str, arch: str,
                   cert_label: Optional[str], use_pem):
        mime = 'application/x-pem-file' if use_pem else 'application/pkix-cert'
        pki_arch = self.architectures[ArchLabel(arch)]
        cert_label = CertLabel(cert_label) if cert_label is not None else None

        cert = pki_arch.service_registry.get_cert_from_repo(
            ServiceLabel(label), cert_label
        )
        if cert is None:
            raise NotFound()

        data = cert.dump()
        if use_pem:
            data = pem.armor('certificate', data)
        return Response(data, mimetype=mime)

    def serve_plugin(self, request: Request, plugin_label: str, *, label: str,
                     arch: str):
        pki_arch = self.architectures[ArchLabel(arch)]
        services = pki_arch.service_registry
        plugin_label = PluginLabel(plugin_label)
        label = ServiceLabel(label)
        try:
            plugin_info = services.get_plugin_info(plugin_label, label)
        except ConfigurationError:
            raise NotFound()

        content_type = plugin_info.content_type
        req_content = request.stream.read()
        try:
            response_bytes = services.invoke_plugin(
                plugin_label, label, req_content, at_time=self.at_time
            )
        except PluginServiceRequestError as e:
            raise BadRequest(e.user_msg)
        return Response(response_bytes, mimetype=content_type)

    def serve_zip(self, *, arch):
        try:
            pki_arch = self.architectures[ArchLabel(arch)]
        except KeyError:
            raise NotFound()
        zip_buffer = BytesIO()
        pki_arch.zip_certs(zip_buffer)
        zip_buffer.seek(0)
        data = zip_buffer.read()
        cd_header = f'attachment; filename="{arch}-certificates.zip"'
        return Response(data, mimetype='application/zip',
                        headers={'Content-Disposition': cd_header})

    def serve_pfx(self, request: Request, *, arch):
        pki_arch = self.architectures[ArchLabel(arch)]
        try:
            cert = request.form['cert']
        except KeyError:
            raise BadRequest()

        cert = CertLabel(cert)
        if not (pyca_cryptography_present() and
                pki_arch.is_subject_key_available(cert)):
            raise NotFound()

        pass_bytes = request.form.get('passphrase', '').encode('utf8')
        data = pki_arch.package_pkcs12(cert, password=pass_bytes or None)
        cd_header = f'attachment; filename="{cert}.pfx"'
        return Response(data, mimetype='application/x-pkcs12',
                        headers={'Content-Disposition': cd_header})

    def dispatch(self, request: Request):
        adapter = self.url_map.bind_to_environ(request.environ)
        # TODO even though this is a testing tool, inserting some safeguards
        #  to check request size etc. might be prudent
        try:
            endpoint, values = adapter.match()
            assert isinstance(endpoint, str)
            if self.with_web_ui:
                if endpoint == 'index':
                    return Response(self.index_html, mimetype='text/html')
                if endpoint == 'any-cert':
                    return self.serve_any_cert(**values)
                if endpoint == 'cert-bundle':
                    return self.serve_zip(**values)
                if endpoint == 'pfx-download':
                    return self.serve_pfx(request, **values)
            if endpoint == 'ocsp':
                return self.serve_ocsp_response(request, **values)
            if endpoint == 'tsa':
                return self.serve_timestamp_response(request, **values)
            if endpoint == 'crls':
                return self.serve_crl(**values)
            if endpoint == 'certs':
                return self.serve_cert(**values)
            if endpoint == 'plugin':
                return self.serve_plugin(request, **values)
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


def _check_env_flag(env, flag_name):
    val = env.get(flag_name, '0')
    try:
        return bool(int(val))
    except ValueError:
        return False


class LazyAnimator:
    def __init__(self):
        self.animator = None

    def _load(self):
        if self.animator is not None:
            return
        env = os.environ
        cfg_file = env['CERTOMANCER_CONFIG']
        key_dir = env['CERTOMANCER_KEY_DIR']
        config_dir = env.get('CERTOMANCER_EXTRA_CONFIG_DIR', None)
        with_web_ui = not _check_env_flag(env, 'CERTOMANCER_NO_WEB_UI')
        extl_config = not _check_env_flag(env, 'CERTOMANCER_NO_EXTRA_CONFIG')

        cfg = CertomancerConfig.from_file(
            cfg_file, key_search_dir=key_dir, config_search_dir=config_dir,
            allow_external_config=extl_config
        )
        self.animator = Animator(
            AnimatorArchStore(cfg.pki_archs), with_web_ui=with_web_ui
        )

    def __call__(self, environ, start_response):
        self._load()
        return self.animator(environ, start_response)


app = LazyAnimator()
