import logging
import os
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from typing import Optional, Dict, List, Callable

import tzlocal
from asn1crypto import ocsp, tsp, pem
from werkzeug.wrappers import Request, Response
from dateutil.parser import parse as parse_dt
from werkzeug.routing import Map, Rule, BaseConverter, Submount
from werkzeug.exceptions import HTTPException, NotFound, InternalServerError, \
    BadRequest

from certomancer.config_utils import ConfigurationError
from certomancer.crypto_utils import pyca_cryptography_present
from certomancer.registry import (
    PKIArchitecture, ServiceLabel, CertLabel,
    CertomancerObjectNotFoundError, CertomancerConfig, ArchLabel, EntityLabel,
    AttributeCertificateSpec,
    CertificateSpec, PluginLabel, PluginServiceRequestError
)
from certomancer.services import CertomancerServiceError


logger = logging.getLogger(__name__)

pfx_possible = pyca_cryptography_present()


def _now():
    return datetime.now(tz=tzlocal.get_localzone())


FAKE_TIME_HEADER = 'X-Certomancer-Fake-Time'


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
class AnimatorAttrCertInfo:
    spec: AttributeCertificateSpec
    holder_dn: str

    @staticmethod
    def gather_cert_info(pki_arch: PKIArchitecture):

        def _for_attr_cert(spec: AttributeCertificateSpec):
            return AnimatorAttrCertInfo(
                spec=spec,
                holder_dn=pki_arch.entities[spec.holder.name].human_friendly
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
    attr_certs_by_issuer: Dict[EntityLabel, List[AnimatorCertInfo]]

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
            attr_certs_by_issuer=attr_cert_info
        )


WEB_UI_URL_PREFIX = '_certomancer'


def web_ui_rules():
    return [
        Rule('/', endpoint='index', methods=('GET',)),
        Submount("/" + WEB_UI_URL_PREFIX, [
            # convenience endpoint that serves certs without regard for
            # checking whether they belong to any particular (logical)
            # cert repo (these URLs aren't part of the "PKI API", for lack
            # of a better term)
            Rule('/any-cert/<arch>/<label>.<ext:use_pem>',
                 endpoint='any-cert', methods=('GET',)),
            Rule('/any-attr-cert/<arch>/<label>.attr.<ext:use_pem>',
                 endpoint='any-attr-cert', methods=('GET',)),
            Rule('/attr-certs-of/<arch>/<entity_label>-all.attr.cert.pem',
                 endpoint='attr-certs-of', methods=('GET',)),
            Rule('/cert-bundle/<arch>', endpoint='cert-bundle',
                 methods=('GET',)),
            Rule('/pfx-download/<arch>', endpoint='pfx-download',
                 methods=('POST',)),
        ])
    ]


def service_rules():
    return [
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
        Rule("/<arch>/crls/<label>"
             "/archive-<int:crl_no>.<ext(exts='crl'):use_pem>",
             endpoint='crls', methods=('GET',)),
        # Cert repo authority pattern
        Rule('/<arch>/certs/<label>/ca.<ext:use_pem>',
             defaults={'cert_label': None}, endpoint='certs', methods=('GET',)),
        # Cert repo generic pattern
        Rule('/<arch>/certs/<label>/issued/<cert_label>.<ext:use_pem>',
             endpoint='certs', methods=('GET',)),
        # Attr cert repo authority pattern
        Rule('/<arch>/attr-certs/<label>/aa.<ext:use_pem>',
             defaults={'cert_label': None},
             endpoint='attr-certs', methods=('GET',)),
        # Attr cert repo generic pattern
        Rule("/<arch>/attr-certs/<label>/issued/<cert_label>.attr.<ext:use_pem>",
             endpoint='attr-certs', methods=('GET',)),
        Rule("/<arch>/attr-certs/<label>/by-holder/<entity_label>-all.attr.cert.pem",
             endpoint='attr-certs-by-holder', methods=('GET',)),
    ]


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
                 at_time: Optional[datetime] = None, with_web_ui=True,
                 allow_time_override=True):
        self.fixed_time = at_time
        self.architectures = architectures
        self.with_web_ui = with_web_ui
        self.url_map = None
        self.allow_time_override = allow_time_override

        self.url_map = Map(
            service_rules() + (web_ui_rules() if with_web_ui else []),
            converters={'ext': PemExtensionConverter}
        )

        handlers: Dict[str, Callable] = {
            'ocsp': self.serve_ocsp_response,
            'tsa': self.serve_timestamp_response,
            'crls': self.serve_crl,
            'certs': self.serve_cert,
            'attr-certs': self.serve_attr_cert,
            'attr-certs-by-holder': self.serve_attr_certs_of_holder,
            'plugin': self.serve_plugin
        }

        if with_web_ui:
            self.index_html = gen_index(iter(architectures))
            handlers.update({
                'any-cert': self.serve_any_cert,
                'any-attr-cert': self.serve_any_attr_cert,
                'attr-certs-of': self.serve_all_attr_certs_of_holder,
                'cert-bundle': self.serve_zip, 'pfx-download': self.serve_pfx
            })

        self._handlers = handlers

    def at_time(self, request):
        fake_time = None
        if self.allow_time_override:
            fake_time = request.headers.get(FAKE_TIME_HEADER, type=parse_dt)

        return fake_time or self.fixed_time or _now()

    def serve_ocsp_response(self, request: Request, *, label: str, arch: str):
        pki_arch = self.architectures[ArchLabel(arch)]
        ocsp_resp = pki_arch.service_registry.summon_responder(
            ServiceLabel(label), self.at_time(request)
        )
        data = request.stream.read()
        req: ocsp.OCSPRequest = ocsp.OCSPRequest.load(data)
        response = ocsp_resp.build_ocsp_response(req)
        return Response(response.dump(), mimetype='application/ocsp-response')

    def serve_timestamp_response(self, request: Request, *,
                                 label: str, arch: str):
        pki_arch = self.architectures[ArchLabel(arch)]
        tsa = pki_arch.service_registry.summon_timestamper(
            ServiceLabel(label), self.at_time(request)
        )
        data = request.stream.read()
        req: tsp.TimeStampReq = tsp.TimeStampReq.load(data)
        response = tsa.request_tsa_response(req)
        return Response(response.dump(), mimetype='application/timestamp-reply')

    def serve_crl(self, request: Request, *,
                  label: ServiceLabel, arch: str, crl_no, use_pem):
        pki_arch = self.architectures[ArchLabel(arch)]
        mime = 'application/x-pem-file' if use_pem else 'application/pkix-crl'
        if crl_no is not None:
            crl = pki_arch.service_registry.get_crl(label, number=crl_no)
        else:
            crl = pki_arch.service_registry.get_crl(
                label, self.at_time(request)
            )

        data = crl.dump()
        if use_pem:
            data = pem.armor('X509 CRL', data)
        return Response(data, mimetype=mime)

    def serve_any_cert(self, _request: Request, *,
                       arch: str, label: str, use_pem):
        mime = 'application/x-pem-file' if use_pem else 'application/pkix-cert'
        pki_arch = self.architectures[ArchLabel(arch)]
        cert = pki_arch.get_cert(CertLabel(label))

        data = cert.dump()
        if use_pem:
            data = pem.armor('certificate', data)
        return Response(data, mimetype=mime)

    def serve_any_attr_cert(self, _request: Request, *,
                            arch: str, label: str, use_pem):
        mime = (
            'application/x-pem-file'
            if use_pem else 'application/pkix-attr-cert'
        )
        pki_arch = self.architectures[ArchLabel(arch)]
        cert = pki_arch.get_attr_cert(CertLabel(label))

        data = cert.dump()
        if use_pem:
            data = pem.armor('attribute certificate', data)
        return Response(data, mimetype=mime)

    def serve_cert(self, _request: Request, *, label: str, arch: str,
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

    def serve_attr_cert(self, _request: Request, *, label: str, arch: str,
                        cert_label: Optional[str], use_pem):
        pki_arch = self.architectures[ArchLabel(arch)]
        svc_reg = pki_arch.service_registry
        svc_label = ServiceLabel(label)
        if cert_label is None:
            mime = (
                'application/x-pem-file' if use_pem else 'application/pkix-cert'
            )
            # retrieve the AA's certificate
            cert = pki_arch.get_cert(
                svc_reg.determine_repo_issuer_cert(
                    svc_reg.get_attr_cert_repo_info(svc_label),
                )
            )
        else:
            mime = (
                'application/x-pem-file'
                if use_pem else 'application/pkix-attr-cert'
            )
            cert = svc_reg.get_attr_cert_from_repo(
                svc_label, CertLabel(cert_label)
            )
        if cert is None:
            raise NotFound()

        data = cert.dump()
        if use_pem:
            data = pem.armor(
                'attribute certificate'
                if cert_label is not None else 'certificate',
                data
            )
        return Response(data, mimetype=mime)

    def _build_attr_cert_payload(self, pki_arch, cert_specs):
        # TODO support non-PEM with p7b
        data_buf = BytesIO()
        for cert_spec in cert_specs:
            cert = pki_arch.get_attr_cert(cert_spec.label)
            data_buf.write(
                pem.armor(
                    'attribute certificate',
                    cert.dump()
                )
            )
        data = data_buf.getvalue()
        if not data:
            raise NotFound()
        return data

    def serve_all_attr_certs_of_holder(self, _request: Request, *,
                                       arch: str, entity_label: str):
        pki_arch = self.architectures[ArchLabel(arch)]
        cert_specs = pki_arch.enumerate_attr_certs_of_holder(
            EntityLabel(entity_label),
        )
        data = self._build_attr_cert_payload(pki_arch, cert_specs)
        return Response(data, mimetype='application/pkix-attr-cert')

    def serve_attr_certs_of_holder(self, _request: Request, *,
                                   label: str, arch: str, entity_label: str):
        pki_arch = self.architectures[ArchLabel(arch)]
        svc_label = ServiceLabel(label)
        info = pki_arch.service_registry.get_attr_cert_repo_info(svc_label)
        if not info.publish_by_holder:
            raise NotFound()
        cert_specs = pki_arch.enumerate_attr_certs_of_holder(
            EntityLabel(entity_label), info.for_issuer,
        )
        data = self._build_attr_cert_payload(pki_arch, cert_specs)
        return Response(data, mimetype='application/pkix-attr-cert')

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
                plugin_label, label, req_content, at_time=self.at_time(request)
            )
        except PluginServiceRequestError as e:
            raise BadRequest(e.user_msg)
        return Response(response_bytes, mimetype=content_type)

    def serve_zip(self, _request: Request, *, arch):
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
            if endpoint == 'index' and self.with_web_ui:
                return Response(self.index_html, mimetype='text/html')
            handler = self._handlers[endpoint]
            return handler(request, **values)
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
        allow_time_override = not _check_env_flag(
            env, 'CERTOMANCER_NO_TIME_OVERRIDE'
        )

        cfg = CertomancerConfig.from_file(
            cfg_file, key_search_dir=key_dir, config_search_dir=config_dir,
            allow_external_config=extl_config
        )
        self.animator = Animator(
            AnimatorArchStore(cfg.pki_archs), with_web_ui=with_web_ui,
            allow_time_override=allow_time_override
        )

    def __call__(self, environ, start_response):
        self._load()
        return self.animator(environ, start_response)


app = LazyAnimator()
