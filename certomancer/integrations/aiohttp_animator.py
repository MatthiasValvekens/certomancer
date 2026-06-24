import logging
from datetime import datetime
from io import BytesIO
from typing import Dict, Optional

from aiohttp import web
from asn1crypto import ocsp, pem, tsp
from dateutil.parser import parse as parse_dt

from certomancer.config_utils import ConfigurationError
from certomancer.registry import (
    ArchLabel,
    CertLabel,
    CertomancerObjectNotFoundError,
    EntityLabel,
    PKIArchitecture,
    PluginLabel,
    PluginServiceRequestError,
    ServiceLabel,
)
from certomancer.services import CertomancerServiceError

from ._animator_shared import (
    FAKE_TIME_HEADER,
    WEB_UI_URL_PREFIX,
    _now,
    gen_index,
)

logger = logging.getLogger(__name__)


def _get_arch(
    architectures: Dict[ArchLabel, PKIArchitecture],
    arch: str,
) -> PKIArchitecture:
    try:
        return architectures[ArchLabel(arch)]
    except KeyError:
        raise web.HTTPNotFound()


@web.middleware
async def _error_middleware(request, handler):
    try:
        return await handler(request)
    except web.HTTPException:
        raise
    except CertomancerObjectNotFoundError as e:
        logger.info(e)
        raise web.HTTPNotFound()
    except PluginServiceRequestError as e:
        raise web.HTTPBadRequest(text=e.user_msg)
    except CertomancerServiceError as e:
        logger.error(e)
        raise web.HTTPInternalServerError()


def build_animator_app(
    architectures: Dict[ArchLabel, PKIArchitecture],
    at_time: Optional[datetime] = None,
    with_web_ui: bool = True,
    allow_time_override: bool = True,
) -> web.Application:
    """Build an aiohttp web.Application that mirrors the WSGI Animator."""

    fixed_time = at_time

    def _resolve_time(request: web.Request) -> datetime:
        if allow_time_override:
            header = request.headers.get(FAKE_TIME_HEADER)
            if header:
                return parse_dt(header)
        return fixed_time or _now()

    # --- service handlers ---

    async def serve_ocsp(request: web.Request) -> web.Response:
        arch = request.match_info['arch']
        label = request.match_info['label']
        pki_arch = _get_arch(architectures, arch)
        ocsp_resp = pki_arch.service_registry.summon_responder(
            ServiceLabel(label), _resolve_time(request)
        )
        data = await request.read()
        req: ocsp.OCSPRequest = ocsp.OCSPRequest.load(data)
        response = ocsp_resp.build_ocsp_response(req)
        return web.Response(
            body=response.dump(),
            content_type='application/ocsp-response',
        )

    async def serve_tsa(request: web.Request) -> web.Response:
        arch = request.match_info['arch']
        label = request.match_info['label']
        pki_arch = _get_arch(architectures, arch)
        tsa = pki_arch.service_registry.summon_timestamper(
            ServiceLabel(label), _resolve_time(request)
        )
        data = await request.read()
        req: tsp.TimeStampReq = tsp.TimeStampReq.load(data)
        response = tsa.request_tsa_response(req)
        return web.Response(
            body=response.dump(),
            content_type='application/timestamp-reply',
        )

    async def serve_crl_latest(request: web.Request) -> web.Response:
        arch = request.match_info['arch']
        label = request.match_info['label']
        ext = request.match_info['ext']
        use_pem = ext.endswith('.pem')
        pki_arch = _get_arch(architectures, arch)
        mime = 'application/x-pem-file' if use_pem else 'application/pkix-crl'
        crl = pki_arch.service_registry.get_crl(
            ServiceLabel(label), _resolve_time(request)
        )
        body = crl.dump()
        if use_pem:
            body = pem.armor('X509 CRL', body)
        return web.Response(body=body, content_type=mime)

    async def serve_crl_archive(request: web.Request) -> web.Response:
        arch = request.match_info['arch']
        label = request.match_info['label']
        crl_no = int(request.match_info['crl_no'])
        ext = request.match_info['ext']
        use_pem = ext.endswith('.pem')
        pki_arch = _get_arch(architectures, arch)
        mime = 'application/x-pem-file' if use_pem else 'application/pkix-crl'
        crl = pki_arch.service_registry.get_crl(
            ServiceLabel(label), number=crl_no
        )
        body = crl.dump()
        if use_pem:
            body = pem.armor('X509 CRL', body)
        return web.Response(body=body, content_type=mime)

    async def serve_cert_ca(request: web.Request) -> web.Response:
        arch = request.match_info['arch']
        label = request.match_info['label']
        ext = request.match_info['ext']
        use_pem = ext.endswith('.pem')
        pki_arch = _get_arch(architectures, arch)
        mime = 'application/x-pem-file' if use_pem else 'application/pkix-cert'
        cert = pki_arch.service_registry.get_cert_from_repo(
            ServiceLabel(label), None
        )
        if cert is None:
            raise web.HTTPNotFound()
        body = cert.dump()
        if use_pem:
            body = pem.armor('certificate', body)
        return web.Response(body=body, content_type=mime)

    async def serve_cert_issued(request: web.Request) -> web.Response:
        arch = request.match_info['arch']
        label = request.match_info['label']
        cert_label = request.match_info['cert_label']
        ext = request.match_info['ext']
        use_pem = ext.endswith('.pem')
        pki_arch = _get_arch(architectures, arch)
        mime = 'application/x-pem-file' if use_pem else 'application/pkix-cert'
        cert = pki_arch.service_registry.get_cert_from_repo(
            ServiceLabel(label), CertLabel(cert_label)
        )
        if cert is None:
            raise web.HTTPNotFound()
        body = cert.dump()
        if use_pem:
            body = pem.armor('certificate', body)
        return web.Response(body=body, content_type=mime)

    async def serve_attr_cert_aa(request: web.Request) -> web.Response:
        arch = request.match_info['arch']
        label = request.match_info['label']
        ext = request.match_info['ext']
        use_pem = ext.endswith('.pem')
        pki_arch = _get_arch(architectures, arch)
        svc_reg = pki_arch.service_registry
        svc_label = ServiceLabel(label)
        mime = 'application/x-pem-file' if use_pem else 'application/pkix-cert'
        cert = pki_arch.get_cert(
            svc_reg.determine_repo_issuer_cert(
                svc_reg.get_attr_cert_repo_info(svc_label),
            )
        )
        if cert is None:
            raise web.HTTPNotFound()
        body = cert.dump()
        if use_pem:
            body = pem.armor('certificate', body)
        return web.Response(body=body, content_type=mime)

    async def serve_attr_cert_issued(request: web.Request) -> web.Response:
        arch = request.match_info['arch']
        label = request.match_info['label']
        cert_label = request.match_info['cert_label']
        ext = request.match_info['ext']
        use_pem = ext.endswith('.pem')
        pki_arch = _get_arch(architectures, arch)
        svc_reg = pki_arch.service_registry
        svc_label = ServiceLabel(label)
        mime = (
            'application/x-pem-file'
            if use_pem
            else 'application/pkix-attr-cert'
        )
        cert = svc_reg.get_attr_cert_from_repo(svc_label, CertLabel(cert_label))
        if cert is None:
            raise web.HTTPNotFound()
        body = cert.dump()
        if use_pem:
            body = pem.armor('attribute certificate', body)
        return web.Response(body=body, content_type=mime)

    def _build_attr_cert_pem_payload(pki_arch, cert_specs):
        data_buf = BytesIO()
        for cert_spec in cert_specs:
            cert = pki_arch.get_attr_cert(cert_spec.label)
            data_buf.write(pem.armor('attribute certificate', cert.dump()))
        data = data_buf.getvalue()
        if not data:
            raise web.HTTPNotFound()
        return data

    async def serve_attr_certs_by_holder(
        request: web.Request,
    ) -> web.Response:
        arch = request.match_info['arch']
        label = request.match_info['label']
        entity_label = request.match_info['entity_label']
        pki_arch = _get_arch(architectures, arch)
        svc_label = ServiceLabel(label)
        info = pki_arch.service_registry.get_attr_cert_repo_info(svc_label)
        if not info.publish_by_holder:
            raise web.HTTPNotFound()
        cert_specs = pki_arch.enumerate_attr_certs_of_holder(
            EntityLabel(entity_label),
            info.for_issuer,
        )
        body = _build_attr_cert_pem_payload(pki_arch, cert_specs)
        return web.Response(
            body=body, content_type='application/pkix-attr-cert'
        )

    async def serve_plugin(request: web.Request) -> web.Response:
        arch = request.match_info['arch']
        label = request.match_info['label']
        plugin_label_str = request.match_info['plugin_label']
        pki_arch = _get_arch(architectures, arch)
        services = pki_arch.service_registry
        plugin_lbl = PluginLabel(plugin_label_str)
        svc_lbl = ServiceLabel(label)
        try:
            plugin_info = services.get_plugin_info(plugin_lbl, svc_lbl)
        except ConfigurationError:
            raise web.HTTPNotFound()
        content_type = plugin_info.content_type
        req_content = await request.read()
        response_bytes = services.invoke_plugin(
            plugin_lbl, svc_lbl, req_content, at_time=_resolve_time(request)
        )
        return web.Response(body=response_bytes, content_type=content_type)

    # --- web UI handlers ---

    async def serve_any_cert(request: web.Request) -> web.Response:
        arch = request.match_info['arch']
        label = request.match_info['label']
        ext = request.match_info['ext']
        use_pem = ext.endswith('.pem')
        pki_arch = _get_arch(architectures, arch)
        mime = 'application/x-pem-file' if use_pem else 'application/pkix-cert'
        cert = pki_arch.get_cert(CertLabel(label))
        body = cert.dump()
        if use_pem:
            body = pem.armor('certificate', body)
        return web.Response(body=body, content_type=mime)

    async def serve_any_attr_cert(request: web.Request) -> web.Response:
        arch = request.match_info['arch']
        label = request.match_info['label']
        ext = request.match_info['ext']
        use_pem = ext.endswith('.pem')
        pki_arch = _get_arch(architectures, arch)
        mime = (
            'application/x-pem-file'
            if use_pem
            else 'application/pkix-attr-cert'
        )
        cert = pki_arch.get_attr_cert(CertLabel(label))
        body = cert.dump()
        if use_pem:
            body = pem.armor('attribute certificate', body)
        return web.Response(body=body, content_type=mime)

    async def serve_attr_certs_of(request: web.Request) -> web.Response:
        arch = request.match_info['arch']
        entity_label = request.match_info['entity_label']
        pki_arch = _get_arch(architectures, arch)
        cert_specs = pki_arch.enumerate_attr_certs_of_holder(
            EntityLabel(entity_label),
        )
        body = _build_attr_cert_pem_payload(pki_arch, cert_specs)
        return web.Response(
            body=body, content_type='application/pkix-attr-cert'
        )

    async def serve_cert_bundle(request: web.Request) -> web.Response:
        arch = request.match_info['arch']
        pki_arch = _get_arch(architectures, arch)
        zip_buffer = BytesIO()
        pki_arch.zip_certs(zip_buffer)
        zip_buffer.seek(0)
        body = zip_buffer.read()
        cd_header = f'attachment; filename="{arch}-certificates.zip"'
        return web.Response(
            body=body,
            content_type='application/zip',
            headers={'Content-Disposition': cd_header},
        )

    async def serve_pfx(request: web.Request) -> web.Response:
        arch = request.match_info['arch']
        pki_arch = _get_arch(architectures, arch)
        post_data = await request.post()
        raw_cert = post_data.get('cert')
        if not isinstance(raw_cert, str):
            raise web.HTTPBadRequest()
        cert_label = CertLabel(raw_cert)
        if not pki_arch.is_subject_key_available(cert_label):
            raise web.HTTPNotFound()
        raw_pass = post_data.get('passphrase', '')
        pass_str = raw_pass if isinstance(raw_pass, str) else ''
        pass_bytes = pass_str.encode('utf8') if pass_str else None
        body = pki_arch.package_pkcs12(cert_label, password=pass_bytes)
        cd_header = f'attachment; filename="{cert_label}.pfx"'
        return web.Response(
            body=body,
            content_type='application/x-pkcs12',
            headers={'Content-Disposition': cd_header},
        )

    # --- build application ---

    app = web.Application(middlewares=[_error_middleware])
    router = app.router

    # Service routes
    router.add_post('/{arch}/ocsp/{label}', serve_ocsp)
    router.add_post('/{arch}/tsa/{label}', serve_tsa)
    router.add_post('/{arch}/plugin/{plugin_label}/{label}', serve_plugin)
    # CRL routes: latest and archive
    router.add_get(
        r'/{arch}/crls/{label}/latest.{ext:(crl|crl\.pem)}',
        serve_crl_latest,
    )
    router.add_get(
        r'/{arch}/crls/{label}/archive-{crl_no:\d+}.{ext:(crl|crl\.pem)}',
        serve_crl_archive,
    )
    # Cert repo routes
    router.add_get(
        r'/{arch}/certs/{label}/ca.{ext:(crt|cert|cer)(\.pem)?}',
        serve_cert_ca,
    )
    router.add_get(
        r'/{arch}/certs/{label}/issued/{cert_label}.{ext:(crt|cert|cer)(\.pem)?}',
        serve_cert_issued,
    )
    # Attr cert repo routes
    router.add_get(
        r'/{arch}/attr-certs/{label}/aa.{ext:(crt|cert|cer)(\.pem)?}',
        serve_attr_cert_aa,
    )
    router.add_get(
        r'/{arch}/attr-certs/{label}/issued/{cert_label}.attr.{ext:(crt|cert|cer)(\.pem)?}',
        serve_attr_cert_issued,
    )
    router.add_get(
        '/{arch}/attr-certs/{label}/by-holder/{entity_label}-all.attr.cert.pem',
        serve_attr_certs_by_holder,
    )

    if with_web_ui:
        index_html = gen_index(architectures.values())

        async def serve_index(request: web.Request) -> web.Response:
            return web.Response(body=index_html, content_type='text/html')

        router.add_get('/', serve_index)

        prefix = '/' + WEB_UI_URL_PREFIX
        router.add_get(
            r'/_certomancer/any-cert/{arch}/{label}.{ext:(crt|cert|cer)(\.pem)?}',
            serve_any_cert,
        )
        router.add_get(
            r'/_certomancer/any-attr-cert/{arch}/{label}.attr.{ext:(crt|cert|cer)(\.pem)?}',
            serve_any_attr_cert,
        )
        router.add_get(
            prefix + '/attr-certs-of/{arch}/{entity_label}-all.attr.cert.pem',
            serve_attr_certs_of,
        )
        router.add_get(
            prefix + '/cert-bundle/{arch}',
            serve_cert_bundle,
        )
        router.add_post(
            prefix + '/pfx-download/{arch}',
            serve_pfx,
        )

    return app


def run_animator_app(
    app: web.Application, host: str = '127.0.0.1', port: int = 9000
) -> None:
    """Convenience wrapper to run the animator app."""
    web.run_app(app, host=host, port=port)
