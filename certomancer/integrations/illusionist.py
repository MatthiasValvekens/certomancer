from datetime import datetime
from typing import Optional

import requests_mock
from asn1crypto import ocsp, tsp
import tzlocal

from certomancer.registry import PKIArchitecture
from functools import partial


class Illusionist:
    """
    Register fake PKI services in a request mocker.
    Supports CRL retrieval (latest only), OCSP, timestamping and service
    plugins.

    :param pki_arch:
        A certomancer PKI architecture.
    """

    def __init__(self, pki_arch: PKIArchitecture,
                 at_time: Optional[datetime] = None):
        self.pki_arch = pki_arch
        self.fixed_time = at_time

    def register(self, mocker: requests_mock.Mocker):
        services = self.pki_arch.service_registry
        for ocsp_info in services.list_ocsp_responders():
            mocker.register_uri(
                'POST', ocsp_info.url,
                content=partial(
                    self.serve_ocsp_response, label=ocsp_info.label
                ),
                headers={'Content-Type': 'application/ocsp-response'}
            )

        for tsa_info in services.list_time_stamping_services():
            mocker.register_uri(
                'POST', tsa_info.url,
                content=partial(
                    self.serve_timestamp_response,
                    label=tsa_info.label
                ),
                headers={'Content-Type': 'application/timestamp-reply'}
            )

        for crl_repo in services.list_crl_repos():
            mocker.register_uri(
                'GET', crl_repo.latest_external_url,
                content=partial(
                    self.serve_crl,
                    label=crl_repo.label
                ),
                headers={'Content-Type': 'application/pkix-crl'}
            )

        for plugin_info in services.list_plugin_services():
            mocker.register_uri(
                'POST', plugin_info.url,
                content=partial(
                    self.serve_plugin, plugin_label=plugin_info.plugin_label,
                    label=plugin_info.label
                ),
                headers={'Content-Type': plugin_info.content_type}
            )

    @property
    def at_time(self):
        return self.fixed_time or datetime.now(tz=tzlocal.get_localzone())

    def serve_ocsp_response(self, request, _context, *, label):
        ocsp_resp = self.pki_arch.service_registry.summon_responder(
            label, self.at_time
        )
        req: ocsp.OCSPRequest = ocsp.OCSPRequest.load(request.body)
        response = ocsp_resp.build_ocsp_response(req)
        return response.dump()

    def serve_timestamp_response(self, request, _context, *, label):
        tsa = self.pki_arch.service_registry.summon_timestamper(
            label, self.at_time
        )
        req: tsp.TimeStampReq = tsp.TimeStampReq.load(request.body)
        response = tsa.request_tsa_response(req)
        return response.dump()

    def serve_crl(self, _request, _context, *, label):
        crl = self.pki_arch.service_registry.get_crl(label, self.at_time)
        return crl.dump()

    def serve_plugin(self, request, _context, *, label, plugin_label):
        return self.pki_arch.service_registry.invoke_plugin(
            plugin_label, label, request.body, at_time=self.at_time
        )
