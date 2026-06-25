import socket
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional
from urllib.parse import urlsplit

import aiohttp
import aiohttp.abc
import aiohttp.test_utils
import aiohttp.web
import tzlocal
from asn1crypto import ocsp, tsp

from certomancer.registry import PKIArchitecture, PluginLabel, ServiceLabel


class _FakeResolver(aiohttp.abc.AbstractResolver):
    def __init__(self, port: int):
        self._port = port

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_INET,
    ):
        return [
            {
                'hostname': host,
                'host': '127.0.0.1',
                'port': self._port,
                'family': family,
                'proto': 0,
                'flags': socket.AI_NUMERICHOST,
            }
        ]

    async def close(self):
        pass


class AsyncIllusionist:
    """
    Serve fake PKI services via an in-process aiohttp TestServer.
    Supports CRL retrieval (latest only), OCSP, timestamping and service
    plugins.

    :param pki_arch:
        A certomancer PKI architecture.
    :param at_time:
        Optional fixed time; if None, uses the current local time.
    """

    def __init__(
        self,
        pki_arch: PKIArchitecture,
        at_time: Optional[datetime] = None,
    ):
        self.pki_arch = pki_arch
        self.fixed_time = at_time

    @property
    def at_time(self) -> datetime:
        return self.fixed_time or datetime.now(tz=tzlocal.get_localzone())

    def _make_ocsp_handler(self, label: ServiceLabel):
        async def handle(request: aiohttp.web.Request) -> aiohttp.web.Response:
            body = await request.read()
            ocsp_resp = self.pki_arch.service_registry.summon_responder(
                label, self.at_time
            )
            req: ocsp.OCSPRequest = ocsp.OCSPRequest.load(body)
            response = ocsp_resp.build_ocsp_response(req)
            return aiohttp.web.Response(
                body=response.dump(),
                content_type='application/ocsp-response',
            )

        return handle

    def _make_tsa_handler(self, label: ServiceLabel):
        async def handle(request: aiohttp.web.Request) -> aiohttp.web.Response:
            body = await request.read()
            tsa = self.pki_arch.service_registry.summon_timestamper(
                label, self.at_time
            )
            req: tsp.TimeStampReq = tsp.TimeStampReq.load(body)
            response = tsa.request_tsa_response(req)
            return aiohttp.web.Response(
                body=response.dump(),
                content_type='application/timestamp-reply',
            )

        return handle

    def _make_crl_handler(self, label: ServiceLabel):
        async def handle(
            request: aiohttp.web.Request,
        ) -> aiohttp.web.Response:
            crl = self.pki_arch.service_registry.get_crl(label, self.at_time)
            return aiohttp.web.Response(
                body=crl.dump(),
                content_type='application/pkix-crl',
            )

        return handle

    def _make_plugin_handler(
        self, plugin_label: PluginLabel, label, content_type: str
    ):
        async def handle(request: aiohttp.web.Request) -> aiohttp.web.Response:
            body = await request.read()
            result = self.pki_arch.service_registry.invoke_plugin(
                plugin_label, label, body, at_time=self.at_time
            )
            return aiohttp.web.Response(
                body=result,
                content_type=content_type,
            )

        return handle

    def build_app(self) -> aiohttp.web.Application:
        """Build an aiohttp Application with all PKI service routes."""
        app = aiohttp.web.Application()
        services = self.pki_arch.service_registry

        for ocsp_info in services.list_ocsp_responders():
            path = urlsplit(ocsp_info.url).path
            app.router.add_post(path, self._make_ocsp_handler(ocsp_info.label))

        for tsa_info in services.list_time_stamping_services():
            path = urlsplit(tsa_info.url).path
            app.router.add_post(path, self._make_tsa_handler(tsa_info.label))

        for crl_repo in services.list_crl_repos():
            path = urlsplit(crl_repo.latest_external_url).path
            app.router.add_get(path, self._make_crl_handler(crl_repo.label))

        for plugin_info in services.list_plugin_services():
            path = urlsplit(plugin_info.url).path
            app.router.add_post(
                path,
                self._make_plugin_handler(
                    plugin_info.plugin_label,
                    plugin_info.label,
                    plugin_info.content_type,
                ),
            )

        return app

    @asynccontextmanager
    async def serving_session(
        self, app: Optional[aiohttp.web.Application] = None
    ):
        """
        Async context manager that starts an in-process TestServer and yields
        an aiohttp.ClientSession whose DNS resolver redirects all hostnames
        to that server.

        :param app:
            Optional pre-built application to serve. Defaults to the result of
            :meth:`build_app`. Pass a customised application (e.g. one returned
            by :meth:`build_app` with extra routes registered) to serve
            additional endpoints alongside the PKI services.
        """
        if app is None:
            app = self.build_app()
        server = aiohttp.test_utils.TestServer(app)
        # Disable the access logger: it reads the local UTC offset, which can
        # be unavailable when the clock is patched (e.g. under freezegun),
        # causing spurious errors that have no bearing on the served responses.
        await server.start_server(access_log=None)
        port = server.port
        assert port is not None
        connector = aiohttp.TCPConnector(
            resolver=_FakeResolver(port),
            use_dns_cache=False,
        )
        session = aiohttp.ClientSession(connector=connector)
        try:
            yield session
        finally:
            await session.close()
            await server.close()
