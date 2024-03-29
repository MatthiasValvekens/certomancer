import logging
import sys
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Iterable, Optional, Union

import click
import tzlocal
from asn1crypto import algos, ocsp, pem
from dateutil.parser import parse as parse_dt

from ._asn1_types import register_extensions
from .config_utils import ConfigurationError
from .registry import (
    ArchLabel,
    AttributeCertificateSpec,
    CertificateSpec,
    CertLabel,
    CertomancerConfig,
    ServiceLabel,
)
from .services import CertomancerServiceError
from .version import __version__

DEFAULT_CONFIG_FILE = 'certomancer.yml'
logger = logging.getLogger(__name__)

# This is a no-op since the registration happens automatically,
# but explicit is better than implicit
register_extensions()


def _log_config():
    _logger = logging.getLogger('certomancer')
    _logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)
    _logger.addHandler(handler)


@contextmanager
def exception_manager():
    msg = exc = None
    try:
        yield
    except click.ClickException:
        raise
    except ConfigurationError as e:
        msg = f"Configuration problem: {str(e)}"
        exc = e
    except CertomancerServiceError as e:
        msg = f"Service problem: {str(e)}"
        exc = e

    if exc is not None:
        logger.error(msg, exc_info=exc)
        raise click.ClickException(msg)


def _lazy_cfg(
    config, key_root, cfg_root, no_external_config, service_url_prefix
):
    config = config or DEFAULT_CONFIG_FILE
    try:
        cfg = CertomancerConfig.from_file(
            config,
            key_search_dir=key_root,
            config_search_dir=cfg_root,
            allow_external_config=not no_external_config,
            external_url_prefix=service_url_prefix,
        )
    except IOError as e:
        raise click.ClickException(
            f"I/O Error processing config from {config}: {e}",
        ) from e

    while True:
        yield cfg


@click.group()
@click.version_option(prog_name='certomancer', version=__version__)
@click.option(
    '--config',
    help=(
        'YAML file to load configuration from '
        f'[default: {DEFAULT_CONFIG_FILE}]'
    ),
    required=False,
    type=click.Path(readable=True, dir_okay=False),
)
@click.option(
    '--key-root',
    help='root folder for key material paths [default: config file '
    'location]',
    required=False,
    type=click.Path(readable=True, file_okay=False),
)
@click.option(
    '--extra-config-root',
    help='root folder for external config paths [default: config '
    'file location]',
    required=False,
    type=click.Path(readable=True, file_okay=False),
)
@click.option(
    '--no-external-config',
    help='disable external config loading',
    required=False,
    type=bool,
    is_flag=True,
)
@click.option(
    '--service-url-prefix',
    help='override configured URL prefix for service URLs',
    required=False,
    type=str,
)
@click.pass_context
@exception_manager()
def cli(
    ctx,
    config,
    key_root,
    extra_config_root,
    no_external_config,
    service_url_prefix,
):
    _log_config()
    ctx.ensure_object(dict)
    ctx.obj['config'] = _lazy_cfg(
        config,
        key_root,
        extra_config_root,
        no_external_config,
        service_url_prefix,
    )


@cli.command(help='create and dump all certificates for a PKI architecture')
@click.pass_context
@click.argument('architecture', type=str, metavar='PKI_ARCH')
@click.argument('output', type=click.Path(writable=True))
@click.option(
    '--flat',
    help='do not group certificates by issuer',
    type=bool,
    is_flag=True,
)
@click.option(
    '--archive',
    help='create a .zip archive instead of individual files',
    type=bool,
    is_flag=True,
)
@click.option(
    '--no-pfx',
    help='do not attempt to create PKCS#12 files',
    type=bool,
    is_flag=True,
)
@click.option(
    '--pfx-pass',
    type=str,
    help='set password for (all) PKCS #12 files. Default is to '
    'leave them unencrypted.',
)
@click.option(
    '--no-pem',
    help='use raw DER instead of PEM output',
    required=False,
    type=bool,
    is_flag=True,
)
@exception_manager()
def mass_summon(
    ctx,
    architecture: str,
    output: str,
    no_pem: bool,
    archive: bool,
    flat: bool,
    no_pfx: bool,
    pfx_pass: str,
):
    cfg: CertomancerConfig = next(ctx.obj['config'])
    pki_arch = cfg.get_pki_arch(ArchLabel(architecture))
    if pfx_pass is not None:
        pfx_pass_bytes = pfx_pass.encode('utf8')
    else:
        pfx_pass_bytes = None

    kwargs = {
        'use_pem': not no_pem,
        'flat': flat,
        'include_pkcs12': not no_pfx,
        'pkcs12_pass': pfx_pass_bytes,
    }
    if archive:
        with open(output, 'wb') as outf:
            pki_arch.zip_certs(outf, **kwargs)
    else:
        pki_arch.dump_certs(output, **kwargs)


@cli.command(help='retrieve a single certificate from a PKI architecture')
@click.pass_context
@click.argument('architecture', type=str, metavar='PKI_ARCH')
@click.argument('cert_label', type=click.Path(writable=True), required=True)
@click.argument('output', type=click.Path(writable=True), required=False)
@click.option(
    '--attr',
    type=bool,
    is_flag=True,
    help='fetch an attribute certificate instead of a regular one',
)
@click.option(
    '--ignore-tty',
    type=bool,
    is_flag=True,
    help='never try to prevent binary data from being written ' 'to stdout',
)
@click.option(
    '--as-pfx',
    type=bool,
    is_flag=True,
    help='output PFX (PKCS #12) file (with key) instead of a ' 'certificate',
)
@click.option('--pfx-pass', type=str, help='set PFX file passphrase')
@click.option(
    '--no-pem',
    help='use raw DER instead of PEM output',
    required=False,
    type=bool,
    is_flag=True,
)
@exception_manager()
def summon(
    ctx,
    architecture: str,
    attr: bool,
    cert_label: str,
    output: str,
    no_pem: bool,
    as_pfx: bool,
    ignore_tty: bool,
    pfx_pass: str,
):
    cfg: CertomancerConfig = next(ctx.obj['config'])
    pki_arch = cfg.get_pki_arch(ArchLabel(architecture))
    output_is_binary = as_pfx or no_pem

    if (
        not ignore_tty
        and output_is_binary
        and output is None
        and sys.stdout.isatty()
    ):
        raise click.ClickException(
            "Refusing to write binary output to a TTY. Pass --ignore-tty if "
            "you really want to ignore this check."
        )

    if as_pfx:
        if attr:
            raise click.ClickException(
                "Attribute certificates are not supported in PKCS#12 output"
            )
        if pfx_pass is not None:
            pfx_pass_bytes = pfx_pass.encode('utf8')
        else:
            pfx_pass_bytes = None
        data = pki_arch.package_pkcs12(
            CertLabel(cert_label), password=pfx_pass_bytes
        )
    else:
        if attr:
            data = pki_arch.get_attr_cert(CertLabel(cert_label)).dump()
        else:
            data = pki_arch.get_cert(CertLabel(cert_label)).dump()
        if not no_pem:
            data = pem.armor(f'{"attribute " if attr else ""}certificate', data)

    if output is None:
        # we want to write bytes, not strings
        sys.stdout.buffer.write(data)
    else:
        with open(output, 'wb') as outf:
            outf.write(data)


@cli.command(help='create a CRL')
@click.pass_context
@click.argument('architecture', type=str, metavar='PKI_ARCH')
@click.argument('crl_repo', type=str)
@click.argument(
    'output', type=click.Path(writable=True, dir_okay=False), required=False
)
@click.option(
    '--ignore-tty',
    type=bool,
    is_flag=True,
    help='never try to prevent binary data from being written ' 'to stdout',
)
@click.option(
    '--no-pem',
    help='use raw DER instead of PEM output',
    required=False,
    type=bool,
    is_flag=True,
)
@click.option(
    '--at-time',
    required=False,
    type=str,
    help=(
        'ISO 8601 timestamp at which to evaluate '
        'revocation status [default: now]'
    ),
)
@exception_manager()
def necronomicon(
    ctx,
    architecture: str,
    crl_repo: str,
    output: str,
    no_pem: bool,
    at_time: Optional[str],
    ignore_tty: bool,
):
    cfg: CertomancerConfig = next(ctx.obj['config'])
    pki_arch = cfg.get_pki_arch(ArchLabel(architecture))
    if at_time is None:
        at_time_dt = datetime.now(tz=tzlocal.get_localzone())
    else:
        at_time_dt = parse_dt(at_time)
    crl = pki_arch.service_registry.get_crl(
        repo_label=ServiceLabel(crl_repo), at_time=at_time_dt
    )

    if output is None and no_pem and not ignore_tty and sys.stdout.isatty():
        raise click.ClickException(
            "Refusing to write binary output to a TTY. Pass --ignore-tty if "
            "you really want to ignore this check."
        )
    data = crl.dump()
    if not no_pem:
        data = pem.armor('X509 CRL', data)

    if output is None:
        sys.stdout.buffer.write(data)
    else:
        with open(output, 'wb') as f:
            f.write(data)


@cli.command(help='query an OCSP responder')
@click.pass_context
@click.argument('architecture', type=str, metavar='PKI_ARCH')
@click.argument('cert_label', type=str, metavar='CERT_LABEL')
@click.argument('responder', type=str, metavar='OCSP_RESPONDER')
@click.argument(
    'output', type=click.Path(writable=True, dir_okay=False), required=False
)
@click.option(
    '--ignore-tty',
    type=bool,
    is_flag=True,
    help='never try to prevent binary data from being written ' 'to stdout',
)
@click.option(
    '--at-time',
    required=False,
    type=str,
    help=(
        'ISO 8601 timestamp at which to evaluate '
        'revocation status [default: now]'
    ),
)
@exception_manager()
def seance(
    ctx,
    architecture: str,
    cert_label: str,
    responder: str,
    output: str,
    ignore_tty: bool,
    at_time: Optional[str],
):
    cfg: CertomancerConfig = next(ctx.obj['config'])
    pki_arch = cfg.get_pki_arch(ArchLabel(architecture))
    if at_time is None:
        at_time_dt = datetime.now(tz=tzlocal.get_localzone())
    else:
        at_time_dt = parse_dt(at_time)

    # Format CertId value based on certificate spec (or attr cert spec)
    # We differentiate between attr certs and regular PKCs based on the
    # responder's service info settings.
    svc_info = pki_arch.service_registry.get_ocsp_info(ServiceLabel(responder))
    cert_spec: Union[CertificateSpec, AttributeCertificateSpec]
    if svc_info.is_aa_responder:
        cert_spec = pki_arch.get_attr_cert_spec(CertLabel(cert_label))
    else:
        cert_spec = pki_arch.get_cert_spec(CertLabel(cert_label))
    issuer_cert_label = cert_spec.resolve_issuer_cert(pki_arch)
    issuer_cert = pki_arch.get_cert(issuer_cert_label)
    cert_id = ocsp.CertId(
        {
            'hash_algorithm': algos.DigestAlgorithm({'algorithm': 'sha256'}),
            'issuer_name_hash': pki_arch.entities.get_name_hash(
                cert_spec.issuer, 'sha256'
            ),
            'issuer_key_hash': issuer_cert.public_key.sha256,
            'serial_number': cert_spec.serial,
        }
    )

    # Initialise the requested OCSP responder
    ocsp_responder = pki_arch.service_registry.summon_responder(
        label=ServiceLabel(responder), at_time=at_time_dt
    )
    sing_resp = ocsp_responder.format_single_ocsp_response(
        cid=cert_id, issuer_cert=issuer_cert
    )
    response = ocsp_responder.assemble_simple_ocsp_responses(
        responses=[sing_resp]
    )

    if output is None and not ignore_tty and sys.stdout.isatty():
        raise click.ClickException(
            "Refusing to write binary output to a TTY. Pass --ignore-tty if "
            "you really want to ignore this check."
        )
    data = response.dump()
    if output is None:
        sys.stdout.buffer.write(data)
    else:
        with open(output, 'wb') as f:
            f.write(data)


@cli.command(help='run the Animator behind a development server')
@click.option(
    '--port',
    help='port to listen on',
    required=False,
    type=int,
    default=9000,
    show_default=True,
)
@click.option(
    '--no-web-ui',
    help='disable the web UI',
    required=False,
    type=bool,
    is_flag=True,
)
@click.option(
    '--no-time-override',
    help='disable time override functionality',
    required=False,
    type=bool,
    is_flag=True,
)
@click.option(
    '--wsgi-prefix',
    required=False,
    type=str,
    help=(
        'WSGI prefix under which to mount the application '
        '(does not affect generated output)'
    ),
)
@click.pass_context
@exception_manager()
def animate(
    ctx,
    port: int,
    no_web_ui: bool,
    no_time_override: bool,
    wsgi_prefix: Optional[str],
):
    try:
        from werkzeug.exceptions import NotFound
        from werkzeug.middleware.dispatcher import DispatcherMiddleware

        from .integrations.animator import Animator, AnimatorArchStore
    except ImportError as e:
        raise click.ClickException(
            "'animate' requires additional dependencies. "
            "Re-run setup with the [web-api] extension set, or install "
            "Werkzeug (and Jinja2 for the web UI) manually."
        ) from e
    cfg: CertomancerConfig = next(ctx.obj['config'])
    from werkzeug.serving import run_simple

    app: Any = Animator(
        AnimatorArchStore(cfg.pki_archs),
        with_web_ui=not no_web_ui,
        allow_time_override=not no_time_override,
    )
    if wsgi_prefix:
        # Serve the Animator under the indicated prefix, wrapped using
        # dispatcher middleware (functionally equivalent to SCRIPT_NAME, but
        # more convenient to run from the CLI in this way)
        app = DispatcherMiddleware(NotFound(), {wsgi_prefix: app})
    run_simple('127.0.0.1', port, app)


@click.pass_context
@click.argument('pki_arch', type=str, metavar='PKI_ARCH')
@click.option(
    '--cert',
    type=str,
    metavar='CERT_LABEL',
    multiple=True,
    help='add cert with its private key (multiple allowed)',
)
# TODO add option to prompt for PIN
@click.option(
    '--pin',
    type=str,
    help='PKCS#11 token PIN',
    metavar='PIN',
    required=False,
    default=None,
)
@click.option(
    '--module',
    help='PKCS#11 module path (.so/.dll/.dylib)',
    type=click.Path(readable=True, dir_okay=False),
)
@click.option(
    '--include-chain',
    type=bool,
    is_flag=True,
    help='include certs relevant for chain of trust',
)
@click.option(
    '--token-label',
    help='PKCS#11 token label',
    type=str,
    required=False,
    metavar='TOKEN',
)
@click.option(
    '--slot-no',
    help='specify PKCS#11 slot to use',
    required=False,
    type=int,
    default=None,
    metavar='SLOT',
)
@exception_manager()
def alch(
    ctx,
    pki_arch: str,
    token_label: Optional[str],
    slot_no: Optional[int],
    pin: Optional[str],
    module: str,
    include_chain: bool,
    cert: Iterable[str],
):
    from certomancer.integrations import alchemist

    cfg: CertomancerConfig = next(ctx.obj['config'])
    arch = cfg.get_pki_arch(ArchLabel(pki_arch))

    session = alchemist.open_pkcs11_session(
        lib_location=module, slot_no=slot_no, token_label=token_label, pin=pin
    )
    try:
        backend = alchemist.DefaultAlchemistBackend(session)
        alchemist.Alchemist(backend, arch).store_key_bundles(
            certs={CertLabel(l) for l in cert}, include_chains=include_chain
        )
    finally:
        session.close()


def _maybe_enable_alchemist():
    try:
        from certomancer.integrations import alchemist
    except ImportError:
        alchemist = None

    hlp = 'write generated certs and keys to a PKCS#11 token'
    if alchemist is not None:
        cli.command(
            short_help=hlp,
            help=(
                'This command is intended to facilitate populating hardware '
                'devices (or software modules with PKCS#11 support) with '
                'data to run tests.'
            ),
        )(alch)
    else:

        def _unavailable():
            raise click.ClickException(
                "This command requires python-pkcs11 to be installed."
            )

        cli.command(help=hlp + ' [dependencies missing]')(_unavailable)


_maybe_enable_alchemist()

cli_root: click.Group = cli
