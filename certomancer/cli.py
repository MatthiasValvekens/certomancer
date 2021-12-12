import sys
from contextlib import contextmanager
from datetime import datetime

from asn1crypto import pem, ocsp, algos
from dateutil.parser import parse as parse_dt

import click
import tzlocal
import logging

from .config_utils import ConfigurationError
from .crypto_utils import pyca_cryptography_present
from .registry import CertomancerConfig, CertLabel, ServiceLabel
from .services import CertomancerServiceError
from .version import __version__

DEFAULT_CONFIG_FILE = 'certomancer.yml'
logger = logging.getLogger(__name__)


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


def _lazy_cfg(config, key_root, cfg_root, no_external_config,
              service_url_prefix):
    config = config or DEFAULT_CONFIG_FILE
    try:
        cfg = CertomancerConfig.from_file(
            config, key_search_dir=key_root, config_search_dir=cfg_root,
            allow_external_config=not no_external_config,
            external_url_prefix=service_url_prefix
        )
    except IOError as e:
        raise click.ClickException(
            f"I/O Error processing config from {config}: {e}",
        ) from e

    while True:
        yield cfg


@click.group()
@click.version_option(prog_name='certomancer', version=__version__)
@click.option('--config',
              help=('YAML file to load configuration from '
                    f'[default: {DEFAULT_CONFIG_FILE}]'),
              required=False, type=click.Path(readable=True, dir_okay=False))
@click.option('--key-root',
              help='root folder for key material paths [default: config file '
                   'location]',
              required=False, type=click.Path(readable=True, file_okay=False))
@click.option('--extra-config-root',
              help='root folder for external config paths [default: config '
                   'file location]',
              required=False, type=click.Path(readable=True, file_okay=False))
@click.option('--no-external-config', help='disable external config loading',
              required=False, type=bool, is_flag=True)
@click.option('--service-url-prefix',
              help='override configured URL prefix for service URLs',
              required=False, type=str)
@click.pass_context
@exception_manager()
def cli(ctx, config, key_root, extra_config_root, no_external_config,
        service_url_prefix):
    _log_config()
    ctx.ensure_object(dict)
    ctx.obj['config'] = _lazy_cfg(
        config, key_root, extra_config_root, no_external_config,
        service_url_prefix
    )


@cli.command(help='create and dump all certificates for a PKI architecture')
@click.pass_context
@click.argument('architecture', type=str, metavar='PKI_ARCH')
@click.argument('output', type=click.Path(writable=True))
@click.option('--flat',
              help='do not group certificates by issuer',
              type=bool, is_flag=True)
@click.option('--archive',
              help='create a .zip archive instead of individual files',
              type=bool, is_flag=True)
@click.option('--no-pfx', help='do not attempt to create PKCS#12 files',
              type=bool, is_flag=True)
@click.option('--pfx-pass', type=str,
              help='set password for (all) PKCS #12 files. Default is to '
                   'leave them unencrypted.')
@click.option('--no-pem', help='use raw DER instead of PEM output',
              required=False, type=bool, is_flag=True)
@exception_manager()
def mass_summon(ctx, architecture, output, no_pem, archive, flat, no_pfx,
                pfx_pass):
    cfg: CertomancerConfig = next(ctx.obj['config'])
    pki_arch = cfg.get_pki_arch(architecture)
    if not no_pfx and not pyca_cryptography_present():
        no_pfx = True
        logger.warning(
            "pyca/cryptography not installed, no PFX files will be created"
        )

    if pfx_pass is not None:
        pfx_pass = pfx_pass.encode('utf8')

    kwargs = {
        'use_pem': not no_pem, 'flat': flat, 'include_pkcs12': not no_pfx,
        'pkcs12_pass': pfx_pass
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
@click.option('--attr', type=bool, is_flag=True,
              help='fetch an attribute certificate instead of a regular one')
@click.option('--ignore-tty', type=bool, is_flag=True,
              help='never try to prevent binary data from being written '
                   'to stdout')
@click.option('--as-pfx', type=bool, is_flag=True,
              help='output PFX (PKCS #12) file (with key) instead of a '
                   'certificate')
@click.option('--pfx-pass', type=str, help='set PFX file passphrase')
@click.option('--no-pem', help='use raw DER instead of PEM output',
              required=False, type=bool, is_flag=True)
@exception_manager()
def summon(ctx, architecture, attr, cert_label, output, no_pem, as_pfx,
           ignore_tty, pfx_pass):
    cfg: CertomancerConfig = next(ctx.obj['config'])
    pki_arch = cfg.get_pki_arch(architecture)
    if as_pfx and not pyca_cryptography_present():
        as_pfx = False
        logger.warning(
            "pyca/cryptography not installed, no PFX files will be created"
        )

    output_is_binary = as_pfx or no_pem

    if not ignore_tty and output_is_binary and \
            output is None and sys.stdout.isatty():
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
            pfx_pass = pfx_pass.encode('utf8')
        data = pki_arch.package_pkcs12(cert_label, password=pfx_pass)
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
@click.argument('output', type=click.Path(writable=True, dir_okay=False),
                required=False)
@click.option('--ignore-tty', type=bool, is_flag=True,
              help='never try to prevent binary data from being written '
                   'to stdout')
@click.option('--no-pem', help='use raw DER instead of PEM output',
              required=False, type=bool, is_flag=True)
@click.option('--at-time', required=False, type=str,
              help=('ISO 8601 timestamp at which to evaluate '
                    'revocation status [default: now]'))
@exception_manager()
def necronomicon(ctx, architecture, crl_repo, output, no_pem, at_time,
                 ignore_tty):
    cfg: CertomancerConfig = next(ctx.obj['config'])
    pki_arch = cfg.get_pki_arch(architecture)
    if at_time is None:
        at_time = datetime.now(tz=tzlocal.get_localzone())
    else:
        at_time = parse_dt(at_time)
    crl = pki_arch.service_registry.get_crl(
        repo_label=ServiceLabel(crl_repo), at_time=at_time
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
@click.argument('output', type=click.Path(writable=True, dir_okay=False),
                required=False)
@click.option('--ignore-tty', type=bool, is_flag=True,
              help='never try to prevent binary data from being written '
                   'to stdout')
@click.option('--at-time', required=False, type=str,
              help=('ISO 8601 timestamp at which to evaluate '
                    'revocation status [default: now]'))
@exception_manager()
def seance(ctx, architecture, cert_label, responder, output,
           ignore_tty, at_time):
    cfg: CertomancerConfig = next(ctx.obj['config'])
    pki_arch = cfg.get_pki_arch(architecture)
    if at_time is None:
        at_time = datetime.now(tz=tzlocal.get_localzone())
    else:
        at_time = parse_dt(at_time)

    # Format CertId value based on certificate spec (or attr cert spec)
    # We differentiate between attr certs and regular PKCs based on the
    # responder's service info settings.
    svc_info = pki_arch.service_registry.get_ocsp_info(ServiceLabel(responder))
    if svc_info.is_aa_responder:
        cert_spec = pki_arch.get_attr_cert_spec(CertLabel(cert_label))
    else:
        cert_spec = pki_arch.get_cert_spec(CertLabel(cert_label))
    issuer_cert_label = cert_spec.resolve_issuer_cert(pki_arch)
    issuer_cert = pki_arch.get_cert(issuer_cert_label)
    cert_id = ocsp.CertId({
        'hash_algorithm': algos.DigestAlgorithm(
            {'algorithm': 'sha256'}
        ),
        'issuer_name_hash': pki_arch.entities.get_name_hash(
            cert_spec.issuer, 'sha256'
        ),
        'issuer_key_hash': issuer_cert.public_key.sha256,
        'serial_number': cert_spec.serial,
    })

    # Initialise the requested OCSP responder
    ocsp_responder = pki_arch.service_registry.summon_responder(
        label=ServiceLabel(responder), at_time=at_time
    )
    sing_resp = ocsp_responder.format_single_ocsp_response(
        cid=cert_id, issuer_cert=issuer_cert
    )
    response = \
        ocsp_responder.assemble_simple_ocsp_responses(responses=[sing_resp])

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
@click.option('--port', help='port to listen on',
              required=False, type=int, default=9000, show_default=True)
@click.option('--no-web-ui', help='disable the web UI',
              required=False, type=bool, is_flag=True)
@click.option('--no-time-override', help='disable time override functionality',
              required=False, type=bool, is_flag=True)
@click.option('--wsgi-prefix', required=False, type=str,
              help=(
                      'WSGI prefix under which to mount the application '
                      '(does not affect generated output)'
              ))
@click.pass_context
@exception_manager()
def animate(ctx, port, no_web_ui, no_time_override, wsgi_prefix):
    try:
        from .integrations.animator import Animator, AnimatorArchStore
        from werkzeug.middleware.dispatcher import DispatcherMiddleware
        from werkzeug.exceptions import NotFound
    except ImportError as e:
        raise click.ClickException(
            "'animate' requires additional dependencies. "
            "Re-run setup with the [web-api] extension set, or install "
            "Werkzeug (and Jinja2 for the web UI) manually."
        ) from e
    cfg: CertomancerConfig = next(ctx.obj['config'])
    from werkzeug.serving import run_simple
    app = Animator(
        AnimatorArchStore(cfg.pki_archs), with_web_ui=not no_web_ui,
        allow_time_override=not no_time_override
    )
    if wsgi_prefix:
        # Serve the Animator under the indicated prefix, wrapped using
        # dispatcher middleware (functionally equivalent to SCRIPT_NAME, but
        # more convenient to run from the CLI in this way)
        app = DispatcherMiddleware(NotFound(), {wsgi_prefix: app})
    run_simple('127.0.0.1', port, app)
