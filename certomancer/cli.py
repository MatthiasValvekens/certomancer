from datetime import datetime

from asn1crypto import pem
from dateutil.parser import parse as parse_dt

import click
import tzlocal
import logging

from .integrations.animator import Animator
from .registry import CertomancerConfig
from .version import __version__

DEFAULT_CONFIG_FILE = 'certomancer.yml'


def _log_config():
    logger = logging.getLogger('certomancer')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def _lazy_cfg(config, key_root):
    config = config or DEFAULT_CONFIG_FILE
    try:
        cfg = CertomancerConfig.from_file(config, key_root)
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
              help='root folder for key material paths [default: CWD]',
              required=False, type=click.Path(readable=True, file_okay=False))
@click.pass_context
def cli(ctx, config, key_root):
    _log_config()
    ctx.ensure_object(dict)
    ctx.obj['config'] = _lazy_cfg(config, key_root)


@cli.command(help='create and dump all certificates for a PKI architecture')
@click.pass_context
@click.argument('architecture', type=str, metavar='PKI_ARCH')
@click.argument('output_dir', type=click.Path(writable=True, file_okay=False))
@click.option('--no-pem', help='use raw DER instead of PEM output',
              required=False, type=bool, is_flag=True)
def summon(ctx, architecture, output_dir, no_pem):
    cfg: CertomancerConfig = next(ctx.obj['config'])
    pki_arch = cfg.get_pki_arch(architecture)
    pki_arch.dump_certs(output_dir, use_pem=not no_pem)


@cli.command(help='create a CRL')
@click.pass_context
@click.argument('architecture', type=str, metavar='PKI_ARCH')
@click.argument('crl_repo', type=str)
@click.argument('output', type=click.Path(writable=True, dir_okay=False))
@click.option('--no-pem', help='use raw DER instead of PEM output',
              required=False, type=bool, is_flag=True)
@click.option('--at-time', required=False, type=str,
              help=('ISO 8601 timestamp at which to evaluate '
                    'revocation status [default: now]'))
def necronomicon(ctx, architecture, crl_repo, output, no_pem, at_time):
    cfg: CertomancerConfig = next(ctx.obj['config'])
    pki_arch = cfg.get_pki_arch(architecture)
    if at_time is None:
        at_time = datetime.now(tz=tzlocal.get_localzone())
    else:
        at_time = parse_dt(at_time)
    crl = pki_arch.service_registry.get_crl(
        repo_label=crl_repo, at_time=at_time
    )

    with open(output, 'wb') as f:
        data = crl.dump()
        if not no_pem:
            data = pem.armor('X509 CRL', data)
        f.write(data)


@cli.command(help='run a local web server with Certomancer-backed PKI services')
@click.option('--port', help='port to listen on',
              required=False, type=int, default=9000, show_default=True)
@click.pass_context
def animate(ctx, port):
    cfg: CertomancerConfig = next(ctx.obj['config'])
    from werkzeug.serving import run_simple
    app = Animator(cfg.pki_archs)
    run_simple('127.0.0.1', port, app)
