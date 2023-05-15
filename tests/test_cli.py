import pathlib
import re

import pytest
from asn1crypto import pem, x509
from click.testing import CliRunner

from certomancer.cli import cli_root
from tests.conftest import TEST_DATA_PATH, collect_files


@pytest.fixture(scope="function", autouse=True)
def cli_runner():
    runner = CliRunner()
    with runner.isolated_filesystem():
        yield runner


def test_version(cli_runner):
    result = cli_runner.invoke(
        cli_root,
        ['--version'],
    )
    m = re.match(r"^certomancer, version \d+\.\d+\.\d+", result.output)
    assert m is not None


def test_mass_summon_explicit_config(cli_runner):
    result = cli_runner.invoke(
        cli_root,
        [
            '--config',
            str(TEST_DATA_PATH / "with-services.yml"),
            'mass-summon',
            '--no-pfx',
            'testing-ca',
            'outdir',
        ],
    )
    assert not result.exit_code, result.output
    outdir = pathlib.Path('outdir')
    assert (outdir / "root").is_dir()
    assert (outdir / "interm").is_dir()
    with (outdir / "root" / "interm.cert.pem").open("rb") as inf:
        interm_cert = x509.Certificate.load(
            pem.unarmor(inf.read(), multiple=False)[2]
        )
    with (outdir / "interm" / "signer1.cert.pem").open("rb") as inf:
        signer_cert = x509.Certificate.load(
            pem.unarmor(inf.read(), multiple=False)[2]
        )
    assert signer_cert.issuer == interm_cert.subject
    dumped = set(collect_files(str(outdir)))
    assert dumped == {
        'interm/signer1-long.cert.pem',
        'interm/signer1.cert.pem',
        'interm/signer2.cert.pem',
        'interm/interm-ocsp.cert.pem',
        'root/interm.cert.pem',
        'root/tsa.cert.pem',
        'root/tsa2.cert.pem',
        'root/root.cert.pem',
    }


@pytest.mark.config_context("with-services.yml")
def test_mass_summon(cli_runner):
    result = cli_runner.invoke(
        cli_root,
        [
            'mass-summon',
            '--no-pfx',
            'testing-ca',
            'outdir',
        ],
    )
    assert not result.exit_code, result.output
    outdir = pathlib.Path('outdir')
    dumped = set(collect_files(str(outdir)))
    assert dumped == {
        'interm/signer1-long.cert.pem',
        'interm/signer1.cert.pem',
        'interm/signer2.cert.pem',
        'interm/interm-ocsp.cert.pem',
        'root/interm.cert.pem',
        'root/tsa.cert.pem',
        'root/tsa2.cert.pem',
        'root/root.cert.pem',
    }


@pytest.mark.config_context("with-services.yml")
@pytest.mark.needcrypto
def test_mass_summon_with_pkcs12(cli_runner):
    result = cli_runner.invoke(
        cli_root,
        [
            'mass-summon',
            'testing-ca',
            'outdir',
        ],
    )
    assert not result.exit_code, result.output
    outdir = pathlib.Path('outdir')
    dumped = set(collect_files(str(outdir)))
    assert dumped == {
        'interm/signer1-long.cert.pem',
        'interm/signer1-long.pfx',
        'interm/signer1.cert.pem',
        'interm/signer1.pfx',
        'interm/signer2.cert.pem',
        'interm/signer2.pfx',
        'interm/interm-ocsp.cert.pem',
        'interm/interm-ocsp.pfx',
        'root/interm.cert.pem',
        'root/interm.pfx',
        'root/tsa.cert.pem',
        'root/tsa.pfx',
        'root/tsa2.cert.pem',
        'root/tsa2.pfx',
        'root/root.cert.pem',
        'root/root.pfx',
    }


@pytest.mark.config_context("with-services.yml")
def test_summon(cli_runner):
    outdir = pathlib.Path('outdir')
    outdir.mkdir()
    result = cli_runner.invoke(
        cli_root,
        ['summon', 'testing-ca', 'signer1', str(outdir / 'test.cert.pem')],
    )
    assert not result.exit_code, result.output
    dumped = set(collect_files(str(outdir)))
    assert dumped == {'test.cert.pem'}

    with (outdir / 'test.cert.pem').open('rb') as inf:
        cert = x509.Certificate.load(pem.unarmor(inf.read())[2])
        assert 'Alice' in cert.subject.human_friendly


@pytest.mark.config_context("with-services.yml")
def test_summon_no_pem(cli_runner):
    outdir = pathlib.Path('outdir')
    outdir.mkdir()
    result = cli_runner.invoke(
        cli_root,
        [
            'summon',
            '--no-pem',
            'testing-ca',
            'signer1',
            str(outdir / 'test.crt'),
        ],
    )
    assert not result.exit_code, result.output
    dumped = set(collect_files(str(outdir)))
    assert dumped == {'test.crt'}

    with (outdir / 'test.crt').open('rb') as inf:
        cert = x509.Certificate.load(inf.read())
        assert 'Alice' in cert.subject.human_friendly


@pytest.mark.config_context("with-services.yml")
def test_summon_stdout(cli_runner):
    result = cli_runner.invoke(
        cli_root,
        [
            'summon',
            'testing-ca',
            'signer1',
        ],
    )
    cert = x509.Certificate.load(pem.unarmor(result.output.encode('ascii'))[2])
    assert 'Alice' in cert.subject.human_friendly


@pytest.mark.config_context("with-services.yml")
def test_summon_der_stdout(cli_runner):
    result = cli_runner.invoke(
        cli_root,
        [
            'summon',
            '--no-pem',
            'testing-ca',
            'signer1',
        ],
    )
    cert = x509.Certificate.load(result.stdout_bytes)
    assert 'Alice' in cert.subject.human_friendly
