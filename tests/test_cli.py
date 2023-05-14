import pathlib
import re

import pytest
from asn1crypto import pem, x509
from click.testing import CliRunner

from certomancer.cli import cli_root


@pytest.fixture(scope="function", autouse=True)
def cli_runner():
    runner = CliRunner()
    with runner.isolated_filesystem():
        yield runner


TEST_DATA_PATH = pathlib.Path("tests", "data").absolute()


def test_version(cli_runner):
    result = cli_runner.invoke(
        cli_root,
        ['--version'],
    )
    m = re.match(r"^certomancer, version \d+\.\d+\.\d+", result.output)
    assert m is not None


def test_mass_summon(cli_runner):
    result = cli_runner.invoke(
        cli_root,
        [
            '--config',
            str(TEST_DATA_PATH / "with-services.yml"),
            'mass-summon',
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
