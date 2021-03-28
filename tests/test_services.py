from datetime import datetime

import pytz

from certomancer.registry import CertomancerConfig, ArchLabel, ServiceLabel

CONFIG = CertomancerConfig.from_file(
    'tests/data/with-services.yml', 'tests/data'
)

ARCH = CONFIG.get_pki_arch(ArchLabel('testing-ca'))


def _check_crl_cardinality(crl, expected_revoked):
    assert len(crl['tbs_cert_list']['revoked_certificates']) == expected_revoked


def test_crl():
    some_crl = ARCH.service_registry.get_crl(
        ServiceLabel('interm'),
        at_time=datetime.fromisoformat('2020-11-01 00:00:00+00:00'),
    )
    _check_crl_cardinality(some_crl, expected_revoked=0)
    some_crl2 = ARCH.service_registry.get_crl(
        ServiceLabel('interm'),
        at_time=datetime.fromisoformat('2020-12-02 00:00:00+00:00'),
    )
    _check_crl_cardinality(some_crl2, expected_revoked=0)
    some_crl3 = ARCH.service_registry.get_crl(
        ServiceLabel('interm'),
        at_time=datetime.fromisoformat('2020-12-29 00:00:00+00:00'),
    )
    _check_crl_cardinality(some_crl3, expected_revoked=1)
    revo = some_crl3['tbs_cert_list']['revoked_certificates'][0]
    rev_time = datetime(2020, 12, 1, tzinfo=pytz.utc)
    assert revo['revocation_date'].native == rev_time

    reason = next(
        ext['extn_value'].native for ext in revo['crl_entry_extensions']
        if ext['extn_id'].native == 'crl_reason'
    )
    assert reason == 'key_compromise'
