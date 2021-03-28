from datetime import timedelta

import pytest

from certomancer.config_utils import parse_duration


@pytest.mark.parametrize(
    'input_str, expected_out',
    [
        ('P03D', timedelta(days=3)),
        ('P03DT5H', timedelta(days=3, hours=5)),
        ('P5H', timedelta(hours=5)),
        ('PT5H', timedelta(hours=5)),
        ('PT50M', timedelta(minutes=50)),
        ('P5H12M', timedelta(hours=5, minutes=12)),
        ('P3WT5H12M', timedelta(days=21, hours=5, minutes=12)),
        ('P3WT5H12M05S', timedelta(days=21, hours=5, minutes=12, seconds=5)),
    ]
)
def test_parse_duration(input_str, expected_out):
    assert parse_duration(input_str) == expected_out


@pytest.mark.parametrize(
    'input_str, err_msg',
    [
        ('', None),
        (' P5H', None),
        ('P5HHH', None),
        ('P5DDD', None),
        ('P5DT05HH', None),
        ('P1Y', ".*reliably represented using timedelta.*"),
        ('P1M', ".*reliably represented using timedelta.*"),
        ('P05Y1M', ".*reliably represented using timedelta.*"),
        ('P5D 05H04M', None),
    ]
)
def test_parse_duration_error(input_str, err_msg):
    with pytest.raises(ValueError, match=err_msg or "Failed.*"):
        assert parse_duration(input_str)