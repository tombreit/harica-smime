"""RFC 4226 and RFC 6238 known-answer tests for hotp/totp."""

import pytest

from harica_smime.otp import hotp, totp


# 20-byte ASCII secret "12345678901234567890" in base32
RFC_SECRET_SHA1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


@pytest.mark.parametrize(
    "counter, expected",
    [
        (0, "755224"),
        (1, "287082"),
        (2, "359152"),
        (3, "969429"),
        (4, "338314"),
        (5, "254676"),
        (6, "287922"),
        (7, "162583"),
        (8, "399871"),
        (9, "520489"),
    ],
)
def test_rfc4226_hotp(counter, expected):
    assert hotp(key=RFC_SECRET_SHA1, counter=counter, digits=6) == expected


@pytest.mark.parametrize(
    "at, expected",
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
    ],
)
def test_rfc6238_totp_sha1(at, expected):
    assert totp(key=RFC_SECRET_SHA1, time_step=30, digits=8, at=at) == expected
