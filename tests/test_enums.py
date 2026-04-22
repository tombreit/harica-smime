import pytest

from harica_smime import CertificateType


def test_values_match_strings():
    assert CertificateType.EMAIL_ONLY.value == "email_only"
    assert CertificateType.NATURAL_LEGAL_LCP.value == "natural_legal_lcp"


def test_coercion_from_string():
    assert CertificateType("email_only") is CertificateType.EMAIL_ONLY
    assert CertificateType("natural_legal_lcp") is CertificateType.NATURAL_LEGAL_LCP


def test_str_mixin_allows_direct_equality():
    # Being a str subclass lets callers compare without .value — useful for
    # Django model fields and JSON round-trips.
    assert CertificateType.EMAIL_ONLY == "email_only"


def test_unknown_value_raises():
    with pytest.raises(ValueError):
        CertificateType("pickup_only")
