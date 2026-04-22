import pytest

from harica_smime import validate_certificate_name
from harica_smime._validators import is_subdomain


class TestIsSubdomain:
    def test_identical_domains(self):
        assert is_subdomain("example.com", "example.com")

    def test_direct_child(self):
        assert is_subdomain("sub.example.com", "example.com")

    def test_nested_grandchild(self):
        assert is_subdomain("a.b.example.com", "example.com")

    def test_sibling_is_not_subdomain(self):
        assert not is_subdomain("other.com", "example.com")

    def test_prefix_match_but_different_domain(self):
        # "fooexample.com" is not a subdomain of "example.com" despite string
        # overlap — the boundary must be a dot.
        assert not is_subdomain("fooexample.com", "example.com")

    def test_non_dotted_non_match(self):
        assert not is_subdomain("localhost", "example.com")


class TestValidateCertificateName:
    def test_empty_is_allowed(self):
        assert validate_certificate_name("") == ""

    def test_short_ascii_ok(self):
        assert validate_certificate_name("Alice Example") == "Alice Example"

    def test_exactly_64_chars_ok(self):
        value = "x" * 64
        assert validate_certificate_name(value) == value

    def test_over_64_chars_rejected(self):
        with pytest.raises(ValueError, match="64 characters"):
            validate_certificate_name("x" * 65)

    def test_parentheses_rejected(self):
        with pytest.raises(ValueError, match="parentheses"):
            validate_certificate_name("Alice (the test user)")

    def test_non_ascii_rejected(self):
        with pytest.raises(ValueError):
            validate_certificate_name("Zoë")

    def test_control_char_rejected(self):
        with pytest.raises(ValueError):
            validate_certificate_name("Alice\tExample")
