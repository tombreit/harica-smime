"""Unit tests for harica_smime.contrib.smoke pure helpers.

Live HARICA calls are covered by tests/integration/test_staging_live.py.
"""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from harica_smime.contrib.smoke import (
    CertSummary,
    IssuanceResult,
    SmokeResult,
    build_csr,
    describe_subject,
    format_report,
)


def test_build_csr_produces_parseable_pem():
    pem = build_csr(common_name="Alice Example", email="alice@example.org")
    csr = x509.load_pem_x509_csr(pem.encode())
    cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    email = csr.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
    assert cn and cn[0].value == "Alice Example"
    assert email and email[0].value == "alice@example.org"


def _make_cert_pem(attrs: list[x509.NameAttribute]) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(attrs)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_describe_subject_email_only_has_just_email():
    pem = _make_cert_pem(
        [x509.NameAttribute(NameOID.EMAIL_ADDRESS, "alice@example.org")]
    )
    s = describe_subject(pem)
    assert s.email is True
    assert s.common_name is False
    assert s.given_name is False
    assert s.surname is False


def test_describe_subject_natural_legal_lcp_has_everything():
    pem = _make_cert_pem(
        [
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, "alice@example.org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Alice Example"),
            x509.NameAttribute(NameOID.GIVEN_NAME, "Alice"),
            x509.NameAttribute(NameOID.SURNAME, "Example"),
        ]
    )
    s = describe_subject(pem)
    assert s.email and s.common_name and s.given_name and s.surname


def test_smoke_result_passed_requires_both_issued_and_names():
    ok_summary = CertSummary(
        common_name=True, email=True, given_name=True, surname=True, subject_dn="x"
    )
    no_names = CertSummary(
        common_name=False, email=True, given_name=False, surname=False, subject_dn="x"
    )
    passed = SmokeResult(
        email_only=IssuanceResult(ok=True, summary=no_names),
        natural_legal_lcp=IssuanceResult(ok=True, summary=ok_summary),
    )
    assert passed.passed is True

    failed_missing_names = SmokeResult(
        email_only=IssuanceResult(ok=True, summary=no_names),
        natural_legal_lcp=IssuanceResult(ok=True, summary=no_names),
    )
    assert failed_missing_names.passed is False

    failed_email_only = SmokeResult(
        email_only=IssuanceResult(ok=False, error="boom"),
        natural_legal_lcp=IssuanceResult(ok=True, summary=ok_summary),
    )
    assert failed_email_only.passed is False


def test_format_report_reports_success():
    s = CertSummary(
        common_name=True,
        email=True,
        given_name=True,
        surname=True,
        subject_dn="CN=Alice Example,E=alice@example.org",
    )
    result = SmokeResult(
        email_only=IssuanceResult(
            ok=True,
            summary=CertSummary(
                common_name=False,
                email=True,
                given_name=False,
                surname=False,
                subject_dn="E=alice@example.org",
            ),
        ),
        natural_legal_lcp=IssuanceResult(ok=True, summary=s),
    )
    report = format_report(result)
    assert "email_only" in report
    assert "natural_legal_lcp" in report
    assert "OK: both cert types issued" in report


def test_format_report_reports_failure():
    result = SmokeResult(
        email_only=IssuanceResult(ok=False, error="connection refused"),
        natural_legal_lcp=IssuanceResult(ok=False, error="skipped"),
    )
    report = format_report(result)
    assert "FAILED: connection refused" in report
    assert "FAIL:" in report
