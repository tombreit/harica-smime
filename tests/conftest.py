"""Shared fixtures for harica_smime tests."""

from __future__ import annotations

import datetime
import io
import zipfile
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from cryptography.x509.oid import NameOID

from harica_smime import Client


TOKEN_HTML = (
    "<!DOCTYPE html><html><body>"
    "<form>"
    '<input name="__RequestVerificationToken" type="hidden" value="csrf-abc-1" />'
    "</form></body></html>"
)
TOKEN_HTML_SECOND = TOKEN_HTML.replace("csrf-abc-1", "csrf-abc-2")
BEARER_TOKEN = "bearer-token-xyz"


def _stub_login(httpserver) -> None:
    """Arrange httpserver to respond to the full login flow."""
    # First GET / for the pre-login verification token.
    httpserver.expect_ordered_request("/").respond_with_data(
        TOKEN_HTML, content_type="text/html"
    )
    # Login POST returning the bearer token as a bare string.
    httpserver.expect_ordered_request(
        "/api/User/Login2FA", method="POST"
    ).respond_with_data(BEARER_TOKEN, content_type="text/plain")
    # Second GET / for the post-login verification token.
    httpserver.expect_ordered_request("/").respond_with_data(
        TOKEN_HTML_SECOND, content_type="text/html"
    )


@pytest.fixture
def stub_login(httpserver):
    """Stage the login flow on the HTTP test server."""
    _stub_login(httpserver)
    return httpserver


@pytest.fixture
def client(httpserver):
    """A Client pointed at the test HTTP server. Not yet logged in."""
    return Client(
        username="api-user@example.org",
        password="correct-horse-battery-staple",
        totp_seed="JBSWY3DPEHPK3PXP",
        base_url=httpserver.url_for(""),
        timeout=5.0,
    )


@pytest.fixture
def logged_in_client(stub_login, client) -> Client:
    client.login()
    return client


# ---------------------------------------------------------------------------
# HARICA-shaped JSON fixtures
# ---------------------------------------------------------------------------

ORG_A = {
    "organizationId": "org-aaaa",
    "groupId": "group-1",
    "domain": "csl.mpg.de",
    "organization": "CSL Example",
    "validity": "2030-01-01T00:00:00.0000000",
    "organizationIdentifier": "LEIXG-123",
}
ORG_B = {
    "organizationId": "org-bbbb",
    "groupId": "group-2",
    "domain": "example.org",
    "organization": "Example Org",
    "validity": "2030-01-01T00:00:00.0000000",
    "organizationIdentifier": "LEIXG-456",
}
ORG_EXPIRED = {
    "organizationId": "org-cccc",
    "groupId": "group-3",
    "domain": "gone.example",
    "organization": "Expired",
    "validity": "2010-01-01T00:00:00.0000000",
    "organizationIdentifier": "LEIXG-OLD",
}


@pytest.fixture
def organizations_payload() -> list[dict[str, Any]]:
    return [ORG_A, ORG_B, ORG_EXPIRED]


# ---------------------------------------------------------------------------
# PKCS#7 ZIP fixture for bulk-issuance responses
# ---------------------------------------------------------------------------


def _make_self_signed_pem() -> tuple[bytes, Any]:
    """Return (cert_pem, cert_obj) of a short-lived self-signed cert."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Subject"),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, "test@example.org"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM), cert


def _pkcs7_der_from_cert(cert: x509.Certificate) -> bytes:
    """Serialize one cert as a certs-only PKCS#7 in DER form."""
    return pkcs7.serialize_certificates([cert], encoding=Encoding.DER)


@pytest.fixture
def p7b_zip_bytes() -> bytes:
    """A realistic bulk-SMIME response: a ZIP containing a single .p7b file."""
    _, cert = _make_self_signed_pem()
    p7b = _pkcs7_der_from_cert(cert)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("1.Test Subject.p7b", p7b)
    return buf.getvalue()
