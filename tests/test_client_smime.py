"""Tests for Client.bulk_smime_certificate — the main entry point.

Covers:
  - Happy path: multipart request shape + PEM list return value.
  - Regression: caller-supplied org_id is honored (bug fix).
  - Retry on empty body from HARICA.
  - Input validation via CertificateType enum + required-name rules.
"""

from __future__ import annotations

import io
import zipfile

import pytest
from werkzeug.wrappers import Response as WResp

from harica_smime import APIError, CertificateType


SAMPLE_CSR = (
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIIBlzCB/QIBADBYMQswCQYDVQQGEwJERTEUMBIGA1UECAwLTml\n"
    "-----END CERTIFICATE REQUEST-----\n"
)


def _empty_p7b_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("dummy.p7b", b"")
    return buf.getvalue()


def test_bulk_smime_happy_path(
    logged_in_client, httpserver, organizations_payload, p7b_zip_bytes
):
    httpserver.expect_request(
        "/api/OrganizationAdmin/GetOrganizations", method="POST"
    ).respond_with_json(organizations_payload)

    seen: dict = {}

    def handler(request):
        seen["form"] = dict(request.form)
        seen["files"] = {k: v.read().decode() for k, v in request.files.items()}
        return WResp(p7b_zip_bytes, status=200)

    httpserver.expect_request(
        "/api/OrganizationAdmin/CreateBulkCertificatesSMIME", method="POST"
    ).respond_with_handler(handler)

    certs = logged_in_client.bulk_smime_certificate(
        csr=SAMPLE_CSR,
        emails="alice@csl.mpg.de",
        certificate_type=CertificateType.NATURAL_LEGAL_LCP,
        given_name="Alice",
        surname="Example",
    )
    assert len(certs) == 1
    assert certs[0].startswith("-----BEGIN CERTIFICATE-----")
    # Org was auto-resolved via validate_email_domains -> "org-aaaa".
    assert seen["form"] == {"groupId": "org-aaaa"}
    csv_body = seen["files"]["csv"]
    assert "FriendlyName" in csv_body
    assert "natural_legal_lcp" in csv_body
    assert "Alice" in csv_body
    assert "Example" in csv_body


def test_caller_supplied_org_id_is_honored(logged_in_client, httpserver, p7b_zip_bytes):
    """Regression test for the bug where bulk_smime_certificate ignored org_id.

    We do NOT stub GetOrganizations — if the bug comes back, validate_email_domains
    would call it and httpserver would log an unhandled request.
    """
    seen: dict = {}

    def handler(request):
        seen["form"] = dict(request.form)
        return WResp(p7b_zip_bytes, status=200)

    httpserver.expect_request(
        "/api/OrganizationAdmin/CreateBulkCertificatesSMIME", method="POST"
    ).respond_with_handler(handler)

    certs = logged_in_client.bulk_smime_certificate(
        csr=SAMPLE_CSR,
        emails="alice@whatever.example",
        certificate_type=CertificateType.EMAIL_ONLY,
        org_id="caller-provided-org",
    )
    assert len(certs) == 1
    assert seen["form"] == {"groupId": "caller-provided-org"}


def test_retries_once_on_empty_body(logged_in_client, httpserver, p7b_zip_bytes):
    httpserver.expect_ordered_request(
        "/api/OrganizationAdmin/CreateBulkCertificatesSMIME", method="POST"
    ).respond_with_data(b"", status=200)
    httpserver.expect_ordered_request(
        "/api/OrganizationAdmin/CreateBulkCertificatesSMIME", method="POST"
    ).respond_with_data(p7b_zip_bytes, status=200)

    certs = logged_in_client.bulk_smime_certificate(
        csr=SAMPLE_CSR,
        emails="alice@csl.mpg.de",
        certificate_type=CertificateType.EMAIL_ONLY,
        org_id="org-aaaa",
    )
    assert len(certs) == 1


def test_two_empty_bodies_raises_api_error(logged_in_client, httpserver):
    httpserver.expect_ordered_request(
        "/api/OrganizationAdmin/CreateBulkCertificatesSMIME", method="POST"
    ).respond_with_data(b"", status=200)
    httpserver.expect_ordered_request(
        "/api/OrganizationAdmin/CreateBulkCertificatesSMIME", method="POST"
    ).respond_with_data(b"", status=200)

    with pytest.raises(APIError, match="zip file is empty"):
        logged_in_client.bulk_smime_certificate(
            csr=SAMPLE_CSR,
            emails="alice@csl.mpg.de",
            certificate_type=CertificateType.EMAIL_ONLY,
            org_id="org-aaaa",
        )


def test_natural_legal_lcp_requires_given_name(logged_in_client):
    with pytest.raises(ValueError, match="given_name"):
        logged_in_client.bulk_smime_certificate(
            csr=SAMPLE_CSR,
            emails="alice@csl.mpg.de",
            certificate_type=CertificateType.NATURAL_LEGAL_LCP,
            surname="Example",
            org_id="org-aaaa",
        )


def test_natural_legal_lcp_requires_surname(logged_in_client):
    with pytest.raises(ValueError, match="surname"):
        logged_in_client.bulk_smime_certificate(
            csr=SAMPLE_CSR,
            emails="alice@csl.mpg.de",
            certificate_type=CertificateType.NATURAL_LEGAL_LCP,
            given_name="Alice",
            org_id="org-aaaa",
        )


def test_string_cert_type_is_coerced(logged_in_client, httpserver, p7b_zip_bytes):
    """Passing the raw string (as Django model would) must still work."""
    httpserver.expect_request(
        "/api/OrganizationAdmin/CreateBulkCertificatesSMIME", method="POST"
    ).respond_with_data(p7b_zip_bytes, status=200)

    certs = logged_in_client.bulk_smime_certificate(
        csr=SAMPLE_CSR,
        emails="alice@csl.mpg.de",
        certificate_type="email_only",
        org_id="org-aaaa",
    )
    assert len(certs) == 1


def test_unknown_cert_type_raises(logged_in_client):
    with pytest.raises(ValueError):
        logged_in_client.bulk_smime_certificate(
            csr=SAMPLE_CSR,
            emails="alice@csl.mpg.de",
            certificate_type="not_a_real_type",
            org_id="org-aaaa",
        )


def test_more_than_3_emails_raises(logged_in_client):
    with pytest.raises(ValueError, match="up to 3"):
        logged_in_client.bulk_smime_certificate(
            csr=SAMPLE_CSR,
            emails=["a@csl.mpg.de", "b@csl.mpg.de", "c@csl.mpg.de", "d@csl.mpg.de"],
            certificate_type=CertificateType.EMAIL_ONLY,
            org_id="org-aaaa",
        )


def test_empty_zip_response_raises(logged_in_client, httpserver):
    httpserver.expect_request(
        "/api/OrganizationAdmin/CreateBulkCertificatesSMIME", method="POST"
    ).respond_with_data(_empty_p7b_zip(), status=200)

    with pytest.raises(APIError):
        logged_in_client.bulk_smime_certificate(
            csr=SAMPLE_CSR,
            emails="alice@csl.mpg.de",
            certificate_type=CertificateType.EMAIL_ONLY,
            org_id="org-aaaa",
        )
