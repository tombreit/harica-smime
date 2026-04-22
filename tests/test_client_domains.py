import pytest

from harica_smime import DomainValidationError


def test_list_organizations_returns_payload(
    logged_in_client, httpserver, organizations_payload
):
    httpserver.expect_request(
        "/api/OrganizationAdmin/GetOrganizations", method="POST"
    ).respond_with_json(organizations_payload)
    assert logged_in_client.list_organizations() == organizations_payload


def test_list_domains_filters_expired(
    logged_in_client, httpserver, organizations_payload
):
    httpserver.expect_request(
        "/api/OrganizationAdmin/GetOrganizations", method="POST"
    ).respond_with_json(organizations_payload)
    domains = logged_in_client.list_domains()
    assert "csl.mpg.de" in domains
    assert "example.org" in domains
    assert "gone.example" not in domains


def test_check_email_domain_reports_valid_and_prevalidated(
    logged_in_client, httpserver
):
    httpserver.expect_request(
        "/api/ServerCertificate/CheckDomainNames", method="POST"
    ).respond_with_json(
        [
            {
                "domain": "csl.mpg.de",
                "isValid": True,
                "isPrevalidated": True,
                "errorMessage": None,
                "warningMessage": None,
            }
        ]
    )
    result = logged_in_client.check_email_domain("alice@csl.mpg.de")
    assert result["domain"] == "csl.mpg.de"
    assert result["is_valid"] is True
    assert result["is_prevalidated"] is True
    assert result["error_message"] is None


def test_check_email_domain_handles_not_prevalidated(logged_in_client, httpserver):
    httpserver.expect_request(
        "/api/ServerCertificate/CheckDomainNames", method="POST"
    ).respond_with_json(
        [
            {
                "domain": "unknown.example",
                "isValid": False,
                "isPrevalidated": False,
                "errorMessage": "Not in the list",
                "warningMessage": None,
            }
        ]
    )
    result = logged_in_client.check_email_domain("bob@unknown.example")
    assert result["is_valid"] is False
    assert result["is_prevalidated"] is False
    assert result["error_message"] == "Not in the list"


def test_check_email_domain_empty_result(logged_in_client, httpserver):
    httpserver.expect_request(
        "/api/ServerCertificate/CheckDomainNames", method="POST"
    ).respond_with_json([])
    result = logged_in_client.check_email_domain("bob@unknown.example")
    assert result["is_valid"] is False
    assert result["error_message"].startswith("No validation result")


def test_validate_email_domains_returns_org_id(
    logged_in_client, httpserver, organizations_payload
):
    httpserver.expect_request(
        "/api/OrganizationAdmin/GetOrganizations", method="POST"
    ).respond_with_json(organizations_payload)
    org = logged_in_client.validate_email_domains(["alice@csl.mpg.de"])
    assert org == "org-aaaa"


def test_validate_email_domains_rejects_mixed_groups(
    logged_in_client, httpserver, organizations_payload
):
    httpserver.expect_request(
        "/api/OrganizationAdmin/GetOrganizations", method="POST"
    ).respond_with_json(organizations_payload)
    with pytest.raises(DomainValidationError, match="different organization groups"):
        logged_in_client.validate_email_domains(["alice@csl.mpg.de", "bob@example.org"])


def test_validate_email_domains_rejects_unknown_domain(
    logged_in_client, httpserver, organizations_payload
):
    httpserver.expect_request(
        "/api/OrganizationAdmin/GetOrganizations", method="POST"
    ).respond_with_json(organizations_payload)
    with pytest.raises(DomainValidationError, match="not supported/found"):
        logged_in_client.validate_email_domains(["bob@nosuch.example"])


def test_subdomain_of_validated_domain_is_accepted(
    logged_in_client, httpserver, organizations_payload
):
    """If csl.mpg.de is validated, foo.csl.mpg.de should be too."""
    httpserver.expect_request(
        "/api/OrganizationAdmin/GetOrganizations", method="POST"
    ).respond_with_json(organizations_payload)
    org = logged_in_client.validate_email_domains(["alice@dept.csl.mpg.de"])
    assert org == "org-aaaa"
