import pytest

from harica_smime import AuthError


def test_login_sets_authorization_header(stub_login, client):
    client.login()
    assert client.http.headers.get("Authorization") == "bearer-token-xyz"
    # A fresh verification token is fetched post-login.
    assert client.http.headers.get("RequestVerificationToken") == "csrf-abc-2"


def test_login_is_cached(stub_login, client):
    client.login()
    first_last_login = client._last_login
    # Second call within LOGIN_LIFETIME must be a no-op — the httpserver was
    # primed with exactly 3 ordered requests; a second real login would
    # trigger an extra request and fail the ordered assertion on teardown.
    client.login()
    assert client._last_login == first_last_login


def test_login_force_refreshes(httpserver):
    """force=True bypasses the cache and re-runs the login flow."""
    # Prime the server with two full login flows (6 sequential requests).
    from tests.conftest import TOKEN_HTML, TOKEN_HTML_SECOND, BEARER_TOKEN

    for _ in range(2):
        httpserver.expect_ordered_request("/").respond_with_data(
            TOKEN_HTML, content_type="text/html"
        )
        httpserver.expect_ordered_request(
            "/api/User/Login2FA", method="POST"
        ).respond_with_data(BEARER_TOKEN, content_type="text/plain")
        httpserver.expect_ordered_request("/").respond_with_data(
            TOKEN_HTML_SECOND, content_type="text/html"
        )

    from harica_smime import Client

    client = Client(
        username="user@example.org",
        password="pw",
        totp_seed="JBSWY3DPEHPK3PXP",
        base_url=httpserver.url_for(""),
    )
    client.login()
    client.login(force=True)
    # No assertions needed: if force weren't honored, the second GET / would
    # hit an unmatched request and the httpserver teardown would complain.


def test_login_auth_failure_raises_auth_error(httpserver):
    from tests.conftest import TOKEN_HTML

    httpserver.expect_ordered_request("/").respond_with_data(
        TOKEN_HTML, content_type="text/html"
    )
    httpserver.expect_ordered_request(
        "/api/User/Login2FA", method="POST"
    ).respond_with_data("bad credentials", status=401)

    from harica_smime import Client

    client = Client(
        username="user@example.org",
        password="wrong",
        totp_seed="JBSWY3DPEHPK3PXP",
        base_url=httpserver.url_for(""),
    )
    with pytest.raises(AuthError):
        client.login()


def test_missing_verification_token_raises(httpserver):
    httpserver.expect_ordered_request("/").respond_with_data(
        "<html>no token here</html>", content_type="text/html"
    )
    from harica_smime import Client

    client = Client(
        username="user@example.org",
        password="pw",
        totp_seed="JBSWY3DPEHPK3PXP",
        base_url=httpserver.url_for(""),
    )
    with pytest.raises(AuthError, match="Could not find"):
        client.login()


def test_health_check_passes_on_200(httpserver):
    httpserver.expect_request("/").respond_with_data("ok", status=200)
    from harica_smime import Client

    c = Client(username="u", password="p", base_url=httpserver.url_for(""))
    c.health_check()  # no exception


def test_health_check_raises_on_503(httpserver):
    httpserver.expect_request("/").respond_with_data("", status=503)
    from harica_smime import Client, APIError

    c = Client(username="u", password="p", base_url=httpserver.url_for(""))
    with pytest.raises(APIError, match="temporarily unavailable"):
        c.health_check()
