"""Tests for the internal urllib-based HTTP session."""

from __future__ import annotations

import re

import pytest

from harica_smime._http import Session, _encode_multipart
from harica_smime.errors import APIError


# ---------------------------------------------------------------------------
# Pure unit tests for the multipart encoder.
# ---------------------------------------------------------------------------


def _split_parts(content_type: str, body: bytes) -> list[bytes]:
    m = re.search(r"boundary=(.+)$", content_type)
    assert m, "no boundary in content type"
    boundary = b"--" + m.group(1).encode()
    # Drop the terminator, split on the boundary markers.
    chunks = body.split(boundary)
    # first is empty (before initial boundary), last is "--\r\n"
    return [c for c in chunks[1:-1]]


class TestEncodeMultipart:
    def test_plain_string_part(self):
        ct, body = _encode_multipart({"groupId": "org-123"})
        assert ct.startswith("multipart/form-data; boundary=")
        parts = _split_parts(ct, body)
        assert len(parts) == 1
        assert b'name="groupId"' in parts[0]
        assert b"\r\norg-123\r\n" in parts[0]
        # No Content-Type for a plain field.
        assert b"Content-Type" not in parts[0]

    def test_bytes_part(self):
        ct, body = _encode_multipart({"raw": b"\x00\x01\x02"})
        parts = _split_parts(ct, body)
        assert b"\r\n\x00\x01\x02\r\n" in parts[0]

    def test_file_tuple_with_filename_and_type(self):
        ct, body = _encode_multipart(
            {"csv": ("bulk_smime.csv", "FriendlyName,CSR\nAlice,pem", "text/csv")}
        )
        parts = _split_parts(ct, body)
        assert b'name="csv"' in parts[0]
        assert b'filename="bulk_smime.csv"' in parts[0]
        assert b"Content-Type: text/csv" in parts[0]

    def test_file_tuple_defaults_to_octet_stream(self):
        ct, body = _encode_multipart({"f": ("blob.bin", b"\xffdata")})
        parts = _split_parts(ct, body)
        assert b"Content-Type: application/octet-stream" in parts[0]

    def test_tuple_with_filename_none_omits_filename(self):
        # HARICA sends groupId as a tuple (None, value).
        ct, body = _encode_multipart({"groupId": (None, "org-xyz")})
        parts = _split_parts(ct, body)
        assert b'name="groupId"' in parts[0]
        assert b"filename=" not in parts[0]

    def test_mixed_fields_order_preserved(self):
        ct, body = _encode_multipart(
            {
                "groupId": (None, "org-1"),
                "csv": ("bulk.csv", "a,b\n1,2", "text/csv"),
            }
        )
        parts = _split_parts(ct, body)
        assert len(parts) == 2
        assert b'name="groupId"' in parts[0]
        assert b'name="csv"' in parts[1]

    def test_boundary_is_unique_per_call(self):
        ct1, _ = _encode_multipart({"x": "y"})
        ct2, _ = _encode_multipart({"x": "y"})
        assert ct1 != ct2


# ---------------------------------------------------------------------------
# Integration-ish tests using pytest-httpserver (real loopback HTTPd).
# ---------------------------------------------------------------------------


def test_get_returns_response(httpserver):
    httpserver.expect_request("/hello").respond_with_data(
        "hi there", content_type="text/plain"
    )
    s = Session()
    resp = s.request("GET", httpserver.url_for("/hello"))
    assert resp.status_code == 200
    assert resp.ok
    assert resp.text == "hi there"


def test_json_body_is_encoded_and_content_type_set(httpserver):
    received: dict = {}

    def handler(request):
        received["body"] = request.get_data(as_text=True)
        received["content_type"] = request.content_type
        from werkzeug.wrappers import Response as WResp

        return WResp(b'{"ok": true}', status=200, content_type="application/json")

    httpserver.expect_request("/login").respond_with_handler(handler)
    s = Session()
    resp = s.request(
        "POST",
        httpserver.url_for("/login"),
        json_body={"email": "a@b", "password": "pw"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert received["content_type"].startswith("application/json")
    assert '"email": "a@b"' in received["body"]


def test_multipart_upload(httpserver):
    received: dict = {}

    def handler(request):
        received["content_type"] = request.content_type
        received["form"] = dict(request.form)
        received["files"] = {k: v.read() for k, v in request.files.items()}
        from werkzeug.wrappers import Response as WResp

        return WResp(b"", status=200)

    httpserver.expect_request("/bulk", method="POST").respond_with_handler(handler)
    s = Session()
    resp = s.request(
        "POST",
        httpserver.url_for("/bulk"),
        files={
            "groupId": (None, "org-abc"),
            "csv": ("bulk.csv", "a,b\n1,2", "text/csv"),
        },
    )
    assert resp.status_code == 200
    assert received["content_type"].startswith("multipart/form-data")
    assert received["form"] == {"groupId": "org-abc"}
    assert received["files"] == {"csv": b"a,b\n1,2"}


def test_cookies_persist_across_requests(httpserver):
    httpserver.expect_request("/login").respond_with_data(
        "",
        headers={"Set-Cookie": "SESSION=abc; Path=/"},
    )

    received_cookies: dict = {}

    def echo(request):
        received_cookies["value"] = request.cookies.get("SESSION")
        from werkzeug.wrappers import Response as WResp

        return WResp(b"ok", status=200)

    httpserver.expect_request("/echo").respond_with_handler(echo)

    s = Session()
    s.request("GET", httpserver.url_for("/login"))
    s.request("GET", httpserver.url_for("/echo"))

    assert received_cookies["value"] == "abc"


def test_default_headers_are_sent(httpserver):
    received: dict = {}

    def h(request):
        received["auth"] = request.headers.get("Authorization")
        received["rvt"] = request.headers.get("RequestVerificationToken")
        from werkzeug.wrappers import Response as WResp

        return WResp(b"ok", status=200)

    httpserver.expect_request("/whoami").respond_with_handler(h)
    s = Session()
    s.headers["Authorization"] = "Bearer secret"
    s.headers["RequestVerificationToken"] = "csrf-xyz"
    s.request("GET", httpserver.url_for("/whoami"))
    assert received["auth"] == "Bearer secret"
    assert received["rvt"] == "csrf-xyz"


def test_non_2xx_does_not_raise(httpserver):
    """A 4xx/5xx response is returned with status_code set; caller decides."""
    httpserver.expect_request("/boom").respond_with_data(
        "nope", status=418, content_type="text/plain"
    )
    s = Session()
    resp = s.request("GET", httpserver.url_for("/boom"))
    assert resp.status_code == 418
    assert not resp.ok
    assert resp.text == "nope"


def test_302_is_followed_by_default(httpserver):
    httpserver.expect_request("/go").respond_with_data(
        "",
        status=302,
        headers={"Location": httpserver.url_for("/dest")},
    )
    httpserver.expect_request("/dest").respond_with_data("landed", status=200)
    s = Session()
    resp = s.request("GET", httpserver.url_for("/go"))
    assert resp.status_code == 200
    assert resp.text == "landed"


def test_302_can_be_refused(httpserver):
    """Opt-out for endpoints that use 302 to signal errors."""
    httpserver.expect_request("/go").respond_with_data(
        "",
        status=302,
        headers={"Location": "/dest"},
    )
    s = Session()
    resp = s.request("GET", httpserver.url_for("/go"), follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers.get("Location") == "/dest"


def test_connection_refused_raises_api_error():
    s = Session(timeout=1.0)
    # Port 1 is unlikely to have anything listening.
    with pytest.raises(APIError):
        s.request("GET", "http://127.0.0.1:1/")


def test_mutually_exclusive_json_and_files():
    s = Session()
    with pytest.raises(ValueError):
        s.request(
            "POST",
            "http://127.0.0.1/",
            json_body={"a": 1},
            files={"b": "c"},
        )
