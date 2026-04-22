"""Minimal urllib-based HTTP session used internally by :mod:`harica_smime`.

The goal is to cover exactly what ``Client`` needs — cookie persistence,
proxies, default headers, JSON bodies, multipart/form-data — without
depending on ``requests``. The public surface is intentionally small.
"""

from __future__ import annotations

import json as _json
import logging
import secrets
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.cookiejar import CookieJar
from typing import Any, Mapping, MutableMapping

from harica_smime.errors import APIError, HTTPError

logger = logging.getLogger(__name__)


MultipartField = (
    str | bytes | tuple[str | None, str | bytes] | tuple[str | None, str | bytes, str]
)


@dataclass
class Response:
    """Minimal response object. Shape-compatible with the subset of the
    ``requests.Response`` API that :class:`Client` uses."""

    status_code: int
    headers: Mapping[str, str]
    content: bytes

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    @property
    def text(self) -> str:
        charset = "utf-8"
        ct = self.headers.get("Content-Type", "")
        if "charset=" in ct:
            charset = ct.split("charset=", 1)[1].split(";", 1)[0].strip()
        return self.content.decode(charset, errors="replace")

    def json(self) -> Any:
        if not self.content:
            return None
        return _json.loads(self.content.decode("utf-8"))


class _CaptureRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler with an opt-out.

    HARICA returns a 302 on ``GET /`` that we must follow (it lands on the
    login HTML containing the CSRF token). But on some authenticated API
    endpoints, a 302 indicates an error and the caller wants to see it
    instead of silently chasing the redirect. :meth:`Session.request`
    sets ``req.follow_redirects`` to ``False`` in that case.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if getattr(req, "follow_redirects", True) is False:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Session:
    """Stateful HTTP session over stdlib urllib.

    Not thread-safe. One instance per :class:`Client`. Cookies accumulated
    during login persist for subsequent requests on the same instance.
    """

    def __init__(
        self,
        *,
        proxies: Mapping[str, str] | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.cookies: CookieJar = CookieJar()
        self.headers: MutableMapping[str, str] = {}
        self.proxies: Mapping[str, str] = dict(proxies) if proxies else {}
        self.timeout = timeout

        handlers: list[urllib.request.BaseHandler] = [
            urllib.request.HTTPCookieProcessor(self.cookies),
            _CaptureRedirectHandler(),
        ]
        if self.proxies:
            handlers.append(urllib.request.ProxyHandler(dict(self.proxies)))
        self._opener = urllib.request.build_opener(*handlers)

    def clear_cookies(self) -> None:
        self.cookies.clear()

    def request(
        self,
        method: str,
        url: str,
        *,
        json_body: Any | None = None,
        files: Mapping[str, MultipartField] | None = None,
        timeout: float | None = None,
        follow_redirects: bool = True,
    ) -> Response:
        """Execute a single HTTP request and return a :class:`Response`.

        Raises :class:`APIError` on transport-level failure (DNS, refused
        connection, timeout). Non-2xx responses are NOT raised here — the
        caller inspects :attr:`Response.ok` and decides what to do.

        When ``follow_redirects`` is False, 3xx responses are returned as-is
        instead of being followed — useful for endpoints that use 302 to
        signal errors.
        """
        if json_body is not None and files is not None:
            raise ValueError("json_body and files are mutually exclusive")

        body: bytes | None = None
        req_headers: dict[str, str] = dict(self.headers)
        for name, value in req_headers.items():
            # urllib rejects None header values silently; catch explicitly.
            if value is None:
                raise ValueError(f"header {name!r} has value None")

        if json_body is not None:
            body = _json.dumps(json_body).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")
        elif files is not None:
            content_type, body = _encode_multipart(files)
            req_headers["Content-Type"] = content_type

        req = urllib.request.Request(
            url=url,
            data=body,
            method=method.upper(),
            headers=req_headers,
        )
        # Picked up by _CaptureRedirectHandler.
        req.follow_redirects = follow_redirects  # type: ignore[attr-defined]

        effective_timeout = timeout if timeout is not None else self.timeout
        try:
            with self._opener.open(req, timeout=effective_timeout) as resp:
                content = resp.read()
                return Response(
                    status_code=resp.status,
                    headers={k: v for k, v in resp.headers.items()},
                    content=content,
                )
        except urllib.error.HTTPError as exc:
            # HTTPError is both an exception and an HTTPResponse-like object.
            # Treat it as a response so the caller can decide.
            try:
                content = exc.read()
            except Exception:  # noqa: BLE001
                content = b""
            return Response(
                status_code=exc.code,
                headers={k: v for k, v in exc.headers.items()}
                if exc.headers is not None
                else {},
                content=content,
            )
        except urllib.error.URLError as exc:
            msg = f"Request failed: {exc.reason}"
            logger.error(msg)
            raise APIError(msg) from exc
        except TimeoutError as exc:
            msg = f"Request timed out after {effective_timeout}s"
            logger.error(msg)
            raise APIError(msg) from exc


def _encode_multipart(
    fields: Mapping[str, MultipartField],
) -> tuple[str, bytes]:
    """Encode ``fields`` as multipart/form-data.

    Each value may be:

    - a ``str`` or ``bytes``: a plain text part
    - a 2-tuple ``(filename, content)``: a file part with default content type
      ``application/octet-stream``. ``filename`` may be ``None`` to emit a
      plain field.
    - a 3-tuple ``(filename, content, content_type)``: a file part with an
      explicit content type.

    Returns ``(content_type_header, body_bytes)``.
    """
    boundary = "----harica_smime" + secrets.token_hex(16)
    crlf = b"\r\n"
    parts: list[bytes] = []

    for name, raw in fields.items():
        filename: str | None = None
        content_type: str | None = None
        content: bytes

        if isinstance(raw, tuple):
            if len(raw) == 2:
                filename, value = raw
            elif len(raw) == 3:
                filename, value, content_type = raw
            else:
                raise ValueError(f"field {name!r}: unsupported tuple length")
            content = value.encode("utf-8") if isinstance(value, str) else value
        else:
            content = raw.encode("utf-8") if isinstance(raw, str) else raw

        disposition = f'form-data; name="{name}"'
        if filename is not None:
            disposition += f'; filename="{filename}"'

        header = f"--{boundary}{crlf.decode()}"
        header += f"Content-Disposition: {disposition}{crlf.decode()}"
        if content_type is not None:
            header += f"Content-Type: {content_type}{crlf.decode()}"
        elif filename is not None:
            header += f"Content-Type: application/octet-stream{crlf.decode()}"
        header += crlf.decode()

        parts.append(header.encode("utf-8"))
        parts.append(content)
        parts.append(crlf)

    parts.append(f"--{boundary}--{crlf.decode()}".encode("utf-8"))

    body = b"".join(parts)
    return f"multipart/form-data; boundary={boundary}", body


__all__ = ["Session", "Response", "HTTPError", "APIError"]
