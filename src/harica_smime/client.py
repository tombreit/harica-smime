"""HARICA REST client.

This module hosts the main :class:`Client` class: the public entry point
for talking to HARICA's certificate management API. Transport is delegated
to :mod:`harica_smime._http`, so this module is free of HTTP minutiae.
"""

from __future__ import annotations

import datetime
import io
import logging
import re
import time
import zipfile
from typing import Any, ClassVar, Literal, Mapping, Sequence, TypedDict

from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    load_der_pkcs7_certificates,
)

from harica_smime import _http
from harica_smime.enums import CertificateType
from harica_smime.errors import (
    APIError,
    AuthError,
    DomainValidationError,
    HTTPError,
)
from harica_smime._validators import is_subdomain
from harica_smime.otp import totp

logger = logging.getLogger(__name__)


def _parse_harica_date(value: str) -> datetime.datetime:
    # HARICA quirk: timestamps carry nanosecond precision (9 fractional digits)
    # which ``datetime.fromisoformat`` rejects. Drop the fractional part — we
    # only use these for day-granularity expiry checks.
    return datetime.datetime.fromisoformat(value.partition(".")[0])


class DomainCheckResult(TypedDict):
    is_valid: bool
    is_prevalidated: bool
    error_message: str | None
    warning_message: str | None
    domain: str


class Client:
    """REST client for HARICA's S/MIME bulk-issuance API."""

    DEFAULT_BASE_URL: ClassVar[str] = "https://cm.harica.gr"
    STAGING_BASE_URL: ClassVar[str] = "https://cm-stg.harica.gr"
    LOGIN_LIFETIME: ClassVar[int] = 300  # seconds

    _MAX_SMIME_EMAILS: ClassVar[int] = 3
    _FRIENDLY_NAME_MAX: ClassVar[int] = 85

    def __init__(
        self,
        *,
        username: str,
        password: str,
        totp_seed: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        proxies: str | Mapping[str, str] | None = None,
        timeout: float = 60.0,
        http: _http.Session | None = None,
    ) -> None:
        logger.debug("Initializing HARICA Client with base_url: %s", base_url)
        self.username = username
        self.password = password
        self.totp_seed = totp_seed
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

        if isinstance(proxies, str):
            proxies = {"http": proxies, "https": proxies}
        self.proxies: Mapping[str, str] | None = proxies

        self.http = http or _http.Session(proxies=self.proxies, timeout=self.timeout)
        self._last_login: float = 0.0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def health_check(self) -> None:
        """Probe the HARICA frontend for availability.

        Raises :class:`APIError` if the service looks unavailable.
        """
        try:
            resp = self.http.request(
                "GET", self.base_url + "/", timeout=min(self.timeout, 30.0)
            )
        except APIError:
            raise

        if resp.status_code >= 500:
            msg = {
                502: "HARICA service is currently unavailable (Bad Gateway)",
                503: "HARICA service is temporarily unavailable (Service Unavailable)",
                504: "HARICA service is currently unavailable (Gateway Timeout)",
            }.get(
                resp.status_code,
                f"HARICA service is currently unavailable (Server Error {resp.status_code})",
            )
            logger.error(msg)
            raise APIError(msg, status_code=resp.status_code)
        if resp.status_code >= 400:
            msg = (
                "HARICA service endpoint not found"
                if resp.status_code == 404
                else f"HARICA service returned client error {resp.status_code}"
            )
            logger.error(msg)
            raise APIError(msg, status_code=resp.status_code)

        logger.debug("HARICA service health check passed")

    def login(self, *, force: bool = False) -> None:
        """Authenticate with HARICA and prime the session.

        Cached for :attr:`LOGIN_LIFETIME` seconds; pass ``force=True`` to
        bypass the cache.
        """
        now = time.time()
        if not force and now < self._last_login + self.LOGIN_LIFETIME:
            logger.debug(
                "Last login was %.2fs < %ds ago, skipping relogin.",
                now - self._last_login,
                self.LOGIN_LIFETIME,
            )
            return

        logger.debug("Logging in...")
        # Clear any previously issued auth.
        for header in ("Authorization", "RequestVerificationToken"):
            self.http.headers.pop(header, None)
        self.http.clear_cookies()

        self.http.headers["RequestVerificationToken"] = self._get_verification_token()

        token = totp(key=self.totp_seed) if self.totp_seed else ""
        login_body = {
            "email": self.username,
            "password": self.password,
            "token": token,
        }
        resp = self.http.request(
            "POST", self.base_url + "/api/User/Login2FA", json_body=login_body
        )
        if resp.status_code != 200:
            msg = (
                f"Login failed with code {resp.status_code}, message: {resp.content!r}"
            )
            logger.error(msg)
            raise AuthError(msg, status_code=resp.status_code)

        auth_token = resp.content.decode("utf-8", errors="replace").strip()
        # HARICA returns the token as a bare string (optionally JSON-quoted).
        if auth_token.startswith('"') and auth_token.endswith('"'):
            auth_token = auth_token[1:-1]
        self.http.headers["Authorization"] = auth_token
        self.http.headers["RequestVerificationToken"] = self._get_verification_token()
        self._last_login = time.time()
        logger.info("Successfully logged in to HARICA API")

    # ------------------------------------------------------------------
    # Internal request plumbing
    # ------------------------------------------------------------------

    def _get_verification_token(self) -> str:
        resp = self.http.request("GET", self.base_url + "/", timeout=self.timeout)
        if resp.status_code != 200:
            msg = (
                f"Error retrieving verification code {resp.status_code}: "
                f"{resp.content!r}"
            )
            logger.error(msg)
            raise AuthError(msg, status_code=resp.status_code)

        tag = "__RequestVerificationToken"
        for line in resp.text.splitlines():
            if tag not in line:
                continue
            match = re.search(r'value="([^"]+)"', line)
            if match:
                return match.group(1)
        msg = f"Could not find {tag} in response"
        logger.error(msg)
        raise AuthError(msg)

    def _request(
        self,
        method: str,
        uri: str,
        *,
        decode_json: bool = True,
        files: Mapping[str, Any] | None = None,
        json_body: Any | None = None,
    ) -> Any:
        """Authenticated request helper used by every API wrapper."""
        self.login()

        logger.debug("%s %s", method, uri)
        start = time.time()
        try:
            resp = self.http.request(
                method,
                self.base_url + uri,
                json_body=json_body,
                files=files,
                # Authenticated API endpoints use 302 to signal errors; show
                # the caller the 302 instead of silently following it.
                follow_redirects=False,
            )
        except APIError:
            logger.exception("Request failed")
            raise
        elapsed = time.time() - start
        logger.debug(
            "Request to %s completed in %.3fs (status=%s)",
            uri,
            elapsed,
            resp.status_code,
        )

        if not resp.ok:
            data = resp.text
            if resp.status_code == 302:
                data = f"{resp.headers.get('Location', '')} {data}"
            msg = f"Error during API request ({resp.status_code}): {data}"
            logger.error(msg)
            raise HTTPError(msg, status_code=resp.status_code)

        logger.debug(
            "Response status: %s, body[:80]=%r", resp.status_code, resp.text[:80]
        )

        if not decode_json:
            return resp

        if not resp.text.strip():
            return None

        try:
            return resp.json()
        except ValueError as exc:
            msg = f"Failed to decode JSON from response. Body: {resp.text!r}"
            logger.error(msg)
            raise APIError(msg) from exc

    # ------------------------------------------------------------------
    # Organizations / domains
    # ------------------------------------------------------------------

    def list_organizations(self) -> list[dict]:
        """List all organizations visible to the authenticated user."""
        return self._request("POST", "/api/OrganizationAdmin/GetOrganizations")

    def check_domain_names(self, domains: Sequence[str]) -> list[dict]:
        """Ask HARICA whether the given domains are valid/prevalidated."""
        body = [{"domain": d} for d in domains]
        return self._request(
            "POST", "/api/ServerCertificate/CheckDomainNames", json_body=body
        )

    def check_email_domain(self, email: str) -> DomainCheckResult:
        """Return :class:`DomainCheckResult` for the domain of ``email``."""
        domain = email.split("@", 1)[1]
        results = self.check_domain_names([domain]) or []
        if not results:
            return DomainCheckResult(
                is_valid=False,
                is_prevalidated=False,
                error_message=f"No validation result returned for domain {domain}",
                warning_message=None,
                domain=domain,
            )
        result = results[0]
        return DomainCheckResult(
            is_valid=bool(result.get("isValid", False)),
            is_prevalidated=bool(result.get("isPrevalidated", False)),
            error_message=result.get("errorMessage") or None,
            warning_message=result.get("warningMessage") or None,
            domain=domain,
        )

    def list_domains(self) -> list[str]:
        """Return sorted list of non-expired domain names."""
        orgs = [
            org
            for org in self.list_organizations()
            if _parse_harica_date(org["validity"]) > datetime.datetime.now()
        ]
        return sorted(org["domain"] for org in orgs)

    def get_domain_details(
        self,
        *,
        name: str | None = None,
        state: Literal["ACTIVE", "INACTIVE"] | None = None,
        sort_by: str = "domain",
    ) -> dict[str, dict]:
        """Return {domain: org-dict}, optionally filtered by ``name``/``state``."""
        orgs = self.list_organizations()

        if name:
            orgs = [org for org in orgs if name in org["domain"]]

        if state:
            now = datetime.datetime.now()
            if state == "ACTIVE":
                orgs = [
                    org for org in orgs if _parse_harica_date(org["validity"]) > now
                ]
            elif state == "INACTIVE":
                orgs = [
                    org for org in orgs if _parse_harica_date(org["validity"]) <= now
                ]
            else:
                raise APIError(f"Unsupported state {state!r}")

        orgs = sorted(orgs, key=lambda o: o[sort_by])
        return {org["domain"]: org for org in orgs}

    def validate_email_domains(self, emails: Sequence[str]) -> str:
        """Resolve a list of emails to a single HARICA ``organizationId``.

        Raises :class:`DomainValidationError` if the emails span multiple
        groups or contain an unknown domain.
        """
        group_id: str | None = None
        first_org_id: str | None = None
        domain_infos = self.get_domain_details()

        for email in emails:
            maildomain = email.split("@", 1)[1]
            cur_group_id: str | None = None
            for domain, info in domain_infos.items():
                if not is_subdomain(maildomain, domain):
                    continue
                if cur_group_id:
                    raise DomainValidationError(
                        f"Domain {maildomain} of {email} belongs to multiple "
                        f"organization groups: {cur_group_id} and {info['groupId']}",
                        status_code=400,
                    )
                cur_group_id = info["groupId"]
                if first_org_id is None:
                    first_org_id = info["organizationId"]
            if not cur_group_id:
                raise DomainValidationError(
                    f"Domain {maildomain} of email {email} not supported/found",
                    status_code=400,
                )
            if group_id and group_id != cur_group_id:
                raise DomainValidationError(
                    f"Domains of {list(emails)} belong to different organization groups",
                    status_code=400,
                )
            group_id = cur_group_id

        assert first_org_id is not None  # loop above ensures this
        return first_org_id

    # ------------------------------------------------------------------
    # Certificate issuance
    # ------------------------------------------------------------------

    def bulk_smime_certificate(
        self,
        *,
        csr: str,
        emails: str | Sequence[str],
        certificate_type: CertificateType | str = CertificateType.EMAIL_ONLY,
        given_name: str | None = None,
        surname: str | None = None,
        org_id: str | None = None,
    ) -> list[str]:
        """Issue an S/MIME certificate via the bulk endpoint.

        ``org_id`` is honored when supplied; when ``None``, the org is auto-
        resolved from the email domains via :meth:`validate_email_domains`.

        Returns a list of PEM-encoded certificates — the leaf first, then
        the issuer chain.
        """
        if isinstance(emails, str):
            emails = [emails]
        else:
            emails = list(emails)

        cert_type = CertificateType(certificate_type)

        if org_id is None:
            org_id = self.validate_email_domains(emails)

        zip_bytes = self._create_bulk_smime(
            emails=emails,
            cert_type=cert_type,
            org_id=org_id,
            given_name=given_name,
            surname=surname,
            csr=csr,
            pickup_password=None,
        )
        # HARICA's bulk endpoint returns a ZIP containing exactly one cert
        # artifact: a ``.p7b`` when a CSR was submitted (our case), or a
        # ``.p12`` when a pickup password was submitted. Anything else is an
        # API surprise and we want to hear about it.
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
            names = [item.filename for item in archive.filelist if item.file_size]
            if len(names) != 1 or not names[0].endswith(".p7b"):
                raise APIError(f"Unexpected archive contents: {names!r}")
            pkcs7_data = archive.read(names[0])
        certs = load_der_pkcs7_certificates(pkcs7_data)
        pem_certs = [cert.public_bytes(Encoding.PEM).decode().strip() for cert in certs]
        logger.debug("Received %d certificates from HARICA", len(pem_certs))
        return pem_certs

    def _create_bulk_smime(
        self,
        *,
        emails: Sequence[str],
        cert_type: CertificateType,
        org_id: str,
        given_name: str | None,
        surname: str | None,
        csr: str | None,
        pickup_password: str | None,
    ) -> bytes:
        """Low-level bulk-SMIME call; returns the raw ZIP bytes from HARICA."""
        if cert_type is CertificateType.NATURAL_LEGAL_LCP:
            if not given_name:
                raise ValueError("given_name is required for natural_legal_lcp")
            if not surname:
                raise ValueError("surname is required for natural_legal_lcp")

        if bool(csr) == bool(pickup_password):
            raise ValueError("Exactly one of csr or pickup_password must be given")

        if not emails:
            raise ValueError("at least one email address must be given")
        if len(emails) > self._MAX_SMIME_EMAILS:
            raise ValueError(
                f"HARICA only allows up to {self._MAX_SMIME_EMAILS} email addresses "
                f"in S/MIME certificates; {len(emails)} given"
            )

        email2 = emails[1] if len(emails) > 1 else ""
        email3 = emails[2] if len(emails) > 2 else ""

        csr_body = ""
        if csr:
            # HARICA's example CSV wants CR+LF line endings inside the CSR.
            csr_body = "\r\n".join(csr.splitlines()) + "\r\n"

        friendly_name = f"{given_name or ''} {surname or ''}".strip() or emails[0]
        if len(friendly_name) > self._FRIENDLY_NAME_MAX:
            logger.debug(
                'Truncating long FriendlyName "%s" to %d chars',
                friendly_name,
                self._FRIENDLY_NAME_MAX,
            )
            friendly_name = friendly_name[: self._FRIENDLY_NAME_MAX]

        header = [
            "FriendlyName",
            "Email",
            "Email2",
            "Email3",
            "GivenName",
            "Surname",
            "PickupPassword",
            "CertType",
            "CSR",
        ]
        row = [
            friendly_name,
            emails[0],
            email2,
            email3,
            given_name or "",
            surname or "",
            pickup_password or "",
            cert_type.value,
            f'"{csr_body}"' if csr_body else "",
        ]
        csv = "\r\n".join([",".join(header), ",".join(row)])
        if csr_body:
            # HARICA quirk: their reference CSV emits a trailing comma after the
            # CSR column on the last row, and the parser rejects submissions
            # without it. Looks like a typo — isn't.
            csv += ","

        def do_request() -> _http.Response:
            return self._request(
                "POST",
                "/api/OrganizationAdmin/CreateBulkCertificatesSMIME",
                decode_json=False,
                files={
                    "groupId": (None, org_id),
                    "csv": ("bulk_smime.csv", csv, "text/csv"),
                },
            )

        response = do_request()
        # HARICA quirk: the bulk endpoint intermittently returns an empty body
        # on the first call even when the request is well-formed; a single
        # retry is enough. Same behavior observed in other HARICA clients.
        if len(response.content) == 0:
            logger.warning("Response for %s was empty, retrying once", emails[0])
            response = do_request()
            if len(response.content) == 0:
                raise APIError(
                    "Error creating SMIME certificate: returned zip file is empty"
                )
        return response.content


__all__ = ["Client", "DomainCheckResult"]
