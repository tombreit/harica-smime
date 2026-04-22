"""Reusable HARICA staging smoke test.

Run the full issuance flow for both certificate types against HARICA's
staging endpoint, then inspect the resulting subject DN for the attributes
we expect. Used by:

- The ``harica-smime smoke`` CLI subcommand (no Django).
- The opt-in pytest integration test (skipped unless live creds are set).
- The Django-aware wrapper ``scripts/test_harica_staging.py``.

The caller is responsible for building a :class:`~harica_smime.Client` with
the right credentials — this module doesn't talk to Django, env vars, or
config files.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from harica_smime.client import Client
from harica_smime.enums import CertificateType

logger = logging.getLogger(__name__)


@dataclass
class CertSummary:
    """Which identity attributes are present in a cert's subject DN."""

    common_name: bool
    email: bool
    given_name: bool
    surname: bool
    subject_dn: str


@dataclass
class IssuanceResult:
    ok: bool
    summary: CertSummary | None = None
    pem: str | None = None
    error: str | None = None


@dataclass
class SmokeResult:
    email_only: IssuanceResult
    natural_legal_lcp: IssuanceResult
    notes: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """True iff the core contract holds: both issued AND natural_legal_lcp
        carries GivenName + Surname in its subject DN."""
        if not (self.email_only.ok and self.natural_legal_lcp.ok):
            return False
        s = self.natural_legal_lcp.summary
        return bool(s and s.given_name and s.surname)


def build_csr(*, common_name: str, email: str, key_size: int = 2048) -> str:
    """Build a fresh CSR suitable for HARICA's S/MIME endpoints.

    The private key is discarded after signing — this is a test helper; real
    clients should hold on to the private key to assemble a PKCS#12.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
                ]
            )
        )
        .sign(private_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def describe_subject(cert_pem: str) -> CertSummary:
    """Summarize a cert's subject DN: which identity attributes are present."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    oids = {attr.oid for attr in cert.subject}
    return CertSummary(
        common_name=NameOID.COMMON_NAME in oids,
        email=NameOID.EMAIL_ADDRESS in oids,
        given_name=NameOID.GIVEN_NAME in oids,
        surname=NameOID.SURNAME in oids,
        subject_dn=cert.subject.rfc4514_string(),
    )


def _issue(
    client: Client,
    *,
    cert_type: CertificateType,
    email: str,
    first_name: str,
    last_name: str,
    org_id: str | None,
) -> IssuanceResult:
    common_name = f"{first_name} {last_name}".strip() or email
    csr_pem = build_csr(common_name=common_name, email=email)
    try:
        certs = client.bulk_smime_certificate(
            csr=csr_pem,
            emails=[email],
            certificate_type=cert_type,
            given_name=first_name,
            surname=last_name,
            org_id=org_id,
        )
    except Exception as exc:  # noqa: BLE001 — callers just want a verdict
        logger.exception("Issuance failed for cert_type=%s", cert_type.value)
        return IssuanceResult(ok=False, error=str(exc))
    if not certs:
        return IssuanceResult(ok=False, error="HARICA returned no certificates")
    leaf_pem = certs[0]
    return IssuanceResult(ok=True, summary=describe_subject(leaf_pem), pem=leaf_pem)


def run_staging_smoke(
    client: Client,
    *,
    email: str,
    first_name: str,
    last_name: str,
    org_id: str | None = None,
    cert_types: Iterable[CertificateType] = (
        CertificateType.EMAIL_ONLY,
        CertificateType.NATURAL_LEGAL_LCP,
    ),
) -> SmokeResult:
    """Issue one certificate per ``cert_types`` and inspect each leaf's subject DN.

    Raises whatever exceptions the login flow raises (authentication failure,
    network error). Per-issuance errors are caught and packed into the
    :class:`SmokeResult`, so the caller can render a report.
    """
    client.health_check()
    client.login()

    results: dict[CertificateType, IssuanceResult] = {
        ct: IssuanceResult(ok=False, error="not run") for ct in cert_types
    }
    for ct in cert_types:
        results[ct] = _issue(
            client,
            cert_type=ct,
            email=email,
            first_name=first_name,
            last_name=last_name,
            org_id=org_id,
        )

    return SmokeResult(
        email_only=results.get(
            CertificateType.EMAIL_ONLY, IssuanceResult(ok=False, error="not run")
        ),
        natural_legal_lcp=results.get(
            CertificateType.NATURAL_LEGAL_LCP,
            IssuanceResult(ok=False, error="not run"),
        ),
    )


def format_report(result: SmokeResult) -> str:
    """Human-readable summary; used by the CLI and the Django wrapper."""
    lines: list[str] = []

    def render(name: str, r: IssuanceResult) -> None:
        lines.append(f"--- {name} ---")
        if not r.ok:
            lines.append(f"  FAILED: {r.error}")
            return
        s = r.summary
        assert s is not None
        lines.append(f"  Subject DN: {s.subject_dn}")
        lines.append(f"  commonName   present: {s.common_name}")
        lines.append(f"  emailAddress present: {s.email}")
        lines.append(f"  givenName    present: {s.given_name}")
        lines.append(f"  surname      present: {s.surname}")

    render(CertificateType.EMAIL_ONLY.value, result.email_only)
    render(CertificateType.NATURAL_LEGAL_LCP.value, result.natural_legal_lcp)

    lines.append("")
    lines.append(
        "OK: both cert types issued; natural_legal_lcp contains GivenName+Surname."
        if result.passed
        else "FAIL: smoke test did not meet the full contract."
    )
    return "\n".join(lines)


__all__ = [
    "build_csr",
    "describe_subject",
    "run_staging_smoke",
    "format_report",
    "SmokeResult",
    "IssuanceResult",
    "CertSummary",
]
