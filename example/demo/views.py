"""Views for the harica-smime demo.

- ``index``        — render the single-page UI.
- ``submit_csr``   — receive the browser-generated CSR and return a signed
  leaf PEM. In **staging mode** (``HARICA_USERNAME`` et al. set in the
  environment) the CSR is forwarded to HARICA's staging endpoint exactly as
  documented in the top-level ``README.md``. In **stub mode** (the default,
  so the demo runs with zero credentials) a throwaway in-process CA signs
  the CSR — the round-trip still exercises the browser-side privacy contract
  (keypair, CSR build, PKCS#12 assembly) without touching the network.
"""

from __future__ import annotations

import base64
import datetime
import json
import logging
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET, require_POST

from harica_smime import APIError, CertificateType, Client

logger = logging.getLogger(__name__)


def _mode() -> str:
    """Return ``"staging"`` if HARICA creds are present, else ``"stub"``."""
    return "staging" if os.environ.get("HARICA_USERNAME") else "stub"


@require_GET
def index(request: HttpRequest) -> HttpResponse:
    return render(
        request,
        "index.html",
        {
            "mode": _mode(),
            "base_url": os.environ.get("HARICA_BASE_URL", Client.STAGING_BASE_URL),
        },
    )


@require_POST
def submit_csr(request: HttpRequest) -> JsonResponse:
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return JsonResponse({"error": "invalid JSON payload"}, status=400)

    csr_pem = payload.get("csr") or ""
    email = payload.get("email") or ""
    given_name = payload.get("given_name") or ""
    surname = payload.get("surname") or ""

    missing = [
        name
        for name, value in (
            ("csr", csr_pem),
            ("email", email),
            ("given_name", given_name),
            ("surname", surname),
        )
        if not value
    ]
    if missing:
        return JsonResponse(
            {"error": f"missing required fields: {', '.join(missing)}"},
            status=400,
        )

    if _mode() == "staging":
        try:
            certs = _issue_via_harica(csr_pem, email, given_name, surname)
        except APIError as exc:
            logger.warning("HARICA issuance failed: %s", exc)
            return JsonResponse({"error": str(exc)}, status=502)
        return JsonResponse({"mode": "staging", "certs": certs})

    try:
        cert_pem = _stub_sign_csr(csr_pem, email, given_name, surname)
    except ValueError as exc:
        return JsonResponse({"error": f"bad CSR: {exc}"}, status=400)
    return JsonResponse({"mode": "stub", "certs": [cert_pem]})


def _issue_via_harica(
    csr_pem: str, email: str, given_name: str, surname: str
) -> list[str]:
    """Forward the CSR to HARICA staging — the real thing."""
    client = Client(
        username=os.environ["HARICA_USERNAME"],
        password=os.environ["HARICA_PASSWORD"],
        totp_seed=os.environ.get("HARICA_TOTP_SEED") or None,
        base_url=os.environ.get("HARICA_BASE_URL", Client.STAGING_BASE_URL),
    )
    return client.bulk_smime_certificate(
        csr=csr_pem,
        emails=[email],
        certificate_type=CertificateType.NATURAL_LEGAL_LCP,
        given_name=given_name,
        surname=surname,
    )


def _stub_sign_csr(csr_pem: str, email: str, given_name: str, surname: str) -> str:
    """Sign the incoming CSR with a throwaway in-process CA.

    The resulting cert is *not* a real S/MIME cert and is not trusted by any
    MUA. It only exists so the browser-side PKCS#12 assembly step has a
    well-formed leaf PEM to package — the point of the demo is to show the
    round-trip and the privacy contract, not to ship valid mail certs.
    """
    try:
        csr = _load_csr_lenient(csr_pem)
    except ValueError as exc:
        raise ValueError(f"could not parse CSR: {exc}") from exc

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "harica-smime demo CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "harica-smime demo"),
        ]
    )

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, f"{given_name} {surname}".strip()),
            x509.NameAttribute(NameOID.GIVEN_NAME, given_name),
            x509.NameAttribute(NameOID.SURNAME, surname),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        ]
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_name)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(email)]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )
    return leaf.public_bytes(serialization.Encoding.PEM).decode("ascii")


# DER bytes of the emailAddress attribute OID (1.2.840.113549.1.9.1) with its
# OBJECT IDENTIFIER tag + length prefix.
_EMAIL_ADDRESS_OID_DER = bytes.fromhex("06092A864886F70D010901")


def _load_csr_lenient(csr_pem: str) -> x509.CertificateSigningRequest:
    """Load a CSR, patching any emailAddress encoded as PrintableString.

    node-forge (bundled by this package as the browser-side helper) emits
    the subject ``emailAddress`` attribute as PrintableString, which is
    invalid per PKCS#9 — it should be IA5String, since '@' is not a legal
    PrintableString codepoint. HARICA's real CA accepts this leniently;
    pyca/cryptography's strict parser rejects it. For the stub-only code
    path (where we only need the CSR's public key), we patch the value's
    BER tag byte in place. The signature becomes invalid after the patch,
    so we skip ``is_signature_valid`` — accept/not-accept is not the job
    of this demo.
    """
    lines = [line for line in csr_pem.splitlines() if not line.startswith("-----")]
    try:
        der = bytearray(base64.b64decode("".join(lines)))
    except ValueError as exc:
        raise ValueError(f"not valid PEM base64: {exc}") from exc

    idx = 0
    while True:
        pos = der.find(_EMAIL_ADDRESS_OID_DER, idx)
        if pos < 0:
            break
        tag_pos = pos + len(_EMAIL_ADDRESS_OID_DER)
        if tag_pos < len(der) and der[tag_pos] == 0x13:  # PrintableString
            der[tag_pos] = 0x16  # IA5String
        idx = pos + len(_EMAIL_ADDRESS_OID_DER)

    return x509.load_der_x509_csr(bytes(der))
