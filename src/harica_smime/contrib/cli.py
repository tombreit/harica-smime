"""Command-line entry point for :mod:`harica_smime`.

Usage::

    python -m harica_smime [global-options] <subcommand> [args...]
    # or, after install:
    harica-smime [global-options] <subcommand> [args...]

Global options:

- ``--base-url URL``         (default from ``HARICA_BASE_URL`` or HARICA prod)
- ``--timeout SEC``          per-request timeout
- ``-v``                     verbose logging (stderr)

Credentials come from ``--username`` / ``--password`` / ``--totp-seed`` flags
or, as a fallback, from the environment variables ``HARICA_USERNAME``,
``HARICA_PASSWORD``, ``HARICA_TOTP_SEED``.

Subcommands: ``list-orgs``, ``list-domains``, ``check-domain``, ``issue``,
``smoke``.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from harica_smime.client import Client
from harica_smime.contrib.smoke import format_report, run_staging_smoke
from harica_smime.enums import CertificateType
from harica_smime.errors import APIError


def _build_client(args: argparse.Namespace) -> Client:
    username = args.username or os.environ.get("HARICA_USERNAME")
    password = args.password or os.environ.get("HARICA_PASSWORD")
    totp_seed = args.totp_seed or os.environ.get("HARICA_TOTP_SEED")
    base_url = (
        args.base_url or os.environ.get("HARICA_BASE_URL") or Client.DEFAULT_BASE_URL
    )

    missing = [
        name
        for name, value in (
            ("HARICA_USERNAME / --username", username),
            ("HARICA_PASSWORD / --password", password),
        )
        if not value
    ]
    if missing:
        print(
            f"error: missing credentials: {', '.join(missing)}",
            file=sys.stderr,
        )
        sys.exit(2)

    assert username is not None and password is not None
    return Client(
        username=username,
        password=password,
        totp_seed=totp_seed,
        base_url=base_url,
        timeout=args.timeout,
    )


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def _cmd_list_orgs(args: argparse.Namespace) -> int:
    client = _build_client(args)
    orgs = client.list_organizations()
    json.dump(orgs, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def _cmd_list_domains(args: argparse.Namespace) -> int:
    client = _build_client(args)
    for domain in client.list_domains():
        print(domain)
    return 0


def _cmd_check_domain(args: argparse.Namespace) -> int:
    client = _build_client(args)
    result = client.check_email_domain(args.email)
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if (result["is_valid"] and result["is_prevalidated"]) else 1


def _cmd_issue(args: argparse.Namespace) -> int:
    client = _build_client(args)
    csr_pem = Path(args.csr).read_text()
    certs = client.bulk_smime_certificate(
        csr=csr_pem,
        emails=args.email,
        certificate_type=CertificateType(args.cert_type),
        given_name=args.given_name,
        surname=args.surname,
        org_id=args.org_id,
    )
    if args.out:
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        for i, pem in enumerate(certs):
            name = "leaf.pem" if i == 0 else f"chain-{i}.pem"
            (out_dir / name).write_text(pem)
            print(f"wrote {out_dir / name}")
    else:
        for pem in certs:
            sys.stdout.write(pem)
            if not pem.endswith("\n"):
                sys.stdout.write("\n")
    return 0


def _cmd_smoke(args: argparse.Namespace) -> int:
    client = _build_client(args)
    try:
        result = run_staging_smoke(
            client,
            email=args.email,
            first_name=args.first_name,
            last_name=args.last_name,
            org_id=args.org_id,
        )
    except APIError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(format_report(result))
    if args.save_cert_dir:
        save_to = Path(args.save_cert_dir)
        save_to.mkdir(parents=True, exist_ok=True)
        for name, issuance in (
            ("email_only", result.email_only),
            ("natural_legal_lcp", result.natural_legal_lcp),
        ):
            if issuance.pem is not None:
                out = save_to / f"harica_{name}.pem"
                out.write_text(issuance.pem)
                print(f"wrote {out}")
    return 0 if result.passed else 1


# ---------------------------------------------------------------------------
# Parser plumbing
# ---------------------------------------------------------------------------


def _make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="harica-smime",
        description="HARICA S/MIME REST client CLI.",
    )
    p.add_argument("--base-url", help="HARICA base URL (env: HARICA_BASE_URL).")
    p.add_argument("--username", help="API user email (env: HARICA_USERNAME).")
    p.add_argument("--password", help="API password (env: HARICA_PASSWORD).")
    p.add_argument(
        "--totp-seed",
        help="Base32 TOTP seed for 2FA (env: HARICA_TOTP_SEED).",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="Per-request timeout in seconds (default: 60).",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging.")

    sp = p.add_subparsers(dest="command", required=True)

    sp_orgs = sp.add_parser("list-orgs", help="Print organizations as JSON.")
    sp_orgs.set_defaults(func=_cmd_list_orgs)

    sp_domains = sp.add_parser(
        "list-domains", help="Print validated domains, one per line."
    )
    sp_domains.set_defaults(func=_cmd_list_domains)

    sp_check = sp.add_parser(
        "check-domain", help="Check whether an email's domain is HARICA-validated."
    )
    sp_check.add_argument("email")
    sp_check.set_defaults(func=_cmd_check_domain)

    sp_issue = sp.add_parser("issue", help="Issue an S/MIME certificate.")
    sp_issue.add_argument("--csr", required=True, help="Path to PEM CSR.")
    sp_issue.add_argument(
        "--email",
        action="append",
        required=True,
        help="Recipient email; repeat for up to 3 addresses.",
    )
    sp_issue.add_argument(
        "--cert-type",
        choices=[ct.value for ct in CertificateType],
        default=CertificateType.EMAIL_ONLY.value,
    )
    sp_issue.add_argument("--given-name")
    sp_issue.add_argument("--surname")
    sp_issue.add_argument("--org-id")
    sp_issue.add_argument(
        "--out", help="Directory to write cert PEMs; prints to stdout if omitted."
    )
    sp_issue.set_defaults(func=_cmd_issue)

    sp_smoke = sp.add_parser(
        "smoke",
        help=("Issue both cert types against staging and verify subject-DN contract."),
    )
    sp_smoke.add_argument("--email", required=True)
    sp_smoke.add_argument("--first-name", default="Harica")
    sp_smoke.add_argument("--last-name", default="Teststaging")
    sp_smoke.add_argument("--org-id")
    sp_smoke.add_argument("--save-cert-dir")
    sp_smoke.set_defaults(func=_cmd_smoke)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _make_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    try:
        return args.func(args)
    except APIError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
