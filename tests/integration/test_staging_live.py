"""Live smoke test against the real HARICA staging endpoint.

Skipped unless ``HARICA_USERNAME``, ``HARICA_PASSWORD``, ``HARICA_TOTP_SEED``,
and ``HARICA_SMOKE_EMAIL`` are all set in the environment. Run explicitly
with:

    HARICA_USERNAME=...  HARICA_PASSWORD=...  HARICA_TOTP_SEED=...  \
    HARICA_SMOKE_EMAIL=alice@example.org \
        pytest tests/integration -v

Do NOT include this test in the default CI run — it talks to a live API.
"""

from __future__ import annotations

import os

import pytest

from harica_smime import Client
from harica_smime.contrib.smoke import run_staging_smoke


REQUIRED_ENV_VARS = (
    "HARICA_USERNAME",
    "HARICA_PASSWORD",
    "HARICA_TOTP_SEED",
    "HARICA_SMOKE_EMAIL",
)


@pytest.fixture
def live_creds() -> dict[str, str]:
    missing = [v for v in REQUIRED_ENV_VARS if not os.environ.get(v)]
    if missing:
        pytest.skip(f"live HARICA creds missing: {', '.join(missing)}")
    return {v: os.environ[v] for v in REQUIRED_ENV_VARS}


def test_staging_smoke(live_creds):
    base_url = os.environ.get("HARICA_BASE_URL", Client.STAGING_BASE_URL)
    first_name = os.environ.get("HARICA_SMOKE_FIRST_NAME", "Smoke")
    last_name = os.environ.get("HARICA_SMOKE_LAST_NAME", "Test")

    client = Client(
        username=live_creds["HARICA_USERNAME"],
        password=live_creds["HARICA_PASSWORD"],
        totp_seed=live_creds["HARICA_TOTP_SEED"],
        base_url=base_url,
        timeout=120.0,
    )

    result = run_staging_smoke(
        client,
        email=live_creds["HARICA_SMOKE_EMAIL"],
        first_name=first_name,
        last_name=last_name,
    )
    assert result.email_only.ok, result.email_only.error
    assert result.natural_legal_lcp.ok, result.natural_legal_lcp.error
    s = result.natural_legal_lcp.summary
    assert s is not None
    assert s.given_name, "natural_legal_lcp leaf missing GivenName"
    assert s.surname, "natural_legal_lcp leaf missing Surname"
    assert s.email, "natural_legal_lcp leaf missing emailAddress"
