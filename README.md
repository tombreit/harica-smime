# harica-smime

`harica-smime` is a Python client for issuing S/MIME email-signing certificates
through HARICA's REST API. It is built around a privacy contract: the keypair is
generated in the user's browser, so your server only ever handles the CSR and
the signed certificate — the private key and PKCS#12 password never leave the
user's device.

## About

- **Core library** (`harica_smime.*`) — the HARICA REST client and its
  supporting types: `Client`, `CertificateType`, the exception hierarchy,
  `validate_certificate_name`.
- **Extras** (`harica_smime.contrib.*`) — optional add-ons that don't belong
  in the core API: the `harica-smime` CLI (`contrib.cli`), the staging
  smoke-test harness (`contrib.smoke`), and a Django app that ships the
  browser-side JavaScript for client-side keypair/CSR generation
  (`contrib.django`).
- **Demo application** — A single-page Django project,
  see [`example/`](./example/README.md).

## Requirements

- Python 3.11+
- Runtime dependencies: [`cryptography`](https://github.com/pyca/cryptography/)
  only (will be pulled in by the `pip` installation, see below)
- [HARICA](https://harica.gr/) API credentials:
  - HARICA username/password
  - HARICA 2FA TOTP seed

## Privacy contract

This library is designed to keep the user's **private key and PKCS#12 import
password on the user's device**. The included JavaScript primitives (shipped
by `harica_smime.contrib.django`) run in the user's browser, generate the
keypair locally, and return only the CSR (public half) for submission to your
server. Your server-side code then calls `Client.bulk_smime_certificate(csr,
...)` with that pre-generated CSR.

Do **not** generate CSRs server-side for user-facing flows — that defeats the
property.

## Install

```bash
pip install harica-smime@git+https://github.com/tombreit/harica-smime.git
```

## Quickstart (server-side)

```python
from harica_smime import Client, CertificateType

client = Client(
    username="api-user@example.org",
    password="...",
    totp_seed="BASE32SEED",
    base_url=Client.STAGING_BASE_URL,
)
certs = client.bulk_smime_certificate(
    csr=pem_csr_from_browser,
    emails=["user@example.org"],
    certificate_type=CertificateType.NATURAL_LEGAL_LCP,
    given_name="Alice",
    surname="Example",
)
# certs[0] is the leaf cert (PEM), certs[1:] is the chain.
```

## Quickstart (CLI)

```bash
export HARICA_USERNAME=... HARICA_PASSWORD=... HARICA_TOTP_SEED=...
harica-smime --base-url https://cm-stg.harica.gr list-orgs
harica-smime --base-url https://cm-stg.harica.gr check-domain user@example.org
harica-smime --base-url https://cm-stg.harica.gr smoke \
    --email user@example.org --first-name Alice --last-name Example
```

## Using the `contrib` extras

Everything under `harica_smime.contrib.*` is optional. Import only the pieces
you need — the core client never depends on them.

### `contrib.cli` — command-line entry point

Installed as the `harica-smime` script (see [Quickstart (CLI)](#quickstart-cli)).
The same entry point is reachable as `python -m harica_smime`. Subcommands:
`list-orgs`, `list-domains`, `check-domain`, `issue`, `smoke`.

### `contrib.smoke` — staging issuance harness

Exercises the full issuance flow (both certificate types) against a live
HARICA endpoint and inspects each leaf's subject DN. Use it from Python to
build your own management command or admin test page:

```python
from harica_smime import Client
from harica_smime.contrib.smoke import run_staging_smoke, format_report

client = Client(
    username="api-user@example.org",
    password="...",
    totp_seed="BASE32SEED",
    base_url=Client.STAGING_BASE_URL,
)
result = run_staging_smoke(
    client,
    email="alice@example.org",
    first_name="Alice",
    last_name="Example",
)
print(format_report(result))
if not result.passed:
    raise SystemExit(1)
```

`SmokeResult.passed` is `True` only if both cert types issue **and** the
`natural_legal_lcp` leaf carries `givenName` + `surname`. The function does
not swallow login or network errors — it raises those; only per-issuance
failures are packed into the returned `SmokeResult`.

### `contrib.django` — Django app with browser-side JavaScript assets

A minimal Django app that ships vendored `forge.min.js` plus a thin wrapper
(`harica-smime-crypto.js`) for generating the keypair, CSR, and PKCS#12
**in the browser**. No models, views, URLs, or templates — the UI is yours
to build. See [Django integration](#django-integration) below for the full
walkthrough.

## Django integration

The flow: the **browser** generates a keypair and CSR; the **server**
forwards the CSR to HARICA and returns the signed cert; the **browser**
assembles the PKCS#12. Private key and PKCS#12 password never leave the
user's device.

### 1. Install and register the app

```bash
pip install harica-smime[django]@git+https://github.com/tombreit/harica-smime.git
```

```python
# settings.py
INSTALLED_APPS = [
    # ...
    "harica_smime.contrib.django",
]
```

The app's label is `harica_smime`. Django's `AppDirectoriesFinder` picks up the
bundled static files under the `harica_smime/` prefix.

### 2. Load the JavaScript in your template

```django
{% load static %}
<script src="{% static 'harica_smime/forge.min.js' %}"></script>
<script src="{% static 'harica_smime/harica-smime-crypto.js' %}"></script>
```

### 3. Generate the keypair and CSR in the browser

```js
const keys = haricaSmime.generateKeypair(2048);
// { publicKey: <forge publicKey>, privateKey: <forge privateKey> }

const csrPem = haricaSmime.buildCsrPem({
  publicKey:  keys.publicKey,
  privateKey: keys.privateKey,
  commonName: "Alice Example",
  email:      "alice@example.org",
});
// -----BEGIN CERTIFICATE REQUEST-----\n...-----END CERTIFICATE REQUEST-----\n
```

Keep `keys.privateKey` in a JavaScript variable only. **Do not** POST it to
your server — that would break the privacy contract. POST only `csrPem`.

### 4. Forward the CSR to HARICA from your server view

```python
# views.py
from harica_smime import APIError, Client, CertificateType

def submit_csr(request):
    client = Client(
        username=settings.HARICA_USERNAME,
        password=settings.HARICA_PASSWORD,
        totp_seed=settings.HARICA_TOTP_SEED,
        base_url=settings.HARICA_BASE_URL,
    )
    try:
        certs = client.bulk_smime_certificate(
            csr=request.POST["csr"],
            emails=[request.user.email],
            certificate_type=CertificateType.NATURAL_LEGAL_LCP,
            given_name=request.user.first_name,
            surname=request.user.last_name,
        )
    except APIError as exc:
        return JsonResponse({"error": str(exc)}, status=502)
    return JsonResponse({"certs": certs})  # leaf + chain, PEM
```

### 5. Assemble the PKCS#12 in the browser and prompt for download

With the signed cert PEM returned from step 4 and the in-memory
`keys.privateKey` from step 3:

```js
const p12Bytes = haricaSmime.buildPkcs12Bytes({
  certPem:      certPem,                   // from the server response
  privateKey:   keys.privateKey,           // still in JS memory, never sent
  password:     userChosenP12Password,     // collected in the browser
  friendlyName: "Alice Example",
});
// Binary string — wrap in a Blob, trigger a download, then drop
// keys.privateKey from memory.
```

The PKCS#12 password is user-chosen in the browser and must never reach
your server.

### Optional: staging health check as a management command

`harica_smime.contrib.smoke` works equally well from a Django management
command — useful for periodic monitoring against HARICA staging:

```python
# yourapp/management/commands/harica_staging_smoke.py
from django.core.management.base import BaseCommand
from harica_smime import Client
from harica_smime.contrib.smoke import run_staging_smoke, format_report

class Command(BaseCommand):
    def handle(self, *args, **opts):
        client = Client(...)  # build from Django settings / env
        result = run_staging_smoke(client, email=..., first_name=..., last_name=...)
        self.stdout.write(format_report(result))
        if not result.passed:
            raise SystemExit(1)
```

### Vendored dependency

`forge.min.js` is [node-forge](https://github.com/digitalbazaar/forge), used
under its BSD-3-Clause license. See
`src/harica_smime/contrib/django/static/harica_smime/forge.LICENSE`.

## Links

### Upstream docs

- <https://guides.harica.gr/en/docs/Guides/Email/IV+OV-request/>
- <https://developer.harica.gr/>

### Other clients

- <https://github.com/hm-edu/harica>
- <https://github.com/ConsortiumGARR/tcs-garr>
- <https://gitlab.mpi-klsb.mpg.de/pcernko/tud-cert-harica/>

## License

EUPL-1.2. See [LICENSE](./LICENSE).
