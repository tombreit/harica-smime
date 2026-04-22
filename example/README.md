# harica-smime Django demo

A single-page Django project that showcases [`harica-smime`](../README.md) end
to end: browser-side keypair + CSR generation, server-side issuance, and
browser-side PKCS#12 assembly. Runs with zero HARICA credentials by default.

## Run it

```bash
cd example
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python manage.py runserver
```

Open <http://127.0.0.1:8000/>, fill the form, click the button, and the
browser will download a `.p12`. Inspect it with:

```bash
openssl pkcs12 -info -in alice_example.org.p12 -nokeys -passin pass:changeit
```

## Modes

**Stub mode (default, no credentials required).**
The server signs your CSR with a throwaway in-process CA. The `.p12` will not
be trusted by any mail client — the point is to exercise the round-trip and
the privacy contract (keypair + CSR + PKCS#12 all assembled in the browser).

**Staging mode.**
Set the environment variables below and restart `runserver`. CSRs are then
forwarded to HARICA's staging endpoint and signed for real.

```bash
export HARICA_USERNAME=api-user@example.org
export HARICA_PASSWORD=...
export HARICA_TOTP_SEED=BASE32SEED
# optional — defaults to https://cm-stg.harica.gr
export HARICA_BASE_URL=https://cm-stg.harica.gr
python manage.py runserver
```

The UI shows which mode is active in a banner at the top of the page.

## What to look at

The demo is deliberately small. The interesting files are:

- [`demo/views.py`](demo/views.py) — the `submit_csr` view, which branches
  between `Client.bulk_smime_certificate(...)` and the local stub signer.
- [`demo/templates/index.html`](demo/templates/demo/index.html) — the
  JavaScript driver that calls `haricaSmime.generateKeypair`,
  `buildCsrPem`, and `buildPkcs12Bytes` from the package's bundled JS assets.

Open your browser's DevTools → Network tab while submitting. The POST body
contains the CSR only — no private key, no PKCS#12 password. That's the
privacy contract, visible to the reader.

## Caveats

- `DEBUG = True`, `ALLOWED_HOSTS = ["*"]`, a hard-coded `SECRET_KEY`, and no
  database. Do not deploy this.
- Tailwind is loaded from its Play CDN.
