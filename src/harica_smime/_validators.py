"""Pure validators and domain helpers."""


def is_subdomain(subdomain: str, domain: str) -> bool:
    """Return True if ``subdomain`` equals ``domain`` or is a descendant of it."""
    return subdomain == domain or subdomain.endswith("." + domain)


def validate_certificate_name(value: str) -> str:
    """Validate a personal-name field for S/MIME certificate compatibility.

    X.509 ``commonName`` is limited to 64 characters, and HARICA's bulk-CSV
    ingest rejects parentheses in the ``FriendlyName`` field. We further
    constrain to printable ASCII to avoid surprises in downstream parsers.

    Raises :class:`ValueError` on violation. Returns ``value`` unchanged on
    success. An empty ``value`` is accepted (the caller decides whether the
    field is required).
    """
    if not value:
        return value

    if len(value) > 64:
        raise ValueError("Name must be 64 characters or less.")

    allowed = set(range(32, 127)) - {ord("("), ord(")")}
    if not all(ord(c) in allowed for c in value):
        raise ValueError(
            "Name must contain only printable ASCII characters "
            "(parentheses not allowed)."
        )
    return value
