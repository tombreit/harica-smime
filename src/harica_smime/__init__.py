"""harica_smime: HARICA S/MIME REST client library."""

from harica_smime._validators import validate_certificate_name
from harica_smime.client import Client, DomainCheckResult
from harica_smime.enums import CertificateType
from harica_smime.errors import (
    APIError,
    AuthError,
    DomainValidationError,
    HTTPError,
)

__all__ = [
    "Client",
    "DomainCheckResult",
    "CertificateType",
    "APIError",
    "AuthError",
    "DomainValidationError",
    "HTTPError",
    "validate_certificate_name",
    "__version__",
]

__version__ = "0.1.0"
