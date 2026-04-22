"""Exception hierarchy for harica_smime.

All client-raised exceptions derive from :class:`APIError`, so callers that
only care about "something went wrong talking to HARICA" can catch the base
class. Callers that want finer discrimination can catch the subclasses.
"""


class APIError(Exception):
    """Base exception for harica_smime.

    Attributes:
        status_code: HTTP status code from the upstream API when applicable,
            otherwise 500 as a placeholder.
    """

    def __init__(self, message: str, status_code: int = 500) -> None:
        super().__init__(message)
        self.status_code = status_code


class AuthError(APIError):
    """Authentication / TOTP failure when logging in to HARICA."""


class HTTPError(APIError):
    """Upstream returned a non-2xx HTTP response."""


class DomainValidationError(APIError):
    """Email domains could not be mapped to a single HARICA organization."""
