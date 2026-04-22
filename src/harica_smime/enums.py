"""Enum types for harica_smime."""

from enum import Enum


class CertificateType(str, Enum):
    """HARICA S/MIME certificate profile.

    - ``EMAIL_ONLY``: subject DN contains only the email address.
    - ``NATURAL_LEGAL_LCP``: IV+OV profile; subject DN contains the person's
      given name, surname, and common name in addition to the email address.
      Requires the HARICA organization to be provisioned for IV+OV.
    """

    EMAIL_ONLY = "email_only"
    NATURAL_LEGAL_LCP = "natural_legal_lcp"
