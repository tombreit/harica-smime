"""HOTP / TOTP primitives used for HARICA's 2FA login."""

import base64
import hmac
import struct
import time


def hotp(
    *,
    key: str,
    counter: int,
    digits: int = 6,
    digest: str = "sha1",
) -> str:
    """Counter-based HMAC one-time password (RFC 4226)."""
    raw_key = base64.b32decode(key.upper() + "=" * ((8 - len(key)) % 8))
    counter_bytes = struct.pack(">Q", counter)
    mac = hmac.new(raw_key, counter_bytes, digest).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">L", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary)[-digits:].zfill(digits)


def totp(
    *,
    key: str,
    time_step: int = 30,
    digits: int = 6,
    digest: str = "sha1",
    at: float | None = None,
) -> str:
    """Time-based one-time password (RFC 6238).

    ``at`` can be provided to freeze the timestamp (useful for testing).
    """
    now = time.time() if at is None else at
    return hotp(key=key, counter=int(now / time_step), digits=digits, digest=digest)
