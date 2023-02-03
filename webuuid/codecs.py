"""Codecs."""
from base64 import (
    b32encode as _b32encode,
    b32decode as _b32decode,
    b64encode as _b64encode,
    urlsafe_b64decode as _urlsafe_b64decode,
    urlsafe_b64encode as _urlsafe_b64encode,
)
from binascii import Error as _BinasciiError
from typing import Any as _Any


def base32_nopadding_decode(value: str) -> bytes:
    """RFC-4648 Base 32 no-padding decoder.

    Args:
        value: String representation of an existing UUID.
    """
    return _b32decode(value.encode().upper() + b"======")


def base32_decode(value: str) -> bytes:
    """RFC-4648 Base 32 decoder.

    Args:
        value: String representation of an existing UUID.
    """
    return _b32decode(value.encode().upper())


def base64_nopadding_decode(value: str) -> bytes:
    """RFC-4648 Base 64 no-padding decoder.

    Support both standard and URL safe alphabets.

    Args:
        value: String representation of an existing UUID.
    """
    return _urlsafe_b64decode(value.encode() + b"==")


def base64_decode(value: str) -> bytes:
    """RFC-4648 Base 64 decoder.

    Support both standard and URL safe alphabets.

    Args:
        value: String representation of an existing UUID.
    """
    return _urlsafe_b64decode(value.encode())


def hex_decode(value: str) -> bytes:
    r"""Hexadecimal decoder.

    Support common hexadecimal and UUID Hex formats like:
    "00000000-0000-0000-0000-000000000000", "{00000000-0000-0000-0000-000000000000}",
    "00000000000000000000000000000000", "\x00000000000000000000000000000000"

    Args:
        value: String representation of an existing UUID.
    """
    return bytes.fromhex(value.strip(r"\x{}").replace("-", ""))


def base32_or_hex_decode(value: str) -> bytes:
    """RFC-4648 Base 32 or hexadecimal decoder.

    Args:
        value: String representation of an existing UUID.
    """
    try:
        return base32_decode(value)
    except _BinasciiError:
        return hex_decode(value)


def standard_hex_encode(value: bytes, *_: _Any) -> str:
    """Encode in standard UUID hex format -"00000000-0000-0000-0000-000000000000").

    Args:
        value: UUID bytes value.

    Returns:
        UUID String representation.
    """
    h = value.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def base32_encode(
    value: bytes, encoding: str = "utf-8", errors: str = "strict", padding: bool = False
) -> str:
    """Encode as RFC-4648 base32 string.

    Args:
        value: Value to encode.
        encoding: Encoding.
        errors: Encoding error handling.
        padding: If True, include padding.

    Returns:
        UUID String representation.
    """
    encoded = _b32encode(value).decode(encoding, errors)
    if padding:
        return encoded
    return encoded[:-6]


def base64_encode(
    value: bytes, encoding: str = "utf-8", errors: str = "strict", padding: bool = False
) -> str:
    """Encode as RFC-4648 base64 string.

    Args:
        value: Value to encode.
        encoding: Encoding.
        errors: Encoding error handling.
        padding: If True, include padding.

    Returns:
        UUID String representation.
    """
    encoded = _b64encode(value).decode(encoding, errors)
    if padding:
        return encoded
    return encoded[:-2]


def base64url_encode(
    value: bytes, encoding: str = "utf-8", errors: str = "strict", padding: bool = False
) -> str:
    """Encode as RFC-4648 base64 URL safe string.

    Args:
        value: Value to encode.
        encoding: Encoding.
        errors: Encoding error handling.
        padding: If True, include padding.

    Returns:
        UUID String representation.
    """
    encoded = _urlsafe_b64encode(value).decode(encoding, errors)
    if padding:
        return encoded
    return encoded[:-2]
