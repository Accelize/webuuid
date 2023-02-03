"""WebUUID."""
from __future__ import annotations
from hashlib import blake2b as _blake2b
from secrets import randbits as _randbits
from time import time_ns as _time_ns
from typing import (
    cast as _cast,
    Any as _Any,
    Callable as _Callable,
    Generator as _Generator,
    Type as _Type,
)
from uuid import UUID as _UUID
from webuuid import codecs
from webuuid.codecs import (
    standard_hex_encode as _standard_hex_encode,
    base32_encode as _base32_encode,
    base64url_encode as _base64url_encode,
    base64_encode as _base64_encode,
)


class Uuid(bytes):
    """UUID with base32 string representation."""

    #: Default str encoder for .decode(), str(), repr(), ...
    STR_ENCODER = codecs.base32_encode

    #: Decoders to use based on the input string length
    STR_DECODERS = {
        22: codecs.base64_nopadding_decode,
        24: codecs.base64_decode,
        26: codecs.base32_nopadding_decode,
        32: codecs.base32_or_hex_decode,
    }

    #: Fallback decoder to use if input string length does not match STR_DECODERS
    FALLBACK_STR_DECODER = codecs.hex_decode

    #: Pydantic field schema
    FIELD_SCHEMA = dict(
        minLength=22,
        maxLength=32,
        example="A2B3C4D5E6F7G2H3I4J5K6L7M2",
        description=(
            "RFC 4648 Base32 encoded 16 bytes UUID (Case insensitive, Without padding)."
        ),
        pattern="^[A-Za-z2-7]{26}$",
    )

    def __new__(
        cls: _Type[bytes],
        value: bytes | bytearray | memoryview | int | str | _UUID | None = None,
        node: bytes | bytearray | memoryview | None = None,
    ) -> "Uuid":
        """UUID class instantiation.

        Args:
            value: Binary or string representation of an existing UUID.
                If not specified generates a new UUID.
            node: 64bits binary value to use in place of the end of the random part of
                the UUID. If specified, use UUID version to 8 instead of 7.
        """
        if value is None:
            if node is None:
                rand_a = _randbits(12)
                rand_b = _randbits(62)
                version = 7
            elif len(node) == 8:
                rand_int = int.from_bytes(node, "big")
                rand_a = rand_int >> 62 | (_randbits(10) << 2)
                rand_b = rand_int & 0x3FFFFFFFFFFFFFFF
                version = 8
            else:
                raise ValueError('"node" size must be 64bits.')
            value_int = (_time_ns() // 1000000 & 0xFFFFFFFFFFFF) << 80  # unix_ts_ms
            value_int |= rand_a << 64  # rand_a
            value_int |= rand_b  # rand_b
            value = cls._set_fields(value_int, version).to_bytes(  # type: ignore
                16, "big"
            )
        else:
            if isinstance(value, str):
                try:
                    value = cls.STR_DECODERS.get(  # type: ignore
                        len(value), cls.FALLBACK_STR_DECODER  # type: ignore
                    )(value)
                except ValueError as exception:
                    raise ValueError(f"Invalid UUID: {exception}")
            elif isinstance(value, _UUID):
                value = value.bytes
            elif isinstance(value, int):
                value = value.to_bytes(16, "big")
            if len(value) != 16:  # type: ignore
                raise ValueError(
                    "Invalid UUID: Excepted 16 bytes, received "
                    f"{len(value)} bytes"  # type: ignore
                )
        return _cast(Uuid, bytes.__new__(cls, value))  # type: ignore

    def __str__(self) -> str:
        return self.decode()

    def __int__(self) -> int:
        try:
            return self._int_value  # noqa
        except AttributeError:
            self._int_value: int = int.from_bytes(self, "big")
        return self._int_value

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self})"

    def __eq__(self, other: object) -> bool:
        return bytes.__eq__(self, self._ensure_comparable(other))

    def __ge__(self, other: object) -> bool:
        return bytes.__ge__(self, self._ensure_comparable(other))

    def __gt__(self, other: object) -> bool:
        return bytes.__gt__(self, self._ensure_comparable(other))

    def __le__(self, other: object) -> bool:
        return bytes.__le__(self, self._ensure_comparable(other))

    def __lt__(self, other: object) -> bool:
        return bytes.__lt__(self, self._ensure_comparable(other))

    def __hash__(self) -> int:
        return bytes.__hash__(self)

    @staticmethod
    def _ensure_comparable(value: object) -> "bytes | bytearray | memoryview | Uuid":
        """Ensure value is comparable with UUID.

        Args:
            value: Input value.

        Returns:
            Comparable value.
        """
        if isinstance(value, (bytes, bytearray, memoryview)):
            return value
        return Uuid(value)  # type: ignore

    @staticmethod
    def _set_fields(value: int, version: int = 8) -> int:
        """Insert version and variant fields in UUID.

        Args:
            value: Input 128 bits int.
            version: UUID version.

        Returns:
            Output 128 bits int.
        """
        value &= ~(0xC000 << 48)
        value |= 0x8000 << 48  # variant
        value &= ~(0xF000 << 64)
        value |= version << 76  # version
        return value

    @classmethod
    def __get_validators__(cls) -> _Generator[_Callable[..., _Any], None, None]:
        """Pydantic validators."""
        yield cls._validate

    @classmethod
    def _validate(
        cls, value: "bytes | bytearray | memoryview | int | str | _UUID | Uuid"
    ) -> "Uuid":
        """Ensure the value is UUID.

        Args:
            value: Value.

        Returns:
            UUID.
        """
        if isinstance(value, cls):
            return value
        return cls(value)

    @classmethod
    def __modify_schema__(cls, field_schema: dict[str, _Any]) -> None:
        """Modify Pydantic schema.

        Args:
            field_schema: Pydantic schema.
        """
        field_schema.update(cls.FIELD_SCHEMA)
        try:
            del field_schema["format"]
        except KeyError:
            return

    def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
        """URL safe UUID string representation.

        Args:
            encoding: Encoding.
            errors: Encoding error handling.

        Returns:
            UUID string.
        """
        try:
            return self._str_value  # noqa
        except AttributeError:
            self._str_value: str = self.STR_ENCODER(encoding, errors)
        return self._str_value

    def standard_hex(self) -> str:
        """Returns the UUID as RFC-4122 standard UUID hex string.

        Returns:
            UUID.
        """
        return _standard_hex_encode(self)

    def base32(self, padding: bool = False) -> str:
        """Returns the UUID as RFC-4648 base32 encoded string.

        Args:
            padding: If True, include padding.

        Returns:
            Encoded UUID.
        """
        return _base32_encode(self, padding=padding)

    def base64(self, padding: bool = False) -> str:
        """Returns the UUID as RFC-4648 base64 encoded string.

        Args:
            padding: If True, include padding.

        Returns:
            Encoded UUID.
        """
        return _base64_encode(self, padding=padding)

    def base64url(self, padding: bool = False) -> str:
        """Returns the UUID as RFC-4648 base64 URL safe encoded string.

        Args:
            padding: If True, include padding.

        Returns:
            Encoded UUID.
        """
        return _base64url_encode(self, padding=padding)

    @classmethod
    def from_hash(cls, value: bytes | bytearray | memoryview) -> "Uuid":
        """Create a UUID by hashing a value.

        Args:
            value: Value to hash.

        Returns:
            Uuid.
        """
        return cls(
            cls._set_fields(
                int.from_bytes(_blake2b(value, digest_size=16).digest(), "big")
            )
        )

    @property
    def node(self) -> bytes:
        """Node part of the UUID (64 last bits, ignoring variant and version fields).

        Returns:
            node.
        """
        return (
            self.__int__() & 0x3FFFFFFFFFFFFFFF | ((self.__int__() >> 64) & 0x3) << 62
        ).to_bytes(8, "big")

    @property
    def urn(self) -> str:
        """Returns the UUID as URN.

        Returns:
            URN.
        """
        return f"urn:uuid:{self.standard_hex()}"

    @property
    def version(self) -> int:
        """Returns UUID version.

        Returns:
            UUID version.
        """
        return int((self.__int__() >> 76) & 0xF)


class UuidBase64(Uuid):
    """UUID with base64url string representation."""

    STR_ENCODER = codecs.base64_encode
    FIELD_SCHEMA = dict(
        minLength=22,
        maxLength=32,
        example="ThrKWkTKz86eEFNhzyXZTg",
        description="RFC-4648 Base64 encoded 16 bytes UUID (Without padding).",
        pattern="^[A-Za-z0-9+/]{22}$",
    )


class UuidBase64Url(Uuid):
    """UUID with base64url string representation."""

    STR_ENCODER = codecs.base64url_encode
    FIELD_SCHEMA = dict(
        minLength=22,
        maxLength=32,
        example="ThrKWkTKz86eEFNhzyXZTg",
        description="RFC-4648 Base64 URL safe encoded 16 bytes UUID (Without padding).",
        pattern="^[A-Za-z0-9_-]{22}$",
    )
