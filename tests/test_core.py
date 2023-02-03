"""Tests."""
import pytest


def test_uuid() -> None:
    """Test Uuid."""
    import base64
    from os import urandom
    from time import sleep
    from uuid import UUID, uuid4
    from webuuid import Uuid, UuidBase64, UuidBase64Url

    uuid = Uuid()

    # UUID fields
    assert UUID(bytes=Uuid()).version == 7
    assert UUID(bytes=Uuid()).version == Uuid().version
    assert Uuid(uuid4()).version == 4
    assert UUID(bytes=Uuid()).variant == uuid4().variant

    # Comparisons
    assert Uuid() != Uuid()
    assert uuid == uuid
    assert uuid == Uuid(uuid)
    value1 = Uuid()
    sleep(0.001)
    value2 = Uuid()
    assert value1 < value2
    assert value1 <= value2
    assert value2 > value1
    assert value2 >= value1

    # Bytes form
    assert len(uuid) == 16
    assert uuid == bytes(uuid)
    assert uuid == memoryview(uuid)
    assert uuid == bytearray(uuid)
    assert Uuid(urandom(16))
    assert hash(uuid) == hash(bytes(uuid))

    with pytest.raises(ValueError):
        assert Uuid(b"X" * 17)

    with pytest.raises(ValueError):
        assert Uuid(b"X" * 15)

    assert Uuid(bytes(Uuid(uuid))) == uuid
    assert Uuid(memoryview(Uuid(uuid))) == uuid
    assert Uuid(bytearray(Uuid(uuid))) == uuid
    assert Uuid(int.from_bytes(uuid, "big")) == uuid
    assert isinstance(Uuid() + Uuid(), bytes)

    # int form
    assert int(uuid) == UUID(bytes=uuid).int

    # "Short UUID" string form
    assert uuid == Uuid(str(uuid))
    assert uuid == Uuid(str(uuid).lower())
    assert len(str(uuid)) == 26
    assert repr(uuid) == f"Uuid({uuid})"
    assert uuid.decode() == str(uuid)
    assert uuid == str(uuid)

    with pytest.raises(ValueError):
        assert Uuid(str(uuid)[:-1] + "#")

    # Standard library UUID
    assert uuid.hex() == UUID(bytes=uuid).hex
    assert uuid.standard_hex() == str(UUID(bytes=uuid))
    assert uuid.urn == UUID(bytes=uuid).urn

    std_uuid = uuid4()
    assert Uuid(std_uuid) == std_uuid.bytes
    assert Uuid(str(std_uuid)) == std_uuid.bytes

    # New UUID from hash
    data = urandom(256)
    assert Uuid.from_hash(data) == Uuid.from_hash(data)
    assert UUID(bytes=Uuid.from_hash(data)).version == 8

    # New UUID with node part
    node = urandom(8)
    assert Uuid(node=node).node == node
    assert UUID(bytes=Uuid(node=urandom(8))).version == 8

    with pytest.raises(ValueError):
        Uuid(node=bytes.fromhex("FE"))

    # Encode to various formats
    assert base64.b32decode(uuid.base32(padding=True).encode()) == uuid
    assert base64.b32decode(uuid.base32().encode() + b"======") == uuid
    assert base64.b64decode(uuid.base64(padding=True).encode()) == uuid
    assert base64.b64decode(uuid.base64().encode() + b"==") == uuid
    assert base64.urlsafe_b64decode(uuid.base64url(padding=True).encode()) == uuid
    assert base64.urlsafe_b64decode(uuid.base64url().encode() + b"==") == uuid
    assert bytes.fromhex(uuid.hex()) == uuid
    assert UUID(uuid.standard_hex()) == uuid

    # Decode from various formats
    assert Uuid(base64.b32encode(uuid).rstrip(b"=").decode()) == uuid
    assert Uuid(base64.b32encode(uuid).decode()) == uuid
    assert Uuid(base64.urlsafe_b64encode(uuid).rstrip(b"=").decode()) == uuid
    assert Uuid(base64.urlsafe_b64encode(uuid).decode()) == uuid
    assert Uuid(base64.b64encode(uuid).rstrip(b"=").decode()) == uuid
    assert Uuid(base64.b64encode(uuid).decode()) == uuid
    assert Uuid(r"\x" + uuid.hex()) == uuid
    assert Uuid(str(UUID(bytes=uuid))) == uuid
    assert Uuid("{%s}" % str(UUID(bytes=uuid))) == uuid
    assert Uuid(uuid.hex()) == uuid

    # Subclasses
    assert UuidBase64(uuid).decode() == uuid.base64()
    assert UuidBase64Url(uuid).decode() == uuid.base64url()


def test_pydantic() -> None:
    """Test usage with Pydantic model."""
    try:
        from pydantic import BaseModel, Field
    except ImportError:
        pytest.skip("Pydantic not installed.")

    from uuid import UUID
    from webuuid import Uuid

    class TestModel(BaseModel):
        """Test Pydantic model."""

        value: Uuid = Field(default_factory=Uuid)

    uuid = Uuid()
    assert TestModel(value=str(uuid)).value == uuid
    assert TestModel(value=uuid).value == uuid
    assert TestModel(value=bytes(uuid)).value == uuid
    assert TestModel(value=UUID(bytes=uuid)).value == uuid

    # Default field value
    assert TestModel().value != uuid

    # Schema
    assert "A2B3C4D5E6F7G2H3I4J5K6L7M2" in TestModel.schema_json()
