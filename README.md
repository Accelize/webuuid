![Tests](https://github.com/JGoutin/webuuid/workflows/tests/badge.svg)
[![codecov](https://codecov.io/gh/JGoutin/webuuid/branch/main/graph/badge.svg?token=mgtUTV7PwM)](https://codecov.io/gh/JGoutin/webuuid)
[![PyPI](https://img.shields.io/pypi/v/webuuid.svg)](https://pypi.org/project/webuuid)

# WebUuid: Optimized UUID primary key for web services

## Why using this library ?

This library as been created to help solve the following question: What is the best
format for ID in a web service and its database ?

The library trie to answer this question using modern UUID and short user-friendly 
string representation.

### Why using UUID instead of auto-incrementing integer with SQL databases ?

Traditionally, auto-incrementing integer are used as Primary keys in databases.
But, UUID are also a good candidate for the following reasons:

Pros:

* **Offline generation:** Auto-incrementing require to call the database first and 
  insert a row to generate the ID value. With UUID, the ID can be generated everywhere,
  and eventually write in the database later if required.
* **Security/Privacy:** UUID is not guessable. If an integer is used as ID and an API 
  allow to query using this ID anyone can easily try to guess ID values to list, count 
  or get some data. This can lead to data leak that can be a security or privacy issue.
* **Uniqueness & collision resistance:** When running a service on a scalable 
  environment (With multiple concurrent servers) or on multiple environments with data 
  that may need to be merged, using auto-incrementing integer will likely lead to 
  collisions (Or complex setup/data reconciliation to avoid it).
  UUID are optimized for almost perfect uniqueness (see below), so there is not such 
  problem like this with them.

Cons:

* **Storage size:** Auto-incrementing integer are smallest in database 
  (4 or 8 bytes instead of 16 bytes).

Fixed cons:

* **SQL Insert performance:** UUID1 to UUID5 are not time sortable, so inserting them in
  a large table lead to a performance penalty.
  Fortunately, with RFC-4122(rev1), there is now UUID6 and UUID7 that are time 
  sortable. This library use UUID7 by default, or UUID8 with sortable timestamp when 
  used with node.
* **Privacy**: UUID1 uses MAC address in its "node" part, this have privacy issue.
  There is no privacy issue with UUID7 that rely on random data instead.

### Why using "short" UUID string format instead of common UUID format ?

The RFC-4122 provides a standard string representation format 
(like `f81d4fae-7dec-11d0-a765-00a0c91e6bf6`) based on hexadecimal representation.

But, there are many other way to encode some bytes in strings, and it is easy to convert
the UUID between all of its formats if required.

#### Popularity and compatibility

RFC-4648 base64 and base32 are very common bytes encoding codecs and are easily 
available in many programming languages and common libraries.

There is some alternate base32 like codecs, but not standardized and not as common,
we'll not use them here.

#### Size 

The RFC-4122 standard UUID string representation is 36 characters length 
(or eventually 32 characters length if keeping only the hexadecimal part)

The equivalent size for RFC-4648 base32 is 26 characters (-27%) and 22 characters (-38%)
for RFC-4648 base64 (without padding in both cases). The storage is more efficient than
hexadecimal. This allows to reduce the traffic in web service requests.

#### User-friendliness

The main advantage of the RFC-4122 format is that it is easy to read the internal
UUID bytes format in it. But, in practices, users don't need to know that the used UUID 
is an UUID7 or 8. So this is not relevant in the use case of a web service.

To be user-friendly an ID should be easy to read, compare and copy by the user 
(Not only with copy/paste).

Base32 is case-insensitive and characters that can be confused are not used in its 
alphabet, this make it more user-friendly than base64. The reduced size also improve 
user-friendliness in comparison with hexadecimal notation. So base32 is a good 
compromise.

### About uniqueness

Since UUID7 as a fixed number of possible values and use a random part, there is still
a very low statistical chance that two generated UUID are identical.
This represents 1/18889465931478580854784 chance to have two identical UUID, 
and that apply only for a period of 1 millisecond. 

This can be managed by:

* EASY SOLUTION: Adding a "unique" clause in database that will raise an error when
  trying to insert the duplicated UUID row.
* MEDIUM SOLUTION: In addition of the previous solution, the application code may 
 handle this case and retry with another ID if a duplicate is detected.
* MISSION CRITICAL SOLUTION: Using UUID8 with node and ensure this node is unique in 
  your application.

## Features:

 * Optimized for database use (Size and performance).
 * Short and user-friendly string representation (With many options).
 * Possibility to use a custom "node" part to help guarantee uniqueness in mission 
   critical application. 
 * Possibility to import a UUID from any 16 bytes length binary in many format and types
  (`bytes`, `int`, `str`, `uuid.UUID`, ...).
 * Possibility to create UUID from a hash to help with deduplication.
 * Included Pydantic support.
 * Fully typped.
 * No external dependencies and pure Python.
 * Easy subclassing.

## Installation

WebUuid is available on PyPI, so it can be installed like any other Python package.

Example with Pip:
```bash
pip install webuuid
```

WebUuid does not require any external dependency and is a pure Python library.

## Usage

### UUID generation

By default, is the class is used without argument, a new UUID7 is generated:

```python
import webuuid


webuuid.Uuid()
```

The class can also be loaded from any 16 bytes length object or its representation as 
source:

```python
import base64
import os
import webuuid


# Using byte-like objects as source
bytes_obj = os.urandom(16)
webuuid.Uuid(bytes_obj)

memoryview_obj = memoryview(bytes_obj)
webuuid.Uuid(memoryview_obj)

bytearray_obj = bytearray(bytes_obj)
webuuid.Uuid(bytearray_obj)

# Using int as source
int_obj = int.from_bytes(bytes_obj, "big")
webuuid.Uuid(int_obj)

# Using base64/base32/hexadecimal str representations
base32_obj = base64.b32encode(bytes_obj).decode()
webuuid.Uuid(base32_obj)

base64_obj = base64.b64encode(bytes_obj).decode()
webuuid.Uuid(base64_obj)

base64url_obj = base64.urlsafe_b64encode(bytes_obj).decode()
webuuid.Uuid(base64url_obj)

hex_obj = bytes_obj.hex()
webuuid.Uuid(hex_obj)

# Using base64/base32 str representations without padding
webuuid.Uuid(base32_obj.rstrip("="))
webuuid.Uuid(base64_obj.rstrip("="))
webuuid.Uuid(base64url_obj.rstrip("="))
```

A standard library `uuid.UUID` can also be used as source:

```python
import uuid
import webuuid


stdlib_uuid = uuid.uuid4()

# Using standard UUID as source
uuid_obj = webuuid.Uuid(stdlib_uuid)
webuuid.Uuid(str(stdlib_uuid))

# Going back to standard library UUID
uuid.UUID(bytes=uuid_obj)
```

#### UUID with custom node

It is also possible to generate a new UUID with a custom "node". This is mainly be 
useful if you do not want relly entirely on randomness to improve the collision 
resistance.
In this case the node need be unique in all your application and may be 
generated/validated against a centralized registry or using a base value that is unique
by design (Example: in a Cloud environment, server/instance ID and process ID).

In the case, the first 64 bits of the UUID are generated normally 
(With 48 bits of timestamp and 10 random bits), the 64 endings bytes (Ignoring version 
and variant fields) are the custom node.

```python
import webuuid
import os


# Using a random value as node
node = urandom(8)

# Generation from node
my_uuid = webuuid.Uuid(node=node)

# The node can be accessed using the following property
my_uuid.node
```

In the case, the generated UUID wil be an UUID8 instead of an UUID7.

#### UUID from hash

It is possible to generate a UUID using the hash of a byte-like input data. This can be 
useful for tables that need deduplication on row IDs.

In this case, like any hash, the UUID is always the same for the same input data.
There is no timestamp in the UUID, so it is not time sortable and can have a negative 
impact on the database performance on INSERT in large tables.

```python
import webuuid
import json


data = json.dumps({"key": "value"}).encode()
my_uuid = webuuid.Uuid.from_hash(data)
```

In the case, the generated UUID will be an UUID8 instead of an UUID7.

The hash function used is `blake2b`.

### UUID class features

The `webuuid.Uuid` class is a subclass of `bytes` and supports all the bytes objects
standards features with the following changes:

* `webuuid.Uuid.decode()` returns an encoded `str` representation using the
  base32 encoding (By default, but can be easily changed) instead of the classical UTF-8
  encoding.
* Using `str()` on `webuuid.Uuid` objects returns the same result as 
  `webuuid.Uuid.decode()`.
* `webuuid.Uuid` can be compared with other `webuuid.Uuid` or byte-like objects but also
  with any `str`, `uuid.UUID` or `int` that can be used as input with `webuuid.Uuid`
  directly.
* `int()` can be used directly  on `webuuid.Uuid` objects. 

In addition to bytes features, the class provides some methods to convert it to various
`str` representations:
* `webuuid.Uuid.base32()`: RFC-4648 Base 32 representation (Without padding by default).
* `webuuid.Uuid.base64()`: RFC-4648 Base 64 representation (Without padding by default).
* `webuuid.Uuid.base64url()`: RFC-4648 Base 64 URL safe representation (Without padding 
  by default).
* `webuuid.Uuid.standard_hex()`: RFC-4122 UUID hexadecimal representation.

#### String representation customization

The `webuuid.Uuid` class use the RFC-4648 Base 32 without padding `str` representation 
by default.

The library also provides the following classes that use a different default 
representation:
* `webuuid.UuidBase64`: RFC-4648 Base 64 without padding.
* `webuuid.UuidBase64Url`: RFC-4648 Base 64 URL safe without padding.

The class can also easily be subclassed to use any representation of your choice as
default output, but also as input:

```python
import webuuid


def custom_encoder(
    value: bytes, encoding: str = "utf-8", errors: str = "strict"
) -> str:
    """Custom encoder.
    
    Args:
        value: UUID bytes input value.
        encoding: See `bytes.decode()` argument.
        errors: See `bytes.decode()` argument.
    """
    # Custom codec implementation


def custom_decoder(value: str) -> bytes:
    """Custom decoder.

    Args:
        value: Input string value.
    """
    # Custom codec implementation


class CustomUuid(webuuid.Uuid):
    """Custom UUID that only support the specified codec."""

    # Set custom codec
    STR_ENCODER = custom_encoder
    FALLBACK_STR_DECODER = custom_decoder

    # Disable other codecs.
    STR_DECODERS = dict()


class CustomCompatibleUuid(webuuid.Uuid):
    """Custom UUID that add the support for an extra codec."""

    # Set custom encoder
    STR_ENCODER = custom_encoder

    # Add customer decoder.
    # In this example the encoder generate a 48 characters length str
    STR_DECODERS = webuuid.Uuid.STR_DECODERS.copy()
    STR_DECODERS[48] = custom_decoder
```

### Usage with other libraries

This part give some tips on how to use WebUuid with some common libraries.

#### JSON serialization/deserialization

In web application it is very common to serialize/deserialize data in JSON. By default,
the standard `json` library (And compatible alternative) only supports base Python 
types, but it is easy to add the `webuuid.Uuid` support to it:

```python
import json
import typing
import webuuid


def json_default_uuid(obj: typing.Any) -> typing.Any:
    """webuuid.uuid JSON serializer.

    Args:
        obj: Object to serialize.
    """
    if isinstance(obj, webuuid.Uuid):
        return str(obj)
    raise TypeError


# Serializing object with UUID
data = {"id": webuuid.Uuid()}
json.loads(data, default=json_default_uuid)
```

Some more high level libraries provides feature to register JSON encoders or `default` 
function for automatic use.

#### Pydantic

[Pydantic](https://github.com/pydantic/pydantic) is a data validation library. 
It is notably used with the [FastAPI](https://fastapi.tiangolo.com/) web framework.

`webuuid.Uuid` as native Pydantic support with validator and schema:

```python
import pydantic
import webuuid


class Model(pydantic.BaseModel):
    """Pydantic model."""
    
    class Config:
        """Config."""

        # Automatically JSON serialize UUID to its string representation
        json_encoders = {webuuid.Uuid: str}

    # UUID field
    id: webuuid.Uuid
    
    # UUID Field generating a default new value if not specified
    value: webuuid.Uuid = pydantic.Field(default_factory=webuuid.Uuid)
```

On custom subclass, the schema can easily be customized by overriding the 
`webuuid.Uuid.FIELD_SCHEMA` class dictionary.

#### Databases libraries

In databases, the UUID can be stored in a 16 bytes length binary column,
like BINARY(16). Depending on the library used and the database engine, the type and the
syntax to use may vary.

##### SQLAlchemy

With [SQLAlchemy](https://www.sqlalchemy.org/), the UUID can be stored using the
`LargeBinary(length=16)` type. SQLAlchemy will use the proper type for the required 
database engine behind the scene.

```python
import sqlalchemy


metadata = sqlalchemy.MetaData()

table = Table(
    "table_name",
    metadata,
    sqlalchemy.Column(
        "uuid",
        sqlalchemy.LargeBinary(length=16),
        primary_key=True,
        index=True
    ),
)
```
