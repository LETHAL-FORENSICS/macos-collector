"""
protobuf_dynamic.py - schemaless ("raw") protobuf decoder.

Biome payloads are protobuf messages, but Apple does not ship the .proto
schemas. This module decodes the wire format directly so we can recover every
field by number without a schema, in the spirit of `protoc --decode_raw` /
blackboxprotobuf, but as a dependency-free, forensics-friendly library.

Design goals
------------
* Never lose data. Unknown / ambiguous bytes are preserved (raw hex retained).
* Preserve repeated fields (a field number seen N times -> list of N values).
* Recurse into nested messages where the bytes plausibly are a message.
* Recognise embedded Apple binary plists (``bplist00``) inside byte fields.
* Be robust: a malformed tail yields a partial decode + an error marker rather
  than raising, so a single bad record never aborts a whole stream.

Wire types (https://protobuf.dev/programming-guides/encoding/):
    0  VARINT          int32/int64/uint/bool/enum/sint(zigzag)
    1  I64             fixed64/sfixed64/double
    2  LEN             string/bytes/embedded message/packed repeated
    3  SGROUP          start group (deprecated)
    4  EGROUP          end group   (deprecated)
    5  I32             fixed32/sfixed32/float
"""

from __future__ import annotations

import base64
import plistlib
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

WIRE_VARINT = 0
WIRE_I64 = 1
WIRE_LEN = 2
WIRE_SGROUP = 3
WIRE_EGROUP = 4
WIRE_I32 = 5

_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


class ProtobufError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Low-level readers
# --------------------------------------------------------------------------- #
def read_varint(buf: bytes, pos: int) -> Tuple[int, int]:
    """Return (value, new_pos). Raises ProtobufError on truncation/overlong."""
    result = 0
    shift = 0
    start = pos
    while True:
        if pos >= len(buf):
            raise ProtobufError(f"truncated varint at offset {start}")
        b = buf[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise ProtobufError(f"overlong varint at offset {start}")


def zigzag_decode(n: int) -> int:
    """Decode a protobuf sint (zigzag) value."""
    return (n >> 1) ^ -(n & 1)


# --------------------------------------------------------------------------- #
# Value model
# --------------------------------------------------------------------------- #
@dataclass
class Field:
    """A single decoded occurrence of one protobuf field."""
    number: int
    wire_type: int
    value: Any                       # int | bytes | "Message" | float-bits
    raw: Optional[bytes] = None      # original bytes for LEN fields

    # populated lazily for LEN fields by the interpreter
    as_string: Optional[str] = None
    as_message: Optional["Message"] = None
    as_plist: Any = None


@dataclass
class Message:
    """A decoded protobuf message: ordered fields + grouping by number."""
    fields: List[Field] = field(default_factory=list)
    error: Optional[str] = None      # set if only a partial decode succeeded

    def by_number(self) -> Dict[int, List[Field]]:
        out: Dict[int, List[Field]] = {}
        for f in self.fields:
            out.setdefault(f.number, []).append(f)
        return out

    # --- convenience accessors used by the extractor layer ------------------ #
    def all_strings(self) -> List[str]:
        """Every UTF-8 string found in this message, recursively."""
        acc: List[str] = []
        for f in self.fields:
            if f.as_string is not None:
                acc.append(f.as_string)
            if f.as_message is not None:
                acc.extend(f.as_message.all_strings())
        return acc

    def walk(self):
        """Yield (path, Field) for every field recursively. Path is a tuple of ints."""
        def _walk(msg: "Message", prefix: Tuple[int, ...]):
            for f in msg.fields:
                path = prefix + (f.number,)
                yield path, f
                if f.as_message is not None:
                    yield from _walk(f.as_message, path)
        yield from _walk(self, ())


# --------------------------------------------------------------------------- #
# Core decoder
# --------------------------------------------------------------------------- #
def _looks_like_message(msg: "Message", raw: bytes) -> bool:
    """
    Heuristic: did `raw` decode cleanly and structurally enough to be treated as
    an embedded message (vs. a coincidental string)?
    """
    if msg.error is not None or not msg.fields:
        return False
    # All field numbers must be valid protobuf field numbers.
    if any(f.number < 1 or f.number > 536870911 for f in msg.fields):
        return False
    # Deprecated group wire-types consume no bytes, which lets arbitrary text
    # "parse" into a pile of pseudo-fields. Real Biome messages don't use them,
    # so their presence means we are mis-reading bytes -> not a message.
    if any(f.wire_type in (WIRE_SGROUP, WIRE_EGROUP) for f in msg.fields):
        return False
    # A single short varint field is too easily a coincidence inside text.
    if len(msg.fields) == 1 and msg.fields[0].wire_type == WIRE_VARINT and len(raw) <= 2:
        return False
    return True


def _try_utf8_printable(raw: bytes):
    """Return decoded str if `raw` is valid UTF-8 with only printable chars, else None."""
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if all((ord(c) >= 0x20 or c in "\t\n\r") for c in s):
        return s
    return None


def _is_stringy(raw: bytes) -> bool:
    """
    True if `raw` looks like plain text rather than a packed protobuf message.
    A protobuf message almost always contains a tag or length byte below 0x20
    (e.g. field<=3 LEN tags, or short length prefixes); human text does not.
    """
    return all((b >= 0x20) or (b in (0x09, 0x0A, 0x0D)) for b in raw)


def _interpret_len_field(f: Field, depth: int, max_depth: int) -> None:
    """Decide whether a LEN field's bytes are a plist / string / message / bytes."""
    raw = bytes(f.value) if isinstance(f.value, (bytes, bytearray)) else b""
    f.raw = raw

    # 1) Embedded Apple binary plist?
    if raw[:8] == b"bplist00":
        try:
            f.as_plist = plistlib.loads(raw)
            return
        except Exception:
            pass  # fall through

    s = _try_utf8_printable(raw)

    # 2) Clean printable text with no control bytes -> string (prefer over a
    #    coincidental message parse). Resilient: nested messages carry control
    #    bytes and so fail _is_stringy, dropping to step 3.
    if s is not None and _is_stringy(raw):
        f.as_string = s
        return

    # 3) Embedded message?
    if depth < max_depth and len(raw) > 0:
        sub = decode(raw, depth=depth + 1, max_depth=max_depth)
        if _looks_like_message(sub, raw):
            f.as_message = sub
            return

    # 4) Valid UTF-8 (e.g. non-ASCII text that wasn't "stringy")?
    if s is not None:
        f.as_string = s
        return
    # 5) Opaque bytes - leave value as raw (callers hex/b64 it).


def decode(buf: bytes, depth: int = 0, max_depth: int = 12) -> Message:
    """
    Decode `buf` as a protobuf message. Always returns a Message; on malformed
    input the Message carries a partial field list and `.error` is set.
    """
    msg = Message()
    pos = 0
    n = len(buf)
    try:
        while pos < n:
            tag, pos = read_varint(buf, pos)
            field_number = tag >> 3
            wire_type = tag & 0x07

            if field_number == 0:
                raise ProtobufError("field number 0 is invalid")

            if wire_type == WIRE_VARINT:
                val, pos = read_varint(buf, pos)
                msg.fields.append(Field(field_number, wire_type, val))

            elif wire_type == WIRE_I64:
                if pos + 8 > n:
                    raise ProtobufError("truncated I64")
                chunk = buf[pos:pos + 8]
                pos += 8
                msg.fields.append(Field(field_number, wire_type, chunk))

            elif wire_type == WIRE_LEN:
                length, pos = read_varint(buf, pos)
                if pos + length > n:
                    raise ProtobufError("truncated LEN payload")
                payload = buf[pos:pos + length]
                pos += length
                f = Field(field_number, wire_type, payload)
                _interpret_len_field(f, depth, max_depth)
                msg.fields.append(f)

            elif wire_type == WIRE_I32:
                if pos + 4 > n:
                    raise ProtobufError("truncated I32")
                chunk = buf[pos:pos + 4]
                pos += 4
                msg.fields.append(Field(field_number, wire_type, chunk))

            elif wire_type in (WIRE_SGROUP, WIRE_EGROUP):
                # Deprecated groups: record marker, do not recurse.
                msg.fields.append(Field(field_number, wire_type, None))

            else:
                raise ProtobufError(f"invalid wire type {wire_type}")
    except ProtobufError as e:
        msg.error = str(e)
    return msg


# --------------------------------------------------------------------------- #
# Typed views of scalar fields
# --------------------------------------------------------------------------- #
def i64_as_double(chunk: bytes) -> float:
    return struct.unpack("<d", chunk)[0]


def i64_as_int(chunk: bytes, signed: bool = False) -> int:
    return struct.unpack("<q" if signed else "<Q", chunk)[0]


def i32_as_float(chunk: bytes) -> float:
    return struct.unpack("<f", chunk)[0]


def i32_as_int(chunk: bytes, signed: bool = False) -> int:
    return struct.unpack("<i" if signed else "<I", chunk)[0]


# --------------------------------------------------------------------------- #
# JSON-able rendering (lossless-ish) for ExtraFields
# --------------------------------------------------------------------------- #
def field_to_jsonable(f: Field) -> Any:
    """Render one Field into a JSON-serialisable, human-readable structure."""
    if f.wire_type == WIRE_VARINT:
        return f.value
    if f.wire_type == WIRE_I64:
        return {
            "_i64": i64_as_int(f.value),
            "_double": _safe(lambda: i64_as_double(f.value)),
        }
    if f.wire_type == WIRE_I32:
        return {
            "_i32": i32_as_int(f.value),
            "_float": _safe(lambda: i32_as_float(f.value)),
        }
    if f.wire_type == WIRE_LEN:
        if f.as_plist is not None:
            return {"_plist": _plist_jsonable(f.as_plist)}
        if f.as_message is not None:
            return message_to_jsonable(f.as_message)
        if f.as_string is not None:
            return f.as_string
        return {"_hex": f.raw.hex(), "_b64": base64.b64encode(f.raw).decode()}
    if f.wire_type in (WIRE_SGROUP, WIRE_EGROUP):
        return {"_group": f.wire_type}
    return {"_unknown_wire": f.wire_type}


def message_to_jsonable(msg: Message) -> Dict[str, Any]:
    """field_number(str) -> value or [values]; repeated fields become lists."""
    grouped = msg.by_number()
    out: Dict[str, Any] = {}
    for num, fields in grouped.items():
        rendered = [field_to_jsonable(f) for f in fields]
        out[str(num)] = rendered[0] if len(rendered) == 1 else rendered
    if msg.error:
        out["_error"] = msg.error
    return out


def _plist_jsonable(obj: Any) -> Any:
    import datetime as _dt
    if isinstance(obj, dict):
        return {str(k): _plist_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [_plist_jsonable(v) for v in obj]
    if isinstance(obj, (bytes, bytearray)):
        return {"_hex": bytes(obj).hex()}
    if isinstance(obj, _dt.datetime):
        return obj.isoformat()
    # NSKeyedArchiver UID: a reference into the plist's $objects array.
    # plistlib.UID exposes its value as .data; preserve it (forensically meaningful).
    if isinstance(obj, plistlib.UID):
        return {"_uid": obj.data}
    return obj


def _safe(fn):
    try:
        v = fn()
        # JSON can't encode inf/nan
        if v != v or v in (float("inf"), float("-inf")):
            return None
        return v
    except Exception:
        return None
