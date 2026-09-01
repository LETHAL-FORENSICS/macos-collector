"""
extract.py - turn a decoded protobuf Message into semantic values.

Two layers, applied in order:
  1. Profile mapping (versioning.PROFILES) - precise field_number -> name when
     a verified mapping exists for the stream + OS version.
  2. Content-shape heuristics - recover bundle IDs, URLs and human-readable
     titles by what the strings *look like*, regardless of field number. This is
     what makes the tool resilient to Apple's schema drift across macOS builds.

The result is a flat dict of canonical keys (bundle_id, menu_title, url, ...)
plus an `extra` dict containing every field NOT consumed by a profile mapping,
so nothing is lost.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from . import protobuf_dynamic as pb
from .protobuf_dynamic import Message, Field
from .timestamps import guess_timestamp, iso
from .versioning import get_profile

# Reverse-DNS bundle id, e.g. com.apple.finder, com.google.Chrome
_BUNDLE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*(\.[A-Za-z0-9-]+){2,}$")
_URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
# common first labels that strongly imply a bundle id
_BUNDLE_HINTS = ("com.", "org.", "io.", "net.", "co.", "dev.", "app.")


def _typed_scalar(f: Field, hint: str) -> Any:
    """Coerce a Field into a Python value per a profile type hint."""
    if hint in ("string",):
        # A string-typed field must be real text. If it is not (e.g. the
        # profile points at a field that actually holds a raw timestamp),
        # return None so the raw value stays in ExtraFields instead of being
        # rendered as b'...' in a text column.
        return f.as_string if f.as_string is not None else None
    if hint in ("bytes",):
        return _bytes_repr(f)
    if hint in ("message",):
        return pb.message_to_jsonable(f.as_message) if f.as_message else None
    if hint in ("bool",):
        return bool(f.value) if f.wire_type == pb.WIRE_VARINT else None
    if hint in ("varint",):
        return f.value if f.wire_type == pb.WIRE_VARINT else None
    if hint in ("double",):
        if f.wire_type == pb.WIRE_I64:
            return pb.i64_as_double(f.value)
        if f.wire_type == pb.WIRE_VARINT:
            return float(f.value)
        return None
    if hint in ("cocoa_time",):
        raw = None
        if f.wire_type == pb.WIRE_I64:
            raw = pb.i64_as_double(f.value)
        elif f.wire_type == pb.WIRE_VARINT:
            raw = float(f.value)
        dt = guess_timestamp(raw) if raw is not None else None
        return iso(dt) if dt else None
    if hint in ("unix_time",):
        if f.wire_type == pb.WIRE_VARINT:
            from .timestamps import unix_to_datetime
            return iso(unix_to_datetime(f.value))
        return None
    return _bytes_repr(f)


def _bytes_repr(f: Field) -> Any:
    if f.as_string is not None:
        return f.as_string
    if f.raw is not None:
        return {"_hex": f.raw.hex()}
    return f.value


def apply_profile(msg: Message, stream: str, os_major: Optional[str]):
    """
    Return (mapped, consumed_numbers) where `mapped` is {canonical_name: value}
    using the verified/ tentative profile. Only top-level fields are mapped.
    """
    profile = get_profile(stream, os_major)
    mapped: Dict[str, Any] = {}
    consumed = set()
    grouped = msg.by_number()
    for num, (name, hint) in profile.items():
        if num in grouped:
            fields = grouped[num]
            vals = [_typed_scalar(f, hint) for f in fields]
            vals = [v for v in vals if v not in (None, "")]
            if not vals:
                continue
            mapped[name] = vals[0] if len(vals) == 1 else vals
            consumed.add(num)
    return mapped, consumed


def heuristics(msg: Message) -> Dict[str, Any]:
    """
    Recover common fields from string content, ignoring field numbers entirely.
    Returns any of: bundle_id, url, title_candidates (list, longest first).
    """
    strings = [s for s in msg.all_strings() if s and s.strip()]
    out: Dict[str, Any] = {}

    bundle = None
    for s in strings:
        cand = s.strip()
        if _BUNDLE_RE.match(cand):
            lc = cand.lower()
            if any(lc.startswith(h) for h in _BUNDLE_HINTS) or ".apple." in lc:
                bundle = cand
                break
            if bundle is None:
                bundle = cand
    if bundle:
        out["bundle_id"] = bundle

    for s in strings:
        if _URL_RE.match(s.strip()):
            out["url"] = s.strip()
            break

    # Title candidates: readable strings that are not the bundle id / url and
    # contain a space or are reasonably long. Longest first.
    used = {out.get("bundle_id"), out.get("url")}
    titles = [
        s.strip() for s in strings
        if s.strip() not in used
        and not _BUNDLE_RE.match(s.strip())
        and not _URL_RE.match(s.strip())
        and (" " in s.strip() or len(s.strip()) >= 4)
    ]
    titles.sort(key=len, reverse=True)
    if titles:
        out["title_candidates"] = titles
    return out


def extra_fields(msg: Message, consumed: set) -> Dict[str, Any]:
    """Everything NOT consumed by a profile mapping, as a JSON-able dict."""
    grouped = msg.by_number()
    out: Dict[str, Any] = {}
    for num, fields in grouped.items():
        if num in consumed:
            continue
        rendered = [pb.field_to_jsonable(f) for f in fields]
        out[str(num)] = rendered[0] if len(rendered) == 1 else rendered
    if msg.error:
        out["_protobuf_error"] = msg.error
    return out


def find_event_time(msg: Message) -> Optional[str]:
    """
    Scan all scalar numeric fields for the most plausible Cocoa timestamp and
    return it as ISO. Used when no profile time field is mapped.
    """
    best = None
    for _path, f in msg.walk():
        raw = None
        if f.wire_type == pb.WIRE_I64:
            raw = pb.i64_as_double(f.value)
        elif f.wire_type == pb.WIRE_VARINT and f.value > 10**8:
            raw = float(f.value)
        if raw is None:
            continue
        dt = guess_timestamp(raw)
        if dt and (best is None or dt > best):
            best = dt
    return iso(best) if best else None
