"""
timestamps.py - time conversion helpers for Apple Biome / SEGB artifacts.

Apple stores most timestamps as "Mac Absolute Time" (a.k.a. Cocoa / Core Data
time): the number of seconds (often a float) since 2001-01-01 00:00:00 UTC.

Biome record payloads occasionally also carry Unix epoch values. Helper
detectors below let callers convert "a number that is probably a timestamp"
into a UTC datetime with a best-effort guess at the epoch.
"""

from __future__ import annotations

import datetime
from typing import Optional

COCOA_EPOCH = datetime.datetime(2001, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
UNIX_EPOCH = datetime.datetime(1970, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)

# Sanity window used when auto-guessing whether a raw number is a timestamp.
# 2001-01-01 .. ~2099. Keeps us from interpreting tiny enums/counters as dates.
_COCOA_MIN = 0.0
_COCOA_MAX = 3.2e9  # ~year 2102 in cocoa seconds


def cocoa_to_datetime(seconds: float) -> datetime.datetime:
    """Convert a Mac Absolute / Cocoa timestamp (seconds since 2001) to UTC datetime."""
    return COCOA_EPOCH + datetime.timedelta(seconds=seconds)


def unix_to_datetime(seconds: float) -> datetime.datetime:
    """Convert a Unix timestamp (seconds since 1970) to UTC datetime."""
    return UNIX_EPOCH + datetime.timedelta(seconds=seconds)


def iso(dt: Optional[datetime.datetime]) -> str:
    """ISO-8601 in UTC with a trailing Z, or empty string for None."""
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def guess_timestamp(value: float) -> Optional[datetime.datetime]:
    """
    Best-effort: given a raw numeric value pulled from a protobuf field, decide
    whether it looks like a Cocoa timestamp and return the datetime, else None.

    Nanosecond/millisecond variants are normalised. Returns UTC datetime or None.
    """
    if value is None:
        return None
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None

    # Normalise obvious nanosecond / millisecond scales down to seconds.
    for scale in (1.0, 1e-3, 1e-6, 1e-9):
        s = v * scale
        if _COCOA_MIN < s < _COCOA_MAX:
            return cocoa_to_datetime(s)
    return None
