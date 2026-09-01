"""
versioning.py - stream + OS-version "profiles" mapping protobuf field numbers
to semantic names.

IMPORTANT (read before trusting field numbers):
    Apple does not publish the .proto schemas for Biome streams, and field
    numbering differs across streams and OS versions. The maps below are a
    *best-effort scaffold*. Treat any mapping marked TENTATIVE as a hypothesis
    to validate against ground-truth samples on the specific macOS build you are
    analysing - do NOT cite a field's meaning in a report on the strength of
    this table alone.

    The extractor (extract.py) deliberately does NOT depend on these maps being
    complete: it falls back to content-shape heuristics (reverse-DNS bundle IDs,
    URLs, human-readable titles), which are resilient to schema drift. Profiles,
    when populated and verified, simply make extraction precise instead of
    heuristic.

Profile entry format:
    PROFILES[stream_name][os_major] = {
        field_number: (canonical_name, type_hint),
        ...
    }
type_hint is consumed by extract.py:
    "string" | "bool" | "varint" | "double" | "cocoa_time" | "unix_time"
    | "message" | "bytes"
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

# os_major is a string like "26", "15", "14". "default" applies to any version.

PROFILES: Dict[str, Dict[str, Dict[int, Tuple[str, str]]]] = {
    # --- App.MenuItem (macOS Tahoe 26+, SEGB v2) ----------------------------- #
    # TENTATIVE. Field numbers below are placeholders demonstrating the profile
    # mechanism; the heuristic layer carries real extraction until verified.
    "App.MenuItem": {
        "default": {
            1: ("bundle_id", "string"),
            2: ("menu_title", "string"),
            3: ("app_display_name", "string"),
            4: ("event_time", "cocoa_time"),
        },
    },

    # --- App usage / focus / web usage -------------------------------------- #
    # Verified against real macOS Sonoma App.InFocus records. The payload holds
    # the app identity/version; the event time lives in the SEGB record header
    # (surfaced as RecordedTime1 and used as EventTime by the row builder).
    "App.InFocus": {
        "default": {
            1: ("bundle_id", "string"),       # app / SpringBoard transition reason
            9: ("app_version", "string"),
            10: ("app_item_id", "string"),
        },
    },
    "App.WebUsage": {
        "default": {
            1: ("bundle_id", "string"),
            2: ("url", "string"),
            3: ("event_time", "cocoa_time"),
            4: ("window_title", "string"),
        },
    },
    "App.Usage": {
        "default": {
            1: ("bundle_id", "string"),
            2: ("event_time_start", "cocoa_time"),
            3: ("event_time_end", "cocoa_time"),
        },
    },
    "App.UserActivity": {
        "default": {
            1: ("bundle_id", "string"),
            2: ("event_time", "cocoa_time"),
        },
    },

    # --- Media consumption / now playing ------------------------------------ #
    # Field numbers verified against real macOS Sonoma (15.x) Media.NowPlaying
    # and App.MediaUsage records (Brave/YouTube, WhatsApp calls, etc.).
    # Event time is taken from the SEGB record header, not the payload.
    "MediaUsage": {
        "default": {
            5: ("artist", "string"),          # channel / artist / contact
            6: ("position_seconds", "varint"),
            8: ("media_title", "string"),     # title / page / call label
            14: ("output_device", "message"), # nested; subfield 3 = device name
            15: ("bundle_id", "string"),      # app that played the media
        },
    },
    "NowPlaying": {
        "default": {
            5: ("artist", "string"),
            6: ("position_seconds", "varint"),
            8: ("media_title", "string"),
            14: ("output_device", "message"),
            15: ("bundle_id", "string"),
        },
    },
}

# Friendly aliasing: the folder name on disk may differ slightly from the keys
# above. Normalise common variants to a canonical profile key.
STREAM_ALIASES = {
    "app.menuitem": "App.MenuItem",
    "_dkevent.app.infocus": "App.InFocus",
    "app.infocus": "App.InFocus",
    "app.webusage": "App.WebUsage",
    "_dkevent.safari.history": "App.WebUsage",
    "app.activity": "App.UserActivity",
    "app.useractivity": "App.UserActivity",
    "app.usage": "App.Usage",
    "_dkevent.app.usage": "App.Usage",
    "mediausage": "MediaUsage",
    "media.usage": "MediaUsage",
    "app.mediausage": "MediaUsage",
    "mediarendered": "MediaUsage",
    "nowplaying": "NowPlaying",
    "media.nowplaying": "NowPlaying",
}


def canonical_stream(stream_name: str) -> str:
    """Map a raw on-disk stream/folder name to a canonical profile key."""
    if not stream_name:
        return stream_name
    key = stream_name.strip().lower()
    if key in STREAM_ALIASES:
        return STREAM_ALIASES[key]
    # If it already matches a profile key case-insensitively, normalise case.
    for k in PROFILES:
        if k.lower() == key:
            return k
    return stream_name


def get_profile(stream_name: str, os_major: Optional[str]) -> Dict[int, Tuple[str, str]]:
    """Return {field_number: (name, type_hint)} for a stream + OS major version."""
    canon = canonical_stream(stream_name)
    stream_profiles = PROFILES.get(canon, {})
    if os_major and os_major in stream_profiles:
        return dict(stream_profiles[os_major])
    return dict(stream_profiles.get("default", {}))
