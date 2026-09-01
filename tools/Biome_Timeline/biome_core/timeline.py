"""
timeline.py - unified timeline layer.

Parsing stays per-stream (each stream keeps its own row builder and honest
field extraction). This module merges those per-stream rows into one
time-sorted timeline schema:

  - one canonical EventTime column every row populates (start time for
    interval artifacts, event time for point artifacts) used for sorting
  - a Stream column so rows can be filtered per artifact
  - a superset of columns; fields that do not apply to a stream stay blank

Sort order: EventTime ascending; rows with no recoverable time sort last,
preserving file order among themselves.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

from .models import MENU_COLUMNS, APP_USAGE_COLUMNS, MEDIA_COLUMNS
from .rows import build_menu_row, build_app_usage_row, build_media_row
from .segb import SegbRecord

# ---------------------------------------------------------------------------
# Unified timeline schema (superset, ordered for reading left -> right)
# ---------------------------------------------------------------------------
TIMELINE_COLUMNS = [
    # identity / provenance
    "EventTime",            # canonical sort key (ISO-8601 UTC)
    "Stream",               # which Biome stream produced the row
    "EventType",            # FocusGained / PageView / Play / MenuAction / ...
    "Description",          # one-line human-readable summary
    # subject
    "BundleID",
    "AppDisplayName",
    # web
    "URL",
    "PageTitle",
    # focus / usage intervals
    "EventTimeStart",
    "EventTimeEnd",
    "DurationSeconds",
    # media
    "MediaTitle",
    "Artist",
    "PlaybackState",
    "PositionSeconds",
    "OutputDevice",
    # menu
    "MenuTitle",
    # record forensics
    "LocalRemote",
    "DeletedState",
    "CrcOk",
    "RecordedTime1",
    "RecordedTime2",
    "SegbVersion",
    "RecordOffset",
    "SourceFile",
    "SourceHash",
    "ExtraFields",
]

# Column-name translations from the per-artifact schemas into the unified
# schema. Anything not listed copies across under the same name.
_RENAME = {
    "WindowTitle": "PageTitle",     # app-usage web rows carry title here
    "Title": "PageTitle",
}


def to_timeline_row(row: Dict) -> Dict:
    """Map a per-artifact row into the unified timeline schema."""
    out = {c: "" for c in TIMELINE_COLUMNS}
    for k, v in row.items():
        k2 = _RENAME.get(k, k)
        if k2 in out and v not in (None, ""):
            out[k2] = v
    # Canonical EventTime: prefer the row's own EventTime; for interval
    # artifacts fall back to the start; last resort the SEGB recorded time.
    if not out["EventTime"]:
        out["EventTime"] = (row.get("EventTimeStart")
                            or row.get("RecordedTime1")
                            or "")
    # Canonical EventType where the per-artifact schema had none.
    if not out["EventType"]:
        if out["MenuTitle"]:
            out["EventType"] = "MenuAction"
        elif out["PlaybackState"]:
            out["EventType"] = out["PlaybackState"]
        elif out["MediaTitle"]:
            out["EventType"] = "MediaEvent"
    return out


# ---------------------------------------------------------------------------
# Stream routing: which builder handles which stream.
# Keys are canonical stream names as they appear on disk. Matching is done
# by exact name first, then by prefix ("Safari." etc). Unknown streams fall
# through to the generic app-usage builder, whose heuristics extract
# bundle/url/title/time from content shape without a profile.
# ---------------------------------------------------------------------------
ROUTES: Dict[str, Callable] = {
    # menu
    "App.MenuItem": build_menu_row,
    # apps (focus / usage)
    "App.InFocus": build_app_usage_row,
    "ScreenTime.AppUsage": build_app_usage_row,
    "App.Intent": build_app_usage_row,
    # web
    "App.WebUsage": build_app_usage_row,
    "Safari.Navigations": build_app_usage_row,
    "Safari.PageLoad": build_app_usage_row,
    "ProactiveHarvesting.Safari.PageView": build_app_usage_row,
    # media
    "App.MediaUsage": build_media_row,
    "Media.NowPlaying": build_media_row,
    "MediaUsage": build_media_row,
    "NowPlaying": build_media_row,
}

# Subcommand -> which streams it includes. "all" means no filter.
BUNDLES: Dict[str, Optional[List[str]]] = {
    "all": None,
    "apps": ["App.InFocus", "ScreenTime.AppUsage", "App.Intent"],
    "web": ["App.WebUsage", "Safari.Navigations", "Safari.PageLoad",
            "ProactiveHarvesting.Safari.PageView"],
    "media": ["App.MediaUsage", "Media.NowPlaying", "MediaUsage", "NowPlaying"],
    "menu": ["App.MenuItem"],
}


def builder_for(stream: str) -> Callable:
    """Route a stream name to its row builder; unknown -> generic app usage."""
    if stream in ROUTES:
        return ROUTES[stream]
    if stream.startswith(("Media.", "App.Media")):
        return build_media_row
    if stream == "App.MenuItem":
        return build_menu_row
    return build_app_usage_row


# Prefixes that safely imply bundle membership even for stream names we have
# never seen (schema-drift tolerance). Deliberately narrow: "App." would match
# nearly everything, so only unambiguous family prefixes are listed.
_BUNDLE_PREFIXES = {
    "web": ("Safari.",),
    "media": ("Media.",),
}


def stream_selected(stream: str, bundle_name: str,
                    bundle: Optional[List[str]]) -> bool:
    """True if this stream is included by the active subcommand bundle."""
    if bundle is None:
        return True
    if stream in bundle:
        return True
    return stream.startswith(_BUNDLE_PREFIXES.get(bundle_name, ()))


def dedupe_rows(rows: List[Dict]) -> List[Dict]:
    """Collapse consecutive near-identical events.

    Biome writes a fresh record on every minor state change, so one playback
    or one app focus produces many rows that differ only by a sub-second
    timestamp. Two rows are treated as the same event when they share stream,
    bundle, title/url, and event type. Only runs of identical events collapse;
    the first occurrence is kept. This is what turns a 300k-row dump into a
    readable timeline.
    """
    out: List[Dict] = []
    last_key = None
    for r in rows:
        key = (r.get("Stream"), r.get("BundleID"),
               r.get("MediaTitle") or r.get("URL") or r.get("PageTitle")
               or r.get("MenuTitle") or r.get("AppDisplayName"),
               r.get("EventType"))
        if key == last_key and any(key[1:]):
            continue
        out.append(r)
        last_key = key
    return out


def sort_rows(rows: List[Dict]) -> List[Dict]:
    """Time-sort: EventTime ascending, blank times last (stable)."""
    dated = [(i, r) for i, r in enumerate(rows)]
    return [r for _, r in sorted(
        dated, key=lambda t: (t[1].get("EventTime") == "",
                              t[1].get("EventTime") or "", t[0]))]
