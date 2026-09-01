"""
models.py - stable output schemas for each tool.

Each row is a plain dict keyed by the canonical column names from the spec.
ExtraFields is held as a Python object (dict); the CSV writer serialises it to a
JSON string, while the JSONL writer emits it as a true object.
"""

from __future__ import annotations

# Column orders are FIXED so CSVs stay consistent across macOS versions.

MENU_COLUMNS = [
    "Host", "User", "SourceFile", "SourceHash", "RecordOffset", "Stream",
    "LocalRemote", "SegbVersion", "EventTime", "RecordedTime1", "RecordedTime2",
    "BundleID", "AppDisplayName", "MenuTitle", "Description",
    "DeletedState", "CrcOk", "ExtraFields",
]

APP_USAGE_COLUMNS = [
    "Host", "User", "SourceFile", "SourceHash", "RecordOffset", "Stream",
    "LocalRemote", "SegbVersion", "EventTimeStart", "EventTimeEnd",
    "RecordedTime1", "RecordedTime2", "BundleID", "AppDisplayName",
    "EventType", "WindowTitle", "URL", "Description",
    "DeletedState", "CrcOk", "ExtraFields",
]

MEDIA_COLUMNS = [
    "Host", "User", "SourceFile", "SourceHash", "RecordOffset", "Stream",
    "LocalRemote", "SegbVersion", "EventTime", "RecordedTime1", "RecordedTime2",
    "BundleID", "AppDisplayName", "MediaTitle", "Artist", "PlaybackState",
    "PositionSeconds", "DurationSeconds", "OutputDevice", "Description",
    "DeletedState", "CrcOk", "ExtraFields",
]

SCHEMAS = {
    "menu": MENU_COLUMNS,
    "appusage": APP_USAGE_COLUMNS,
    "media": MEDIA_COLUMNS,
}


def blank_row(columns):
    return {c: "" for c in columns}
