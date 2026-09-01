"""
rows.py - convert a (SegbRecord + decoded Message) into a schema row for each
artifact family. Kept separate from the CLIs so it is unit-testable.
"""

from __future__ import annotations

from typing import Dict, Optional

from . import extract
from .models import blank_row, MENU_COLUMNS, APP_USAGE_COLUMNS, MEDIA_COLUMNS
from .protobuf_dynamic import decode, Message
from .segb import SegbRecord
from .timestamps import iso
from .versioning import canonical_stream


# Heuristic mapping of common media playback-state enum integers -> labels.
_PLAYBACK = {0: "Stop", 1: "Play", 2: "Pause", 3: "Forward", 4: "Rewind"}


def _common(rec: SegbRecord, ctx: Dict, columns) -> Dict:
    row = blank_row(columns)
    row["Host"] = ctx.get("host", "")
    row["User"] = ctx.get("user", "")
    row["SourceFile"] = ctx.get("source_file", "")
    row["SourceHash"] = ctx.get("source_hash", "")
    row["RecordOffset"] = ctx.get("offset_fmt", "dec") == "hex" and hex(rec.offset) or rec.offset
    row["Stream"] = ctx.get("stream", "")
    row["LocalRemote"] = ctx.get("local_remote", "")
    row["SegbVersion"] = rec.segb_version
    row["RecordedTime1"] = iso(rec.recorded_time1)
    row["RecordedTime2"] = iso(rec.recorded_time2)
    row["DeletedState"] = rec.deleted_state.value
    row["CrcOk"] = "" if rec.crc_ok is None else rec.crc_ok
    return row


def _decode(rec: SegbRecord) -> Message:
    return decode(rec.payload)


def _strict_flag(row: Dict, msg: Message, expected, strict: bool):
    if not strict:
        return
    missing = [k for k in expected if not row.get(k)]
    if missing:
        extra = row.get("ExtraFields") or {}
        if isinstance(extra, dict):
            extra["_strict_missing"] = missing
            row["ExtraFields"] = extra


# --------------------------------------------------------------------------- #
# App.MenuItem
# --------------------------------------------------------------------------- #
def build_menu_row(rec: SegbRecord, ctx: Dict, os_major=None, strict=False) -> Dict:
    msg = _decode(rec)
    stream = canonical_stream(ctx.get("stream", "App.MenuItem"))
    mapped, consumed = extract.apply_profile(msg, stream, os_major)
    heur = extract.heuristics(msg)

    row = _common(rec, ctx, MENU_COLUMNS)
    bundle = mapped.get("bundle_id") or heur.get("bundle_id", "")
    app_name = mapped.get("app_display_name", "")
    title = mapped.get("menu_title")
    if not title and heur.get("title_candidates"):
        # prefer a candidate that isn't the app display name
        for c in heur["title_candidates"]:
            if c != app_name and c != bundle:
                title = c
                break
    event_time = mapped.get("event_time") or extract.find_event_time(msg) or iso(rec.recorded_time1)

    row["BundleID"] = bundle
    row["AppDisplayName"] = app_name or _app_from_bundle(bundle)
    row["MenuTitle"] = title or ""
    row["EventTime"] = event_time
    row["ExtraFields"] = extract.extra_fields(msg, consumed)
    row["Description"] = _desc("App.MenuItem", row.get("AppDisplayName") or bundle, row["MenuTitle"])
    _strict_flag(row, msg, ["BundleID", "MenuTitle"], strict)
    return row


# --------------------------------------------------------------------------- #
# App usage / focus / web usage
# --------------------------------------------------------------------------- #
def build_app_usage_row(rec: SegbRecord, ctx: Dict, os_major=None, strict=False) -> Dict:
    msg = _decode(rec)
    stream = canonical_stream(ctx.get("stream", "App.Usage"))
    mapped, consumed = extract.apply_profile(msg, stream, os_major)
    heur = extract.heuristics(msg)

    row = _common(rec, ctx, APP_USAGE_COLUMNS)
    bundle = mapped.get("bundle_id") or heur.get("bundle_id", "")
    url = mapped.get("url") or heur.get("url", "")
    win = mapped.get("window_title", "")
    if not win and heur.get("title_candidates"):
        for c in heur["title_candidates"]:
            if c not in (bundle, url):
                win = c
                break
    start = mapped.get("event_time_start") or mapped.get("event_time")
    end = mapped.get("event_time_end")
    if not start:
        start = extract.find_event_time(msg) or iso(rec.recorded_time1)

    row["BundleID"] = bundle
    row["AppDisplayName"] = mapped.get("app_display_name", "") or _app_from_bundle(bundle)
    row["URL"] = url
    row["WindowTitle"] = win
    row["EventTimeStart"] = start
    row["EventTimeEnd"] = end or ""
    row["EventType"] = _event_type(stream, url)
    row["ExtraFields"] = extract.extra_fields(msg, consumed)
    label = url or win or row["AppDisplayName"] or bundle
    row["Description"] = _desc("Biome.AppUsage", row["AppDisplayName"] or bundle,
                               f'{row["EventType"]} {label}'.strip())
    _strict_flag(row, msg, ["BundleID"], strict)
    return row


# --------------------------------------------------------------------------- #
# Media consumption / now playing
# --------------------------------------------------------------------------- #
def build_media_row(rec: SegbRecord, ctx: Dict, os_major=None, strict=False) -> Dict:
    msg = _decode(rec)
    stream = canonical_stream(ctx.get("stream", "MediaUsage"))
    mapped, consumed = extract.apply_profile(msg, stream, os_major)
    heur = extract.heuristics(msg)

    row = _common(rec, ctx, MEDIA_COLUMNS)
    bundle = mapped.get("bundle_id") or heur.get("bundle_id", "")
    title = mapped.get("media_title", "")
    artist = mapped.get("artist", "")
    if not title and heur.get("title_candidates"):
        cands = [c for c in heur["title_candidates"] if c not in (bundle,)]
        if cands:
            title = cands[0]
        if len(cands) > 1 and not artist:
            artist = cands[1]

    pstate = mapped.get("playback_state")
    pstate_label = _PLAYBACK.get(pstate, pstate) if pstate is not None else ""

    row["BundleID"] = bundle
    row["AppDisplayName"] = mapped.get("app_display_name", "") or _app_from_bundle(bundle)
    row["MediaTitle"] = title
    row["Artist"] = artist
    row["PlaybackState"] = pstate_label if pstate_label is not None else ""
    row["PositionSeconds"] = _num(mapped.get("position_seconds"))
    row["DurationSeconds"] = _num(mapped.get("duration_seconds"))
    row["OutputDevice"] = mapped.get("output_device", "")
    row["EventTime"] = mapped.get("event_time") or extract.find_event_time(msg) or iso(rec.recorded_time1)
    row["ExtraFields"] = extract.extra_fields(msg, consumed)
    media_label = f'{row["PlaybackState"]} "{title}"'.strip() if title else row["PlaybackState"]
    row["Description"] = _desc("Biome.Media", row["AppDisplayName"] or bundle, media_label)
    _strict_flag(row, msg, ["BundleID", "MediaTitle"], strict)
    return row


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _desc(prefix: str, app: str, detail: str) -> str:
    app = app or "?"
    detail = (detail or "").strip()
    return f"{prefix}: {app} - {detail}".rstrip(" -")


def _app_from_bundle(bundle: str) -> str:
    if not bundle:
        return ""
    return bundle.rsplit(".", 1)[-1]


def _event_type(stream: str, url: str) -> str:
    s = (stream or "").lower()
    if "webusage" in s or "history" in s or url:
        return "PageView"
    if "infocus" in s:
        return "FocusGained"
    if "useractivity" in s or "activity" in s:
        return "Activity"
    return "Usage"


def _num(v):
    if v is None:
        return ""
    try:
        return round(float(v), 3)
    except (TypeError, ValueError):
        return v
