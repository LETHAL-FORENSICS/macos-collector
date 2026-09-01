"""
discovery.py - locate SEGB files under a Biome tree and infer context from paths.

Biome layout (macOS):
    ~/Library/Biome/streams/{public,restricted}/<StreamName>/{local,remote}/<file>
iOS layout:
    /private/var/mobile/Library/Biome/streams/...
    /private/var/db/biome/streams/...

We infer, where possible, from the path:
    * stream name  (the folder under .../streams/<scope>/)
    * local vs remote
    * user (from /Users/<name>/ on macOS)
"""

from __future__ import annotations

import os
import plistlib
import re
from typing import Iterator, Optional, Tuple

from . import segb

_USER_RE = re.compile(r"/Users/([^/]+)/", re.IGNORECASE)
_STREAMS_RE = re.compile(r"/streams/(?:public|restricted|private)/([^/]+)/", re.IGNORECASE)
_STREAMS_RE2 = re.compile(r"/streams/([^/]+)/", re.IGNORECASE)


def iter_segb_files(
    target: str,
    recurse: bool = True,
    local_only: bool = False,
    remote_only: bool = False,
) -> Iterator[str]:
    """Yield SEGB file paths under `target` (file or directory)."""
    if os.path.isfile(target):
        if segb.is_segb_file(target):
            yield target
        return

    for root, dirs, files in os.walk(target):
        low = root.replace("\\", "/").lower()
        if local_only and "/remote" in low:
            continue
        if remote_only and "/local" in low:
            continue
        for name in sorted(files):
            path = os.path.join(root, name)
            if segb.is_segb_file(path):
                yield path
        if not recurse:
            dirs[:] = []


def local_or_remote(path: str) -> str:
    low = path.replace("\\", "/").lower()
    if "/remote/" in low or low.endswith("/remote"):
        return "remote"
    if "/local/" in low or low.endswith("/local"):
        return "local"
    return ""


def infer_stream(path: str, fallback: Optional[str] = None) -> str:
    p = path.replace("\\", "/")
    m = _STREAMS_RE.search(p)
    if m:
        return m.group(1)
    m = _STREAMS_RE2.search(p)
    if m and m.group(1).lower() not in ("local", "remote"):
        return m.group(1)
    # else use the parent-of-(local|remote) directory name
    parts = [x for x in p.split("/") if x]
    for i, part in enumerate(parts):
        if part.lower() in ("local", "remote") and i > 0:
            return parts[i - 1]
    return fallback or ""


def infer_user(path: str, fallback: Optional[str] = None) -> str:
    m = _USER_RE.search(path.replace("\\", "/"))
    if m:
        return m.group(1)
    if "/var/mobile/" in path.replace("\\", "/").lower():
        return "mobile"
    return fallback or ""


def detect_os_major(
    explicit: Optional[str] = None,
    system_version_plist: Optional[str] = None,
) -> Optional[str]:
    """Return the macOS/iOS major version as a string (e.g. '26'), or None."""
    if explicit:
        return explicit.split(".")[0]
    if system_version_plist and os.path.isfile(system_version_plist):
        try:
            with open(system_version_plist, "rb") as f:
                pl = plistlib.load(f)
            ver = pl.get("ProductVersion") or pl.get("ProductBuildVersion")
            if ver:
                return str(ver).split(".")[0]
        except Exception:
            return None
    return None
