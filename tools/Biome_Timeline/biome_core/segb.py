"""
segb.py - SEGB v1 & v2 container parsing for Apple Biome streams.

Byte layouts below are derived from public research:
  * CCL Solutions Group `ccl-segb` (Alex Caithness) - reference implementation.
  * Cellebrite, "Understanding and Decoding the Newest iOS SEGB Format".
  * D204N6 (Geraldine Blay) Biome blog series.

SEGB v1 (older macOS/iOS Biome streams)
---------------------------------------
  File header: 56 bytes. The ASCII magic ``SEGB`` sits at the END of the header
  (bytes 52:56). The first 4 bytes (LE u32) are the end-of-data offset.
  Each record: 32-byte header then payload, 8-byte aligned.
    record header  <i i d d I i>:
        length(i32) state(i32) ts1(double cocoa) ts2(double cocoa)
        crc32(u32)  unknown(i32)
  State: 1=Written, 3=Deleted, 4=Unknown.

SEGB v2 (newer macOS Tahoe 26 / iOS 17+ Biome streams, incl. App.MenuItem)
--------------------------------------------------------------------------
  File header: 32 bytes  <4s i d 16s>:
        magic "SEGB", entries_count(i32), creation(double cocoa), pad(16)
  Records start at offset 32. Each entry begins with an 8-byte prefix
  (crc32 u32 + unknown i32) that MUST be skipped before the protobuf payload.
  A trailer grows backwards from EOF: ``entries_count`` x 16-byte records
        <i i d>: end_offset(i32, rel. to entry area) state(i32) ts(double cocoa)
  Entries are laid out in ascending end_offset order; payloads are 4-byte aligned.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import os
import struct
import zlib
from typing import BinaryIO, Iterable, List, Optional

from .timestamps import cocoa_to_datetime
import datetime

MAGIC = b"SEGB"

V1_HEADER_LEN = 56
V1_RECORD_HEADER_LEN = 32
V1_ALIGN = 8

V2_HEADER_LEN = 32
V2_ENTRY_PREFIX_LEN = 8
V2_TRAILER_ENTRY_LEN = 16
V2_ALIGN = 4


class EntryState(enum.IntEnum):
    Written = 1
    Deleted = 3
    Unknown = 4

    @classmethod
    def from_raw(cls, raw: int) -> "EntryState | int":
        try:
            return cls(raw)
        except ValueError:
            return raw


class DeletedState(str, enum.Enum):
    NORMAL = "normal"
    CARVED = "carved"
    CORRUPT = "corrupt"


@dataclasses.dataclass
class SegbRecord:
    """One record recovered from a SEGB container (v1 or v2 normalised)."""
    segb_version: int                       # 1 or 2
    offset: int                             # byte offset of the payload
    payload: bytes                          # protobuf bytes (entry prefix removed)
    recorded_time1: Optional[datetime.datetime]
    recorded_time2: Optional[datetime.datetime]
    entry_state: object                     # EntryState or raw int
    deleted_state: DeletedState
    crc_stored: Optional[int] = None
    crc_calc: Optional[int] = None

    @property
    def crc_ok(self) -> Optional[bool]:
        if self.crc_stored is None or self.crc_calc is None:
            return None
        return self.crc_stored == self.crc_calc


@dataclasses.dataclass
class SegbResult:
    """Outcome of parsing one SEGB file: records + integrity metadata."""
    path: str
    segb_version: Optional[int]
    sha256: str
    file_size: int
    records: List[SegbRecord] = dataclasses.field(default_factory=list)
    expected_records: Optional[int] = None
    warnings: List[str] = dataclasses.field(default_factory=list)


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #
def detect_version(data: bytes) -> Optional[int]:
    """Return 1, 2, or None based on SEGB magic placement."""
    if len(data) >= V2_HEADER_LEN and data[0:4] == MAGIC:
        return 2
    if len(data) >= V1_HEADER_LEN and data[V1_HEADER_LEN - 4:V1_HEADER_LEN] == MAGIC:
        return 1
    return None


# --------------------------------------------------------------------------- #
# v1
# --------------------------------------------------------------------------- #
def _parse_v1(data: bytes, result: SegbResult) -> None:
    end_of_data, = struct.unpack("<I", data[0:4])
    if end_of_data > len(data):
        result.warnings.append(
            f"end-of-data offset {end_of_data} exceeds file size {len(data)} (truncated?)")
        end_of_data = len(data)

    pos = V1_HEADER_LEN
    count = 0
    while pos + V1_RECORD_HEADER_LEN <= end_of_data:
        hdr = data[pos:pos + V1_RECORD_HEADER_LEN]
        length, state_raw, ts1, ts2, crc_stored, _unknown = struct.unpack("<iiddIi", hdr)
        payload_off = pos + V1_RECORD_HEADER_LEN
        if length < 0 or payload_off + length > len(data):
            result.warnings.append(f"record at {pos}: bad length {length}; stopping")
            break
        payload = data[payload_off:payload_off + length]

        # Skip empty or zero-only record slots. Biome pre-allocates fixed-size
        # (128 KB) stream files; unused slots are zero padding, not events. On
        # streams the OS is not populating (e.g. Safari web streams for a
        # non-Safari user), most slots are empty and must not become rows.
        if not payload or not any(payload):
            pos = payload_off + length
            rem = pos % V1_ALIGN
            if rem:
                pos += V1_ALIGN - rem
            continue

        crc_calc = zlib.crc32(payload) & 0xFFFFFFFF

        state = EntryState.from_raw(state_raw)
        if state == EntryState.Deleted:
            dstate = DeletedState.CARVED
        elif crc_stored and crc_calc != crc_stored:
            dstate = DeletedState.CORRUPT
        else:
            dstate = DeletedState.NORMAL

        result.records.append(SegbRecord(
            segb_version=1, offset=payload_off, payload=payload,
            recorded_time1=_safe_cocoa(ts1), recorded_time2=_safe_cocoa(ts2),
            entry_state=state, deleted_state=dstate,
            crc_stored=crc_stored, crc_calc=crc_calc,
        ))
        count += 1

        pos = payload_off + length
        rem = (pos - 0) % V1_ALIGN
        if rem:
            pos += V1_ALIGN - rem
    result.expected_records = None  # v1 header has no record count


# --------------------------------------------------------------------------- #
# v2
# --------------------------------------------------------------------------- #
def _parse_v2(data: bytes, result: SegbResult) -> None:
    magic, entries_count, creation_raw, _pad = struct.unpack("<4sid16s", data[0:V2_HEADER_LEN])
    result.expected_records = entries_count

    trailer_size = V2_TRAILER_ENTRY_LEN * entries_count
    if trailer_size > len(data) - V2_HEADER_LEN:
        result.warnings.append(
            f"trailer size {trailer_size} implausible for file ({len(data)} bytes); file truncated?")
        entries_count = max(0, (len(data) - V2_HEADER_LEN) // V2_TRAILER_ENTRY_LEN)
        trailer_size = V2_TRAILER_ENTRY_LEN * entries_count

    trailer_start = len(data) - trailer_size
    trailer = []
    for i in range(entries_count):
        off = trailer_start + i * V2_TRAILER_ENTRY_LEN
        end_offset, state_raw, ts_raw = struct.unpack(
            "<iid", data[off:off + V2_TRAILER_ENTRY_LEN])
        trailer.append((end_offset, state_raw, ts_raw))

    trailer.sort(key=lambda t: t[0])
    pos = V2_HEADER_LEN
    parsed = 0
    for end_offset, state_raw, ts_raw in trailer:
        state = EntryState.from_raw(state_raw)
        abs_end = end_offset + V2_HEADER_LEN
        if state == EntryState.Unknown:        # state 4 == empty slot
            continue
        if abs_end <= pos or abs_end > len(data):
            result.warnings.append(f"v2 entry end_offset {end_offset} out of range; skipping")
            continue
        entry_raw = data[pos:abs_end]
        if len(entry_raw) < V2_ENTRY_PREFIX_LEN:
            result.warnings.append(f"v2 entry at {pos} shorter than prefix; skipping")
            pos = abs_end
            continue
        crc_stored, _unknown = struct.unpack("<Ii", entry_raw[:V2_ENTRY_PREFIX_LEN])
        payload = entry_raw[V2_ENTRY_PREFIX_LEN:]
        crc_calc = zlib.crc32(payload) & 0xFFFFFFFF

        if state == EntryState.Deleted:
            dstate = DeletedState.CARVED
        elif crc_stored and crc_calc != crc_stored:
            dstate = DeletedState.CORRUPT
        else:
            dstate = DeletedState.NORMAL

        result.records.append(SegbRecord(
            segb_version=2, offset=pos + V2_ENTRY_PREFIX_LEN, payload=payload,
            recorded_time1=_safe_cocoa(ts_raw), recorded_time2=None,
            entry_state=state, deleted_state=dstate,
            crc_stored=crc_stored, crc_calc=crc_calc,
        ))
        parsed += 1

        pos = abs_end
        rem = end_offset % V2_ALIGN
        if rem:
            pos += V2_ALIGN - rem

    if result.expected_records is not None:
        written = sum(1 for t in trailer if t[1] == EntryState.Written)
        if parsed < written:
            result.warnings.append(
                f"parsed {parsed} of {written} 'written' entries (possible corruption)")


# --------------------------------------------------------------------------- #
# Optional carver (slack / unused area)
# --------------------------------------------------------------------------- #
def _carve(data: bytes, result: SegbResult, version: int) -> None:
    """
    Best-effort recovery of protobuf-shaped records from unused space. Heuristic
    and opt-in: scans byte-by-byte for a position that decodes as a plausible
    message consuming a reasonable run of bytes. Marked DeletedState=carved.
    """
    from .protobuf_dynamic import decode

    covered = set()
    for r in result.records:
        covered.update(range(r.offset, r.offset + len(r.payload)))

    i = 0
    n = len(data)
    found = 0
    while i < n and found < 256:
        if i in covered:
            i += 1
            continue
        # Cheap pre-filter: a record usually starts with a small tag byte.
        msg = decode(data[i:i + 4096])
        if msg.error is None and len(msg.fields) >= 2 and msg.all_strings():
            # crude length estimate: re-encode is hard; just record a window
            blob = data[i:i + 4096]
            result.records.append(SegbRecord(
                segb_version=version, offset=i, payload=blob,
                recorded_time1=None, recorded_time2=None,
                entry_state=EntryState.Unknown, deleted_state=DeletedState.CARVED,
            ))
            found += 1
            i += 64
        else:
            i += 1
    if found:
        result.warnings.append(f"carver recovered {found} candidate record(s) (heuristic)")


# --------------------------------------------------------------------------- #
# Public entry points
# --------------------------------------------------------------------------- #
def parse_bytes(data: bytes, path: str = "<bytes>", carve: bool = False) -> SegbResult:
    sha = hashlib.sha256(data).hexdigest()
    version = detect_version(data)
    result = SegbResult(path=path, segb_version=version, sha256=sha, file_size=len(data))
    if version is None:
        result.warnings.append("no SEGB magic found; not a SEGB file")
        return result
    try:
        if version == 1:
            _parse_v1(data, result)
        else:
            _parse_v2(data, result)
    except Exception as e:  # never let one file abort a batch
        result.warnings.append(f"fatal parse error: {e!r}")
    if carve:
        _carve(data, result, version)
    return result


def parse_file(path: str, carve: bool = False) -> SegbResult:
    with open(path, "rb") as f:
        data = f.read()
    return parse_bytes(data, path=path, carve=carve)


def is_segb_file(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(V1_HEADER_LEN)
    except OSError:
        return False
    return detect_version(head) is not None


def _safe_cocoa(v: float) -> Optional[datetime.datetime]:
    try:
        if v != v:  # NaN
            return None
        return cocoa_to_datetime(v)
    except (OverflowError, ValueError):
        return None
