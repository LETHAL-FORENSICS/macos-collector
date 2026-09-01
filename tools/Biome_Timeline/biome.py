#!/usr/bin/env python3
"""
biome - parse Apple Biome (SEGB) streams into a time-sorted timeline.

usage:
  biome all   -l -o timeline.csv          sweep every stream on this Mac
  biome all   -d <triage_dir> -o timeline.csv
  biome apps  -l -o apps.csv              app focus / usage
  biome web   -l -o web.csv               URLs and page views
  biome media -l -o media.csv             playback: title, artist, device
  biome menu  -l -o menu.csv              menu actions (macOS Tahoe 26+)

input:
  -l, --live            read this Mac's ~/Library/Biome/streams
  -d, --directory DIR   read an offline/triage copy of a Biome tree
  -f, --file FILE       read a single SEGB file

output:
  -o, --output FILE     CSV timeline (default: print JSONL to stdout)
  --jsonl FILE          also write JSONL
  --no-sort             keep file order instead of time-sorting

Rows carry a canonical EventTime (sort key), a Stream column for filtering,
per-record SHA-256 / offset / CRC / DeletedState for provenance, and any
unmapped protobuf fields preserved in ExtraFields.
"""

import argparse
import os
import sys
import socket

from biome_core import discovery, segb
from biome_core.output import CsvWriter, JsonlWriter
from biome_core.timeline import (TIMELINE_COLUMNS, BUNDLES, builder_for,
                                 stream_selected, to_timeline_row, sort_rows,
                                 dedupe_rows)

__version__ = "2.1.0"

LIVE_ROOT = os.path.expanduser("~/Library/Biome/streams")


def _parser(sub: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=f"biome {sub}")
    src = p.add_argument_group("input")
    src.add_argument("-l", "--live", action="store_true",
                     help="read this Mac's ~/Library/Biome/streams")
    src.add_argument("-d", "--directory",
                     help="offline/triage Biome tree to scan")
    src.add_argument("-f", "--file", help="single SEGB file")
    src.add_argument("--local-only", action="store_true")
    src.add_argument("--remote-only", action="store_true")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--output", help="CSV timeline output file")
    out.add_argument("--jsonl", help="JSONL output file")
    out.add_argument("--full", action="store_true",
                     help="keep every record; disable de-duplication")
    out.add_argument("--no-sort", action="store_true",
                     help="keep file order instead of time-sorting")
    out.add_argument("--offset-format", choices=["dec", "hex"], default="dec")

    beh = p.add_argument_group("behaviour")
    beh.add_argument("--os-version", help="source macOS version, e.g. 14.5")
    beh.add_argument("--system-version-plist",
                     help="SystemVersion.plist from the source for OS detection")
    beh.add_argument("--strict", action="store_true",
                     help="flag rows missing expected fields in ExtraFields")
    beh.add_argument("--carve", action="store_true",
                     help="also scan slack space for carved records")
    beh.add_argument("-q", "--quiet", action="store_true")
    return p


def _resolve_input(args) -> str:
    """Return the scan target, enforcing live/offline rules."""
    if args.live:
        if args.directory:
            print("error: use either -l (live) or -d (offline), not both",
                  file=sys.stderr)
            sys.exit(2)
        if not os.path.isdir(LIVE_ROOT):
            print(f"error: {LIVE_ROOT} not found on this machine",
                  file=sys.stderr)
            sys.exit(2)
        try:
            os.listdir(LIVE_ROOT)
        except PermissionError:
            print("error: macOS privacy protection (TCC) is blocking access to "
                  "~/Library/Biome.\nGrant your terminal Full Disk Access: "
                  "System Settings > Privacy & Security > Full Disk Access, "
                  "then fully restart the terminal.", file=sys.stderr)
            sys.exit(2)
        return LIVE_ROOT
    target = args.file or args.directory
    if not target:
        print("error: provide -l (live), -d <dir> (offline), or -f <file>",
              file=sys.stderr)
        sys.exit(2)
    return target


def _run(sub: str, argv) -> int:
    args = _parser(sub).parse_args(argv)
    target = _resolve_input(args)
    bundle = BUNDLES[sub]
    os_major = discovery.detect_os_major(args.os_version,
                                         args.system_version_plist)
    host = socket.gethostname() if args.live else ""

    files = list(discovery.iter_segb_files(
        target, recurse=True,
        local_only=args.local_only, remote_only=args.remote_only))

    rows, n_files, n_warn = [], 0, 0
    for path in files:
        stream = discovery.infer_stream(path, "")
        if not stream_selected(stream, sub, bundle):
            continue
        result = segb.parse_file(path, carve=args.carve)
        n_files += 1
        for w in result.warnings:
            n_warn += 1
            if not args.quiet:
                print(f"[warn] {path}: {w}", file=sys.stderr)
        ctx = {
            "host": host,
            "user": discovery.infer_user(path),
            "source_file": path,
            "source_hash": result.sha256,
            "stream": stream,
            "local_remote": discovery.local_or_remote(path),
            "offset_fmt": args.offset_format,
        }
        build = builder_for(stream)
        for rec in result.records:
            try:
                row = build(rec, ctx, os_major=os_major, strict=args.strict)
            except Exception as e:      # one bad record never aborts the batch
                if not args.quiet:
                    print(f"[warn] {path}@{rec.offset}: {e!r}", file=sys.stderr)
                continue
            rows.append(to_timeline_row(row))

    if not args.no_sort:
        rows = sort_rows(rows)
    if not args.full:
        rows = dedupe_rows(rows)

    writers = []
    if args.output:
        d = os.path.dirname(os.path.abspath(args.output))
        os.makedirs(d, exist_ok=True)
        writers.append(CsvWriter(args.output, TIMELINE_COLUMNS))
    if args.jsonl:
        os.makedirs(os.path.dirname(os.path.abspath(args.jsonl)), exist_ok=True)
        writers.append(JsonlWriter(args.jsonl))
    if not writers:
        writers.append(JsonlWriter("/dev/stdout"))

    for r in rows:
        for w in writers:
            w.write(r)
    for w in writers:
        w.close()

    if not args.quiet:
        print(f"[done] files={n_files} rows={len(rows)} warnings={n_warn}",
              file=sys.stderr)
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ("--version", "-V"):
        print(f"biome {__version__}")
        return 0
    if not argv or argv[0] in ("-h", "--help") or argv[0] not in BUNDLES:
        print(__doc__.strip(), file=sys.stderr)
        return 0 if argv and argv[0] in ("-h", "--help") else 2
    return _run(argv[0], argv[1:])


if __name__ == "__main__":
    sys.exit(main())
