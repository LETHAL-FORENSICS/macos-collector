# biome

Parse Apple Biome (SEGB) streams on macOS into a time-sorted activity
timeline. One command, one CSV, ready for Timeline Explorer.

macOS records user behavior under `~/Library/Biome`: application focus,
web activity, media playback, and menu actions (macOS Tahoe 26+). This
tool decodes those streams and outputs one row per event with full
forensic provenance.

Pure Python 3, standard library only. No installation, no dependencies.

## Quick start

```bash
python3 biome.py all -l -o timeline.csv
```

Example output from an exfiltration case:

```
EventTime                 Stream            EventType    Description
2026-03-12T02:14:07.000Z  App.InFocus       FocusGained  Terminal - FocusGained
2026-03-12T02:15:33.000Z  App.WebUsage      PageView     Safari - PageView https://mega.nz/login
2026-03-12T02:16:41.000Z  App.InFocus       FocusGained  Finder - FocusGained Client_Contracts
2026-03-12T02:19:02.000Z  App.MenuItem      MenuAction   Finder - Compress "Client_Contracts"
2026-03-12T02:31:48.000Z  App.MenuItem      MenuAction   Finder - Empty Trash
```

Five rows place the user at the keyboard at 02:14, on a file sharing
site, in a sensitive folder, compressing it, then emptying the Trash.

## Input: -l or -d

`-l` (live) reads this Mac's own `~/Library/Biome/streams`. Use only
when the machine in front of you is the subject.

`-d` (directory) reads evidence collected from another system: a triage
package or a mounted image.

```bash
# live response on the subject Mac
python3 biome.py all -l -o HOST01-timeline.csv

# triage / disk image
python3 biome.py all -d /Cases/CASE-01/triage/Users/jdoe/Library/Biome/streams \
    -o CASE-01-jdoe-timeline.csv
```

Do not run `-l` during case analysis: it parses the analyst machine, not
the evidence. If `-l` reports a permission error, grant the terminal Full
Disk Access (System Settings > Privacy & Security) and restart it.

## Commands

```bash
python3 biome.py all   -d <streams> -o timeline.csv   # full merged timeline
python3 biome.py apps  -d <streams> -o apps.csv       # application focus and usage
python3 biome.py web   -d <streams> -o web.csv        # URLs and page views
python3 biome.py media -d <streams> -o media.csv      # playback and output device
python3 biome.py menu  -d <streams> -o menu.csv       # menu actions (Tahoe 26+)
```

| Command | Streams | Investigative value |
|---|---|---|
| apps  | App.InFocus, ScreenTime.AppUsage, App.Intent | user presence, active application, dwell time |
| web   | App.WebUsage, Safari.Navigations, Safari.PageLoad | browsing incl. in-app WebViews, survives cleared history |
| media | App.MediaUsage, Media.NowPlaying | activity anchoring, paired devices (HomePod, AirPods) |
| menu  | App.MenuItem | discrete user actions: Compress, Empty Trash, Export |
| all   | every stream found | full behavioral reconstruction |

`menu` is empty on macOS 14 and earlier; the stream exists from Tahoe 26.
Unknown or renamed streams are still decoded: bundle IDs, URLs, titles and
timestamps are recovered from content shape, so future macOS versions
produce rows instead of nothing.

## Options

```
-f <file>        single SEGB file
--jsonl <file>   JSONL output for pipelines
--carve          recover deleted records from slack space
--no-sort        preserve file order
-q               quiet
```

## Output columns

`EventTime` (sort key), `Stream`, `EventType`, `Description`, then detail
(BundleID, URL, MediaTitle, OutputDevice, ...) and provenance per row:
source file, SHA-256, record offset, SEGB version, CRC result, and
`DeletedState` (normal / carved / corrupt). Unmapped protobuf fields are
preserved in `ExtraFields`; nothing is dropped.

## Scope of interpretation

Apple publishes no schemas for Biome. The `Media.NowPlaying`, `App.MediaUsage`
and `App.InFocus` field mappings in this release were verified against real
macOS Sonoma (15.x) records. Other streams still rely on best-effort profiles
plus content-shape heuristics; treat those labels as investigative leads
pending corroboration. Timestamps, offsets, hashes and raw values are exact
and reproducible against ccl-segb on the same file.

## Notes for investigators

Biome web streams (`App.WebUsage`, `Safari.Navigations`, `Safari.PageLoad`)
only capture Safari / WebKit activity. A subject who browses in Chrome, Brave,
Firefox or Edge leaves little or nothing in these streams; their browsing must
be recovered from the browser's own history instead. Media played inside a
third-party browser does still appear in `Media.NowPlaying` under that
browser's bundle id, so activity is not always invisible.

By default the timeline collapses runs of identical consecutive events, since
Biome writes a new record on every minor state change. Use `--full` to keep
every raw record.

## Credits

SEGB format research: CCL Solutions Group (ccl-segb), Cellebrite, d204n6
"Breaking Down the Biomes". App.MenuItem documentation: Unit 42.

## License

MIT
