"""
file_finder.py
--------------
Scans your Windows machine for local Audio, Video, and Image files.
No files are copied or moved — only their URIs are collected.

Results are:
  • Printed to the terminal
  • Saved as a clickable HTML report and/or txt file to selected location (default save to User Desktop)

Hidden file support:
  • Uses Windows file attributes (FILE_ATTRIBUTE_HIDDEN = 0x2) via ctypes
  • Also detects hidden/system directories so they can be included or skipped
  • Symlinks are detected and labelled in the report

Requirements: Python 3.10+  (no third-party libraries needed)

Usage:
    python file_finder.py
"""

import os
import time
import sys
import ctypes
from pathlib import Path
from datetime import datetime

# ── File type registry ────────────────────────────────────────────────────────

FILE_TYPES = {
    "Video": {
        "MP4":  [".mp4"],
        "MKV":  [".mkv"],
        "AVI":  [".avi"],
        "MOV":  [".mov"],
        "WMV":  [".wmv"],
        "FLV":  [".flv"],
        "WEBM": [".webm"],
        "M4V":  [".m4v"],
        "MPEG": [".mpeg", ".mpg"],
        "3GP":  [".3gp"],
    },
    "Audio": {
        "MP3":  [".mp3"],
        "WAV":  [".wav"],
        "FLAC": [".flac"],
        "AAC":  [".aac"],
        "OGG":  [".ogg"],
        "WMA":  [".wma"],
        "M4A":  [".m4a"],
        "AIFF": [".aiff", ".aif"],
        "OPUS": [".opus"],
        "AMR":  [".amr"],
    },
    "Image": {
        "JPEG": [".jpg", ".jpeg"],
        "PNG":  [".png"],
        "GIF":  [".gif"],
        "BMP":  [".bmp"],
        "TIFF": [".tiff", ".tif"],
        "WEBP": [".webp"],
        "SVG":  [".svg"],
        "HEIC": [".heic", ".heif"],
        "RAW":  [".raw", ".cr2", ".nef", ".arw"],
        "ICO":  [".ico"],
    },
}

# System directories always skipped regardless of hidden setting
ALWAYS_SKIP = {
    "system volume information", "windows", "program files",
    "program files (x86)", "programdata", "recovery", "boot", "efi",
}

# Hidden/system dirs skipped only when include_hidden=False
HIDDEN_SYSTEM_DIRS = {
    "$recycle.bin", "$winreagent", "$windows.~bt", "$windows.~ws",
    "msocache", "perflogs",
}

# Windows attribute flags
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4

# ── Terminal helpers ──────────────────────────────────────────────────────────

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def sep(char="─", width=62):
    print(char * width)

def header(title: str):
    clear()
    sep("═")
    print(f"  🔍  File Finder  ▸  {title}")
    sep("═")
    print()

def prompt_choice(options: list[str], label: str = "Choose") -> int:
    """Numbered single-choice menu. Returns 0-based index."""
    for i, opt in enumerate(options, 1):
        print(f"  [{i}] {opt}")
    print()
    while True:
        raw = input(f"  {label} › ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return int(raw) - 1
        print(f"  ⚠  Enter a number between 1 and {len(options)}.")

def prompt_multi_choice(options: list[str], label: str = "Select") -> list[int]:
    """
    Numbered multi-choice menu.
    Enter one number, several comma-separated, or A for all.
    Returns list of 0-based indices.
    """
    for i, opt in enumerate(options, 1):
        print(f"  [{i:>2}] {opt}")
    print(f"  [ A] All of the above")
    print()
    while True:
        raw = input(f"  {label} (e.g. 1,3 or A) › ").strip().upper()
        if raw == "A":
            return list(range(len(options)))
        parts = [p.strip() for p in raw.split(",")]
        indices, valid = [], True
        for p in parts:
            if p.isdigit() and 1 <= int(p) <= len(options):
                indices.append(int(p) - 1)
            else:
                valid = False
                break
        if valid and indices:
            return list(dict.fromkeys(indices))
        print(f"  ⚠  Invalid input. Enter numbers 1–{len(options)} or A.")

def prompt_yes_no(question: str, default_yes: bool = True) -> bool:
    hint = "[Y/n]" if default_yes else "[y/N]"
    raw = input(f"  {question} {hint} › ").strip().lower()
    if raw == "":
        return default_yes
    return raw in ("y", "yes")

# ── Windows attribute helpers ─────────────────────────────────────────────────

def win_attributes(path: Path) -> int:
    """Return Windows file attributes as an int, or 0 on failure."""
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        return attrs if attrs != 0xFFFFFFFF else 0
    except Exception:
        return 0

def is_hidden(path: Path) -> bool:
    """True if the path has the Windows HIDDEN or SYSTEM attribute set."""
    attrs = win_attributes(path)
    return bool(attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))

def is_symlink(path: Path) -> bool:
    """True if path is a symbolic link or junction point."""
    try:
        return path.is_symlink()
    except Exception:
        return False

# ── Desktop path (registry-aware for OneDrive setups) ────────────────────────

def get_desktop() -> Path:
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        )
        desktop, _ = winreg.QueryValueEx(key, "Desktop")
        winreg.CloseKey(key)
        return Path(desktop)
    except Exception:
        return Path.home() / "Desktop"

# ── Scanner ───────────────────────────────────────────────────────────────────

def path_to_uri(p: Path) -> str:
    """Convert a Windows absolute path to a file:/// URI."""
    return "file:///" + str(p).replace("\\", "/")

class FileResult:
    """Holds a found file's path plus metadata flags."""
    __slots__ = ("path", "hidden", "symlink")

    def __init__(self, path: Path):
        self.path    = path
        self.hidden  = is_hidden(path)
        self.symlink = is_symlink(path)

# Scan mode constants
SCAN_REGULAR = "regular"   # visible files only
SCAN_HIDDEN  = "hidden"    # hidden/system files only
SCAN_BOTH    = "both"      # everything


def format_eta(seconds: float) -> str:
    """Format a number of seconds into a human-readable ETA string."""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        m, s = divmod(int(seconds), 60)
        return f"{m}m {s}s"
    else:
        h, rem = divmod(int(seconds), 3600)
        m = rem // 60
        return f"{h}h {m}m"


def scan(root: Path, extensions: set[str], scan_mode: str) -> list[FileResult]:
    """
    Walk root recursively and return FileResult objects for every match.
    Nothing is copied or moved.

    scan_mode must be one of: SCAN_REGULAR, SCAN_HIDDEN, SCAN_BOTH.
    Prints a live progress line showing current folder, files found,
    elapsed time, and estimated time remaining.
    """
    results: list[FileResult] = []

    mode_label = {
        "regular": "Regular only",
        "hidden":  "Hidden only",
        "both":    "Regular + Hidden",
    }[scan_mode]

    sep()
    print(f"  Scanning      : {root}")
    print(f"  Formats       : {', '.join(sorted(extensions))}")
    print(f"  File mode     : {mode_label}")
    sep()
    print()
    print("  ⚠  Scan in progress — please do not close this window.")
    print()

    dirs_visited  = 0
    start_time    = time.time()
    last_update   = start_time
    UPDATE_EVERY  = 0.2          # seconds between progress refreshes

    # We use a rolling average of dirs/sec to estimate remaining time.
    # Because we don't know the total dir count up front, ETA is calculated
    # from the observed scan rate against a rolling sample window.
    rate_window   = []           # list of (timestamp, dirs_visited) samples
    WINDOW_SIZE   = 10           # samples to average over

    terminal_width = 78

    def progress_line(current_dir: str, found: int, elapsed: float, eta_str: str):
        """Overwrite the current terminal line with a status update."""
        label   = f"  ⏳ Scanning... | Found: {found} | Elapsed: {format_eta(elapsed)} | ETA: {eta_str}"
        # Truncate the directory path so the whole line fits
        max_dir = terminal_width - len(label) - 5
        if len(current_dir) > max_dir > 0:
            current_dir = "..." + current_dir[-(max_dir - 3):]
        line = f"{label}  {current_dir}"
        # \r returns to line start; pad with spaces to clear previous longer line
        print(f"\r{line:<{terminal_width}}", end="", flush=True)

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, onerror=None):
        current = Path(dirpath)
        dirs_visited += 1

        def keep_dir(name: str) -> bool:
            p = current / name
            dir_is_hidden = is_hidden(p) or name.startswith(".")
            if scan_mode == SCAN_REGULAR and dir_is_hidden:
                return False
            if scan_mode == SCAN_HIDDEN and not dir_is_hidden:
                return False
            return True

        dirnames[:] = [d for d in dirnames if keep_dir(d)]

        for filename in filenames:
            fp = current / filename
            if Path(filename).suffix.lower() not in extensions:
                continue
            file_is_hidden = is_hidden(fp) or filename.startswith(".")
            if scan_mode == SCAN_REGULAR and file_is_hidden:
                continue
            if scan_mode == SCAN_HIDDEN and not file_is_hidden:
                continue
            results.append(FileResult(fp))

        # Throttle progress updates to avoid slowing the scan
        now = time.time()
        if now - last_update >= UPDATE_EVERY:
            elapsed = now - start_time

            # Build a rolling rate sample
            rate_window.append((now, dirs_visited))
            if len(rate_window) > WINDOW_SIZE:
                rate_window.pop(0)

            # Estimate ETA from rolling dirs/sec rate.
            # We don't know total dirs, so we use a heuristic: a full C:\ scan
            # typically visits ~100k–300k dirs. We use 200k as a soft estimate
            # and blend it with observed progress to get a rough remaining time.
            if len(rate_window) >= 2:
                dt = rate_window[-1][0] - rate_window[0][0]
                dd = rate_window[-1][1] - rate_window[0][1]
                rate = dd / dt if dt > 0 else 1
                ESTIMATED_TOTAL_DIRS = 200_000
                remaining_dirs = max(ESTIMATED_TOTAL_DIRS - dirs_visited, 0)
                eta_secs = remaining_dirs / rate if rate > 0 else 0
                eta_str  = f"~{format_eta(eta_secs)}" if eta_secs > 0 else "almost done"
            else:
                eta_str = "calculating..."

            progress_line(str(current), len(results), elapsed, eta_str)
            last_update = now

    # Clear the progress line and print the final summary
    elapsed = time.time() - start_time
    print(f"\r{'':< {terminal_width}}", end="", flush=True)   # clear line
    print(f"\r  ✅ Scan complete — {dirs_visited} folders visited in {format_eta(elapsed)}.")
    print()

    return results

# ── Output ────────────────────────────────────────────────────────────────────

def osc8_link(uri: str, label: str) -> str:
    """
    Wrap label in an OSC 8 hyperlink escape sequence.
    Supported by: Windows Terminal, VS Code terminal, ConEmu, and most
    modern terminals. Falls back to plain text in unsupported terminals.
    The URI points to the parent FOLDER so Explorer opens the location
    without executing the file.
    """
    return f"\033]8;;{uri}\033\\{label}\033]8;;\033\\"


def print_results(results: list[FileResult], scan_mode: str):
    """
    Print each file to the terminal as a clickable OSC 8 hyperlink.
    Clicking opens the file's parent folder in File Explorer.
    """
    print()
    sep()
    hidden_count  = sum(1 for r in results if r.hidden)
    symlink_count = sum(1 for r in results if r.symlink)
    print(f"  Found {len(results)} file(s)", end="")
    if scan_mode != SCAN_REGULAR and hidden_count:
        print(f"  ({hidden_count} hidden, {symlink_count} symlink/junction)", end="")
    print("\n")
    print("  (Ctrl+click or click a link to open its folder in File Explorer)\n")
    for r in results:
        folder_uri = path_to_uri(r.path.parent)
        flags = ""
        if r.hidden:  flags += " [hidden]"
        if r.symlink: flags += " [link]"
        link = osc8_link(folder_uri, str(r.path))
        print(f"  {link}{flags}")
    sep()
    print()

def save_txt(
    results: list[FileResult],
    output_path: Path,
    category: str,
    formats: list[str],
    scan_mode: str,
):
    """
    Save a plain-text report. Each line is the full file path.
    Hidden and symlinked files are flagged inline.
    """
    timestamp     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hidden_setting = {
        SCAN_REGULAR: "Excluded",
        SCAN_HIDDEN:  "Hidden only",
        SCAN_BOTH:    "Included",
    }[scan_mode]
    hidden_count  = sum(1 for r in results if r.hidden)
    symlink_count = sum(1 for r in results if r.symlink)

    lines = [
        "=" * 62,
        f"  File Finder Report — {category}",
        "=" * 62,
        f"  Generated : {timestamp}",
        f"  Formats   : {', '.join(formats)}",
        f"  Hidden    : {hidden_setting}",
        f"  Found     : {len(results)} file(s)  "
        f"({hidden_count} hidden, {symlink_count} symlink/junction)",
        "=" * 62,
        "",
    ]
    for r in results:
        flags = ""
        if r.hidden:  flags += "  [hidden]"
        if r.symlink: flags += "  [link]"
        lines.append(f"{r.path}{flags}")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def save_html(
    results: list[FileResult],
    output_path: Path,
    category: str,
    formats: list[str],
    scan_mode: str,
):
    """
    Save an HTML report. Each row links to the file's parent folder in
    File Explorer. Hidden and symlinked files are visually labelled.
    """
    timestamp     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hidden_count  = sum(1 for r in results if r.hidden)
    symlink_count = sum(1 for r in results if r.symlink)

    rows = ""
    for r in results:
        folder_uri = path_to_uri(r.path.parent)
        badges = ""
        if r.hidden:  badges += '<span class="badge-hidden">hidden</span>'
        if r.symlink: badges += '<span class="badge-link">link</span>'
        rows += (
            f'    <tr{"  class=\"row-hidden\"" if r.hidden else ""}>'
            f'<td class="name"><a href="{folder_uri}" title="Open folder in Explorer">'
            f'{r.path.name}</a> {badges}</td>'
            f'<td class="path">{r.path.parent}</td>'
            f'<td class="ext">{r.path.suffix.lower()}</td>'
            f'</tr>\n'
        )

    hidden_setting = {
        SCAN_REGULAR: "Excluded",
        SCAN_HIDDEN:  "Hidden only",
        SCAN_BOTH:    "Included",
    }[scan_mode]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>File Finder – {category}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: Segoe UI, Arial, sans-serif;
      background: #f4f6f9;
      color: #222;
      padding: 32px 24px;
    }}
    h1  {{ font-size: 1.4rem; font-weight: 600; margin-bottom: 4px; }}
    .meta {{ font-size: 0.85rem; color: #666; margin-bottom: 24px; }}
    .summary {{
      display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap;
    }}
    .badge {{
      background: #fff; border: 1px solid #dde1e8; border-radius: 6px;
      padding: 8px 16px; font-size: 0.85rem;
    }}
    .badge strong {{ display: block; font-size: 1.2rem; }}
    table {{
      width: 100%; border-collapse: collapse; background: #fff;
      border-radius: 8px; overflow: hidden;
      box-shadow: 0 1px 4px rgba(0,0,0,.08);
    }}
    thead {{ background: #1a73e8; color: #fff; }}
    th, td {{ padding: 10px 14px; text-align: left; font-size: 0.88rem; }}
    tbody tr:nth-child(even) {{ background: #f9fafc; }}
    tbody tr:hover {{ background: #eef4ff; }}
    tr.row-hidden {{ opacity: 0.75; font-style: italic; }}
    td.name a {{
      color: #1a73e8; text-decoration: none; font-weight: 500;
    }}
    td.name a:hover {{ text-decoration: underline; }}
    td.path {{ color: #555; font-size: 0.82rem; word-break: break-all; }}
    td.ext  {{ color: #888; font-size: 0.82rem; }}
    .badge-hidden {{
      display: inline-block; font-size: 0.7rem; font-style: normal;
      background: #fff3cd; color: #856404; border: 1px solid #ffc107;
      border-radius: 4px; padding: 1px 6px; margin-left: 4px;
      vertical-align: middle;
    }}
    .badge-link {{
      display: inline-block; font-size: 0.7rem; font-style: normal;
      background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb;
      border-radius: 4px; padding: 1px 6px; margin-left: 4px;
      vertical-align: middle;
    }}
    .footer {{ margin-top: 20px; font-size: 0.78rem; color: #aaa; }}
  </style>
</head>
<body>
  <h1>🔍 File Finder Report — {category}</h1>
  <p class="meta">
    Generated: {timestamp} &nbsp;|&nbsp;
    Formats: {', '.join(formats)} &nbsp;|&nbsp;
    Hidden files: {hidden_setting}
  </p>

  <div class="summary">
    <div class="badge"><strong>{len(results)}</strong> files found</div>
    <div class="badge"><strong>{category}</strong> category</div>
    <div class="badge"><strong>{len(formats)}</strong> format(s) selected</div>
    <div class="badge"><strong>{hidden_count}</strong> hidden</div>
    <div class="badge"><strong>{symlink_count}</strong> symlink / junction</div>
  </div>

  <table>
    <thead>
      <tr>
        <th>File name (click to open folder)</th>
        <th>Location</th>
        <th>Type</th>
      </tr>
    </thead>
    <tbody>
{rows}    </tbody>
  </table>

  <p class="footer">
    Each link opens the file's folder in Windows File Explorer — the file itself is not executed.
    Hidden files are shown in italics with a <span class="badge-hidden">hidden</span> badge.
    Symbolic links / junctions carry a <span class="badge-link">link</span> badge.
  </p>
</body>
</html>
"""
    output_path.write_text(html, encoding="utf-8")

# ── Flow ──────────────────────────────────────────────────────────────────────

def pick_category() -> list[str]:
    """Returns a list of one or more category names."""
    header("Step 1 — Media Category")
    categories = list(FILE_TYPES.keys())
    for i, cat in enumerate(categories, 1):
        print(f"  [{i}] {cat}")
    print(f"  [ A] All  (Video + Audio + Image)")
    print()
    while True:
        raw = input("  Select one or more (e.g. 1,3 or A) › ").strip().upper()
        if raw == "A":
            return categories
        parts = [p.strip() for p in raw.split(",")]
        indices, valid = [], True
        for p in parts:
            if p.isdigit() and 1 <= int(p) <= len(categories):
                indices.append(int(p) - 1)
            else:
                valid = False
                break
        if valid and indices:
            chosen = list(dict.fromkeys(categories[i] for i in indices))
            return chosen
        print(f"  ⚠  Enter numbers 1–{len(categories)} (comma-separated) or A.")

def pick_formats(categories: list[str]) -> tuple[set[str], list[str]]:
    """
    If a single category was chosen, let the user pick specific formats.
    If All was chosen, use every extension across all categories automatically.
    """
    if len(categories) > 1:
        # All categories selected — collect every extension
        extensions: set[str] = set()
        chosen: list[str] = []
        for cat in categories:
            for name, exts in FILE_TYPES[cat].items():
                extensions.update(exts)
                chosen.append(name)
        header("Step 2 — Formats")
        print(f"  All categories selected — including all {len(chosen)} formats automatically.")
        print()
        return extensions, chosen

    category = categories[0]
    header(f"Step 2 — {category} Formats")
    format_names = list(FILE_TYPES[category].keys())
    indices = prompt_multi_choice(format_names, label="Select format(s)")
    extensions = set()
    chosen = []
    for i in indices:
        name = format_names[i]
        extensions.update(FILE_TYPES[category][name])
        chosen.append(name)
    print(f"\n  Selected: {', '.join(chosen)}")
    return extensions, chosen

def pick_scan_mode() -> str:
    header("Step 3 — File Visibility")
    print("  Hidden items have the Windows HIDDEN or SYSTEM attribute set.")
    print("  They are normally invisible in File Explorer.")
    print()
    options = [
        "Regular files only  (visible files — default)",
        "Hidden files only   (HIDDEN / SYSTEM attribute, dot-files)",
        "Both                (all files regardless of visibility)",
    ]
    idx = prompt_choice(options, label="Select scan mode")
    return [SCAN_REGULAR, SCAN_HIDDEN, SCAN_BOTH][idx]

def pick_output_format() -> str:
    """Returns one of: 'txt', 'html', 'both'."""
    header("Step 4 — Output Format")
    options = [
        "Text (.txt)        — plain list of file paths",
        "HTML (.html)       — clickable report, opens folders in Explorer",
        "Both               — save a .txt and a .html report",
    ]
    idx = prompt_choice(options, label="Select output format")
    return ["txt", "html", "both"][idx]


def pick_output_path(label: str) -> Path:
    header("Step 5 — Output Location")
    desktop = get_desktop()
    print(f"  Default save folder:")
    print(f"  {desktop}")
    print()
    raw = input("  Press Enter to use Desktop, or type a full folder path › ").strip()
    folder = Path(raw) if raw else desktop
    folder.mkdir(parents=True, exist_ok=True)
    return folder / f"FileFinder_{label}"   # extension added later per format

def confirm(
    label: str,
    formats: list[str],
    scan_mode: str,
    output_fmt: str,
    output_base: Path,
) -> bool:
    mode_label = {
        SCAN_REGULAR: "Regular files only",
        SCAN_HIDDEN:  "Hidden files only",
        SCAN_BOTH:    "Both (regular + hidden)",
    }[scan_mode]
    fmt_label = {
        "txt":  ".txt only",
        "html": ".html only",
        "both": ".txt  +  .html",
    }[output_fmt]
    header("Step 6 — Confirm & Run")
    print(f"  Category      : {label}")
    print(f"  Formats       : {', '.join(formats)}")
    print(f"  Scan root     : C:\\")
    print(f"  File mode     : {mode_label}")
    print(f"  Output format : {fmt_label}")
    print(f"  Save to       : {output_base.parent}")
    print()
    return prompt_yes_no("Start scan?", default_yes=True)

def run_again() -> bool:
    print()
    return prompt_yes_no("Run another scan?", default_yes=True)

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    if sys.platform != "win32":
        print("\n  ⚠  This script is designed for Windows.")
        print("     Pass a custom root as an argument to use on other platforms.\n")

    ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("C:\\")

    while True:
        categories             = pick_category()
        extensions, fmt_labels = pick_formats(categories)
        scan_mode              = pick_scan_mode()
        label                  = "All" if len(categories) > 1 else categories[0]
        output_fmt             = pick_output_format()
        output_base            = pick_output_path(label)

        if confirm(label, fmt_labels, scan_mode, output_fmt, output_base):
            results = scan(ROOT, extensions, scan_mode)

            if results:
                print_results(results, scan_mode)
                saved = []
                if output_fmt in ("txt", "both"):
                    p = output_base.with_suffix(".txt")
                    save_txt(results, p, label, fmt_labels, scan_mode)
                    saved.append(p)
                if output_fmt in ("html", "both"):
                    p = output_base.with_suffix(".html")
                    save_html(results, p, label, fmt_labels, scan_mode)
                    saved.append(p)
                sep("═")
                hidden_count = sum(1 for r in results if r.hidden)
                print(f"  ✅  {len(results)} file(s) found  ({hidden_count} hidden).")
                print(f"  📄  Report(s) saved:")
                for p in saved:
                    print(f"      {p}")
                sep("═")
            else:
                print("\n  No files found matching your selection.\n")
        else:
            print("\n  Scan cancelled.\n")

        if not run_again():
            print("\n  Goodbye! 👋\n")
            input("  Press Enter to close... ")
            break

if __name__ == "__main__":
    main()
