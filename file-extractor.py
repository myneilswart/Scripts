"""
file_extractor.py
-----------------
Scans the Windows root drive (C:\\) and extracts files by media type.
Supports Video, Audio, and Image categories with fine-grained format selection.

Usage:
    python file-extractor.py
"""

import os
import shutil
import sys
from pathlib import Path

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

# Folders to skip (system/hidden dirs that cause permission errors or noise)
SKIP_DIRS = {
    "$recycle.bin", "system volume information", "windows",
    "program files", "program files (x86)", "programdata",
    "recovery", "boot", "efi",
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def clear():
    os.system("cls" if os.name == "nt" else "clear")


def separator(char="─", width=60):
    print(char * width)


def header(title: str):
    clear()
    separator("═")
    print(f"  🗂  File Extractor  ▸  {title}")
    separator("═")
    print()


def prompt_choice(options: list[str], label: str = "Choose an option") -> int:
    """
    Display a numbered menu and return the 0-based index of the chosen item.
    """
    for i, option in enumerate(options, 1):
        print(f"  [{i}] {option}")
    print()

    while True:
        raw = input(f"  {label} › ").strip()
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                return idx
        print(f"  ⚠  Please enter a number between 1 and {len(options)}.")


def prompt_multi_choice(options: list[str], label: str = "Select formats") -> list[int]:
    """
    Display a numbered menu and let the user pick one, several (comma-separated),
    or ALL. Returns a list of 0-based indices.
    """
    for i, option in enumerate(options, 1):
        print(f"  [{i:>2}] {option}")
    print(f"  [ A] All of the above")
    print()

    while True:
        raw = input(f"  {label} (e.g. 1,3,5 or A) › ").strip().upper()

        if raw == "A":
            return list(range(len(options)))

        parts = [p.strip() for p in raw.split(",")]
        indices = []
        valid = True
        for part in parts:
            if part.isdigit():
                idx = int(part) - 1
                if 0 <= idx < len(options):
                    indices.append(idx)
                else:
                    valid = False
                    break
            else:
                valid = False
                break

        if valid and indices:
            return list(dict.fromkeys(indices))   # deduplicated, order preserved

        print(f"  ⚠  Invalid input. Enter numbers 1–{len(options)} or A.")


def get_desktop() -> Path:
    """
    Resolve the real Desktop path from the Windows registry.
    Handles OneDrive-redirected Desktops correctly.
    Falls back to ~/Desktop if the registry lookup fails.
    """
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


def get_output_dir(category: str) -> Path:
    """Save extracted files to a named subfolder on the user's real Desktop."""
    desktop = get_desktop()
    path = desktop / f"ExtractedFiles_{category}"
    path.mkdir(parents=True, exist_ok=True)
    print(f"\n  Output folder: {path}")
    return path


def should_skip(path: Path) -> bool:
    """Return True if this directory should be skipped entirely."""
    return path.name.lower() in SKIP_DIRS


# ── Core scan ─────────────────────────────────────────────────────────────────

def scan_and_copy(root: Path, extensions: set[str], output_dir: Path) -> tuple[int, int]:
    """
    Walk *root* recursively, copy every file whose suffix is in *extensions*
    to *output_dir*.

    Returns (files_found, files_copied).
    """
    found = 0
    copied = 0

    print()
    separator()
    print(f"  Scanning: {root}")
    print(f"  Matching: {', '.join(sorted(extensions))}")
    print(f"  Output:   {output_dir}")
    separator()
    print()

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, onerror=None):
        current = Path(dirpath)

        # Prune directories we should skip (modifying dirnames in-place stops os.walk)
        dirnames[:] = [
            d for d in dirnames
            if not should_skip(current / d)
            and not (current / d).name.startswith(".")
        ]

        for filename in filenames:
            suffix = Path(filename).suffix.lower()
            if suffix in extensions:
                found += 1
                src = current / filename

                # Preserve a flattened-but-unique name to avoid collisions
                relative = src.relative_to(root)
                safe_name = "__".join(relative.parts)      # e.g. Users__Alice__video.mp4
                dest = output_dir / safe_name

                try:
                    shutil.copy2(src, dest)
                    copied += 1
                    print(f"  ✔  {src}")
                except PermissionError:
                    print(f"  ✖  (permission denied) {src}")
                except Exception as exc:
                    print(f"  ✖  {src}  [{exc}]")

    return found, copied


# ── Flow ──────────────────────────────────────────────────────────────────────

def pick_category() -> str:
    header("Select Category")
    categories = list(FILE_TYPES.keys())
    idx = prompt_choice(categories, label="Media type")
    return categories[idx]


def pick_formats(category: str) -> set[str]:
    header(f"{category} ▸ Select Formats")
    format_names = list(FILE_TYPES[category].keys())
    indices = prompt_multi_choice(format_names, label="Format(s)")

    extensions: set[str] = set()
    chosen_labels = []
    for i in indices:
        name = format_names[i]
        extensions.update(FILE_TYPES[category][name])
        chosen_labels.append(name)

    print(f"\n  Selected: {', '.join(chosen_labels)}")
    return extensions


def confirm(category: str, extensions: set[str], output_dir: Path) -> bool:
    header("Confirm & Run")
    print(f"  Category  : {category}")
    print(f"  Extensions: {', '.join(sorted(extensions))}")
    print(f"  Root scan : C:\\")
    print(f"  Output    : {output_dir}")
    print()
    answer = input("  Start extraction? [Y/n] › ").strip().lower()
    return answer in ("", "y", "yes")


def run_again() -> bool:
    print()
    answer = input("  Run another extraction? [Y/n] › ").strip().lower()
    return answer in ("", "y", "yes")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    # Windows-only guard
    if sys.platform != "win32":
        print("\n  ⚠  This script is designed for Windows (scans C:\\).")
        print("     On other platforms, edit ROOT below or pass a path as an argument.\n")

    ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("C:\\")

    while True:
        category   = pick_category()
        extensions = pick_formats(category)
        output_dir = get_output_dir(category)

        if confirm(category, extensions, output_dir):
            found, copied = scan_and_copy(ROOT, extensions, output_dir)

            print()
            separator("═")
            print(f"  ✅  Done!  {copied} / {found} file(s) copied to:")
            print(f"      {output_dir}")
            separator("═")
        else:
            print("\n  Extraction cancelled.")

        if not run_again():
            print("\n  Goodbye! 👋\n")
            input("  Press Enter to close the terminal... ")
            break


if __name__ == "__main__":
    main()
