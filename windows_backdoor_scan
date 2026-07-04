#!/usr/bin/env python3
"""
Windows Backdoor / Persistence Triage Scanner
==============================================

Purpose:
    Scans a Windows machine for common indicators associated with backdoors,
    malware persistence, and unauthorized remote access. This is a TRIAGE
    tool, not a guarantee of a clean system -- it surfaces things worth
    investigating, it does not replace a proper EDR/AV product or a trained
    incident responder.

Requirements:
    Python 3.8+ on Windows
    pip install psutil pywin32

Run as Administrator for full visibility (some registry hives, services,
and scheduled tasks are hidden from unprivileged users).

Note on false positives:
    A small, explicit whitelist (KNOWN_GOOD_PATH_FRAGMENTS and
    KNOWN_GOOD_WMI_NAMES near the top of this file) suppresses well-known
    Microsoft components (e.g. Windows Defender's own binaries under
    ProgramData, and a couple of built-in WMI subscriptions) so they don't
    drown out real findings. This whitelist is intentionally narrow --
    extend it carefully, since a whitelist that's too broad defeats the
    purpose of the scan.

Usage:
    python win_backdoor_scan.py                 # run all checks, print report
    python win_backdoor_scan.py --json out.json # also save machine-readable report
"""

import argparse
import ctypes
import json
import os
import subprocess
import sys
import winreg
from datetime import datetime

try:
    import psutil
except ImportError:
    print("Missing dependency: psutil. Install with: pip install psutil")
    sys.exit(1)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

SUSPICIOUS_PATH_FRAGMENTS = [
    r"\appdata\local\temp",
    r"\appdata\roaming",
    r"\windows\temp",
    r"\users\public",
    r"\programdata",
    r"\recycle.bin",
]

SUSPICIOUS_PROCESS_NAMES = {
    "nc.exe", "ncat.exe", "netcat.exe", "psexec.exe", "mimikatz.exe",
    "powersploit.exe", "cobaltstrike.exe", "meterpreter.exe",
}

# Common remote-access / tunneling ports worth flagging if unexpected
WATCH_PORTS = {4444, 4445, 1337, 31337, 6666, 6667, 8081, 9001, 12345}

# Known-legitimate path fragments that live under otherwise-"suspicious"
# parent directories (e.g. ProgramData). Anything matching one of these is
# treated as expected Windows/Microsoft behavior and NOT flagged, even
# though it also matches a SUSPICIOUS_PATH_FRAGMENTS entry above.
# This list intentionally stays narrow -- broadening it too far would
# reintroduce the blind spots it's meant to close.
KNOWN_GOOD_PATH_FRAGMENTS = [
    r"\programdata\microsoft\windows defender\platform",
    r"\programdata\microsoft\windows defender\definition updates",
    r"\programdata\microsoft\windows defender\network inspection system",
    r"\programdata\microsoft\microsoft antimalware",
]

# desktop.ini is a benign Windows folder-customization file that appears in
# almost every folder on the system -- never worth flagging on its own.
BENIGN_FILENAMES = {"desktop.ini"}

# Known Windows-native WMI event subscriptions. Real attacker persistence
# uses this same mechanism, so we don't blanket-whitelist the technique --
# only these specific, well-documented, built-in names.
KNOWN_GOOD_WMI_NAMES = {
    "scm event log filter",
    "bvtfilter",
}


def matches_known_good(path_lower: str) -> bool:
    """True if a lowercased path matches a documented, expected Microsoft
    location. Used to suppress false positives from the broader
    SUSPICIOUS_PATH_FRAGMENTS heuristic."""
    return any(frag in path_lower for frag in KNOWN_GOOD_PATH_FRAGMENTS)


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run_cmd(cmd: str) -> str:
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30
        )
        return result.stdout
    except Exception as e:
        return f"[error running command: {e}]"


def add_finding(findings: list, category: str, severity: str, detail: str):
    findings.append({
        "category": category,
        "severity": severity,  # info | low | medium | high
        "detail": detail,
    })


# ----------------------------------------------------------------------
# Checks
# ----------------------------------------------------------------------

def check_registry_run_keys(findings: list):
    """Autostart entries in Run / RunOnce for HKLM and HKCU."""
    hives = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    for hive, path in hives:
        try:
            key = winreg.OpenKey(hive, path)
        except FileNotFoundError:
            continue
        try:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                except OSError:
                    break
                i += 1
                value_l = str(value).lower()
                sev = "info"
                if any(frag in value_l for frag in SUSPICIOUS_PATH_FRAGMENTS) \
                        and not matches_known_good(value_l):
                    sev = "medium"
                add_finding(
                    findings, "autostart_registry", sev,
                    f"{path} -> {name} = {value}"
                )
        finally:
            winreg.CloseKey(key)


def check_startup_folders(findings: list):
    """Files dropped in user/global Startup folders."""
    candidates = [
        os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                     r"Microsoft\Windows\Start Menu\Programs\StartUp"),
        os.path.join(os.environ.get("APPDATA", ""),
                     r"Microsoft\Windows\Start Menu\Programs\Startup"),
    ]
    for folder in candidates:
        if not folder or not os.path.isdir(folder):
            continue
        for f in os.listdir(folder):
            if f.lower() in BENIGN_FILENAMES:
                continue
            full = os.path.join(folder, f)
            add_finding(findings, "startup_folder", "low", f"Startup item: {full}")


def check_scheduled_tasks(findings: list):
    """List scheduled tasks; flag ones running from suspicious paths or with
    encoded PowerShell commands."""
    output = run_cmd("schtasks /query /fo LIST /v")
    tasks = output.split("\n\n")
    for task in tasks:
        low = task.lower()
        if "taskname" not in low:
            continue
        name_line = next((l for l in task.splitlines() if l.lower().startswith("taskname")), "")
        run_line = next((l for l in task.splitlines() if l.lower().startswith("task to run")), "")
        sev = "info"
        reasons = []
        if any(frag in low for frag in SUSPICIOUS_PATH_FRAGMENTS) \
                and not matches_known_good(low):
            sev = "medium"
            reasons.append("runs from a suspicious path")
        if "-enc" in low or "-encodedcommand" in low or "frombase64string" in low:
            sev = "high"
            reasons.append("uses encoded/obfuscated PowerShell")
        if "hidden" in low:
            sev = "medium"
            reasons.append("hidden window style")
        if reasons:
            add_finding(
                findings, "scheduled_task", sev,
                f"{name_line.strip()} | {run_line.strip()} | flags: {', '.join(reasons)}"
            )


def check_services(findings: list):
    """Enumerate services, flag ones running from unusual paths or unsigned binaries."""
    output = run_cmd(
        'powershell -NoProfile -Command '
        '"Get-CimInstance Win32_Service | Select-Object Name,DisplayName,PathName,StartMode,State '
        '| ConvertTo-Json"'
    )
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            data = [data]
    except Exception:
        add_finding(findings, "services", "info", "Could not parse service list via PowerShell.")
        return

    for svc in data:
        path = (svc.get("PathName") or "").strip('"')
        low = path.lower()
        if not path:
            continue
        sev = "info"
        reasons = []
        if any(frag in low for frag in SUSPICIOUS_PATH_FRAGMENTS) \
                and not matches_known_good(low):
            sev = "medium"
            reasons.append("binary in a suspicious path")
        exe_path = path.split(".exe")[0] + ".exe" if ".exe" in low else path
        exe_path = exe_path.strip()
        if reasons:
            add_finding(
                findings, "service", sev,
                f"{svc.get('Name')} ({svc.get('DisplayName')}) -> {path} "
                f"[State={svc.get('State')}] flags: {', '.join(reasons)}"
            )


def check_wmi_persistence(findings: list):
    """WMI Event Subscriptions are a classic fileless persistence technique.
    A handful of subscription names are built into Windows itself (see
    KNOWN_GOOD_WMI_NAMES) and are suppressed; anything else is flagged as
    high severity since legitimate third-party use of this mechanism is
    rare and attacker use of it is common."""
    output = run_cmd(
        'powershell -NoProfile -Command '
        '"Get-WmiObject -Namespace root\\subscription -Class __EventFilter | '
        'Select-Object Name,Query | ConvertTo-Json"'
    )
    output2 = run_cmd(
        'powershell -NoProfile -Command '
        '"Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer | '
        'Select-Object Name,CommandLineTemplate | ConvertTo-Json"'
    )
    for label, out in [("EventFilter", output), ("CommandLineEventConsumer", output2)]:
        out = out.strip()
        if not out or out in ("null", ""):
            continue
        try:
            parsed = json.loads(out)
            if isinstance(parsed, dict):
                parsed = [parsed]
        except Exception:
            parsed = None

        if parsed is None:
            # Couldn't parse -- surface it rather than silently drop it.
            add_finding(
                findings, "wmi_persistence", "high",
                f"Found {label} subscription(s) -- inspect manually: {out[:500]}"
            )
            continue

        for entry in parsed:
            entry_name = str(entry.get("Name", "")).strip().lower()
            if entry_name in KNOWN_GOOD_WMI_NAMES:
                add_finding(
                    findings, "wmi_persistence", "info",
                    f"{label} '{entry.get('Name')}' matches known Windows-native "
                    f"subscription -- not flagged."
                )
                continue
            add_finding(
                findings, "wmi_persistence", "high",
                f"Unrecognized {label} subscription -- inspect manually: {json.dumps(entry)[:500]}"
            )


def check_processes(findings: list):
    """Running processes: unusual paths, no signature info easily available
    without extra tooling, so we flag by name/path heuristics."""
    for proc in psutil.process_iter(["pid", "name", "exe", "ppid"]):
        try:
            info = proc.info
            name = (info.get("name") or "").lower()
            exe = (info.get("exe") or "").lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        if name in SUSPICIOUS_PROCESS_NAMES:
            add_finding(
                findings, "process", "high",
                f"PID {info.get('pid')} name={name} exe={exe} "
                f"(matches known offensive-tool name)"
            )
            continue

        if exe and any(frag in exe for frag in SUSPICIOUS_PATH_FRAGMENTS) \
                and not matches_known_good(exe):
            add_finding(
                findings, "process", "medium",
                f"PID {info.get('pid')} name={name} running from suspicious path: {exe}"
            )


def check_network_connections(findings: list):
    """Established/listening connections; flag watch-listed ports and
    connections to raw IPs on high ports."""
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        add_finding(
            findings, "network", "info",
            "Access denied enumerating connections -- rerun as Administrator."
        )
        return

    for c in conns:
        if not c.raddr:
            continue
        rport = c.raddr.port
        sev = "info"
        reasons = []
        if rport in WATCH_PORTS:
            sev = "medium"
            reasons.append("remote port on common backdoor/C2 watch-list")
        if c.status == "ESTABLISHED" and reasons:
            try:
                pname = psutil.Process(c.pid).name() if c.pid else "?"
            except Exception:
                pname = "?"
            add_finding(
                findings, "network", sev,
                f"PID {c.pid} ({pname}) {c.laddr} -> {c.raddr} [{c.status}] "
                f"flags: {', '.join(reasons)}"
            )


def check_hosts_file(findings: list):
    hosts_path = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"), r"System32\drivers\etc\hosts"
    )
    if not os.path.isfile(hosts_path):
        return
    with open(hosts_path, "r", errors="ignore") as f:
        lines = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    if lines:
        add_finding(
            findings, "hosts_file", "medium",
            f"Non-default entries present in hosts file ({len(lines)} lines): "
            f"{'; '.join(lines[:10])}"
        )


def check_local_users(findings: list):
    output = run_cmd(
        'powershell -NoProfile -Command '
        '"Get-LocalUser | Select-Object Name,Enabled,PasswordRequired | ConvertTo-Json"'
    )
    admins_output = run_cmd(
        'powershell -NoProfile -Command '
        '"Get-LocalGroupMember -Group Administrators | Select-Object Name,ObjectClass | ConvertTo-Json"'
    )
    add_finding(findings, "local_users", "info", f"Local users: {output.strip()[:1000]}")
    add_finding(findings, "local_admins", "info", f"Administrators group members: {admins_output.strip()[:1000]}")


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Windows backdoor/persistence triage scanner")
    parser.add_argument("--json", help="Path to write a JSON report", default=None)
    args = parser.parse_args()

    if os.name != "nt":
        print("This script must be run on Windows.")
        sys.exit(1)

    if not is_admin():
        print("[!] Not running as Administrator -- some checks (services, some registry "
              "hives, some connections) may be incomplete. Consider re-running elevated.\n")

    findings = []
    checks = [
        ("Registry Run keys", check_registry_run_keys),
        ("Startup folders", check_startup_folders),
        ("Scheduled tasks", check_scheduled_tasks),
        ("Services", check_services),
        ("WMI event subscriptions", check_wmi_persistence),
        ("Running processes", check_processes),
        ("Network connections", check_network_connections),
        ("Hosts file", check_hosts_file),
        ("Local users/admins", check_local_users),
    ]

    print(f"Windows Backdoor Triage Scan -- {datetime.now().isoformat()}\n" + "=" * 60)
    for label, fn in checks:
        print(f"[*] Running check: {label}")
        try:
            fn(findings)
        except Exception as e:
            add_finding(findings, label, "info", f"Check failed to run: {e}")

    print("\n" + "=" * 60)
    print("REPORT")
    print("=" * 60)

    sev_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 4))

    high = [f for f in findings if f["severity"] == "high"]
    medium = [f for f in findings if f["severity"] == "medium"]
    low = [f for f in findings if f["severity"] == "low"]
    info = [f for f in findings if f["severity"] == "info"]

    print(f"\nHIGH severity findings: {len(high)}")
    for f in high:
        print(f"  [HIGH]   ({f['category']}) {f['detail']}")

    print(f"\nMEDIUM severity findings: {len(medium)}")
    for f in medium:
        print(f"  [MEDIUM] ({f['category']}) {f['detail']}")

    print(f"\nLOW severity findings: {len(low)}")
    for f in low:
        print(f"  [LOW]    ({f['category']}) {f['detail']}")

    print(f"\nINFO items: {len(info)} (see JSON report for full detail if saved)")

    if not high and not medium and not low:
        print("\nNo strong indicators found. This does NOT guarantee a clean system --")
        print("it means nothing on this checklist stood out. Consider a full AV/EDR scan too.")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({
                "scan_time": datetime.now().isoformat(),
                "findings": findings,
            }, f, indent=2)
        print(f"\nFull JSON report written to: {args.json}")


if __name__ == "__main__":
    main()
