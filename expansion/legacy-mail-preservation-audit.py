#!/usr/bin/env python3
"""Read-only inventory of legacy mail routing and stored-mail locations.

Run as root on NYC1 or SYD1 with --node nyc1 or --node syd1 respectively.
This never sends mail, changes configuration, walks message bodies, or prints
the contents of queue files or configuration lookup tables. It reports only
selected effective settings, exact catch-all map presence, queue summary,
and metadata for conventional mbox/Maildir storage locations. Absence from
these locations does not prove that other mail storage is empty.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys


VERSION = "1.0.1"
NODES = {
    "nyc1": ("fastping", ("fastping.it.com", "litehaus.online")),
    "syd1": ("primecrate", ("primercrate.rs",)),
}
KEYS = (
    "myhostname", "mydestination", "virtual_maps", "virtual_alias_domains",
    "virtual_alias_maps", "virtual_mailbox_domains", "virtual_mailbox_maps",
    "relay_domains", "mail_spool_directory", "home_mailbox", "mailbox_command",
    "mailbox_transport", "virtual_mailbox_base", "virtual_transport",
    "local_transport", "queue_directory",
)
MAP_KEYS = frozenset({"virtual_maps", "virtual_alias_maps", "virtual_mailbox_maps"})
LOCAL_MAP = re.compile(r"(?:proxy:)?(?:hash|btree|lmdb|cdb|dbm|texthash):/[A-Za-z0-9_./+\-]+\Z")
SAFE_TEXT = re.compile(r"[A-Za-z0-9_.,/@:$ +{}~%=\-]*\Z")
SAFE_PATH = re.compile(r"/[A-Za-z0-9_./+\-]*\Z")
PATH_ENV = "/usr/sbin:/usr/bin:/sbin:/bin"


def run(*args: str, timeout: int = 12) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=timeout, check=False,
            text=True, encoding="utf-8", errors="replace",
            env={"PATH": PATH_ENV, "LC_ALL": "C", "LANG": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return 124, ""
    return proc.returncode, proc.stdout


def safe_label(value: str) -> str:
    """Prevent terminal control characters or giant filenames in output."""
    clean = re.sub(r"[^A-Za-z0-9_.@+\-/]", "?", value)
    return clean[:180] + ("..." if len(clean) > 180 else "")


def public_setting(key: str, value: str) -> str:
    if re.search(r"(?i)password|passwd|secret|token|passphrase", value):
        return "[sensitive-looking value withheld]"
    if key == "mailbox_command":
        return "[configured; command withheld]" if value else "[not configured]"
    if key in MAP_KEYS:
        tokens = [part for part in re.split(r"[\s,]+", value) if part]
        if not tokens:
            return "[none]"
        if len(tokens) <= 8 and all(LOCAL_MAP.fullmatch(part) for part in tokens):
            return ", ".join(tokens)
        return "[configured; non-local or complex map details withheld]"
    if key == "virtual_alias_domains" and ":/" in value:
        return "[map-backed; details withheld]"
    if key in {"mail_spool_directory", "virtual_mailbox_base", "queue_directory"}:
        return value if SAFE_PATH.fullmatch(value) else "[non-simple path withheld]"
    if len(value) > 500 or not SAFE_TEXT.fullmatch(value):
        return "[non-simple value withheld]"
    return value or "[empty]"


def config() -> dict[str, str]:
    code, output = run("postconf", "-x", *KEYS)
    if code != 0:
        raise RuntimeError("postconf -x failed or timed out; configuration unknown")
    values: dict[str, str] = {}
    for line in output.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip()
    missing = sorted(set(KEYS) - values.keys())
    if missing:
        raise RuntimeError("postconf omitted expected settings: " + ", ".join(missing))
    print("\nSELECTED EFFECTIVE POSTFIX SETTINGS")
    for key in KEYS:
        print(f"{key}={public_setting(key, values[key])}")
    return values


def alias_lookups(values: dict[str, str], domains: tuple[str, ...]) -> None:
    print("\nEXACT CATCH-ALL ALIAS MAP LOOKUPS (targets withheld)")
    tokens = [part for part in re.split(r"[\s,]+", values["virtual_alias_maps"]) if part]
    local = [part for part in tokens if LOCAL_MAP.fullmatch(part)]
    if not local:
        print("No supported local indexed alias map; recipient handling needs separate review.")
        return
    if len(local) != len(tokens) or len(local) > 8:
        print("Some alias maps cannot be queried by this audit; findings are incomplete.")
    for table in local[:8]:
        print("Map: " + table)
        for domain in domains:
            status, result = run("postmap", "-q", "@" + domain, table, timeout=5)
            verdict = ("exact entry present" if status == 0 and result.strip() else
                       "no exact entry" if status == 1 and not result.strip() else
                       "lookup inconclusive")
            print(f"  @{domain}: {verdict}")
    print("These are exact lookups, not acceptance or delivery proofs.")


def queue_summary() -> None:
    print("\nPOSTFIX QUEUE SUMMARY")
    code, output = run("postqueue", "-p", timeout=20)
    if code:
        print("Queue status unavailable; do not infer an empty queue.")
    else:
        last = output.splitlines()[-1].strip() if output.splitlines() else ""
        print(last if last.startswith("-- ") or last == "Mail queue is empty" else
              "Queue summary format unrecognized; inspect locally without sharing message metadata.")


def dovecot_location() -> None:
    print("\nDOVECOT GLOBAL STORAGE HINT")
    code, output = run("systemctl", "is-active", "dovecot")
    if code != 0 or output.strip() != "active":
        print("Dovecot not active; its stored-mail location is not inferred.")
        return
    code, output = run("doveconf", "-h", "mail_location")
    if code:
        print("Dovecot mail_location unavailable.")
    else:
        print("mail_location=" + public_setting("mail_location", output.strip()))
        print("Per-user and namespace overrides are not inspected here.")


def mbox_directories(values: dict[str, str]) -> None:
    print("\nTRADITIONAL MBOX FILE METADATA (no message contents)")
    paths = {Path("/var/mail"), Path("/var/spool/mail")}
    spool = values["mail_spool_directory"]
    if SAFE_PATH.fullmatch(spool):
        paths.add(Path(spool))
    visited: set[str] = set()
    found = False
    for path in sorted(paths):
        resolved = str(path.resolve())
        if resolved in visited:
            continue
        visited.add(resolved)
        if not path.is_dir():
            continue
        print("Directory: " + safe_label(str(path)))
        try:
            for item in sorted(path.iterdir()):
                metadata = item.lstat()
                if stat.S_ISREG(metadata.st_mode):
                    found = True
                    print(f"  {safe_label(item.name)}: {metadata.st_size} bytes")
        except OSError:
            print("  listing incomplete: read or permission error")
    if not found:
        print("No top-level regular mbox files found in inspected directories.")


def report_maildir(path: Path) -> None:
    totals: dict[str, int | str] = {}
    for kind in ("new", "cur"):
        try:
            with os.scandir(path / kind) as entries:
                totals[kind] = sum(entry.is_file(follow_symlinks=False) for entry in entries)
        except OSError:
            totals[kind] = "unavailable"
    print(f"  {safe_label(str(path))}: new={totals['new']} cur={totals['cur']}")


def maildirs(values: dict[str, str]) -> None:
    print("\nMAILDIR METADATA (message filenames and bodies withheld)")
    found: set[str] = set()
    for account in pwd.getpwall():
        home = Path(account.pw_dir)
        if home != Path("/root") and (not home.is_absolute() or not home.is_relative_to("/home")):
            continue
        candidate = home / "Maildir"
        if candidate.is_dir():
            found.add(str(candidate))
    roots = [Path("/var/vmail")]
    base = values["virtual_mailbox_base"]
    if SAFE_PATH.fullmatch(base) and base not in {"/var/mail", "/var/spool/mail"}:
        roots.append(Path(base))
    scanned: set[str] = set()
    for root in roots:
        canonical = str(root.resolve())
        if canonical in scanned or not root.is_dir():
            continue
        scanned.add(canonical)
        visited = 0
        for current, dirs, _files in os.walk(root, topdown=True, followlinks=False):
            visited += 1
            depth = len(Path(current).relative_to(root).parts)
            if {"new", "cur"}.issubset(dirs):
                found.add(str(Path(current)))
                dirs[:] = []
            elif depth >= 5:
                dirs[:] = []
            if visited >= 5000:
                print("  scan limit reached under " + safe_label(str(root)) + "; listing incomplete")
                break
    for path in sorted(found):
        report_maildir(Path(path))
    if not found:
        print("No Maildir roots found in inspected conventional locations.")
    print("Other locations, nested folders, database-backed storage and backups are not assessed.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", required=True, choices=sorted(NODES))
    args = parser.parse_args()
    expected_hostname, domains = NODES[args.node]
    observed = socket.gethostname().split(".")[0].lower()
    print(f"LEGACY MAIL PRESERVATION AUDIT {VERSION} | {args.node} | observed host {safe_label(observed)}", flush=True)
    print("Read-only. No email, DNS writes, service restart, or message contents.")
    if observed != expected_hostname:
        print("STOPPED: unexpected host; no audit run.")
        return 2
    if os.geteuid() != 0:
        print("STOPPED: run with sudo to inspect all owned mailboxes accurately.")
        return 2
    try:
        values = config()
        alias_lookups(values, domains)
        queue_summary()
        dovecot_location()
        mbox_directories(values)
        maildirs(values)
    except (RuntimeError, OSError, ValueError) as exc:
        print("STOPPED: " + safe_label(str(exc)))
        return 2
    print("\nAUDIT COMPLETE: presence here does not prove domain delivery; absence does not prove no other stored mail.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Interrupted; no configuration was changed.")
        sys.exit(130)
