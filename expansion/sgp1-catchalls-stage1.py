#!/usr/bin/env python3
"""SGP1 catch-all receiving, stage 1. Python 3.10+, Linux, standard library.

sudo python3 sgp1-catchalls-stage1.py                 # inspect and show plan
sudo python3 sgp1-catchalls-stage1.py --apply         # back up, apply, verify
sudo python3 sgp1-catchalls-stage1.py --rollback latest

Adds one managed Postfix hash map and updates only virtual_alias_domains and
virtual_alias_maps in main.cf. Preserves the existing virtual map, master.cf,
Dovecot, credentials, DNS, TLS, and sender permissions. Sends no test mail.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile

VERSION = "1.0.0"
DOMAINS = (
    "80days.site", "analoglogic.blog", "blairboulevard.website", "botforum.dev",
    "dailystonks.org", "fastping.it.com", "gongle.us", "litehaus.online",
    "primercrate.rs", "lickyour.skin", "showmesome.skin", "showmeyour.skin",
    "showsome.skin", "specter.in.net", "stealingdatais.gay", "whispr.dev", "yt.cafe",
)
DESTINATION = "tom@localhost"
CONFIG = Path("/etc/postfix")
MAIN = CONFIG / "main.cf"
MAP = CONFIG / "unified-catchalls"
DB = CONFIG / "unified-catchalls.db"
ORIGINAL_MAP = "hash:/etc/postfix/virtual"
MANAGED_MAP = "hash:/etc/postfix/unified-catchalls"
BACKUPS = Path("/root/sgp1-catchalls-backups")
TARGETS = {"main.cf": MAIN, "unified-catchalls": MAP, "unified-catchalls.db": DB}
MARKER = "# Managed by sgp1-catchalls-stage1.py; all recipients -> tom@localhost\n"
EXPECTED_MAP = {"@" + domain: DESTINATION for domain in DOMAINS}
PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
ENV = {"PATH": PATH, "LC_ALL": "C", "LANG": "C"}
FIELDS = (
    "config_directory", "mail_version", "myhostname", "mydestination",
    "virtual_alias_domains", "virtual_alias_maps", "virtual_mailbox_domains",
    "relay_domains", "home_mailbox", "mailbox_transport", "local_transport",
    "alias_maps", "multi_instance_directories", "smtpd_relay_restrictions",
    "mynetworks", "content_filter", "smtpd_milters", "non_smtpd_milters",
)
DOMAIN = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\Z")


class Stop(RuntimeError):
    """An unsupported or failed condition that must not be guessed around."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Stop(message)


def command(name: str, *args: str, allowed: tuple[int, ...] = (0,)) -> tuple[int, str]:
    path = shutil.which(name, path=PATH)
    require(path is not None, f"Required tool is unavailable: {name}. Nothing will be installed automatically.")
    try:
        result = subprocess.run(
            [path, *args], stdin=subprocess.DEVNULL, capture_output=True,
            text=True, encoding="utf-8", errors="replace", check=False,
            timeout=30, env=ENV,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Stop(f"{name} could not finish ({type(error).__name__}).") from error
    require(result.returncode in allowed,
            f"{name} failed with exit {result.returncode}. Raw configuration diagnostics are withheld.")
    return result.returncode, result.stdout


def settings(directory: Path | None = None) -> dict[str, str]:
    args = ("-c", str(directory)) if directory else ()
    _, output = command("postconf", *args, "-x", *FIELDS)
    found = {}
    for line in output.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            found[key.strip()] = value.strip()
    require(set(FIELDS) <= set(found), "Postfix did not report every required setting.")
    return found


def items(value: str) -> list[str]:
    return [item for item in re.split(r"[\s,]+", value.strip()) if item]


def domain_items(value: str, label: str) -> list[str]:
    result = items(value)
    require(all(DOMAIN.fullmatch(x) and ".." not in x for x in result),
            f"{label} contains patterns or lookup tables; targeted review is required.")
    return result


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def snapshot(path: Path) -> tuple[dict, bytes | None]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"exists": False}, None
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
            f"Refusing non-regular, symlinked, or hard-linked file: {path}")
    require(info.st_size <= 32 * 1024 * 1024, f"File too large for this targeted change: {path}")
    data = path.read_bytes()
    return {"exists": True, "sha256": digest(data), "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid, "gid": info.st_gid}, data


def atomic_file(path: Path, data: bytes, metadata: dict) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".sgp1-mail-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fchown(stream.fileno(), metadata["uid"], metadata["gid"])
            os.fchmod(stream.fileno(), metadata["mode"])
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def private_json(path: Path, value: dict) -> None:
    atomic_file(path, (json.dumps(value, indent=2) + "\n").encode(),
                {"uid": 0, "gid": 0, "mode": 0o600})


def replace_setting(text: str, key: str, value: str) -> str:
    """Replace one main.cf logical setting, preserving unrelated text/comments."""
    lines = text.splitlines(keepends=True)
    hits = [i for i, line in enumerate(lines) if re.match(r"^" + re.escape(key) + r"\s*=", line)]
    require(len(hits) <= 1, f"Duplicate {key} settings require review before editing.")
    newline = "\r\n" if "\r\n" in text else "\n"
    replacement = f"{key} = {value}{newline}"
    if not hits:
        return text + (newline if text and not text.endswith("\n") else "") + replacement
    start = hits[0]
    stop = start + 1
    comments = []
    while stop < len(lines):
        line = lines[stop]
        if not line.strip() or line.lstrip().startswith("#"):
            comments.append(line)
            stop += 1
        elif line.startswith((" ", "\t")):
            stop += 1
        else:
            break
    return "".join(lines[:start] + [replacement] + comments + lines[stop:])


def map_entries(table: str) -> dict[str, str]:
    _, output = command("postmap", "-s", table)
    result = {}
    for line in output.splitlines():
        pair = line.split(None, 1)
        require(len(pair) == 2, "An alias-map entry could not be parsed safely.")
        key, value = pair
        require(key not in result, "Duplicate compiled alias-map key encountered.")
        result[key] = value.strip()
    return result


def inspect() -> dict:
    cfg = settings()
    require(cfg["config_directory"] == str(CONFIG), "Unexpected Postfix configuration directory.")
    require(cfg["myhostname"] == "mail.whispr.dev", "This is not the audited mail.whispr.dev configuration.")
    require(not cfg["multi_instance_directories"], "Multiple Postfix instances need a separate plan.")
    require(cfg["home_mailbox"] == "Maildir/" and not cfg["mailbox_transport"], "Mailbox transport changed since the audit.")
    require(cfg["local_transport"] == "local:mail.whispr.dev", "Local transport changed since the audit.")
    require(cfg["alias_maps"] == "hash:/etc/aliases", "Local alias configuration changed since the audit.")
    maps = items(cfg["virtual_alias_maps"])
    require(maps in ([ORIGINAL_MAP], [ORIGINAL_MAP, MANAGED_MAP]),
            "The virtual alias-map chain differs from the audited layout.")
    local = domain_items(cfg["mydestination"], "mydestination")
    require("localhost" in local, "localhost is not a local mail destination.")
    for field in ("mydestination", "virtual_mailbox_domains", "relay_domains"):
        overlap = set(domain_items(cfg[field], field)) & set(DOMAINS)
        require(not overlap, f"Requested domains overlap {field}: {', '.join(sorted(overlap))}")
    current_domains = domain_items(cfg["virtual_alias_domains"], "virtual_alias_domains")
    require("whispr.dev" in current_domains, "The existing whispr.dev virtual domain is missing.")
    require(items(cfg["smtpd_relay_restrictions"]) ==
            ["permit_mynetworks", "permit_sasl_authenticated", "defer_unauth_destination"],
            "Relay restrictions differ from the supplied audit; review them first.")
    command("postfix", "status")
    command("systemctl", "is-active", "dovecot")
    original = map_entries(ORIGINAL_MAP)
    require(original.get("@whispr.dev") == DESTINATION, "The existing whispr.dev catch-all target changed.")
    for key in (DESTINATION, "@localhost", "tom"):
        require(key not in original, f"The original virtual map rewrites {key}; terminal routing needs review.")
    for key, value in original.items():
        if "@" in key and key.rsplit("@", 1)[1].lower() in DOMAINS:
            require(value == DESTINATION, f"An existing alias for {key} has another destination; refusing to override it.")
    code, value = command("postalias", "-q", "tom", "hash:/etc/aliases", allowed=(0, 1))
    require(code == 1 and not value.strip(), "A local alias for tom exists; review its delivery path first.")
    try:
        account = pwd.getpwnam("tom")
    except KeyError as error:
        raise Stop("The local mailbox user tom was not found.") from error
    require(account.pw_uid != 0, "The mailbox user must not be root.")
    mailbox = Path(account.pw_dir) / "Maildir"
    require(all((mailbox / x).is_dir() for x in ("cur", "new", "tmp")), "tom's existing Maildir was not found.")
    require(not os.path.lexists(Path(account.pw_dir) / ".forward"), "tom has a .forward file; review it before modifying routes.")
    before = {name: snapshot(path)[0] for name, path in TARGETS.items()}
    require(before["main.cf"]["exists"] and before["main.cf"]["uid"] == 0
            and not before["main.cf"]["mode"] & 0o022,
            "main.cf must be root-owned and not writable by other users.")
    source = MAP.read_bytes() if before[MAP.name]["exists"] else None
    compiled = map_entries(MANAGED_MAP) if before[DB.name]["exists"] else None
    expected_source = (MARKER + "".join(f"@{d}\t{DESTINATION}\n" for d in DOMAINS)).encode()
    if source is not None or compiled is not None:
        require(source == expected_source and compiled == EXPECTED_MAP,
                "Managed map files exist but do not match this script; refusing to overwrite them.")
    domains = list(dict.fromkeys([*current_domains, *DOMAINS]))
    new_main = replace_setting(MAIN.read_bytes().decode("utf-8"), "virtual_alias_domains", ", ".join(domains))
    new_main = replace_setting(new_main, "virtual_alias_maps", f"{ORIGINAL_MAP}, {MANAGED_MAP}")
    watched = (CONFIG / "virtual", CONFIG / "virtual.db", CONFIG / "master.cf", Path("/etc/aliases"), Path("/etc/aliases.db"))
    return {"config": cfg, "before": before, "source": expected_source, "main": new_main.encode(),
            "domains": domains, "watch": {str(p): snapshot(p)[0] for p in watched},
            "no_op": maps == [ORIGINAL_MAP, MANAGED_MAP] and set(domains) == set(current_domains)
                     and source == expected_source and compiled == EXPECTED_MAP}


def verify_routes(expected_domains: list[str]) -> None:
    cfg = settings()
    require(domain_items(cfg["virtual_alias_domains"], "virtual_alias_domains") == expected_domains,
            "The installed virtual-domain list did not match the planned list.")
    require(items(cfg["virtual_alias_maps"]) == [ORIGINAL_MAP, MANAGED_MAP], "Installed alias-map chain differs.")
    require(map_entries(MANAGED_MAP) == EXPECTED_MAP, "Managed catch-all database verification failed.")
    original = map_entries(ORIGINAL_MAP)
    require(original.get("@whispr.dev") == DESTINATION, "The original whispr.dev route changed.")
    command("postfix", "status")
    command("systemctl", "is-active", "dovecot")


def safe_backup_directory(path: Path) -> None:
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077,
            f"Backup directory must be a private root-owned real directory: {path}")


def restore_files(directory: Path, manifest: dict, partial: bool) -> None:
    require(set(manifest["before"]) == set(TARGETS) and set(manifest["after"]) == set(TARGETS),
            "Invalid backup file set.")
    originals = {}
    for name, path in TARGETS.items():
        current, _ = snapshot(path)
        allowed = [manifest["after"][name]]
        if partial:
            allowed.append(manifest["before"][name])
        require(current in allowed, f"Rollback stopped: {path} changed outside this transaction.")
        prior = manifest["before"][name]
        if prior["exists"]:
            data = (directory / (name + ".before")).read_bytes()
            require(digest(data) == prior["sha256"], f"Backup checksum failed: {name}")
            originals[name] = data
    # Existing map files first; main.cf then switches the configuration back.
    for name in (MAP.name, DB.name, MAIN.name):
        prior = manifest["before"][name]
        if prior["exists"]:
            atomic_file(TARGETS[name], originals[name], prior)
    command("postfix", "check")
    command("postfix", "reload")
    for name, path in TARGETS.items():
        if not manifest["before"][name]["exists"]:
            with contextlib.suppress(FileNotFoundError):
                path.unlink()
    command("postfix", "status")


def rollback(name: str) -> None:
    safe_backup_directory(BACKUPS)
    if name == "latest":
        name = (BACKUPS / "latest").read_text(encoding="utf-8").strip()
    directory = Path(name)
    require(directory.is_absolute() and directory.parent == BACKUPS and directory.name not in (".", ".."),
            "Rollback must name a direct backup directory under " + str(BACKUPS))
    safe_backup_directory(directory)
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    require(manifest.get("format") == 1 and manifest.get("status") in ("prepared", "applying", "applied", "rolling-back"),
            "This backup is not an outstanding stage-1 transaction.")
    partial = manifest["status"] != "applied"
    manifest["status"] = "rolling-back"
    private_json(directory / "manifest.json", manifest)
    restore_files(directory, manifest, partial=partial)
    manifest["status"] = "rolled-back"
    private_json(directory / "manifest.json", manifest)
    print("ROLLBACK COMPLETE: the previous receiving configuration has been restored.")


def apply(plan: dict) -> None:
    if plan["no_op"]:
        verify_routes(plan["domains"])
        print("ALREADY CONFIGURED: all 17 catch-alls are present; no files changed or services reloaded.")
        return
    BACKUPS.mkdir(mode=0o700, exist_ok=True)
    safe_backup_directory(BACKUPS)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    directory = BACKUPS / stamp
    directory.mkdir(mode=0o700)
    print("Backup: " + str(directory), flush=True)
    for name, path in TARGETS.items():
        current, data = snapshot(path)
        require(current == plan["before"][name], f"Concurrent change detected: {path}")
        if data is not None:
            atomic_file(directory / (name + ".before"), data, {"uid": 0, "gid": 0, "mode": 0o600})
    with tempfile.TemporaryDirectory(prefix=".sgp1-mail-stage-", dir=CONFIG) as stage_name:
        stage = Path(stage_name)
        stage_main = stage / MAIN.name
        stage_map = stage / MAP.name
        stage_main.write_bytes(plan["main"])
        (stage / "master.cf").write_bytes((CONFIG / "master.cf").read_bytes())
        stage_map.write_bytes(plan["source"])
        os.chmod(stage_main, 0o600)
        os.chmod(stage_map, 0o600)
        command("postmap", "hash:" + str(stage_map))
        require(map_entries("hash:" + str(stage_map)) == EXPECTED_MAP, "Staged catch-all database differs.")
        staged = settings(stage)
        require(domain_items(staged["virtual_alias_domains"], "staged virtual_alias_domains") == plan["domains"],
                "Staged Postfix configuration did not parse as planned.")
        require(items(staged["virtual_alias_maps"]) == [ORIGINAL_MAP, MANAGED_MAP], "Staged alias-map chain differs.")
        data = {MAIN.name: plan["main"], MAP.name: plan["source"], DB.name: (stage / DB.name).read_bytes()}
        after = {}
        for name, payload in data.items():
            meta = plan["before"][name] if name == MAIN.name else {"mode": 0o644, "uid": 0, "gid": 0}
            after[name] = {"exists": True, "sha256": digest(payload), "mode": meta["mode"], "uid": meta["uid"], "gid": meta["gid"]}
        manifest = {"format": 1, "version": VERSION, "status": "prepared",
                    "before": plan["before"], "after": after, "domains": plan["domains"]}
        private_json(directory / "manifest.json", manifest)
        for name, path in TARGETS.items():
            require(snapshot(path)[0] == plan["before"][name], f"Concurrent change detected: {path}")
        for path, expected in plan["watch"].items():
            require(snapshot(Path(path))[0] == expected, "An existing routing file changed; run the plan again.")
        live_started = False
        try:
            manifest["status"] = "applying"
            private_json(directory / "manifest.json", manifest)
            live_started = True
            # Install the complete map before enabling it in main.cf.
            for name in (MAP.name, DB.name, MAIN.name):
                atomic_file(TARGETS[name], data[name], after[name])
            command("postfix", "check")
            command("postfix", "reload")
            verify_routes(plan["domains"])
            manifest["status"] = "applied"
            private_json(directory / "manifest.json", manifest)
            atomic_file(BACKUPS / "latest", (str(directory) + "\n").encode(), {"uid": 0, "gid": 0, "mode": 0o600})
        except (Exception, KeyboardInterrupt) as error:
            if live_started:
                print("Apply did not complete; attempting to restore the saved configuration.", flush=True)
                try:
                    manifest["status"] = "rolling-back"
                    private_json(directory / "manifest.json", manifest)
                    restore_files(directory, manifest, partial=True)
                    manifest["status"] = "failed-restored"
                    private_json(directory / "manifest.json", manifest)
                except (Exception, KeyboardInterrupt) as recovery:
                    raise Stop(f"Automatic rollback could not complete: {recovery}. Backup: {directory}") from error
                raise Stop(f"Apply failed; the previous configuration was restored. Cause: {error}") from error
            raise
    print("STAGE 1 COMPLETE: all 17 receiving domains and catch-all map entries are configured.")
    print("Postfix configuration checks and reload succeeded; Postfix and Dovecot report active.")
    print("This does not establish external delivery. DNS, sender identities, and mail authentication are next.")
    print("Rollback: sudo python3 sgp1-catchalls-stage1.py --rollback " + str(directory))


def interruption(signum: int, frame: object) -> None:
    raise KeyboardInterrupt(f"signal {signum}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--apply", action="store_true", help="Apply the reviewed receiving configuration.")
    actions.add_argument("--rollback", metavar="BACKUP_OR_LATEST", help="Restore a saved transaction if files have not drifted.")
    args = parser.parse_args()
    require(sys.platform == "linux" and sys.version_info >= (3, 10), "Run on Linux SGP1 with Python 3.10 or newer.")
    require(os.geteuid() == 0, "Run with sudo on SGP1.")
    # Lock the existing directory inode: the read-only plan creates no lock file.
    lock = os.open(CONFIG, os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise Stop("Another stage-1 operation is already running.") from error
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, interruption)
        if args.rollback:
            rollback(args.rollback)
            return 0
        plan = inspect()
        print(f"SGP1 CATCH-ALL RECEIVING {VERSION}")
        print("Confirmed existing route: @whispr.dev -> tom@localhost -> existing tom Maildir")
        print("Receiving domains: " + ", ".join(DOMAINS))
        print("New map: " + str(MAP))
        print("main.cf settings: virtual_alias_domains and virtual_alias_maps")
        print("Action: " + ("already configured" if plan["no_op"] else "prepare 17 catch-alls and reload Postfix"))
        if args.apply:
            apply(plan)
        else:
            print("PLAN ONLY: no files written and no services reloaded. Use --apply to perform this change.")
        return 0
    finally:
        os.close(lock)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Stop, OSError, ValueError, KeyError) as error:
        print("STOP: " + str(error), file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("STOP: interrupted. If live changes had started, check the rollback message above.", file=sys.stderr)
        raise SystemExit(130)
