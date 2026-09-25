#!/usr/bin/env python3
"""Receiving-only yt.cafe MX pilot, Python 3.10+, standard library only.

Run locally on Windows; no SSH, sudo, package installs or email sending.
  python sgp1-yt-cafe-mx-pilot.py                 # fresh read + local backup
  python sgp1-yt-cafe-mx-pilot.py --local-check   # backup write check, no token/DNS
  python sgp1-yt-cafe-mx-pilot.py --apply         # add ONE apex MX if absent
  python sgp1-yt-cafe-mx-pilot.py --status FOLDER # inspect a saved operation
  python sgp1-yt-cafe-mx-pilot.py --rollback FOLDER

Cloudflare user token: Zone / Zone / Read and Zone / DNS / Edit for yt.cafe.
DNS Read suffices for preview/status. The token is entered without echo,
sent only to api.cloudflare.com over verified HTTPS, and never saved.
Backups contain private DNS data; share terminal output, not JSON files.

Writes are limited to creating MX yt.cafe -> 10 mail.whispr.dev (TTL 300),
or deleting that same, unchanged, owned record during explicit rollback.
An already-correct MX is preserved; any other existing MX blocks this pilot.
POST and DELETE are never automatically retried. Keep the printed backup
folder if interrupted: --status reconciles an uncertain operation by ID
and its unique comment. --rollback requires the original local journal.

DNS edits are not atomic with other administrators' edits. Fresh reads and
postchecks detect drift; avoid simultaneous edits to yt.cafe's mail records.
Public checks use a recursive resolver and can be cached. This tool cannot
prove global propagation or delivery; verify an ordinary incoming message.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import datetime as dt
import getpass
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
import warnings

VERSION = "1.0.2"
DOMAIN = "yt.cafe"
MAIL_HOST = "mail.whispr.dev"
EXPECTED_IPV4 = "68.183.227.135"
API_BASE = "https://api.cloudflare.com/client/v4"
DNS_BASE = "https://cloudflare-dns.com/dns-query"
MAX_BODY = 8 * 1024 * 1024
MARKER_PREFIX = "sgp1-yt-cafe-mx-pilot:"
DESIRED = {"type": "MX", "name": DOMAIN, "content": MAIL_HOST,
           "priority": 10, "ttl": 300, "proxied": False}


class PilotError(Exception):
    """A redacted, user-facing error; never include credentials/raw HTTP bodies."""


def norm(value: object) -> str:
    return str(value).lower().rstrip(".")


def valid_id(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{32}", value) is not None


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PilotError("HTTP redirect refused; credentials were not forwarded.")


def request_json(url: str, method: str = "GET", token: str | None = None,
                 body: dict | None = None) -> dict:
    # No retries: a write can succeed even when its response is lost.
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc not in ("api.cloudflare.com", "cloudflare-dns.com"):
        raise PilotError("Unexpected HTTPS destination refused.")
    if token is not None and parsed.netloc != "api.cloudflare.com":
        raise PilotError("Credential use outside the Cloudflare API refused.")
    headers = {"Accept": "application/json" if token else "application/dns-json",
               "User-Agent": "sgp1-yt-cafe-mx-pilot/" + VERSION}
    if token:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, method=method, headers=headers,
                                 data=json.dumps(body).encode("utf-8") if body is not None else None)
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=20) as response:
            raw = response.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise PilotError("HTTPS response exceeded the size limit.")
        result = json.loads(raw)
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
        hint = " Check token permissions and scope." if status in (401, 403) else ""
        raise PilotError(f"HTTPS status {status}.{hint}") from None
    except (urllib.error.URLError, OSError):
        raise PilotError("HTTPS connection, TLS verification or response failed.") from None
    except (ValueError, UnicodeError):
        raise PilotError("HTTPS returned invalid JSON.") from None
    if not isinstance(result, dict):
        raise PilotError("Unexpected JSON response shape.")
    return result


class Cloudflare:
    def __init__(self, token: str):
        self._token = token
        self.zone_id: str | None = None

    def call(self, method: str, path: str, params: dict | None = None,
             body: dict | None = None) -> dict:
        base = f"/zones/{self.zone_id}/dns_records" if self.zone_id else ""
        allowed = (method == "GET" and path == "/zones" and (params or {}).get("name") == DOMAIN)
        allowed |= bool(base and path == base and method in ("GET", "POST"))
        allowed |= bool(base and method == "DELETE" and path.startswith(base + "/")
                        and valid_id(path[len(base) + 1:]))
        if not allowed:
            raise PilotError("API endpoint outside the pilot scope refused.")
        if method == "POST":
            marker = (body or {}).get("comment", "")
            if (body != {**DESIRED, "comment": marker}
                    or not marker.startswith(MARKER_PREFIX)
                    or not valid_id(marker[len(MARKER_PREFIX):])):
                raise PilotError("Unexpected DNS write refused.")
        url = API_BASE + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = request_json(url, method, self._token, body)
        if data.get("success") is not True:
            codes = [str(e["code"]) for e in data.get("errors", [])
                     if isinstance(e, dict) and type(e.get("code")) is int]
            raise PilotError("Cloudflare rejected the request (codes: " +
                             (", ".join(codes) or "unknown") + ").")
        return data

    def listing(self, path: str, params: dict) -> list[dict]:
        rows: list[dict] = []
        seen: set[str] = set()
        requested_page_size = 50
        for page in range(1, 1001):
            data = self.call("GET", path, {**params, "page": page,
                                           "per_page": requested_page_size})
            batch, info = data.get("result"), data.get("result_info")
            if not isinstance(batch, list) or not isinstance(info, dict):
                raise PilotError("Missing records or pagination metadata.")
            page_size = info.get("per_page", requested_page_size)
            if (info.get("page") != page or type(page_size) is not int
                    or not 1 <= page_size <= requested_page_size
                    or len(batch) > page_size):
                raise PilotError("Invalid pagination metadata.")
            for row in batch:
                if not isinstance(row, dict) or not valid_id(row.get("id")) or row["id"] in seen:
                    raise PilotError("Invalid or repeated record in API listing.")
                rows.append(row)
                seen.add(row["id"])
            # An API count can lag a recent DNS write or describe an unfiltered
            # set. A short final page, rather than total_count, ends a listing.
            if len(batch) < page_size:
                return rows
        raise PilotError("API pagination limit reached.")

    def zone(self) -> dict:
        zones = self.listing("/zones", {"name": DOMAIN})
        if len(zones) != 1 or norm(zones[0].get("name")) != DOMAIN:
            raise PilotError("Expected one accessible exact yt.cafe zone; check token scope.")
        zone = zones[0]
        if zone.get("status") != "active" or zone.get("type") != "full":
            raise PilotError("yt.cafe is not an active full zone; review before changing DNS.")
        if not valid_id((zone.get("account") or {}).get("id")):
            raise PilotError("Missing valid account identity.")
        self.zone_id = zone["id"]
        return zone

    def records(self) -> list[dict]:
        rows = self.listing(f"/zones/{self.zone_id}/dns_records", {})
        for row in rows:
            name = norm(row.get("name"))
            if not (name == DOMAIN or name.endswith("." + DOMAIN)) or not isinstance(row.get("type"), str):
                raise PilotError("Unexpected record outside yt.cafe; snapshot not trusted.")
        return rows

    def create(self, marker: str) -> dict:
        return self.call("POST", f"/zones/{self.zone_id}/dns_records",
                         body={**DESIRED, "comment": marker}).get("result", {})

    def delete(self, record_id: str) -> None:
        data = self.call("DELETE", f"/zones/{self.zone_id}/dns_records/{record_id}")
        if (data.get("result") or {}).get("id") != record_id:
            raise PilotError("Delete response did not identify the requested record.")


def exact(rows: list[dict], name: str, kind: str) -> list[dict]:
    return [r for r in rows if norm(r.get("name")) == name and r.get("type") == kind]


def desired_route(record: dict) -> bool:
    return (record.get("type") == "MX" and norm(record.get("name")) == DOMAIN
            and norm(record.get("content")) == MAIL_HOST
            and record.get("priority") == 10 and record.get("proxied", False) is False)


def plan(rows: list[dict]) -> str:
    mx = exact(rows, DOMAIN, "MX")
    if mx:
        if len(mx) == 1 and desired_route(mx[0]):
            return "KEEP"
        raise PilotError("Unexpected existing yt.cafe MX set. Pilot stopped without replacing it.")
    if exact(rows, DOMAIN, "CNAME"):
        raise PilotError("Apex CNAME found; review before adding MX.")
    if any(norm(r.get("name")) == "_mta-sts." + DOMAIN for r in rows):
        raise PilotError("MTA-STS record found; review its mail-server policy before cutover.")
    return "ADD"


def dns_answers(name: str, kind: int) -> list[str]:
    data = request_json(DNS_BASE + "?" + urllib.parse.urlencode({"name": name, "type": kind}))
    if data.get("Status") != 0 or data.get("TC") is not False:
        raise PilotError("Public DNS returned an error or incomplete answer.")
    rows = data.get("Answer", [])
    if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
        raise PilotError("Malformed public DNS answer.")
    if any(r.get("type") == 5 for r in rows) and kind != 5:
        raise PilotError("Unexpected public CNAME chain.")
    return [str(r.get("data", "")) for r in rows if r.get("type") == kind and norm(r.get("name")) == name]


def public_precheck(zone: dict) -> None:
    delegated = {norm(v) for v in dns_answers(DOMAIN, 2)}
    assigned = {norm(v) for v in zone.get("name_servers", [])}
    if not assigned or delegated != assigned:
        raise PilotError("Public nameservers do not match this Cloudflare zone.")
    if (set(dns_answers(MAIL_HOST, 1)) != {EXPECTED_IPV4}
            or dns_answers(MAIL_HOST, 28) or dns_answers(MAIL_HOST, 5)):
        raise PilotError("Mail host DNS differs from the tested IPv4-only destination.")
    print("Public DNS: zone nameservers match; mail.whispr.dev -> 68.183.227.135.")


def public_mx_report() -> None:
    try:
        observed = [v.split() for v in dns_answers(DOMAIN, 15)]
        match = (len(observed) == 1 and len(observed[0]) == 2
                 and observed[0][0] == "10" and norm(observed[0][1]) == MAIL_HOST)
        print("Public MX: observed 10 mail.whispr.dev (recursive resolver)." if match else
              "Public MX: not yet observed at this recursive resolver; cached answers may persist.")
    except PilotError:
        print("Public MX: check unavailable; this does not undo the verified API change.")
    print("DNS caches vary; this check does not prove global propagation or mailbox delivery.")


def atomic_json(path: Path, value: dict) -> None:
    fd, temporary = tempfile.mkstemp(prefix=path.name + "-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=2, ensure_ascii=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def os_error_code(exc: OSError) -> str:
    code = getattr(exc, "winerror", None) or exc.errno
    return "OS error " + (str(code) if code is not None else "unknown")


def writable_backup_root() -> Path:
    """Prove local journal writes before accepting credentials or changing DNS."""
    home = Path.home()
    candidates = (home / "sgp1-mail-dns-backups",
                  home / "AppData" / "Local" / "sgp1-mail-dns-backups")
    errors = []
    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True, mode=0o700)
            with tempfile.TemporaryFile(dir=candidate) as probe:
                probe.write(b"pilot backup write check\n")
                probe.flush()
                os.fsync(probe.fileno())
            if candidate != candidates[0]:
                print("Original backup directory is not writable; using: " + str(candidate))
            else:
                print("Backup directory writable: " + str(candidate))
            return candidate
        except OSError as exc:
            errors.append(str(candidate) + " (" + os_error_code(exc) + ")")
    raise PilotError("Cannot create a private DNS backup in either profile folder: " +
                     "; ".join(errors) + ". DNS was not changed.")


@contextmanager
def local_lock():
    """Keep the process lock independent of any existing DNS backup folder."""
    lock_path = Path(tempfile.gettempdir()) / "sgp1-yt-cafe-mx-pilot.lock"
    try:
        handle = lock_path.open("a+b")
    except OSError as exc:
        raise PilotError("Cannot open local pilot lock at " + str(lock_path) +
                         " (" + os_error_code(exc) + "). DNS was not changed.") from None
    with handle:
        if handle.tell() == 0:
            try:
                handle.write(b"0")
                handle.flush()
            except OSError as exc:
                raise PilotError("Cannot initialize local pilot lock (" + os_error_code(exc) +
                                 "). DNS was not changed.") from None
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise PilotError("Cannot acquire local pilot lock (" + os_error_code(exc) +
                             "); another run or local access policy may be responsible.") from None
        try:
            yield
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def save_state(folder: Path, state: dict, phase: str) -> None:
    state["phase"], state["updated_at"] = phase, now()
    atomic_json(folder / "transaction.json", state)


def load_state(folder: Path) -> dict:
    try:
        raw = (folder / "transaction.json").read_bytes()
        if len(raw) > MAX_BODY:
            raise ValueError()
        state = json.loads(raw)
        valid = (state["schema"] == 1 and state["program"] == "sgp1-yt-cafe-mx-pilot"
                 and state["domain"] == DOMAIN and valid_id(state["transaction_id"])
                 and state["marker"] == MARKER_PREFIX + state["transaction_id"]
                 and state["desired"] == DESIRED and valid_id(state["zone_id"])
                 and valid_id(state["account_id"])
                 and state["phase"] in ("preview", "prepared", "no_change", "create_pending",
                                         "created", "complete", "delete_pending", "rolled_back")
                 and (state.get("created_id") is None or valid_id(state["created_id"])))
        if not valid or not isinstance(state["before_records"], list):
            raise ValueError()
        if state["phase"] not in ("preview", "prepared", "no_change") and plan(state["before_records"]) != "ADD":
            raise ValueError()
        return state
    except (OSError, ValueError, TypeError, KeyError, PilotError):
        raise PilotError("Cannot trust this pilot transaction.json; use the original backup folder.") from None


def fingerprint(record: dict) -> dict:
    keys = ("id", "type", "name", "content", "priority", "ttl", "proxied", "comment",
            "tags", "settings", "created_on", "modified_on", "comment_modified_on", "tags_modified_on")
    result = {k: record.get(k) for k in keys}
    result["name"], result["content"] = norm(result["name"]), norm(result["content"])
    return result


def owned_record(rows: list[dict], state: dict) -> dict | None:
    record_id = state.get("created_id")
    matches = [r for r in rows if r["id"] == record_id or r.get("comment") == state["marker"]]
    if not matches:
        return None
    if len(matches) != 1:
        raise PilotError("Conflicting pilot record identities; no deletion allowed.")
    record = matches[0]
    if (not desired_route(record) or record.get("ttl") != 300
            or record.get("comment") != state["marker"]
            or (record_id is not None and record["id"] != record_id)
            or record.get("locked") or (record.get("meta") or {}).get("managed_by_apps")
            or (state.get("created_record") is not None
                and fingerprint(record) != fingerprint(state["created_record"]))):
        raise PilotError("Pilot record was changed or its ownership cannot be verified; no deletion allowed.")
    return record


def commands(folder: Path) -> None:
    def quote(value: object) -> str:
        return "'" + str(value).replace("'", "''") + "'"
    script = quote(Path(__file__).resolve())
    print("Backup: " + str(folder))
    print("Status: python " + script + " --status " + quote(folder))
    print("Rollback: python " + script + " --rollback " + quote(folder))


def start(api: Cloudflare, root: Path, apply: bool) -> int:
    zone = api.zone()
    rows = api.records()
    transaction_id = uuid.uuid4().hex
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    folder = root / ("pilot-yt-cafe-" + stamp + "-" + transaction_id[:10])
    folder.mkdir(mode=0o700)
    state = {"schema": 1, "program": "sgp1-yt-cafe-mx-pilot", "version": VERSION,
             "domain": DOMAIN, "transaction_id": transaction_id,
             "marker": MARKER_PREFIX + transaction_id, "desired": DESIRED,
             "zone_id": zone["id"], "account_id": zone["account"]["id"],
             "created_at": now(), "before_records": rows, "zone": zone,
             "created_id": None, "created_record": None}
    save_state(folder, state, "prepared" if apply else "preview")
    commands(folder)
    print(f"Saved {len(rows)} yt.cafe DNS records locally. Keep transaction.json private.")
    action = plan(rows)
    print("Plan: " + ("KEEP existing MX and its TTL/metadata." if action == "KEEP" else
                       "ADD MX yt.cafe -> 10 mail.whispr.dev, TTL 300."))
    if action == "KEEP":
        save_state(folder, state, "no_change")
        print("ALREADY CONFIGURED: no DNS changes; this run owns no record to roll back.")
        public_mx_report()
        return 0
    public_precheck(zone)
    if not apply:
        print("PREVIEW COMPLETE: no DNS changes. Use --apply to make the displayed change.")
        return 0
    # Recheck the same zone and all captured records immediately before the write.
    fresh_zone = api.zone()
    fresh_rows = api.records()
    if (fresh_zone["id"] != state["zone_id"] or fresh_zone["account"]["id"] != state["account_id"]
            or sorted(fresh_rows, key=lambda r: r["id"]) != sorted(rows, key=lambda r: r["id"])):
        raise PilotError("DNS changed after the backup; stopped before writing. Rerun for a fresh plan.")
    save_state(folder, state, "create_pending")
    print("Creating the single yt.cafe MX record...", flush=True)
    try:
        created = api.create(state["marker"])
        if not isinstance(created, dict) or not valid_id(created.get("id")):
            raise PilotError("Create response did not contain a valid record ID.")
        state["created_id"] = created["id"]
        owned_record([created], state)
        state["created_record"] = created
        save_state(folder, state, "created")
        after = api.records()
        owned = owned_record(after, state)
        if owned is None or len(exact(after, DOMAIN, "MX")) != 1:
            raise PilotError("Postcheck did not find exactly the intended owned MX.")
        state["after_records"] = after
        save_state(folder, state, "complete")
    except (Exception, KeyboardInterrupt) as exc:
        print("APPLY NOT FULLY VERIFIED: the write may have reached Cloudflare. No retry was made.")
        if isinstance(exc, PilotError):
            print(str(exc))
        print("Run the Status command above before retrying or editing DNS.")
        return 3
    print("PILOT COMPLETE: Cloudflare now has MX yt.cafe -> 10 mail.whispr.dev (TTL 300).")
    public_mx_report()
    print("Next: verify public-MX delivery to a fresh @yt.cafe address in the tom@whispr.dev inbox.")
    print("Use an existing external mail account if available. The old direct-SMTP test bypasses MX.")
    return 0


def recover(api: Cloudflare, folder: Path, rollback: bool) -> int:
    state = load_state(folder)
    commands(folder)
    zone = api.zone()
    if zone["id"] != state["zone_id"] or zone["account"]["id"] != state["account_id"]:
        raise PilotError("Saved zone/account identity differs from the live zone; stopped.")
    rows = api.records()
    print("Saved operation phase: " + state["phase"])
    if state["phase"] in ("preview", "prepared", "no_change"):
        print("This operation never submitted a DNS write; there is nothing to roll back.")
        return 0
    record = owned_record(rows, state)
    if record is None:
        if state["created_id"] is None or state["phase"] not in ("delete_pending", "rolled_back"):
            print("The owned record is not in this API listing; its absence is not yet verified.")
            print("No DNS changes made. Repeat Status later; do not run Apply again.")
            return 3
        original_ids = {r["id"] for r in state["before_records"]}
        if not original_ids.issubset({r["id"] for r in rows}):
            raise PilotError("Other original DNS records are missing from the API listing; "
                             "cannot verify rollback from this read.")
        print("The recorded pilot record is absent; no deletion needed.")
        if rollback:
            save_state(folder, state, "rolled_back")
        if exact(rows, DOMAIN, "MX"):
            print("Other MX records exist; preserved. The pre-pilot MX state is not restored.")
        else:
            print("Cloudflare currently has no explicit apex MX, matching the pre-pilot MX state.")
        return 0
    # When a POST reply was lost, the saved unique marker recovers ownership.
    state["created_id"], state["created_record"] = record["id"], record
    save_state(folder, state, state["phase"])
    mx = exact(rows, DOMAIN, "MX")
    if not rollback:
        print("Owned pilot MX is present and unchanged.")
        if len(mx) != 1:
            print("Additional apex MX records exist; review before further changes.")
            return 3
        public_mx_report()
        return 0
    if len(mx) != 1:
        raise PilotError("Apex MX set changed since the pilot; review it before rollback.")
    # Check the owned record and MX set again before deleting by its exact ID.
    before_delete = api.records()
    record = owned_record(before_delete, state)
    if record is None or len(exact(before_delete, DOMAIN, "MX")) != 1:
        raise PilotError("MX changed during rollback checks; nothing deleted.")
    state["before_rollback_records"] = before_delete
    save_state(folder, state, "delete_pending")
    print("Deleting only the unchanged pilot MX record...", flush=True)
    try:
        api.delete(record["id"])
        after = api.records()
        if owned_record(after, state) is not None or exact(after, DOMAIN, "MX"):
            raise PilotError("Rollback postcheck did not find the expected absence of apex MX.")
        state["after_rollback_records"] = after
        save_state(folder, state, "rolled_back")
    except (Exception, KeyboardInterrupt) as exc:
        print("ROLLBACK NOT FULLY VERIFIED: no automatic retry. Run Status before another action.")
        if isinstance(exc, PilotError):
            print(str(exc))
        return 3
    print("ROLLBACK COMPLETE: the pilot MX was deleted; yt.cafe again has no explicit apex MX.")
    print("Cached MX answers may persist until their TTLs expire. Other DNS records were preserved.")
    return 0


def hidden_token() -> str:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            token = getpass.getpass("Cloudflare API token (hidden; stays on this PC): ").strip()
    except (getpass.GetPassWarning, EOFError):
        raise PilotError("A hidden token prompt is unavailable; run in an interactive terminal.") from None
    except OSError as exc:
        raise PilotError("Hidden token prompt failed (" + os_error_code(exc) +
                         "); no DNS request was sent. Run in an interactive PowerShell window.") from None
    if not token or len(token) > 1024 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise PilotError("Invalid token input; enter only the API token at the hidden prompt.")
    return token


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="back up and add the one MX record")
    mode.add_argument("--local-check", action="store_true", help="test local backup writing; no token or network")
    mode.add_argument("--status", type=Path, metavar="FOLDER", help="read-only DNS recovery check")
    mode.add_argument("--rollback", type=Path, metavar="FOLDER", help="remove this operation's unchanged MX")
    args = parser.parse_args()
    print("SGP1 YT.CAFE MX PILOT " + VERSION)
    print("Scope: yt.cafe receiving MX only. This script sends no email.")
    print("Mode: " + ("LOCAL CHECK (no network)" if args.local_check else
                       "APPLY" if args.apply else "ROLLBACK" if args.rollback else
                       "STATUS (no DNS writes)" if args.status else "PREVIEW (no DNS writes)"))
    try:
        with local_lock():
            folder = args.status or args.rollback
            if folder:
                folder = folder.expanduser().resolve()
                load_state(folder)  # Reject invalid recovery input before requesting credentials.
            else:
                root = writable_backup_root()
            if args.local_check:
                print("LOCAL CHECK PASSED: a private backup folder is writable; no Cloudflare request made.")
                return 0
            api = Cloudflare(hidden_token())
            return recover(api, folder, bool(args.rollback)) if folder else start(api, root, args.apply)
    except PilotError as exc:
        print("STOPPED: " + str(exc))
        return 2
    except KeyboardInterrupt:
        print("Interrupted. If a backup path was printed, use its Status command before rerunning.")
        return 130
    except Exception as exc:
        print("STOPPED: local/response error (" + type(exc).__name__ + "). No automatic retry.")
        print("If a backup path was printed, use its Status command before another action.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
