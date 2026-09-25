#!/usr/bin/env python3
"""Receiving-only MX additions for seven domains already hosted on SGP1.

Python 3.10+, standard library. Run locally on Windows, never over SSH.

  python sgp1-seven-mx-add.py --local-check         # no token or network
  python sgp1-seven-mx-add.py                       # fresh DNS backup + preview
  python sgp1-seven-mx-add.py --apply               # backup, then add up to 7 MX
  python sgp1-seven-mx-add.py --status FOLDER       # inspect saved operation
  python sgp1-seven-mx-add.py --rollback FOLDER     # remove only owned, unchanged MX

The target mail.whispr.dev and its catch-all path have passed live SMTP,
Thunderbird and public-MX delivery checks for yt.cafe. The seven exact zones
below had no explicit apex MX at the 22 September read; fresh reads determine
what is safe now. Unexpected MX, apex CNAME, zone/delegation mismatch, or
MTA-STS policy stops this batch before a write. Correct existing MX is kept.

One token with Zone / Zone / Read and Zone / DNS / Edit for these zones is
entered at a hidden prompt. It is sent only to the Cloudflare API and never
saved. Full DNS snapshots contain private TXT values; keep transaction.json
private and share only terminal output. No new server, mail client or package
is required. No SMTP senders, SPF, DKIM or DMARC records are changed.

Every POST/DELETE is journaled before sending. Failed/uncertain writes are
never retried automatically. Retain the printed folder and use --status.
DNS updates across zones are sequential and not an atomic transaction.
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
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
import warnings

VERSION = "1.0.1"
DOMAINS = (
    "80days.site", "analoglogic.blog", "blairboulevard.website", "gongle.us",
    "showsome.skin", "specter.in.net", "stealingdatais.gay",
)
MAIL_HOST = "mail.whispr.dev"
EXPECTED_IP = "68.183.227.135"
API_BASE = "https://api.cloudflare.com/client/v4"
DNS_BASE = "https://cloudflare-dns.com/dns-query"
MARKER_PREFIX = "sgp1-seven-mx-add:"
LIMIT = 8 * 1024 * 1024


class Stop(Exception):
    """Redacted operational error: never print a token or raw DNS response."""


class ZoneNotVisible(Stop):
    """The token's zone listing did not include this exact domain."""


class HTTPStatus(Stop):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def norm(value: object) -> str:
    return str(value).lower().rstrip(".")


def ident(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value) is not None


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def error_number(exc: OSError) -> str:
    return str(getattr(exc, "winerror", None) or exc.errno or "unknown")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Stop("HTTPS redirect refused.")


def json_request(url: str, method: str = "GET", token: str | None = None,
                 payload: dict | None = None) -> dict:
    target = urllib.parse.urlsplit(url)
    if (target.scheme != "https" or target.netloc not in
            ("api.cloudflare.com", "cloudflare-dns.com") or
            (token is not None and target.netloc != "api.cloudflare.com")):
        raise Stop("HTTPS destination outside this script's scope.")
    headers = {"Accept": "application/json" if token else "application/dns-json",
               "User-Agent": "sgp1-seven-mx-add/" + VERSION}
    if token:
        headers["Authorization"] = "Bearer " + token
    if payload is not None:
        headers["Content-Type"] = "application/json"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, headers=headers, data=data, method=method)
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=20) as response:
            raw = response.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise Stop("HTTPS response exceeded size limit.")
        result = json.loads(raw)
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
        hint = " Check token permissions for all seven zones." if status in (401, 403) else ""
        raise HTTPStatus(status, f"HTTPS status {status}.{hint}") from None
    except (urllib.error.URLError, OSError):
        raise Stop("HTTPS connection, TLS validation, or response failed.") from None
    except (UnicodeError, ValueError):
        raise Stop("HTTPS returned invalid JSON.") from None
    if not isinstance(result, dict):
        raise Stop("Unexpected HTTPS response shape.")
    return result


class Cloudflare:
    def __init__(self, token: str):
        self.token = token
        self.ids: dict[str, str] = {}

    def call(self, domain: str, method: str, records: bool = False,
             record_id: str | None = None, params: dict | None = None,
             payload: dict | None = None) -> dict:
        if domain not in DOMAINS:
            raise Stop("Domain outside this seven-zone batch.")
        if not records:
            if method != "GET" or record_id or payload or (params or {}).get("name") != domain:
                raise Stop("Unsupported zone request.")
            path = "/zones"
        else:
            zone_id = self.ids.get(domain)
            if not ident(zone_id):
                raise Stop("Zone has not been verified for this domain.")
            path = f"/zones/{zone_id}/dns_records"
            if method == "DELETE":
                if not ident(record_id) or payload or params:
                    raise Stop("Unexpected delete request.")
                path += "/" + record_id
            elif method == "POST":
                marker = (payload or {}).get("comment", "")
                parts = marker[len(MARKER_PREFIX):].split(":", 1) if marker.startswith(MARKER_PREFIX) else []
                if (record_id or params or payload != desired(domain, marker)
                        or len(parts) != 2 or not ident(parts[0]) or parts[1] != domain):
                    raise Stop("Unexpected DNS write refused.")
            elif method != "GET" or record_id or payload:
                raise Stop("Unsupported DNS request.")
        url = API_BASE + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        response = json_request(url, method, self.token, payload)
        if response.get("success") is not True:
            codes = [str(e["code"]) for e in response.get("errors", [])
                     if isinstance(e, dict) and type(e.get("code")) is int]
            raise Stop("Cloudflare API rejected request (codes: " +
                       (", ".join(codes) or "unknown") + ").")
        return response

    def listing(self, domain: str, records: bool, params: dict) -> list[dict]:
        rows: list[dict] = []
        seen: set[str] = set()
        for page in range(1, 1001):
            result = self.call(domain, "GET", records=records,
                               params={**params, "page": page, "per_page": 50})
            batch, info = result.get("result"), result.get("result_info")
            if not isinstance(batch, list) or not isinstance(info, dict):
                raise Stop("Incomplete DNS listing response.")
            size = info.get("per_page", 50)
            if (info.get("page") != page or type(size) is not int
                    or not 1 <= size <= 50 or len(batch) > size):
                raise Stop("Invalid DNS page metadata.")
            for row in batch:
                if not isinstance(row, dict) or not ident(row.get("id")) or row["id"] in seen:
                    raise Stop("Duplicate or invalid record in DNS listing.")
                rows.append(row)
                seen.add(row["id"])
            # total_count can be stale after an update or include unfiltered
            # records. A short page, rather than metadata equality, is final.
            if len(batch) < size:
                return rows
        raise Stop("DNS page limit reached.")

    def zone(self, domain: str) -> dict:
        zones = self.listing(domain, False, {"name": domain})
        if not zones:
            raise ZoneNotVisible(f"{domain}: not visible to this token in Cloudflare's zone listing.")
        if len(zones) != 1 or norm(zones[0].get("name")) != domain:
            raise Stop(f"{domain}: Cloudflare returned unexpected zones for this exact name.")
        zone = zones[0]
        if (not ident(zone.get("id")) or zone.get("status") != "active"
                or zone.get("type") != "full"
                or not ident((zone.get("account") or {}).get("id"))):
            raise Stop(f"{domain}: zone is not active, full, or identifiable.")
        self.ids[domain] = zone["id"]
        return zone

    def all_records(self, domain: str) -> list[dict]:
        rows = self.listing(domain, True, {})
        if any(not isinstance(r.get("type"), str) or
               not (norm(r.get("name")) == domain or
                    norm(r.get("name")).endswith("." + domain)) for r in rows):
            raise Stop(f"{domain}: API returned records outside its exact zone.")
        return rows

    def create(self, domain: str, marker: str) -> dict:
        result = self.call(domain, "POST", records=True,
                           payload=desired(domain, marker)).get("result")
        if not isinstance(result, dict) or not ident(result.get("id")):
            raise Stop(f"{domain}: create response lacked a valid record ID.")
        return result

    def delete(self, domain: str, record_id: str) -> None:
        result = self.call(domain, "DELETE", records=True, record_id=record_id).get("result")
        if not isinstance(result, dict) or result.get("id") != record_id:
            raise Stop(f"{domain}: delete response did not identify the requested record.")


def desired(domain: str, marker: str | None = None) -> dict:
    value = {"type": "MX", "name": domain, "content": MAIL_HOST,
             "priority": 10, "ttl": 300, "proxied": False}
    if marker is not None:
        value["comment"] = marker
    return value


def apex(rows: list[dict], domain: str, kind: str) -> list[dict]:
    return [r for r in rows if norm(r.get("name")) == domain and r.get("type") == kind]


def correct_mx(record: dict, domain: str) -> bool:
    return (record.get("type") == "MX" and norm(record.get("name")) == domain
            and norm(record.get("content")) == MAIL_HOST
            and record.get("priority") == 10 and record.get("proxied", False) is False)


def action(rows: list[dict], domain: str) -> str:
    mx = apex(rows, domain, "MX")
    if mx:
        if len(mx) == 1 and correct_mx(mx[0], domain):
            return "KEEP"
        raise Stop(f"{domain}: unexpected apex MX exists; no existing mail route will be replaced.")
    if apex(rows, domain, "CNAME"):
        raise Stop(f"{domain}: apex CNAME found; review before adding MX.")
    if any(norm(r.get("name")) == "_mta-sts." + domain for r in rows):
        raise Stop(f"{domain}: MTA-STS marker found; review policy before changing MX.")
    return "ADD"


def dns_answers(name: str, kind: int) -> list[str]:
    url = DNS_BASE + "?" + urllib.parse.urlencode({"name": name, "type": kind})
    data = json_request(url)
    rows = data.get("Answer", [])
    if (data.get("Status") != 0 or data.get("TC") is not False
            or not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows)):
        raise Stop(f"{name}: public DNS query failed or returned incomplete data.")
    return [str(r.get("data", "")) for r in rows
            if r.get("type") == kind and norm(r.get("name")) == name]


def verify_public(zones: dict[str, dict]) -> None:
    if (set(dns_answers(MAIL_HOST, 1)) != {EXPECTED_IP}
            or dns_answers(MAIL_HOST, 28) or dns_answers(MAIL_HOST, 5)):
        raise Stop("Public mail host DNS differs from the tested IPv4-only target.")
    for domain in DOMAINS:
        ns = {norm(n) for n in dns_answers(domain, 2)}
        if not ns or ns != {norm(n) for n in zones[domain].get("name_servers", [])}:
            raise Stop(f"{domain}: public delegation differs from this Cloudflare zone.")


def atomic_json(path: Path, data: dict) -> None:
    fd, temporary = tempfile.mkstemp(prefix=path.name + "-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def backup_root() -> Path:
    home = Path.home()
    candidates = (home / "sgp1-mail-dns-backups",
                  home / "AppData" / "Local" / "sgp1-mail-dns-backups")
    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True, mode=0o700)
            with tempfile.TemporaryFile(dir=candidate) as handle:
                handle.write(b"backup write check\n")
                handle.flush()
                os.fsync(handle.fileno())
            print("Backup location: " + str(candidate))
            return candidate
        except OSError:
            continue
    raise Stop("Neither private backup folder is writable; no token or DNS change attempted.")


@contextmanager
def local_lock():
    lock_path = Path(tempfile.gettempdir()) / "sgp1-seven-mx-add.lock"
    try:
        handle = lock_path.open("a+b")
    except OSError as exc:
        raise Stop(f"Cannot open local pilot lock (OS error {error_number(exc)}).") from None
    with handle:
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise Stop(f"Cannot acquire local batch lock (OS error {error_number(exc)}).") from None
        try:
            yield
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def save(folder: Path, state: dict) -> None:
    state["updated_at"] = now()
    atomic_json(folder / "transaction.json", state)


def load(folder: Path) -> dict:
    try:
        raw = (folder / "transaction.json").read_bytes()
        if len(raw) > LIMIT:
            raise ValueError()
        state = json.loads(raw)
        if (state["schema"] != 1 or state["program"] != "sgp1-seven-mx-add"
                or not ident(state["transaction_id"])
                or state["domains"] != list(DOMAINS)
                or set(state["entries"]) != set(DOMAINS)):
            raise ValueError()
        accounts = set()
        for domain in DOMAINS:
            entry = state["entries"][domain]
            if (not ident(entry["zone_id"]) or not ident(entry["account_id"])
                    or not isinstance(entry["before"], list)
                    or entry["planned"] not in ("ADD", "KEEP")
                    or entry["marker"] != MARKER_PREFIX + state["transaction_id"] + ":" + domain
                    or entry["phase"] not in ("prepared", "keep", "write_rejected", "create_pending", "created",
                                              "verified", "delete_pending", "rolled_back")
                    or (entry.get("created_id") is not None and not ident(entry["created_id"]))):
                raise ValueError()
            accounts.add(entry["account_id"])
            if action(entry["before"], domain) != entry["planned"]:
                raise ValueError()
        if len(accounts) != 1:
            raise ValueError()
        return state
    except (OSError, ValueError, KeyError, TypeError, Stop):
        raise Stop("Cannot trust the saved transaction.json; use the original folder.") from None


def fingerprint(row: dict) -> dict:
    keys = ("id", "type", "name", "content", "priority", "ttl", "proxied", "comment",
            "tags", "settings", "created_on", "modified_on", "comment_modified_on", "tags_modified_on")
    result = {k: row.get(k) for k in keys}
    result["name"] = norm(result["name"])
    result["content"] = norm(result["content"])
    return result


def owned(rows: list[dict], domain: str, entry: dict) -> dict | None:
    rec_id = entry.get("created_id")
    matches = [r for r in rows if r.get("comment") == entry["marker"] or
               (rec_id is not None and r["id"] == rec_id)]
    if not matches:
        return None
    if len(matches) != 1:
        raise Stop(f"{domain}: conflicting owned record identities.")
    row = matches[0]
    if (not correct_mx(row, domain) or row.get("ttl") != 300
            or row.get("comment") != entry["marker"]
            or (rec_id is not None and row["id"] != rec_id)
            or row.get("locked") or (row.get("meta") or {}).get("managed_by_apps")
            or (entry.get("created_record") is not None and
                fingerprint(row) != fingerprint(entry["created_record"]))):
        raise Stop(f"{domain}: owned record changed or cannot be verified; no deletion.")
    return row


def command_lines(folder: Path) -> None:
    def quote(v: object) -> str:
        return "'" + str(v).replace("'", "''") + "'"
    script = quote(Path(__file__).resolve())
    print("Backup: " + str(folder))
    print("Status: python " + script + " --status " + quote(folder))
    print("Rollback: python " + script + " --rollback " + quote(folder))


def fresh_equal(api: Cloudflare, domain: str, entry: dict) -> None:
    zone = api.zone(domain)
    if zone["id"] != entry["zone_id"] or zone["account"]["id"] != entry["account_id"]:
        raise Stop(f"{domain}: zone identity changed since backup.")
    fresh = api.all_records(domain)
    if sorted(fresh, key=lambda r: r["id"]) != sorted(entry["before"], key=lambda r: r["id"]):
        raise Stop(f"{domain}: DNS changed since backup; no write to this zone.")


def run(api: Cloudflare, root: Path, apply: bool) -> int:
    zones = {}
    entries = {}
    accounts = set()
    not_visible = []
    # Check scope for every zone before reading full DNS or creating a journal.
    # A token limited to the yt.cafe pilot otherwise fails on the first domain
    # with little indication of which permissions or resources to correct.
    for domain in DOMAINS:
        try:
            zones[domain] = api.zone(domain)
        except ZoneNotVisible:
            not_visible.append(domain)
    if not_visible:
        print("TOKEN SCOPE CHECK FAILED: Cloudflare did not list: " + ", ".join(not_visible))
        print("Check Zone > Zone > Read and the token's included Zone resources for all seven domains.")
        print("This response cannot distinguish a missing permission from excluded zones.")
        print("No DNS records were read or changed; no transaction backup was created.")
        return 2
    for index, domain in enumerate(DOMAINS, 1):
        zone = zones[domain]
        rows = api.all_records(domain)
        planned = action(rows, domain)
        zones[domain] = zone
        accounts.add(zone["account"]["id"])
        entries[domain] = {"zone_id": zone["id"], "account_id": zone["account"]["id"],
                           "before": rows, "planned": planned, "phase": "prepared",
                           "created_id": None, "created_record": None}
        print(f"[{index:02d}/07] {domain}: {planned}")
    if len(accounts) != 1:
        raise Stop("These seven zones are not in one accessible Cloudflare account.")
    verify_public(zones)
    transaction_id = uuid.uuid4().hex
    for domain, entry in entries.items():
        entry["marker"] = MARKER_PREFIX + transaction_id + ":" + domain
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    folder = root / ("seven-mx-" + stamp + "-" + transaction_id[:10])
    folder.mkdir(mode=0o700)
    state = {"schema": 1, "program": "sgp1-seven-mx-add", "version": VERSION,
             "transaction_id": transaction_id, "domains": list(DOMAINS),
             "created_at": now(), "zones": zones, "entries": entries}
    save(folder, state)
    command_lines(folder)
    print("Backed up all seven zones. Keep transaction.json private.")
    if not apply:
        print("PREVIEW COMPLETE: no DNS writes. The apply run will take a new, fresh backup.")
        return 0

    # Recheck all seven zones before the first write, then each zone again
    # immediately before its own write. A partial batch remains in the journal.
    for domain in DOMAINS:
        try:
            fresh_equal(api, domain, entries[domain])
        except Stop as exc:
            print("STOPPED BEFORE ANY DNS WRITE: " + str(exc))
            return 2
    for domain in DOMAINS:
        entry = entries[domain]
        if entry["planned"] == "KEEP":
            entry["phase"] = "keep"
            save(folder, state)
            continue
        try:
            fresh_equal(api, domain, entry)
        except Stop as exc:
            print("BATCH STOPPED WITH POSSIBLE EARLIER CHANGES: " + str(exc))
            print("Use the Status command above before another action.")
            return 3
        entry["phase"] = "create_pending"
        save(folder, state)
        print("Creating " + domain + " MX...", flush=True)
        try:
            record = api.create(domain, entry["marker"])
            entry["created_id"] = record["id"]
            owned([record], domain, entry)
            entry["created_record"] = record
            entry["phase"] = "created"
            save(folder, state)
            after = api.all_records(domain)
            current = owned(after, domain, entry)
            if current is None or len(apex(after, domain, "MX")) != 1:
                raise Stop(f"{domain}: postcheck did not find exactly the intended MX.")
            entry["phase"] = "verified"
            save(folder, state)
            print("VERIFIED: " + domain + " MX 10 " + MAIL_HOST)
        except (Exception, KeyboardInterrupt) as exc:
            if isinstance(exc, HTTPStatus) and exc.status in (401, 403) and entry["created_id"] is None:
                entry["phase"] = "write_rejected"
                save(folder, state)
                print(f"{domain}: Cloudflare refused this DNS write (HTTP {exc.status}).")
                print("No MX was created for this domain by this request; earlier verified zones remain.")
                print("Check this token's Zone / DNS / Edit scope for the seven zones before proceeding.")
                return 3 if any(e["phase"] == "verified" for e in entries.values()) else 2
            print("BATCH INCOMPLETE. A write may have succeeded; no retry was made.")
            if isinstance(exc, Stop):
                print(str(exc))
            print("Use the Status command above; do not run Apply again yet.")
            return 3
    print("SEVEN-ZONE MX BATCH COMPLETE: all seven now have the intended MX.")
    print("Public DNS caches may lag; no SMTP message was sent by this script.")
    return 0


def inspect(api: Cloudflare, folder: Path, rollback: bool) -> int:
    state = load(folder)
    entries = state["entries"]
    command_lines(folder)
    state_ok = True
    for domain in reversed(DOMAINS) if rollback else DOMAINS:
        entry = entries[domain]
        zone = api.zone(domain)
        if zone["id"] != entry["zone_id"] or zone["account"]["id"] != entry["account_id"]:
            raise Stop(f"{domain}: saved zone/account differs from the live zone.")
        rows = api.all_records(domain)
        mx = apex(rows, domain, "MX")
        phase = entry["phase"]
        if phase in ("prepared", "keep", "write_rejected"):
            print(f"{domain}: {phase.upper()}; this transaction owns no record here.")
            if phase in ("prepared", "write_rejected") and rollback:
                continue
            if phase in ("prepared", "write_rejected") or (phase == "keep" and
                                       (len(mx) != 1 or not correct_mx(mx[0], domain))):
                state_ok = False
            continue
        record = owned(rows, domain, entry)
        if phase == "rolled_back":
            if record is not None:
                raise Stop(f"{domain}: a rolled-back record reappeared; inspect manually.")
            print(f"{domain}: previously rolled back, no owned MX present.")
            continue
        if record is None:
            if phase != "delete_pending" or entry.get("created_id") is None:
                print(f"{domain}: create outcome uncertain; no deletion or retry.")
                state_ok = False
                continue
            original_ids = {r["id"] for r in entry["before"]}
            if not original_ids.issubset({r["id"] for r in rows}):
                raise Stop(f"{domain}: incomplete DNS listing, rollback cannot be verified.")
            entry["phase"] = "rolled_back"
            save(folder, state)
            print(f"{domain}: deletion confirmed after an uncertain response.")
            continue
        if len(mx) != 1:
            print(f"{domain}: additional/conflicting MX exists; no deletion.")
            state_ok = False
            continue
        if not rollback:
            print(f"{domain}: owned MX present and unchanged (saved phase {phase}).")
            if phase not in ("verified", "delete_pending") or entry.get("created_id") is None:
                state_ok = False
            continue
        if entry.get("created_id") is None:
            print(f"{domain}: no saved record ID; ownership insufficient for rollback.")
            state_ok = False
            continue
        # Re-read immediately before deleting only the matching ID.
        fresh = api.all_records(domain)
        checked = owned(fresh, domain, entry)
        if checked is None or len(apex(fresh, domain, "MX")) != 1:
            raise Stop(f"{domain}: MX changed during rollback precheck; no deletion.")
        entry["phase"] = "delete_pending"
        save(folder, state)
        print("Deleting only the unchanged owned MX for " + domain + "...", flush=True)
        try:
            api.delete(domain, record["id"])
            after = api.all_records(domain)
            if owned(after, domain, entry) is not None or apex(after, domain, "MX"):
                raise Stop(f"{domain}: rollback postcheck failed; status needed.")
            entry["phase"] = "rolled_back"
            save(folder, state)
            print("ROLLED BACK: " + domain)
        except (Exception, KeyboardInterrupt) as exc:
            if isinstance(exc, Stop):
                print(str(exc))
            print("ROLLBACK OUTCOME UNCERTAIN. No automatic retry; run Status.")
            return 3
    print("STATUS COMPLETE." if not rollback else "ROLLBACK REVIEW COMPLETE.")
    return 0 if state_ok else 3


def token_prompt() -> str:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            secret = getpass.getpass("Cloudflare user API token (hidden; not saved): ").strip()
    except (getpass.GetPassWarning, EOFError, OSError):
        raise Stop("Hidden credential prompt unavailable; run in interactive PowerShell.") from None
    if not secret or len(secret) > 1024 or any(ord(c) < 33 or ord(c) > 126 for c in secret):
        raise Stop("Invalid credential input at hidden prompt.")
    return secret


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--local-check", action="store_true", help="test local backup writing, no network")
    mode.add_argument("--apply", action="store_true", help="save fresh backup, then add 7 exact MX records")
    mode.add_argument("--status", type=Path, metavar="FOLDER", help="read-only inspection of a saved batch")
    mode.add_argument("--rollback", type=Path, metavar="FOLDER", help="delete only unchanged records this batch owns")
    args = parser.parse_args()
    print("SGP1 SEVEN ADD-ONLY MX " + VERSION)
    print("Mode: " + ("LOCAL CHECK" if args.local_check else "APPLY" if args.apply else
                      "STATUS" if args.status else "ROLLBACK" if args.rollback else "PREVIEW"))
    try:
        with local_lock():
            folder = args.status or args.rollback
            if folder:
                folder = folder.expanduser().resolve()
                load(folder)  # Validate a private journal before requesting credentials.
            else:
                root = backup_root()
            if args.local_check:
                print("LOCAL CHECK PASSED: no token, internet request, or DNS change.")
                return 0
            api = Cloudflare(token_prompt())
            return inspect(api, folder, bool(args.rollback)) if folder else run(api, root, args.apply)
    except Stop as exc:
        print("STOPPED: " + str(exc))
        return 2
    except KeyboardInterrupt:
        print("Interrupted. If a backup folder was printed, check its Status before rerunning.")
        return 130
    except Exception as exc:
        print("STOPPED: local/response failure (" + type(exc).__name__ + ").")
        print("If a backup folder was printed, check its Status before retrying.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
