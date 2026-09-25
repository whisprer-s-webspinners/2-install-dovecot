#!/usr/bin/env python3
"""Move one registrar-forwarded domain at a time to SGP1 receiving.

Python 3.10+, standard library. Run on the Windows PC, not on a VPS:
    python sgp1-registrar-mx-cutover.py --domain botforum.dev
    python sgp1-registrar-mx-cutover.py --domain botforum.dev --apply
    python sgp1-registrar-mx-cutover.py --domain botforum.dev --status FOLDER
    python sgp1-registrar-mx-cutover.py --domain botforum.dev --resume FOLDER
    python sgp1-registrar-mx-cutover.py --domain botforum.dev --rollback FOLDER

The last command can remove this script's unchanged new MX ONLY BEFORE any
old MX was deleted. Restoring the prior registrar set after deletion would
restore a route that rejected fresh random recipients in these tests; reversal
therefore requires manual review of the full private DNS snapshot.

Only the selected domain's apex MX may change. This tool makes no SMTP or IMAP
connections, sends no email, and does not change SPF, DKIM, DMARC, web DNS,
server configuration or client settings. It prompts once for a Cloudflare
user API token with Zone/Zone/Read and Zone/DNS/Edit for that domain.
The token is hidden, used only for the API over verified HTTPS, never saved.
Keep transaction.json private: the backup includes all DNS TXT and comments.

Writes are journaled BEFORE every POST/DELETE and never automatically retried
after uncertain responses. DNS changes are visible at different times to
different resolvers; inspect the printed status before any restart/retry.
The old eforward1 host rejected random recipients at RCPT TO for all four
domains. That does not prove specific old aliases or all other MX hosts reject.
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

VERSION = "1.0.0"
DOMAINS = ("botforum.dev", "lickyour.skin", "showmesome.skin", "showmeyour.skin")
DOMAIN = ""  # Set once from the required, allowlisted --domain argument.
NEW_HOST = "mail.whispr.dev"
NEW_IP = "68.183.227.135"
API_URL = "https://api.cloudflare.com/client/v4"
DOH_URL = "https://cloudflare-dns.com/dns-query"
MARKER = "sgp1-registrar-mx-cutover:"
MAX_BYTES = 8 * 1024 * 1024
OLD = (
    (10, "eforward1.registrar-servers.com"),
    (10, "eforward2.registrar-servers.com"),
    (10, "eforward3.registrar-servers.com"),
    (15, "eforward4.registrar-servers.com"),
    (20, "eforward5.registrar-servers.com"),
)


class Stop(Exception):
    """Expected failure safe to display without an API token or DNS TXT data."""


class HTTPStatus(Stop):
    def __init__(self, code: int):
        super().__init__(f"HTTPS {code}; check this token's DNS permissions if 401/403.")
        self.code = code


def norm(value: object) -> str:
    return str(value).lower().rstrip(".")


def valid_id(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{32}", value) is not None


def stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def say(message: str) -> None:
    print(message, flush=True)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Stop("HTTPS redirect refused.")


def request_json(url: str, *, method: str = "GET", token: str | None = None,
                 body: dict | None = None) -> dict:
    target = urllib.parse.urlsplit(url)
    if (target.scheme != "https" or target.netloc not in
            ("api.cloudflare.com", "cloudflare-dns.com")
            or (token is not None and target.netloc != "api.cloudflare.com")):
        raise Stop("HTTPS destination outside this tool's scope.")
    headers = {"Accept": "application/json" if token else "application/dns-json",
               "User-Agent": "sgp1-registrar-mx-cutover/" + VERSION}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        url, headers=headers, method=method,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=20) as response:
            raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise Stop("HTTPS response exceeded the size limit.")
        result = json.loads(raw)
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        raise HTTPStatus(code) from None
    except (urllib.error.URLError, OSError):
        raise Stop("HTTPS connection, TLS verification or response failed.") from None
    except (ValueError, UnicodeError):
        raise Stop("HTTPS response was not valid JSON.") from None
    if not isinstance(result, dict):
        raise Stop("Unexpected HTTPS response shape.")
    return result


def token_prompt() -> str:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            secret = getpass.getpass("Cloudflare user API token (hidden; not saved): ").strip()
    except (getpass.GetPassWarning, EOFError, OSError):
        raise Stop("A hidden token prompt is unavailable; run in interactive PowerShell.") from None
    if not secret or len(secret) > 1024 or any(ord(c) < 33 or ord(c) > 126 for c in secret):
        raise Stop("Invalid credential input at hidden prompt.")
    return secret


class Cloudflare:
    def __init__(self, token: str):
        self.token = token
        self.zone_id: str | None = None

    def call(self, method: str, path: str, *, params: dict | None = None,
             body: dict | None = None) -> dict:
        base = f"/zones/{self.zone_id}/dns_records" if valid_id(self.zone_id) else ""
        if method == "GET" and path == "/zones":
            if (params or {}).get("name") != DOMAIN or body is not None:
                raise Stop("Unexpected zone request.")
        elif method == "GET" and path == base and base and body is None:
            pass
        elif method == "POST" and path == base and base and params is None:
            marker = (body or {}).get("comment")
            if (not isinstance(marker, str) or not marker.startswith(MARKER)
                    or not valid_id(marker[len(MARKER):]) or body != desired(marker)):
                raise Stop("Unexpected MX creation refused.")
        elif method == "DELETE" and base and params is None and body is None and path.startswith(base + "/"):
            if not valid_id(path[len(base) + 1:]):
                raise Stop("Unexpected DNS deletion ID.")
        else:
            raise Stop("API endpoint outside the selected domain's allowed actions.")
        url = API_URL + path
        if params is not None:
            url += "?" + urllib.parse.urlencode(params)
        result = request_json(url, method=method, token=self.token, body=body)
        if result.get("success") is not True:
            codes = [str(e["code"]) for e in result.get("errors", [])
                     if isinstance(e, dict) and type(e.get("code")) is int]
            raise Stop("Cloudflare refused the request (code " + (",".join(codes) or "unknown") + ").")
        return result

    def listing(self, path: str, params: dict) -> list[dict]:
        rows: list[dict] = []
        seen: set[str] = set()
        for page in range(1, 1001):
            response = self.call("GET", path, params={**params, "page": page, "per_page": 50})
            batch, info = response.get("result"), response.get("result_info")
            size = info.get("per_page", 50) if isinstance(info, dict) else None
            if (not isinstance(batch, list) or not isinstance(info, dict)
                    or info.get("page") != page or type(size) is not int
                    or not 1 <= size <= 50 or len(batch) > size):
                raise Stop("Incomplete API listing; use Status before another write.")
            for row in batch:
                if not isinstance(row, dict) or not valid_id(row.get("id")) or row["id"] in seen:
                    raise Stop("Repeated or invalid API record; list not trusted.")
                rows.append(row)
                seen.add(row["id"])
            if len(batch) < size:
                return rows
        raise Stop("API page limit reached.")

    def zone(self) -> dict:
        zones = self.listing("/zones", {"name": DOMAIN})
        if len(zones) != 1 or norm(zones[0].get("name")) != DOMAIN:
            raise Stop("Expected one accessible exact " + DOMAIN + " Cloudflare zone.")
        zone = zones[0]
        if (not valid_id(zone.get("id")) or zone.get("status") != "active"
                or zone.get("type") != "full"
                or not valid_id((zone.get("account") or {}).get("id"))):
            raise Stop("Cloudflare zone is not active, full or identifiable.")
        self.zone_id = zone["id"]
        return zone

    def records(self) -> list[dict]:
        if not valid_id(self.zone_id):
            raise Stop("No verified zone.")
        rows = self.listing(f"/zones/{self.zone_id}/dns_records", {})
        if any(not isinstance(r.get("type"), str)
               or not (norm(r.get("name")) == DOMAIN
                       or norm(r.get("name")).endswith("." + DOMAIN)) for r in rows):
            raise Stop("API listing includes an out-of-zone DNS record.")
        return rows

    def create(self, marker: str) -> dict:
        result = self.call("POST", f"/zones/{self.zone_id}/dns_records",
                           body=desired(marker)).get("result")
        if not isinstance(result, dict) or not valid_id(result.get("id")):
            raise Stop("MX create response had no valid record ID; use Status.")
        return result

    def delete(self, record_id: str) -> None:
        result = self.call("DELETE", f"/zones/{self.zone_id}/dns_records/{record_id}").get("result")
        if not isinstance(result, dict) or result.get("id") != record_id:
            raise Stop("MX delete response had an unexpected ID; use Status.")


def desired(marker: str) -> dict:
    return {"type": "MX", "name": DOMAIN, "content": NEW_HOST,
            "priority": 10, "ttl": 300, "proxied": False, "comment": marker}


def mx(rows: list[dict]) -> list[dict]:
    return [r for r in rows if norm(r.get("name")) == DOMAIN and r.get("type") == "MX"]


def material(row: dict) -> tuple:
    fields = ("id", "type", "name", "content", "priority", "ttl",
              "proxied", "comment", "tags", "settings")
    return tuple(norm(row.get(key)) if key in ("name", "content")
                 else json.dumps(row.get(key), sort_keys=True) for key in fields)


def old_records(rows: list[dict]) -> list[dict]:
    current = mx(rows)
    if len(current) != 5 or sorted((r.get("priority"), norm(r.get("content"))) for r in current) != sorted(OLD):
        raise Stop("The five current MX records differ from the verified old set; no write.")
    for row in current:
        if row.get("locked") or (row.get("meta") or {}).get("managed_by_apps"):
            raise Stop("An old MX is managed or locked; no write.")
        if type(row.get("ttl")) is not int or row.get("ttl") < 1:
            raise Stop("Old MX has an invalid TTL; no write.")
    if any(norm(r.get("name")) == "_mta-sts." + DOMAIN for r in rows):
        raise Stop("MTA-STS policy marker needs review before changing its MX.")
    if any(norm(r.get("name")) == DOMAIN and r.get("type") == "CNAME" for r in rows):
        raise Stop("Unexpected apex CNAME.")
    old_hostnames_in_zone = {host for _, host in OLD if host.endswith("." + DOMAIN)}
    if any(norm(r.get("name")) in old_hostnames_in_zone
           and r.get("type") in ("A", "AAAA", "CNAME") for r in rows):
        raise Stop("An old MX host now has an address or alias in this Cloudflare zone.")
    return sorted(current, key=lambda r: (r["priority"], norm(r["content"])))


def doh(name: str, kind: str) -> tuple[int, list[str]]:
    number = {"NS": 2, "A": 1, "AAAA": 28, "MX": 15, "CNAME": 5}[kind]
    response = request_json(DOH_URL + "?" + urllib.parse.urlencode({"name": name, "type": kind}))
    question = response.get("Question")
    if (type(response.get("Status")) is not int or response.get("Status") not in (0, 3)
            or response.get("TC") is not False or not isinstance(question, list)
            or len(question) != 1 or not isinstance(question[0], dict)
            or norm(question[0].get("name")) != name or question[0].get("type") != number):
        raise Stop("Public DNS answer incomplete for " + name + ".")
    answer = response.get("Answer", [])
    if not isinstance(answer, list) or any(not isinstance(r, dict) for r in answer):
        raise Stop("Malformed public DNS answer for " + name + ".")
    if kind in ("A", "AAAA") and any(
        r.get("type") == 5 and norm(r.get("name")) == name for r in answer
    ):
        raise Stop("An MX target returned a CNAME; review before changing this mail route.")
    return response["Status"], [str(r.get("data", "")) for r in answer
                                if r.get("type") == number and norm(r.get("name")) == name]


def target_check(zone: dict) -> None:
    public_ns = set(map(norm, doh(DOMAIN, "NS")[1]))
    if not public_ns or public_ns != set(map(norm, zone.get("name_servers", []))):
        raise Stop("Public delegation does not match this Cloudflare zone.")
    if (doh(NEW_HOST, "A")[1] != [NEW_IP]
            or doh(NEW_HOST, "AAAA")[1] or doh(NEW_HOST, "CNAME")[1]):
        raise Stop("SGP1 mail host does not resolve to its verified IPv4-only address.")


def public_precheck(zone: dict) -> None:
    target_check(zone)
    published = []
    for value in doh(DOMAIN, "MX")[1]:
        parts = value.split()
        if len(parts) != 2 or not parts[0].isdecimal():
            raise Stop("Unexpected public MX representation.")
        published.append((int(parts[0]), norm(parts[1])))
    if sorted(published) != sorted(OLD):
        raise Stop("Public MX differs from the five expected old records.")
    say("Public precheck: delegation matches, five exact old MX targets match, SGP1 address verified.")


def atomic_json(path: Path, value: dict) -> None:
    fd, tmp = tempfile.mkstemp(prefix=path.name + "-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as file:
            json.dump(value, file, ensure_ascii=True, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def backup_root() -> Path:
    home = Path.home()
    choices = (home / "sgp1-mail-dns-backups",
               home / "AppData" / "Local" / "sgp1-mail-dns-backups")
    for choice in choices:
        try:
            choice.mkdir(parents=True, exist_ok=True, mode=0o700)
            with tempfile.TemporaryFile(dir=choice) as probe:
                probe.write(b"registrar MX backup check\n")
                probe.flush()
                os.fsync(probe.fileno())
            say("Backup location: " + str(choice))
            return choice
        except OSError:
            continue
    raise Stop("No private profile backup directory is writable; no token was requested.")


@contextmanager
def single_run():
    path = Path(tempfile.gettempdir()) / "sgp1-registrar-mx-cutover.lock"
    try:
        handle = path.open("a+b")
        with handle:
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                yield
            finally:
                handle.seek(0)
                if os.name == "nt":
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError:
        raise Stop("Could not take the local operation lock; try after the other run finishes.") from None


def save(folder: Path, state: dict) -> None:
    state["updated_at"] = stamp()
    atomic_json(folder / "transaction.json", state)


def load(folder: Path) -> dict:
    try:
        raw = (folder / "transaction.json").read_bytes()
        if len(raw) > MAX_BYTES:
            raise ValueError()
        state = json.loads(raw)
        pending = state.get("pending")
        if (state["schema"] != 1 or state["program"] != "sgp1-registrar-mx-cutover"
                or state["domain"] != DOMAIN or DOMAIN not in DOMAINS
                or not valid_id(state["transaction_id"])
                or state["marker"] != MARKER + state["transaction_id"]
                or not valid_id(state["zone_id"]) or not valid_id(state["account_id"])
                or not isinstance(state["before"], list)
                or not isinstance(state["deleted_ids"], list)
                or len(set(state["deleted_ids"])) != len(state["deleted_ids"])
                or (state.get("created_id") is not None
                    and not valid_id(state["created_id"]))
                or (state.get("created_record") is not None
                    and not isinstance(state["created_record"], dict))
                or state["phase"] not in ("prepared", "create_pending", "create_rejected",
                                          "created", "complete", "rolled_back")
                or (pending is not None and
                    (not isinstance(pending, dict)
                     or pending.get("action") not in ("create", "delete", "rollback")
                     or (pending.get("action") in ("delete", "rollback")
                         and not valid_id(pending.get("id")))))):
            raise ValueError()
        original = old_records(state["before"])
        if not set(state["deleted_ids"]).issubset({r["id"] for r in original}):
            raise ValueError()
        return state
    except (OSError, ValueError, TypeError, KeyError, Stop):
        raise Stop("Saved transaction is invalid; use the original private backup folder.") from None


def commands(folder: Path) -> None:
    q = lambda value: "'" + str(value).replace("'", "''") + "'"
    script = q(Path(__file__).resolve())
    say("Backup: " + str(folder))
    prefix = "python " + script + " --domain " + q(DOMAIN)
    say("Status: " + prefix + " --status " + q(folder))
    say("Resume: " + prefix + " --resume " + q(folder))
    say("Rollback (only before old-record deletions): " + prefix + " --rollback " + q(folder))


def inspect_rows(rows: list[dict], state: dict) -> tuple[dict | None, list[dict], list[str]]:
    before = {r["id"]: r for r in state["before"]}
    old = old_records(state["before"])
    old_ids = {r["id"] for r in old}
    current = {r["id"]: r for r in rows}
    other_ids = set(before) - old_ids
    if (not other_ids.issubset(current)
            or any(material(current[id]) != material(before[id]) for id in other_ids)):
        raise Stop("Unrelated DNS changed since backup; pause for review.")
    for record in old:
        observed = current.get(record["id"])
        if observed is not None and material(observed) != material(record):
            raise Stop("An old MX changed since backup; pause for review.")
    marker_matches = [r for r in rows if r.get("comment") == state["marker"]]
    if len(marker_matches) > 1:
        raise Stop("Two records carry this transaction's marker; no write.")
    new = marker_matches[0] if marker_matches else None
    if state.get("created_id") is not None:
        if new is None or new["id"] != state["created_id"]:
            if (state.get("pending") or {}).get("action") != "rollback" and state["phase"] != "rolled_back":
                raise Stop("Managed new MX disappeared or changed identity; no write.")
    if new is not None:
        if (new.get("type") != "MX" or norm(new.get("name")) != DOMAIN
                or norm(new.get("content")) != NEW_HOST
                or new.get("priority") != 10 or new.get("ttl") != 300
                or new.get("proxied", False) is not False
                or new.get("locked") or (new.get("meta") or {}).get("managed_by_apps")
                or (state.get("created_record") is not None
                    and material(new) != material(state["created_record"]))):
            raise Stop("Managed new MX changed; no write.")
    allowed_ids = set(before) | ({new["id"]} if new is not None else set())
    if set(current) != allowed_ids - (old_ids - set(current)):
        raise Stop("DNS changed outside this transaction; no write.")
    extra_mx = [r for r in mx(rows) if r["id"] not in old_ids
                and (new is None or r["id"] != new["id"])]
    if extra_mx:
        raise Stop("An unexpected MX was added; no write.")
    present = [r for r in old if r["id"] in current]
    missing = [r["id"] for r in old if r["id"] not in current]
    unexpected_missing = set(missing) - set(state["deleted_ids"])
    if unexpected_missing:
        pending = state.get("pending") or {}
        if pending.get("action") != "delete" or unexpected_missing != {pending.get("id")}:
            raise Stop("Old MX disappeared without a saved deletion intent; no write.")
    return new, present, missing


def zone_guard(api: Cloudflare, state: dict) -> None:
    zone = api.zone()
    if zone["id"] != state["zone_id"] or zone["account"]["id"] != state["account_id"]:
        raise Stop("This token accesses a different zone/account from the backup.")


def reconcile(api: Cloudflare, folder: Path, state: dict, *, allow_write: bool) -> tuple[dict | None, list[dict]]:
    zone_guard(api, state)
    rows = api.records()
    new, present, missing = inspect_rows(rows, state)
    pending = state.get("pending")
    if pending and pending["action"] == "create":
        if new is None:
            raise Stop("Create outcome uncertain; no owned MX currently visible. No retry; inspect later.")
        state["created_id"] = new["id"]
        state["created_record"] = new
        state["pending"] = None
        save(folder, state)
    elif pending and pending["action"] == "delete":
        if pending["id"] in missing and pending["id"] not in state["deleted_ids"]:
            state["deleted_ids"].append(pending["id"])
        state["pending"] = None
        save(folder, state)
    elif pending and pending["action"] == "rollback":
        if new is None:
            state["phase"] = "rolled_back"
            state["pending"] = None
            save(folder, state)
        else:
            state["pending"] = None
            save(folder, state)
    if new is not None and state["created_id"] is None:
        raise Stop("New MX exists without a saved creation intent; no write.")
    if new is None and state["created_id"] is not None and state["phase"] != "rolled_back":
        raise Stop("Managed MX is missing; no write.")
    if new is not None and state["created_record"] is None:
        state["created_record"] = new
        save(folder, state)
    if not allow_write:
        say("Status: " + str(len(present)) + " old MX remain; owned new MX " +
            ("present" if new is not None else "absent") + ".")
        if state["phase"] == "rolled_back":
            say("This transaction's new MX was removed; the old registrar set remains.")
        elif new is not None and not present:
            say("COMPLETE: Cloudflare API shows sole MX 10 mail.whispr.dev.")
        elif new is not None:
            say("PARTIAL: new MX exists; Resume can remove only the remaining verified old MX.")
        else:
            say("This transaction owns no MX; no DNS repair is complete.")
    return new, present


def finish(api: Cloudflare, folder: Path, state: dict) -> int:
    new, present = reconcile(api, folder, state, allow_write=True)
    if new is None or not valid_id(state.get("created_id")):
        raise Stop("No verified managed MX; old records will not be deleted.")
    target_check(api.zone())
    for record in present:
        current_new, current_old = reconcile(api, folder, state, allow_write=True)
        if current_new is None or record["id"] not in {r["id"] for r in current_old}:
            raise Stop("MX drift before deletion; inspect Status.")
        state["pending"] = {"action": "delete", "id": record["id"]}
        save(folder, state)
        say("Deleting verified old MX " + str(record["priority"]) + " " + norm(record["content"]) + "... ")
        api.delete(record["id"])
        reconcile(api, folder, state, allow_write=True)
    final_new, final_old = reconcile(api, folder, state, allow_write=True)
    if final_new is None or final_old or len(mx(api.records())) != 1:
        raise Stop("Final API verification failed; inspect Status.")
    state["phase"] = "complete"
    save(folder, state)
    say("CUTOVER COMPLETE: sole Cloudflare MX 10 mail.whispr.dev for " + DOMAIN + ".")
    say("Public caches may lag. This script sent no mail; verify one public-MX message later.")
    return 0


def begin(api: Cloudflare, root: Path, *, apply: bool) -> int:
    zone = api.zone()
    before = api.records()
    original = old_records(before)
    public_precheck(zone)
    transaction_id = uuid.uuid4().hex
    folder = root / ("registrar-mx-" + DOMAIN + "-" +
                     dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") +
                     "-" + transaction_id[:10])
    folder.mkdir(mode=0o700)
    state = {"schema": 1, "program": "sgp1-registrar-mx-cutover", "domain": DOMAIN,
             "version": VERSION, "transaction_id": transaction_id,
             "marker": MARKER + transaction_id,
             "zone_id": zone["id"], "account_id": zone["account"]["id"],
             "before": before, "created_at": stamp(), "phase": "prepared",
             "pending": None, "created_id": None, "created_record": None, "deleted_ids": []}
    save(folder, state)
    commands(folder)
    say("Saved full " + DOMAIN + " DNS backup locally. Keep transaction.json private.")
    say("Plan: add MX 10 mail.whispr.dev, then remove only:")
    for row in original:
        say("  " + str(row["priority"]) + " " + norm(row["content"]))
    if not apply:
        say("PREVIEW COMPLETE: no DNS write. Apply takes a fresh backup.")
        return 0
    if sorted(material(r) for r in api.records()) != sorted(material(r) for r in before):
        raise Stop("DNS changed after backup; no write. Re-run to take a fresh snapshot.")
    state["phase"] = "create_pending"
    state["pending"] = {"action": "create"}
    save(folder, state)
    say("Creating the working " + DOMAIN + " MX first...")
    try:
        created = api.create(state["marker"])
    except HTTPStatus as exc:
        if exc.code in (401, 403):
            state["phase"] = "create_rejected"
            state["pending"] = None
            save(folder, state)
            say(f"Cloudflare refused the first DNS write (HTTP {exc.code}).")
            say("No MX was created by that refused request. Check DNS Edit scope; then start a fresh Apply.")
            return 2
        raise
    state["created_id"] = created["id"]
    # The POST representation may differ from a later list representation.
    # Lock the fingerprint to the first verified list result in reconcile().
    state["created_record"] = None
    state["pending"] = None
    state["phase"] = "created"
    save(folder, state)
    return finish(api, folder, state)


def undo(api: Cloudflare, folder: Path, state: dict) -> int:
    new, present = reconcile(api, folder, state, allow_write=True)
    if state["deleted_ids"] or len(present) != 5:
        raise Stop("Old MX deletions began. Restoring the registrar set is not automated.")
    if new is None or not valid_id(state.get("created_id")):
        raise Stop("No unchanged owned MX can be removed.")
    state["pending"] = {"action": "rollback", "id": new["id"]}
    save(folder, state)
    api.delete(new["id"])
    reconcile(api, folder, state, allow_write=True)
    say("PRE-DELETION ROLLBACK COMPLETE: managed MX removed; old set is still present.")
    return 0


def main() -> int:
    global DOMAIN
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--domain", choices=DOMAINS, required=True,
                        help="exact Cloudflare zone for this one-domain transaction")
    parser.add_argument("--version", action="version", version=VERSION)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--apply", action="store_true")
    modes.add_argument("--status", metavar="FOLDER", type=Path)
    modes.add_argument("--resume", metavar="FOLDER", type=Path)
    modes.add_argument("--rollback", metavar="FOLDER", type=Path)
    args = parser.parse_args()
    DOMAIN = args.domain
    say("SGP1 REGISTRAR MX CUTOVER " + VERSION)
    mode = "APPLY" if args.apply else "STATUS" if args.status else \
           "RESUME" if args.resume else "ROLLBACK" if args.rollback else "PREVIEW"
    say("Mode: " + mode + "; receiving DNS only, " + DOMAIN + ".")
    try:
        with single_run():
            folder = args.status or args.resume or args.rollback
            state = load(folder.expanduser().resolve()) if folder else None
            root = backup_root() if folder is None else None
            api = Cloudflare(token_prompt())
            if state is None:
                return begin(api, root, apply=args.apply)
            folder = folder.expanduser().resolve()
            commands(folder)
            if args.status:
                reconcile(api, folder, state, allow_write=False)
                return 0
            if args.resume:
                return finish(api, folder, state)
            return undo(api, folder, state)
    except Stop as exc:
        say("STOPPED: " + str(exc))
        say("If a Backup path was printed, run its Status command before any retry.")
        return 2
    except KeyboardInterrupt:
        say("INTERRUPTED: a write may have reached Cloudflare. Run Status before retrying.")
        return 3
    except Exception as exc:
        say("INCOMPLETE: local or API response failure (" + type(exc).__name__ + ").")
        say("If a Backup path was printed, run Status before any retry.")
        return 3


if __name__ == "__main__":
    sys.exit(main())
