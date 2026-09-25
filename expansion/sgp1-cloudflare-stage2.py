#!/usr/bin/env python3
"""SGP1 stage 2: local Cloudflare DNS backup, MX preview and public TLS checks.

Python 3.10+; standard library only. Run on your Windows PC, not through SSH:
    python sgp1-cloudflare-stage2.py

Requires a Cloudflare user API token with Zone / Zone / Read and
Zone / DNS / Read for the 17 exact zones below. DNS Edit also permits reading,
but this program has no write mode. The token is entered at a hidden prompt,
used only with api.cloudflare.com, and never saved. Redirects are refused.

Only local backup/report files are written. Remote operations are HTTP GET,
DNS queries, SMTP greeting/EHLO/STARTTLS/QUIT, and an IMAPS greeting. No mail,
recipients, passwords, AUTH commands, package installs or server changes.

Backups include all API-visible DNS records in the 17 zones, including TXT
values and comments. Keep snapshot.json private; share report.txt instead.
This is a DNS-record snapshot, not a backup of all Cloudflare account settings.
The MX plan is for review only, not an apply or restore program.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings

VERSION = "1.0.0"
DOMAINS = (
    "80days.site", "analoglogic.blog", "blairboulevard.website", "botforum.dev",
    "dailystonks.org", "fastping.it.com", "gongle.us", "litehaus.online",
    "primercrate.rs", "lickyour.skin", "showmesome.skin", "showmeyour.skin",
    "showsome.skin", "specter.in.net", "stealingdatais.gay", "whispr.dev", "yt.cafe",
)
MAIL_HOST = "mail.whispr.dev"
EXPECTED_IPV4 = "68.183.227.135"
API_BASE = "https://api.cloudflare.com/client/v4"
DNS_BASE = "https://cloudflare-dns.com/dns-query"
TIMEOUT = 10
MAX_BODY = 16 * 1024 * 1024


class CheckError(Exception):
    """A deliberately redacted operational error, safe for the report."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CheckError("HTTP redirect refused; no credentials were forwarded.")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def normal_name(value: str) -> str:
    return value.lower().rstrip(".")


def safe_text(value: object, limit: int = 600) -> str:
    text = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(value))
    return text if len(text) <= limit else text[:limit] + " [truncated]"


def network_error(exc: Exception) -> str:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "TLS certificate verification failed (code %s)" % exc.verify_code
    if isinstance(exc, ssl.SSLError):
        return "TLS handshake failed"
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "connection or response timed out"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, urllib.error.URLError):
        if isinstance(exc.reason, Exception):
            return network_error(exc.reason)
        return "HTTPS connection failed"
    if isinstance(exc, OSError):
        return "network/OS error (code %s)" % (getattr(exc, "winerror", None) or exc.errno)
    return type(exc).__name__


def get_json(url: str, headers: dict[str, str], timeout: int = 15) -> dict:
    """GET only, bounded reads, TLS verification, no redirect or raw error body."""
    if urllib.parse.urlsplit(url).scheme != "https":
        raise CheckError("Only HTTPS is allowed.")
    request = urllib.request.Request(url, headers=headers, method="GET")
    opener = urllib.request.build_opener(NoRedirect())
    for attempt in range(3):
        try:
            with opener.open(request, timeout=timeout) as response:
                raw = response.read(MAX_BODY + 1)
            if len(raw) > MAX_BODY:
                raise CheckError("HTTP response exceeded the size limit.")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise CheckError("Unexpected JSON response shape.")
            return data
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            if status in (429, 500, 502, 503, 504) and attempt < 2:
                time.sleep(attempt + 1)
                continue
            hint = " Check the token's permissions and zone scope." if status in (401, 403) else ""
            raise CheckError(f"HTTPS returned status {status}.{hint}") from None
        except (urllib.error.URLError, OSError) as exc:
            raise CheckError(network_error(exc)) from None
        except (ValueError, UnicodeError):
            raise CheckError("Invalid JSON response.") from None
    raise CheckError("HTTPS retries exhausted.")


class Cloudflare:
    def __init__(self, token: str):
        self._token = token

    def get(self, path: str, params: dict) -> dict:
        if not re.fullmatch(r"/zones(?:/[a-f0-9]{32}/dns_records)?", path):
            raise CheckError("Unexpected API endpoint refused.")
        data = get_json(API_BASE + path + "?" + urllib.parse.urlencode(params), {
            "Authorization": "Bearer " + self._token,
            "Accept": "application/json", "User-Agent": "sgp1-mail-preview/" + VERSION,
        })
        if data.get("success") is not True:
            codes = [str(x.get("code")) for x in data.get("errors", [])
                     if isinstance(x, dict) and isinstance(x.get("code"), int)]
            raise CheckError("Cloudflare API rejected the read (codes: " + (", ".join(codes) or "unknown") + ").")
        return data

    def listing(self, path: str, params: dict, per_page: int) -> list[dict]:
        records: list[dict] = []
        seen: set[str] = set()
        for page in range(1, 1001):
            payload = self.get(path, {**params, "page": page, "per_page": per_page})
            batch = payload.get("result")
            info = payload.get("result_info")
            if not isinstance(batch, list) or not isinstance(info, dict):
                raise CheckError("Missing list or pagination metadata; snapshot not trusted.")
            total = info.get("total_count")
            if not isinstance(total, int) or total < 0 or info.get("page") != page:
                raise CheckError("Invalid pagination metadata; snapshot not trusted.")
            for record in batch:
                if not isinstance(record, dict) or not isinstance(record.get("id"), str):
                    raise CheckError("Invalid API record; snapshot not trusted.")
                if record["id"] in seen:
                    raise CheckError("Duplicate API record across pages; rerun the snapshot.")
                seen.add(record["id"])
                records.append(record)
            if len(records) == total:
                return records
            if not batch or len(records) > total:
                raise CheckError("Incomplete or changing pagination; rerun the snapshot.")
        raise CheckError("Pagination limit reached; snapshot incomplete.")

    def zone_snapshot(self, domain: str) -> dict:
        zones = self.listing("/zones", {"name": domain}, 50)
        matches = [z for z in zones if normal_name(z.get("name", "")) == domain]
        if len(matches) != 1:
            raise CheckError("Expected one accessible exact zone; found %d. Check token scope." % len(matches))
        zone = matches[0]
        if not re.fullmatch(r"[a-f0-9]{32}", zone["id"]):
            raise CheckError("Invalid Cloudflare zone ID.")
        records = self.listing("/zones/" + zone["id"] + "/dns_records", {}, 100)
        if any(not isinstance(r.get("name"), str) or not isinstance(r.get("type"), str)
               or not (normal_name(r["name"]) == domain or normal_name(r["name"]).endswith("." + domain))
               for r in records):
            raise CheckError("Unexpected record outside the exact zone; snapshot not trusted.")
        return {
            "zone_id": zone["id"], "name": domain,
            "account_id": (zone.get("account") or {}).get("id"),
            "status": zone.get("status"), "type": zone.get("type"),
            "name_servers": zone.get("name_servers", []),
            "captured_at": utc_now(), "records": records,
        }


def atomic_json(path: Path, data: dict) -> None:
    raw = (json.dumps(data, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    fd, temporary = tempfile.mkstemp(prefix=path.name + "-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def exact_records(zone: dict, name: str, kind: str) -> list[dict]:
    return [r for r in zone["records"]
            if normal_name(r["name"]) == name and r["type"] == kind]


def txt_value(record: dict) -> str:
    value = str(record.get("content", "")).strip()
    if value.startswith('"'):
        try:
            return "".join(shlex.split(value))
        except ValueError:
            return value
    return value


def domain_plan(zone: dict) -> dict:
    name = zone["name"]
    before = exact_records(zone, name, "MX")
    same = (len(before) == 1 and before[0].get("priority") == 10
            and normal_name(str(before[0].get("content", ""))) == MAIL_HOST)
    spf = [r for r in exact_records(zone, name, "TXT")
           if re.match(r"^v=spf1(?:\s|$)", txt_value(r), re.I)]
    dmarc = exact_records(zone, "_dmarc." + name, "TXT")
    dkim = [r for r in zone["records"] if r["type"] in ("TXT", "CNAME")
            and normal_name(r["name"]).endswith("._domainkey." + name)]
    findings = []
    if zone["status"] != "active" or zone["type"] != "full":
        findings.append("Zone is not active/full; verify authoritative DNS before cutover.")
    if exact_records(zone, name, "CNAME"):
        findings.append("Apex CNAME present; review Cloudflare coexistence/flattening before adding MX.")
    if any(r.get("content", "").strip() == "." for r in before):
        findings.append("Existing null MX: proposed change would enable incoming mail.")
    if any(r.get("locked") or (r.get("meta") or {}).get("managed_by_apps") for r in before):
        findings.append("An MX record appears managed/locked; review the managing service.")
    if any(normal_name(r["name"]) == "_mta-sts." + name for r in zone["records"]):
        findings.append("MTA-STS DNS record present; check the HTTPS policy allows mail.whispr.dev before cutover.")
    if any(r["type"] == "TLSA" for r in zone["records"]):
        findings.append("TLSA record(s) present; review DANE for the old and new MX hosts.")
    if len(spf) > 1:
        findings.append("Multiple apex SPF policies found; review before enabling new senders.")
    return {
        "domain": name, "zone_id": zone["zone_id"],
        "action": "KEEP" if same else ("REPLACE MX SET" if before else "ADD MX"),
        "before_mx": before,
        "proposed_mx": before if same else [{"type": "MX", "name": name,
            "content": MAIL_HOST, "priority": 10, "ttl": 300}],
        "spf_records": len(spf), "dmarc_records": len(dmarc),
        "dkim_record_names": sorted({normal_name(r["name"]) for r in dkim}),
        "findings": findings,
    }


def dns_query(name: str, kind: str) -> dict:
    try:
        data = get_json(DNS_BASE + "?" + urllib.parse.urlencode({"name": name, "type": kind}),
                        {"Accept": "application/dns-json"})
        if data.get("Status") != 0 or data.get("TC") is True:
            raise CheckError("DNS status %s or truncated answer" % data.get("Status", "unknown"))
        answers = data.get("Answer", [])
        if not isinstance(answers, list) or any(not isinstance(r, dict) for r in answers):
            raise CheckError("Invalid DNS answer shape")
        return {"ok": True, "answers": answers, "dnssec_ad": data.get("AD") is True}
    except CheckError as exc:
        return {"ok": False, "error": str(exc)}


def dns_values(result: dict, name: str, type_number: int) -> list[str]:
    return sorted({str(r.get("data", "")) for r in result.get("answers", [])
                   if r.get("type") == type_number and normal_name(r.get("name", "")) == name})


def socket_line(sock: socket.socket) -> bytes:
    line = bytearray()
    while len(line) < 8192:
        char = sock.recv(1)
        if not char:
            raise CheckError("Server closed the connection before a complete greeting/reply.")
        line.extend(char)
        if char == b"\n":
            return bytes(line)
    raise CheckError("Server reply exceeded the line limit.")


def smtp_reply(sock: socket.socket) -> tuple[int, list[bytes]]:
    lines = []
    first_code = None
    for _ in range(50):
        line = socket_line(sock)
        if len(line) < 4 or not line[:3].isdigit() or line[3:4] not in (b"-", b" "):
            raise CheckError("Malformed SMTP reply.")
        code = int(line[:3])
        if first_code is not None and code != first_code:
            raise CheckError("Inconsistent multiline SMTP reply.")
        first_code = code
        lines.append(line[4:].strip())
        if line[3:4] == b" ":
            return code, lines
    raise CheckError("SMTP reply exceeded the multiline limit.")


def probe(address: str, port: int) -> dict:
    result = {"address": address, "port": port, "tcp": False, "tls_verified": False}
    sock = None
    try:
        if not ipaddress.ip_address(address).is_global:
            raise CheckError("Non-public address skipped.")
        sock = socket.create_connection((address, port), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
        result["tcp"] = True
        if port in (25, 587):
            code, _ = smtp_reply(sock)
            if code != 220:
                raise CheckError("SMTP greeting returned %d." % code)
            result["smtp_greeting"] = True
            sock.sendall(b"EHLO mailcheck.invalid\r\n")
            code, lines = smtp_reply(sock)
            if code != 250:
                raise CheckError("SMTP EHLO returned %d." % code)
            if not any(line.upper() == b"STARTTLS" for line in lines):
                raise CheckError("SMTP reachable, but STARTTLS was not advertised.")
            sock.sendall(b"STARTTLS\r\n")
            code, _ = smtp_reply(sock)
            if code != 220:
                raise CheckError("STARTTLS returned %d." % code)
        context = ssl.create_default_context()
        sock = context.wrap_socket(sock, server_hostname=MAIL_HOST)
        result.update(tls_verified=True, tls_version=sock.version(),
                      certificate_expires=sock.getpeercert().get("notAfter"))
        if port == 993:
            if not socket_line(sock).upper().startswith(b"* OK"):
                raise CheckError("IMAPS did not return an unauthenticated OK greeting.")
        else:
            sock.sendall(b"EHLO mailcheck.invalid\r\n")
            code, _ = smtp_reply(sock)
            if code != 250:
                raise CheckError("Encrypted SMTP EHLO returned %d." % code)
            sock.sendall(b"QUIT\r\n")
        result["ok"] = True
    except CheckError as exc:
        result.update(ok=False, error=str(exc))
    except (OSError, ValueError) as exc:
        result.update(ok=False, error=network_error(exc))
    finally:
        if sock is not None:
            sock.close()
    return result


def read_token() -> str:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            token = getpass.getpass("Cloudflare API token (hidden; stays on this PC): ").strip()
    except (getpass.GetPassWarning, EOFError):
        raise CheckError("A hidden prompt is unavailable. Run in an interactive PowerShell terminal.") from None
    if not token or re.search(r"\s|[^\x21-\x7e]", token):
        raise CheckError("Empty token or invalid whitespace/characters; try copying it again.")
    return token


def run(output_root: Path, skip_network: bool) -> int:
    output_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
    folder = Path(tempfile.mkdtemp(prefix=stamp, dir=output_root))
    report: list[str] = []

    def say(value: str = "") -> None:
        value = safe_text(value, 6000)
        print(value, flush=True)
        report.append(value)

    snapshot = {"format": "sgp1-cloudflare-snapshot-v1", "version": VERSION,
                "started_at": utc_now(), "complete": False, "domains": list(DOMAINS),
                "zones": [], "errors": []}
    snapshot_path = folder / "snapshot.json"
    say("SGP1 CLOUDFLARE BACKUP AND MX PREVIEW " + VERSION)
    say("Read-only: 17 DNS zones; SMTP/TLS checks send no mail and perform no login.")
    say("Local output: " + str(folder))
    try:
        client = Cloudflare(read_token())
        for index, domain in enumerate(DOMAINS, 1):
            say("[%02d/17] Reading %s" % (index, domain))
            try:
                zone = client.zone_snapshot(domain)
                snapshot["zones"].append(zone)
                say("  Saved %d DNS records; zone status %s." % (len(zone["records"]), zone["status"]))
            except CheckError as exc:
                snapshot["errors"].append({"domain": domain, "error": str(exc)})
                say("  UNKNOWN: " + str(exc))
            atomic_json(snapshot_path, snapshot)
        del client
        snapshot["complete"] = len(snapshot["zones"]) == len(DOMAINS) and not snapshot["errors"]
        snapshot["finished_at"] = utc_now()
        atomic_json(snapshot_path, snapshot)
        account_ids = {z["account_id"] for z in snapshot["zones"]}
        same_account = len(account_ids) == 1 and None not in account_ids and "" not in account_ids
        say("\nDNS SNAPSHOT: %d/17 zones; single account: %s" %
            (len(snapshot["zones"]), "confirmed for captured zones" if same_account else "NOT CONFIRMED"))
        plans = [domain_plan(z) for z in snapshot["zones"]]
        atomic_json(folder / "mx-plan.json", {
            "format": "sgp1-mx-preview-v1", "created_at": utc_now(), "review_only": True,
            "snapshot_sha256": hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
            "snapshot_complete": snapshot["complete"], "single_account": same_account,
            "target": MAIL_HOST, "priority": 10, "domains": plans,
        })
        say("\nPROPOSED MX ROUTING (preview only; KEEP preserves the existing record and TTL)")
        for plan in plans:
            before = "; ".join("%s %s [TTL %s]" % (r.get("priority"), r.get("content"), r.get("ttl"))
                               for r in plan["before_mx"]) or "no explicit MX"
            say(plan["domain"] + ": " + plan["action"])
            say("  Current: " + before)
            if plan["action"] != "KEEP":
                say("  Proposed: 10 " + MAIL_HOST + " [TTL 300]")
            say("  Existing DNS: SPF %d; DMARC %d; DKIM names %d (presence only, not validation)." %
                (plan["spf_records"], plan["dmarc_records"], len(plan["dkim_record_names"])))
            for finding in plan["findings"]:
                say("  REVIEW: " + finding)

        checks = {"created_at": utc_now(), "findings": [], "public_dns": {}, "probes": []}
        hub_zone = next((z for z in snapshot["zones"] if z["name"] == "whispr.dev"), None)
        say("\nMAIL HOST: " + MAIL_HOST)
        if hub_zone:
            address_records = [r for r in hub_zone["records"]
                               if normal_name(r["name"]) == MAIL_HOST and r["type"] in ("A", "AAAA", "CNAME")]
            for record in address_records:
                say("  Cloudflare %s %s; proxied=%s" %
                    (record["type"], record.get("content"), record.get("proxied")))
            if any(r["type"] == "CNAME" for r in address_records):
                checks["findings"].append("MX target has a CNAME; resolve before cutover.")
            if any(r.get("proxied") for r in address_records):
                checks["findings"].append("Mail host is proxied; standard Cloudflare HTTP proxying cannot carry SMTP/IMAP.")
            if not any(r["type"] == "A" and r.get("content") == EXPECTED_IPV4 and r.get("proxied") is False
                       for r in address_records):
                checks["findings"].append("Expected DNS-only A record " + EXPECTED_IPV4 + " not confirmed.")
        else:
            checks["findings"].append("whispr.dev DNS snapshot unavailable; host settings unknown.")

        if skip_network:
            checks["findings"].append("Public DNS and port/TLS checks skipped by request; reachability unknown.")
        else:
            queries = [(MAIL_HOST, "A"), (MAIL_HOST, "AAAA"), (MAIL_HOST, "CNAME")]
            queries += [(d, "NS") for d in DOMAINS]
            say("Checking public DNS using Cloudflare's recursive resolver (cached results are possible)...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                futures = {pool.submit(dns_query, n, t): (n, t) for n, t in queries}
                for future in concurrent.futures.as_completed(futures):
                    name, kind = futures[future]
                    checks["public_dns"][name + " " + kind] = future.result()
            for kind, number in (("A", 1), ("AAAA", 28), ("CNAME", 5)):
                response = checks["public_dns"][MAIL_HOST + " " + kind]
                values = dns_values(response, MAIL_HOST, number)
                say("  Public " + kind + ": " + (", ".join(values) or ("none returned" if response["ok"] else response["error"])))
                if not response["ok"]:
                    checks["findings"].append("Public " + kind + " query failed; DNS unknown.")
                elif kind == "A" and values != [EXPECTED_IPV4]:
                    checks["findings"].append("Public A set differs from the known SGP1 IPv4; review before cutover.")
                elif kind == "CNAME" and values:
                    checks["findings"].append("Public MX target is a CNAME; review before cutover.")
            for zone in snapshot["zones"]:
                response = checks["public_dns"][zone["name"] + " NS"]
                actual = {normal_name(n) for n in dns_values(response, zone["name"], 2)}
                expected = {normal_name(n) for n in zone["name_servers"]}
                if not response["ok"] or not actual or actual != expected:
                    checks["findings"].append(zone["name"] + ": public NS result does not confirm this Cloudflare zone's assigned nameservers.")
            v6 = dns_values(checks["public_dns"][MAIL_HOST + " AAAA"], MAIL_HOST, 28)
            if len(v6) > 4:
                checks["findings"].append("More than four IPv6 addresses published; only the first four are probed.")
            addresses = [EXPECTED_IPV4] + v6[:4]
            say("Checking ports 25, 587 and 993 from THIS PC; TLS hostname: " + MAIL_HOST)
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                futures = {pool.submit(probe, address, port): (address, port)
                           for address in addresses for port in (25, 587, 993)}
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    checks["probes"].append(result)
                    label = "%s:%d" % (result["address"], result["port"])
                    say("  " + label + ": " + ("PASS " + str(result["tls_version"]) + "; certificate expires " + str(result["certificate_expires"])
                        if result["ok"] else "NOT VERIFIED: " + result["error"]))
            if any(not p["ok"] for p in checks["probes"]):
                checks["findings"].append("A failed connection can originate at this PC/ISP, the path, or SGP1. Retest the failing path from another node; do not infer the server is down.")
        for finding in checks["findings"]:
            say("REVIEW: " + finding)
        atomic_json(folder / "checks.json", checks)
        say("\n" + ("PREVIEW COMPLETE" if snapshot["complete"] else "PREVIEW INCOMPLETE") + ": no DNS or server configuration was changed.")
        say("No email was sent. Greeting/TLS checks do not prove mailbox delivery, login, outbound delivery, or spam handling.")
        say("Public DNS results are recursive observations, not direct authoritative queries. API reads are a per-zone snapshot, not an atomic account export.")
        say("Next: review this report, verify an external message reaches the mailbox, then prepare a pilot MX cutover.")
        say("Backups: " + str(folder))
        say("Share report.txt or terminal output. Keep snapshot.json private; it contains full DNS data and comments.")
        return 0 if snapshot["complete"] else 2
    except (CheckError, OSError) as exc:
        message = str(exc) if isinstance(exc, CheckError) else "Local file operation failed (%s)." % type(exc).__name__
        say("STOPPED: " + message)
        say("No DNS or server configuration was changed.")
        return 2
    except KeyboardInterrupt:
        say("\nInterrupted. No DNS or server configuration was changed; any completed snapshot remains in the output folder.")
        return 130
    finally:
        with (folder / "report.txt").open("w", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(report) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output-root", type=Path, default=Path.home() / "sgp1-mail-dns-backups",
                        help="Local backup directory (default: your user profile / sgp1-mail-dns-backups).")
    parser.add_argument("--skip-network", action="store_true", help="Back up/preview DNS only; mark public reachability unknown.")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    if sys.version_info < (3, 10):
        parser.error("Python 3.10 or newer is required.")
    try:
        return run(args.output_root.expanduser().resolve(), args.skip_network)
    except OSError as exc:
        print("Could not save local output (%s). No DNS changes were made." % type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
