#!/usr/bin/env python3
"""Read public A/AAAA answers for four domains' existing custom MX hosts.

Run directly on Windows with Python 3.10+. This script only performs public
HTTPS DNS queries; it needs no Cloudflare token and changes nothing. A DNS
answer cannot establish whether a host stores mail or has a working mailbox.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import sys
import urllib.error
import urllib.parse
import urllib.request


VERSION = "1.0.0"
SGP1_IP = ipaddress.IPv4Address("68.183.227.135")
HOSTS = (
    ("dailystonks.org", "mx1.dailystonks.org"),
    ("dailystonks.org", "mx2.dialystonks.org"),
    ("dailystonks.org", "mx3.dailystonks.org"),
    ("dailystonks.org", "mx4.dailystonks.org"),
    ("dailystonks.org", "mx5.dailystonks.org"),
    ("fastping.it.com", "mail.fastping.it.com"),
    ("litehaus.online", "mail.litehaus.online"),
    ("primercrate.rs: published MX", "_dc-mx.2faae15247e6.primercrate.rs"),
    ("primercrate.rs: configured MX in earlier backup", "mail.primercrate.rs"),
    ("intended SGP1 host", "mail.whispr.dev"),
)
URL = "https://cloudflare-dns.com/dns-query"
LIMIT = 64 * 1024
TYPES = {"A": 1, "AAAA": 28}


class LookupError(Exception):
    """A DNS request failed; the host's current address is unknown."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def lookup(name: str, kind: str) -> tuple[int, list[str]]:
    if name not in {host for _, host in HOSTS} or kind not in TYPES:
        raise LookupError("Host or record type is outside this inventory.")
    uri = URL + "?" + urllib.parse.urlencode({"name": name, "type": kind})
    request = urllib.request.Request(
        uri, headers={"Accept": "application/dns-json",
                      "User-Agent": "sgp1-legacy-host-resolve/" + VERSION},
        method="GET",
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=10) as response:
            body = response.read(LIMIT + 1)
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        raise LookupError(f"HTTPS {code}") from None
    except (urllib.error.URLError, OSError):
        raise LookupError("HTTPS request failed or timed out") from None
    if len(body) > LIMIT:
        raise LookupError("response too large")
    try:
        data = json.loads(body)
    except (ValueError, UnicodeError):
        raise LookupError("invalid DNS JSON") from None
    question = data.get("Question") if isinstance(data, dict) else None
    if (not isinstance(question, list) or len(question) != 1
            or not isinstance(question[0], dict)
            or str(question[0].get("name", "")).lower().rstrip(".") != name
            or question[0].get("type") != TYPES[kind]
            or type(data.get("Status")) is not int or data.get("Status") not in (0, 3)
            or data.get("TC") is not False):
        raise LookupError("unusable or truncated DNS answer")
    if data["Status"] == 3:
        return 3, []
    answer = data.get("Answer", [])
    if not isinstance(answer, list):
        raise LookupError("malformed DNS answer")
    addresses: set[str] = set()
    for row in answer:
        if not isinstance(row, dict):
            raise LookupError("malformed DNS record")
        if row.get("type") != TYPES[kind]:
            continue
        # DoH can include an address for the endpoint of a CNAME chain.
        # Label it as a resolved result, not necessarily a direct A/AAAA.
        try:
            address = ipaddress.ip_address(str(row.get("data", "")))
        except ValueError:
            raise LookupError("invalid address in DNS answer") from None
        if address.version != (4 if kind == "A" else 6):
            raise LookupError("address family differs from DNS question")
        addresses.add(str(address))
    return 0, sorted(addresses)


def main() -> int:
    if len(sys.argv) != 1:
        print("Usage: python sgp1-legacy-host-resolve.py", file=sys.stderr)
        return 2
    print("SGP1 LEGACY MAIL HOST RESOLUTION " + VERSION)
    print("Time (UTC): " + dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"))
    print("Read-only public DNS; no token, mail, or DNS change.\n", flush=True)
    errors = 0
    for label, host in HOSTS:
        print(label + " | " + host, flush=True)
        result: dict[str, list[str]] = {}
        for kind in TYPES:
            try:
                status, addresses = lookup(host, kind)
            except LookupError as exc:
                errors += 1
                print(f"  {kind}: UNKNOWN ({exc})", flush=True)
                continue
            if status == 3:
                print(f"  {kind}: NXDOMAIN", flush=True)
            else:
                print(f"  {kind}: {', '.join(addresses) if addresses else 'no address returned'}", flush=True)
                result[kind] = addresses
        if str(SGP1_IP) in result.get("A", []):
            print("  NOTE: this public IPv4 answer includes the current SGP1 mail IP.", flush=True)
    print("\nDNS resolution does not prove SMTP delivery or reveal stored messages.")
    print("Share this terminal output to decide which old mail hosts need inspection.")
    if errors:
        print(f"INCOMPLETE: {errors} DNS lookup(s) unknown; no changes made.")
        return 1
    print("HOST INVENTORY COMPLETE: no changes made.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nStopped; no changes were made.", file=sys.stderr)
        sys.exit(130)
