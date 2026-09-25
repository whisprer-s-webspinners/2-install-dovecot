#!/usr/bin/env python3
"""Read current public MX records for eight existing mail routes.

Python 3.10+, standard library only. Run on the Windows PC with no arguments.
Makes eight HTTPS GET requests to Cloudflare's public DNS resolver. Does not
request an API token, send mail, change DNS, or write local files.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


VERSION = "1.0.0"
DOMAINS = (
    "botforum.dev", "dailystonks.org", "fastping.it.com", "litehaus.online",
    "primercrate.rs", "lickyour.skin", "showmesome.skin", "showmeyour.skin",
)
DOH_URL = "https://cloudflare-dns.com/dns-query"
MAX_RESPONSE_BYTES = 64 * 1024
TARGET_PATTERN = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*", re.IGNORECASE)


class InventoryError(Exception):
    """DNS lookup failed or returned an answer we cannot safely interpret."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def public_mx(domain: str) -> list[tuple[int, str, int]]:
    """Return (priority, target, observed TTL) from one exact-name MX query."""
    if domain not in DOMAINS:
        raise InventoryError("Unexpected domain; refusing the request.")
    url = DOH_URL + "?" + urllib.parse.urlencode({"name": domain, "type": "MX"})
    request = urllib.request.Request(
        url, headers={"Accept": "application/dns-json",
                      "User-Agent": "sgp1-eight-mx-inventory/" + VERSION},
        method="GET",
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=10) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        raise InventoryError(f"Public DNS returned HTTPS {code}.") from None
    except (urllib.error.URLError, OSError):
        raise InventoryError("Public DNS HTTPS request failed or timed out.") from None
    if len(body) > MAX_RESPONSE_BYTES:
        raise InventoryError("Public DNS response was too large.")
    try:
        data = json.loads(body)
    except (ValueError, UnicodeError):
        raise InventoryError("Public DNS returned invalid JSON.") from None
    if not isinstance(data, dict) or type(data.get("Status")) is not int:
        raise InventoryError("Public DNS returned an invalid response.")
    if data["Status"] != 0 or data.get("TC") is not False:
        raise InventoryError(f"Public DNS error (status {data['Status']}) or truncated answer.")
    question = data.get("Question")
    if (not isinstance(question, list) or len(question) != 1
            or not isinstance(question[0], dict)
            or str(question[0].get("name", "")).lower().rstrip(".") != domain
            or question[0].get("type") != 15):
        raise InventoryError("Public DNS answered a different question.")
    answers = data.get("Answer", [])
    if not isinstance(answers, list):
        raise InventoryError("Public DNS answer is malformed.")
    records: list[tuple[int, str, int]] = []
    for row in answers:
        if not isinstance(row, dict):
            raise InventoryError("Public DNS record is malformed.")
        owner = str(row.get("name", "")).lower().rstrip(".")
        if owner != domain:
            continue
        if row.get("type") == 5:
            raise InventoryError("Queried name returned a CNAME; inspect this DNS zone.")
        if row.get("type") != 15:
            continue
        parts = str(row.get("data", "")).split()
        ttl = row.get("TTL")
        if (len(parts) != 2 or not parts[0].isascii() or not parts[0].isdecimal()
                or not 0 <= int(parts[0]) <= 65535 or len(parts[1]) > 255
                or not TARGET_PATTERN.fullmatch(parts[1].rstrip("."))
                or type(ttl) is not int or ttl < 0):
            raise InventoryError("Public DNS MX entry is malformed.")
        records.append((int(parts[0]), parts[1].lower().rstrip("."), ttl))
    return sorted(records, key=lambda item: (item[0], item[1]))


def main() -> int:
    if len(sys.argv) != 1:
        print("Usage: python sgp1-eight-mx-inventory.py", file=sys.stderr)
        return 2
    print("SGP1 EIGHT LEGACY MX INVENTORY " + VERSION, flush=True)
    print("Time (UTC): " + dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"))
    print("Read-only public DNS; no Cloudflare token, DNS change, or email.\n", flush=True)
    failures = 0
    for index, domain in enumerate(DOMAINS, start=1):
        try:
            records = public_mx(domain)
        except InventoryError as exc:
            failures += 1
            print(f"[{index:02d}/08] {domain}: UNKNOWN - {exc}", flush=True)
            continue
        print(f"[{index:02d}/08] {domain}: {len(records)} MX record(s)", flush=True)
        if not records:
            print("    No explicit MX in this recursive answer; inspect the zone before changes.")
        for priority, target, ttl in records:
            print(f"    {priority} {target} (observed TTL {ttl}s)", flush=True)
    print("\nMX targets show public routing, not where forwarding ultimately delivers.")
    print("For eforward*.registrar-servers.com, inspect provider forwarding destinations.")
    print("For any _dc-mx.* target, inspect the underlying MX and proxy setting in Cloudflare.")
    print("For other old mail hosts, check whether existing mail or queues need preserving.")
    print("Share this terminal output; do not change the eight MX sets yet.")
    if failures:
        print(f"INCOMPLETE: {failures} DNS lookup(s) could not be inventoried.")
        return 1
    print("INVENTORY COMPLETE: eight public MX answers; no changes made.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nStopped; no changes were made.", file=sys.stderr)
        sys.exit(130)
