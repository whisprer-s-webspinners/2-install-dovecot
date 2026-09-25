#!/usr/bin/env python3
"""Read-only mail discovery for SGP1. Python 3.10+, Linux, standard library.

Run: sudo python3 sgp1-mail-audit-v1.py
Use --no-dns to omit public DNS queries. No email is sent and no configuration,
packages, services, databases, or mail files are changed. Output goes to stdout.
The report includes domains, public DNS, selected configuration, and local paths;
it deliberately excludes credentials, key material, mail contents, and logs.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

VERSION = "1.0.0"
DOMAINS = (
    "80days.site", "analoglogic.blog", "blairboulevard.website", "botforum.dev",
    "dailystonks.org", "fastping.it.com", "gongle.us", "litehaus.online",
    "primercrate.rs", "lickyour.skin", "showmesome.skin", "showmeyour.skin",
    "showsome.skin", "specter.in.net", "stealingdatais.gay", "whispr.dev", "yt.cafe",
)
COMMAND_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
ENV = {"PATH": COMMAND_PATH, "LC_ALL": "C", "LANG": "C"}
POSTFIX_FIELDS = (
    "mail_version", "myhostname", "mydomain", "myorigin", "mydestination",
    "inet_interfaces", "inet_protocols", "virtual_alias_domains",
    "virtual_alias_maps", "virtual_mailbox_domains", "virtual_mailbox_maps",
    "virtual_transport", "local_transport", "mailbox_transport", "home_mailbox",
    "alias_maps", "relayhost", "relay_domains", "mynetworks",
    "smtpd_relay_restrictions", "smtpd_recipient_restrictions",
    "smtpd_sender_restrictions", "smtpd_sender_login_maps", "smtpd_sasl_type",
    "smtpd_sasl_path", "smtpd_sasl_auth_enable", "smtpd_tls_security_level",
    "smtpd_tls_auth_only", "smtpd_tls_chain_files", "smtpd_tls_cert_file",
    "smtpd_milters", "non_smtpd_milters", "message_size_limit", "queue_directory",
)
OVERRIDE_FIELDS = frozenset((
    "smtpd_sasl_auth_enable", "smtpd_tls_security_level", "smtpd_tls_auth_only",
    "smtpd_relay_restrictions", "smtpd_recipient_restrictions",
    "smtpd_sender_restrictions", "smtpd_sender_login_maps",
))
DOVECOT_FIELDS = frozenset((
    "protocols", "mail_location", "mail_driver", "mail_path", "mail_home",
    "auth_username_format", "auth_mechanisms", "disable_plaintext_auth",
    "auth_allow_cleartext", "ssl", "ssl_cert",
))
LOCAL_MAP = re.compile(r"(?:proxy:)?(?:hash|btree|lmdb|cdb|dbm|sdbm|texthash):/[A-Za-z0-9_./+\-]+\Z")
PATH_TOKEN = re.compile(r"/[A-Za-z0-9_./+\-]+\Z")
ADDRESS = re.compile(r"[A-Za-z0-9_.+%\-]+(?:@[A-Za-z0-9.\-]+)?\Z")


def executable(name: str) -> str | None:
    return shutil.which(name, path=COMMAND_PATH)


def run(name: str, *args: str, timeout: int = 8) -> tuple[int, str]:
    """Only fixed read/query commands call this; never print raw stderr."""
    command = executable(name)
    if command is None:
        return 127, ""
    try:
        result = subprocess.run(
            [command, *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, check=False, env=ENV,
        )
        return result.returncode, result.stdout
    except subprocess.TimeoutExpired:
        return 124, ""
    except OSError:
        return 126, ""


def public_value(value: str) -> str:
    """Sanitize selected settings; inline map bodies are never reported."""
    value = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", value).strip()
    if re.search(r"\b(?:inline|static):", value, re.I):
        return "[inline/static value withheld; inspect locally if needed]"
    value = re.sub(r"(\w+://)[^\s/@]+(?::[^\s/@]*)?@", r"\1[credentials]@", value)
    value = re.sub(r"(?i)\b(password|passwd|secret|token|passphrase)\s*=\s*\S+", r"\1=[redacted]", value)
    return (value[:1800] + " [truncated]") if len(value) > 1800 else value


def key_values(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip()
    return values


def section(title: str) -> None:
    print("\n" + title, flush=True)


def services() -> None:
    section("SERVICES AND TCP LISTENERS")
    for name in ("postfix", "dovecot", "opendkim", "rspamd", "spamassassin", "postfix-caddy-cert-sync.timer"):
        code, output = run("systemctl", "is-active", name)
        state = output.strip()
        print(f"{name}: {state if state in {'active', 'inactive', 'failed', 'activating', 'deactivating', 'unknown'} else 'unavailable (exit ' + str(code) + ')'}")
    code, output = run("ss", "-H", "-lnt")
    if code:
        print(f"Listeners: unavailable (exit {code})")
        return
    endpoints = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[3].rsplit(":", 1)[-1] in {"25", "110", "143", "465", "587", "993", "995", "4190"}:
            endpoints.add(fields[3])
    print("Local mail listeners: " + (", ".join(sorted(endpoints)) or "none found"))


def postfix() -> dict[str, str]:
    section("POSTFIX: SELECTED EFFECTIVE SETTINGS")
    code, output = run("postconf", "-x", *POSTFIX_FIELDS)
    values = key_values(output)
    if code:
        print(f"postconf returned {code}; available output may be incomplete.")
    for key in POSTFIX_FIELDS:
        print(f"{key} = {public_value(values[key]) if key in values else '[unavailable]'}")
    section("POSTFIX: SUBMISSION SERVICE OVERRIDES")
    code, output = run("postconf", "-P")
    found = False
    for key, value in key_values(output).items():
        if "/inet/" in key and key.rsplit("/", 1)[-1] in OVERRIDE_FIELDS:
            print(f"{public_value(key)} = {public_value(value)}")
            found = True
    if not found:
        print(f"No selected inet overrides reported (exit {code}); this is not a submission-security verdict.")
    return values


def alias_queries(values: dict[str, str]) -> None:
    section("EXISTING CATCH-ALL MAP LOOKUPS")
    raw = values.get("virtual_alias_maps", "")
    tokens = [x for x in re.split(r"[\s,]+", raw) if x]
    maps = [x.removeprefix("proxy:") for x in tokens if LOCAL_MAP.fullmatch(x)]
    if not maps:
        print("No supported local indexed/texthash alias map discovered. Other backends need a targeted review.")
        return
    if len(maps) != len(tokens) or len(maps) > 4:
        print("Some maps are not queried; SQL, regex, inline, and other backends are deliberately skipped.")
    print("These are exact key lookups, not SMTP acceptance tests or complete recursive delivery proofs.")
    for table in maps[:4]:
        print("Map: " + table)
        for key in ("tom@whispr.dev", *("@" + domain for domain in DOMAINS)):
            code, output = run("postmap", "-q", key, table, timeout=3)
            target = output.strip()
            if code == 0 and target:
                recipients = [x.strip() for x in target.split(",")]
                display = ", ".join(recipients) if all(ADDRESS.fullmatch(x) for x in recipients) else "[non-simple destination withheld]"
            elif code == 1 and not target:
                display = "no exact entry"
            else:
                display = f"lookup unavailable/inconclusive (exit {code})"
            print(f"  {key} -> {display}")


def dovecot() -> None:
    section("DOVECOT: STORAGE AND AUTHENTICATION SHAPE")
    code, output = run("dovecot", "--version")
    print("Version: " + (public_value(output) if code == 0 else f"unavailable (exit {code})"))
    code, output = run("doveconf", "-n")
    if code:
        print(f"doveconf unavailable (exit {code}); no raw diagnostic or config is printed.")
        return
    stack: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "}":
            if stack:
                stack.pop()
            continue
        if line.endswith("{") and "=" not in line:
            label = line[:-1].strip()
            stack.append(label)
            if label.split()[0] in {"passdb", "userdb"}:
                print("Authentication block: " + public_value(label))
            continue
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep:
            continue
        if key in DOVECOT_FIELDS or (key == "driver" and any(x.split()[0] in {"passdb", "userdb"} for x in stack)):
            context = "/".join(stack) or "global"
            print(f"{public_value(context)}: {key} = {public_value(value)}")
    print("Authentication arguments, queries, credentials, and private keys are omitted.")


def certificates(values: dict[str, str]) -> None:
    section("CONFIGURED POSTFIX CERTIFICATE FILES")
    paths = set()
    for key in ("smtpd_tls_chain_files", "smtpd_tls_cert_file"):
        for token in re.split(r"[\s,]+", values.get(key, "")):
            if PATH_TOKEN.fullmatch(token):
                paths.add(token)
    if not paths:
        print("No simple certificate path found; configuration needs a targeted review.")
    for path in sorted(paths):
        code, output = run("openssl", "x509", "-in", path, "-noout", "-subject", "-issuer", "-dates")
        print("File: " + path)
        if code:
            print(f"  Certificate details unavailable (exit {code})")
        else:
            for line in output.splitlines():
                if line.startswith(("subject=", "issuer=", "notBefore=", "notAfter=")):
                    print("  " + public_value(line))
    print("File inspection does not prove which certificate remote clients currently receive.")


def dns_query(domain: str, record: str) -> str:
    code, output = run("dig", "+time=2", "+tries=1", "+noall", "+comments", "+answer", domain + ".", record, timeout=5)
    if code:
        return f"unavailable (exit {code})"
    match = re.search(r"status:\s*([A-Z0-9]+)", output)
    if not match:
        return "unrecognised DNS response"
    if match.group(1) != "NOERROR":
        return match.group(1)
    answers = []
    for line in output.splitlines():
        if line.startswith(";"):
            continue
        fields = line.split(None, 4)
        if len(fields) == 5 and fields[3] == record:
            answers.append(fields[4])
    return public_value(" | ".join(answers)) if answers else "no record in answer"


def dns_inventory() -> None:
    section("PUBLIC DNS: MX AND NAMESERVERS")
    if not executable("dig"):
        print("dig is not installed; DNS checks skipped. No packages have been installed.")
        return
    print("Querying the configured resolver; cached results may differ from authoritative DNS.", flush=True)
    jobs = [(domain, record) for domain in DOMAINS for record in ("MX", "NS")]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(dns_query, domain, record) for domain, record in jobs]
        for (domain, record), future in zip(jobs, futures):
            print(f"{domain} {record}: {future.result()}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--no-dns", action="store_true", help="Skip public MX/NS lookups.")
    options = parser.parse_args()
    if sys.platform != "linux":
        print("Run this script on the Linux SGP1 server, not directly on Windows.", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("Run with sudo so the configuration can be inspected without missing permissions.", file=sys.stderr)
        return 2
    print(f"SGP1 MAIL DISCOVERY {VERSION} | {dt.datetime.now(dt.timezone.utc).isoformat()}")
    print(f"Requested design: catch-all for {len(DOMAINS)} domains -> existing tom@whispr.dev mailbox")
    print("Inspection only. No email, configuration changes, package installs, or service restarts.")
    print("Hostname: " + public_value(os.uname().nodename))
    print("Python: " + sys.version.split()[0])
    usage = shutil.disk_usage("/")
    print(f"Root disk: {usage.free / 1024**3:.1f} GiB free of {usage.total / 1024**3:.1f} GiB")
    try:
        memory = Path("/proc/meminfo").read_text(encoding="ascii")
        match = re.search(r"^MemAvailable:\s+(\d+) kB", memory, re.M)
        if match:
            print(f"Available RAM: {int(match.group(1)) / 1024:.0f} MiB")
    except OSError:
        print("Available RAM: unavailable")
    services()
    values = postfix()
    alias_queries(values)
    dovecot()
    certificates(values)
    if not options.no_dns:
        dns_inventory()
    section("STILL TO VERIFY BEFORE CHANGES")
    print("External SMTP reachability, actual sending/receiving, recursive alias termination,")
    print("mailbox delivery and login, SPF/DKIM/DMARC, spam handling, queue condition,")
    print("certificate renewal, backups, DNS ownership, and permissions for application senders.")
    print("Missing tools or skipped checks are unknowns, not passes. End of read-only discovery.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInspection interrupted; no configuration changes were made.", file=sys.stderr)
        raise SystemExit(130)
