#!/usr/bin/env python3
"""Targeted, read-only SMTP path check. Python 3.10+, no extra packages.

On Windows: python sgp1-port25-check.py --label WINDOWS
On LON1:    python3 sgp1-port25-check.py --label LON1
On SGP1:    sudo python3 sgp1-port25-check.py --server

The external target is fixed at SGP1's known IPv4, 68.183.227.135.
Separates TCP connection from the complete SMTP greeting. Waits up to 8 seconds
to connect and up to 40 seconds for the greeting. Sends QUIT only after a 220
greeting. No message, recipient, AUTH, password, EHLO or TLS negotiation is sent.

--server additionally reads service/listener state, selected Postfix settings,
and available UFW, IPv4 iptables and nftables rules. It does not change rules,
reload services, install packages, read mail/log contents, or write report files.
Firewall output is bounded and comments are omitted. Missing tools, truncated
output and failed probes are reported as unknowns, never as successful checks.

Exit 0: diagnostic completed, even if a network probe failed.
Exit 2: invalid invocation or server inspection cannot run. Exit 130: interrupted.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

VERSION = "1.0.0"
MAIL_HOST = "mail.whispr.dev"
SGP1_IP = "68.183.227.135"
LINUX_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
PRINT_LOCK = threading.Lock()
SETTINGS = (
    "myhostname", "inet_interfaces", "inet_protocols",
    "smtpd_delay_reject", "smtpd_client_restrictions",
    "smtpd_client_connection_count_limit", "smtpd_client_connection_rate_limit",
    "smtpd_upstream_proxy_protocol", "smtpd_upstream_proxy_timeout",
    "postscreen_greet_wait", "postscreen_greet_action",
    "postscreen_access_list", "postscreen_dnsbl_action",
    "postscreen_upstream_proxy_protocol", "postscreen_upstream_proxy_timeout",
    "content_filter", "smtpd_proxy_filter", "smtpd_milters", "non_smtpd_milters",
)


class DiagnosticError(Exception):
    pass


def clean(value: object, limit: int = 1200) -> str:
    value = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(value))
    if re.search(r"\b(?:inline|static):", value, re.I):
        return "[inline/static policy omitted; inspect locally if needed]"
    value = re.sub(r"(?i)\b(?:password|passwd|secret|token)\s*=\s*\S+", "[credential omitted]", value)
    value = re.sub(r"(\w+://)[^\s/@]+(?::[^\s/@]*)?@", r"\1[credentials omitted]@", value)
    # DNS/API secrets are never requested; omit arbitrary firewall comments too.
    value = re.sub(r'(?:(?:--)?comment\s+)(?:"(?:\\.|[^"\\])*"|\S+)', 'comment [omitted]', value)
    return value if len(value) <= limit else value[:limit] + " [truncated]"


def say(message: str = "") -> None:
    with PRINT_LOCK:
        print(clean(message, 2400), flush=True)


def error_name(exc: Exception) -> str:
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "timed out"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, ConnectionResetError):
        return "connection reset"
    if isinstance(exc, OSError):
        return "OS/network error %s" % (getattr(exc, "winerror", None) or exc.errno)
    return str(exc) if isinstance(exc, DiagnosticError) else type(exc).__name__


def greeting(sock: socket.socket, timeout: float) -> int:
    """Bound the entire multiline greeting, including a postscreen pre-greet."""
    deadline = time.monotonic() + timeout
    buffer = bytearray()
    expected = None
    lines = 0
    received = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("greeting deadline")
        sock.settimeout(remaining)
        chunk = sock.recv(1024)
        if not chunk:
            raise DiagnosticError("connection closed before a complete SMTP greeting")
        buffer.extend(chunk)
        received += len(chunk)
        if received > 65536:
            raise DiagnosticError("SMTP greeting exceeded 64 KiB")
        while b"\n" in buffer:
            line, _, rest = buffer.partition(b"\n")
            buffer = bytearray(rest)
            lines += 1
            if lines > 50 or len(line) > 8192:
                raise DiagnosticError("SMTP greeting exceeded line limits")
            match = re.fullmatch(rb"([0-9]{3})(?:([ -])[^\r\n]*)?\r?", line)
            if not match:
                raise DiagnosticError("response is not a valid SMTP greeting")
            code = int(match[1])
            if expected is not None and expected != code:
                raise DiagnosticError("inconsistent multiline SMTP greeting")
            expected = code
            if match[2] != b"-":
                return code
        if len(buffer) > 8192:
            raise DiagnosticError("SMTP greeting line exceeded 8 KiB")


def probe(address: str, port: int, label: str, connect_timeout: float, greeting_timeout: float) -> dict:
    prefix = f"{label} -> {address}:{port}"
    result = {"address": address, "port": port, "tcp": False, "greeting_220": False}
    sock = None
    phase = "TCP connection"
    say(prefix + ": connecting...")
    started = time.monotonic()
    try:
        sock = socket.create_connection((address, port), timeout=connect_timeout)
        result["tcp"] = True
        result["connect_seconds"] = round(time.monotonic() - started, 3)
        say(prefix + ": TCP CONNECTED in %.3fs; awaiting full SMTP greeting (up to %.0fs)..." %
            (result["connect_seconds"], greeting_timeout))
        phase = "SMTP greeting"
        started = time.monotonic()
        code = greeting(sock, greeting_timeout)
        result["greeting_code"] = code
        result["greeting_seconds"] = round(time.monotonic() - started, 3)
        if code != 220:
            raise DiagnosticError("SMTP greeting code %d (not ready)" % code)
        result["greeting_220"] = True
        say(prefix + ": SMTP 220 READY after %.3fs; no mail sent." % result["greeting_seconds"])
        try:
            sock.settimeout(2)
            sock.sendall(b"QUIT\r\n")
        except OSError:
            # A close during QUIT does not invalidate an observed 220 greeting.
            pass
    except (OSError, DiagnosticError) as exc:
        result.update(failed_phase=phase, error=error_name(exc))
        say(prefix + ": " + phase.upper() + " NOT VERIFIED: " + result["error"])
    finally:
        if sock is not None:
            sock.close()
    return result


def run_command(name: str, *arguments: str) -> tuple[int, str]:
    executable = shutil.which(name, path=LINUX_PATH)
    if executable is None:
        return 127, ""
    try:
        result = subprocess.run([executable, *arguments], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, encoding="utf-8", errors="replace", timeout=8,
                                env={"PATH": LINUX_PATH, "LC_ALL": "C", "LANG": "C"}, check=False)
        return result.returncode, result.stdout
    except subprocess.TimeoutExpired:
        return 124, ""
    except OSError:
        return 126, ""


def command_report(title: str, name: str, *arguments: str, limit: int = 160) -> None:
    say("\n" + title)
    code, output = run_command(name, *arguments)
    if code:
        say("UNKNOWN: command unavailable/unsuccessful (exit %d)." % code)
        return
    lines = output.splitlines()
    for line in lines[:limit]:
        say("  " + line)
    if not lines:
        say("  No output returned.")
    if len(lines) > limit:
        say("TRUNCATED: %d of %d lines shown. This is not a complete firewall verdict." % (limit, len(lines)))


def server_details() -> bool:
    if not sys.platform.startswith("linux") or not hasattr(os, "geteuid") or os.geteuid() != 0:
        say("Server inspection requires Linux and sudo. Use the SGP1 command supplied with this file.")
        return False
    code, hostname = run_command("postconf", "-h", "myhostname")
    if code or hostname.strip().lower().rstrip(".") != MAIL_HOST:
        say("SGP1 identity not confirmed: expected Postfix myhostname=" + MAIL_HOST + ".")
        say("Stopped server inspection; check that the SSH alias used was sgp1.")
        return False
    say("Confirmed Postfix hostname: " + MAIL_HOST)
    say("\nPOSTFIX SERVICE")
    code, state = run_command("systemctl", "is-active", "postfix")
    state = state.strip()
    if state in ("active", "inactive", "failed", "activating", "deactivating"):
        say("  postfix: " + state)
    else:
        say("  UNKNOWN: service status unavailable (exit %d)." % code)
    say("\nLOCAL TCP LISTENERS (25 and 587)")
    code, output = run_command("ss", "-H", "-lntp")
    if code:
        say("UNKNOWN: ss unavailable/unsuccessful (exit %d)." % code)
    else:
        selected = [line for line in output.splitlines() if len(line.split()) >= 4
                    and line.split()[3].rsplit(":", 1)[-1] in ("25", "587")]
        for line in selected:
            say("  " + line)
        if not selected:
            say("No listeners on 25 or 587 were returned.")
    say("\nSMTP SERVICE DEFINITIONS (command arguments omitted)")
    code, output = run_command("postconf", "-M")
    found = False
    if code:
        say("UNKNOWN: postconf -M failed (exit %d)." % code)
    else:
        for line in output.splitlines():
            fields = line.split()
            if len(fields) >= 8 and fields[1] == "inet" and fields[0].rsplit(":", 1)[-1] in ("smtp", "25", "submission", "587"):
                say("  " + " ".join(fields[:8]))
                found = True
        if not found:
            say("No standard smtp/submission inet entries found; inspect custom service bindings.")
    command_report("SELECTED POSTFIX SETTINGS", "postconf", "-x", *SETTINGS)
    say("\nSELECTED SERVICE OVERRIDES")
    code, output = run_command("postconf", "-P")
    if code:
        say("UNKNOWN: service overrides unavailable (exit %d)." % code)
    else:
        selected = [line for line in output.splitlines() if "/inet/" in line
                    and line.partition("=")[0].strip().rsplit("/", 1)[-1] in SETTINGS]
        for line in selected:
            say("  " + line)
        if not selected:
            say("No overrides for these selected settings.")
    command_report("UFW STATUS AND RULES", "ufw", "status", "verbose", limit=120)
    command_report("IPV4 IPTABLES FILTER RULES", "iptables", "-w", "3", "-S", limit=180)
    command_report("NFTABLES RULESET", "nft", "-n", "list", "ruleset", limit=180)
    say("Cloud-provider firewall rules and provider SMTP restrictions are outside this server inspection.")
    say("The following loopback probes test the local service; they do not test the public network path.")
    return True


def previous_check(path: Path) -> None:
    say("\nEARLIER STAGE 2 CONNECTION DETAIL")
    try:
        if path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("oversized check file")
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        probes = data.get("probes", []) if isinstance(data, dict) else []
        selected = [r for r in probes if isinstance(r, dict) and r.get("address") == SGP1_IP and r.get("port") == 25]
        if not selected:
            raise ValueError("matching probe missing")
        for result in selected:
            tcp = result.get("tcp")
            status = "connected" if tcp is True else ("not established" if tcp is False else "unknown")
            say("  SGP1 port 25 TCP: " + status)
            say("  SMTP 220 greeting observed: " + ("yes" if result.get("smtp_greeting") is True else "not recorded"))
            say("  TLS verified: " + ("yes" if result.get("tls_verified") is True else "no"))
        say("  This is the earlier run's result; new probes below show the current path.")
    except (OSError, ValueError, TypeError):
        say("Earlier checks.json unavailable/unreadable; continuing with fresh probes.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", action="store_true", help="Read SGP1 configuration/firewall and probe loopback; sudo required.")
    parser.add_argument("--label", default="THIS COMPUTER", help="Label only; target remains the fixed SGP1 IPv4.")
    parser.add_argument("--previous-checks", type=Path, help="Optional local Stage 2 checks.json; selected connection flags only.")
    parser.add_argument("--connect-timeout", type=int, choices=range(2, 31), default=8, metavar="2..30")
    parser.add_argument("--greeting-timeout", type=int, choices=range(10, 61), default=40, metavar="10..60")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    if sys.version_info < (3, 10):
        parser.error("Python 3.10+ is required.")
    say("SGP1 SMTP PATH CHECK " + VERSION + " | " + dt.datetime.now(dt.timezone.utc).isoformat())
    say("Read-only. No email, login, firewall change, package install or service restart.")
    if args.previous_checks:
        previous_check(args.previous_checks)
    if args.server and not server_details():
        return 2
    label = "SGP1 LOOPBACK" if args.server else clean(args.label, 50)
    address = "127.0.0.1" if args.server else SGP1_IP
    say("\nPROBES: TCP connection and SMTP greeting are reported separately.")
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(probe, address, port, label, args.connect_timeout, args.greeting_timeout)
                   for port in (25, 587)]
        results = [future.result() for future in futures]
    say("\nRESULTS")
    for result in results:
        say("  %s:%d | TCP=%s | SMTP_220=%s" %
            (address, result["port"], "YES" if result["tcp"] else "NO", "YES" if result["greeting_220"] else "NO"))
    if not args.server:
        if next(r for r in results if r["port"] == 25)["greeting_220"]:
            say("Port 25 answered from this source. Recipient acceptance and mailbox delivery still need a real external message.")
        else:
            say("Port 25 is not verified from this source. Failure alone cannot distinguish source/provider filtering, path filtering or SGP1 issues.")
        say("LON1 is another source, but its provider may also restrict outbound SMTP; a failed LON1 probe is not independent proof of an SGP1 block.")
    say("Diagnostic finished. No DNS or mail configuration was changed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        say("\nInterrupted. No DNS or mail configuration was changed.")
        raise SystemExit(130)
