#!/usr/bin/env python3
"""Probe four OLD published registrar MX routes from LON1, without changing DNS.

Python 3.10+, standard library only. Default mode prints a preview with no
network traffic; --send-all checks each selected published MX set before
sending. Use --skip-domain to omit a previously checked domain. It then
attempts at most ONE message to a fresh random address on each selected
domain through the published priority-10 forwarding host. STARTTLS with a
verified certificate for that host is required. The SMTP envelope sender
is empty. A pre-DATA rejection does not stop checks for other domains.

SMTP acceptance is NOT proof of forwarding or delivery into Thunderbird.
If a DATA response is lost, check the printed test ID before any retry.
Nonarrival is inconclusive: forwarding may target another mailbox, filtering
may interfere, or this test's empty envelope sender may be treated specially.

This script sends no credentials, reads no private DNS data, and changes no
server or DNS configuration. Do not use it after these domains' MX cutover.
"""

from __future__ import annotations

import argparse
import datetime as dt
from email.message import EmailMessage
from email.policy import SMTP as SMTP_POLICY
from email.utils import format_datetime
import json
import re
import smtplib
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

VERSION = "1.0.1"
DOMAINS = ("botforum.dev", "lickyour.skin", "showmesome.skin", "showmeyour.skin")
EXPECTED_MX = (
    (10, "eforward1.registrar-servers.com"),
    (10, "eforward2.registrar-servers.com"),
    (10, "eforward3.registrar-servers.com"),
    (15, "eforward4.registrar-servers.com"),
    (20, "eforward5.registrar-servers.com"),
)
PRIMARY = EXPECTED_MX[0][1]
DOH = "https://cloudflare-dns.com/dns-query"
MAX_DNS_BYTES = 64 * 1024
SMTP_TIMEOUT = 25


class ProbeFailed(Exception):
    """Controlled failure with no secrets in its message."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        raise ProbeFailed("The public DNS lookup redirected; refusing to send.")


def say(message: str) -> None:
    print(message, flush=True)


def safe(value: bytes | str) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", value)[:350]


def public_mx(domain: str) -> tuple[tuple[int, str], ...]:
    if domain not in DOMAINS:
        raise ProbeFailed("Unlisted domain; refusing DNS lookup.")
    request = urllib.request.Request(
        DOH + "?" + urllib.parse.urlencode({"name": domain, "type": "MX"}),
        headers={"Accept": "application/dns-json",
                 "User-Agent": "sgp1-registrar-forwarding-test/" + VERSION},
        method="GET",
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=10) as reply:
            if reply.status != 200:
                raise ProbeFailed(f"{domain}: public DNS returned HTTP {reply.status}.")
            payload = reply.read(MAX_DNS_BYTES + 1)
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
        raise ProbeFailed(f"{domain}: public DNS returned HTTP {status}.") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise ProbeFailed(f"{domain}: public DNS lookup failed.") from None
    if len(payload) > MAX_DNS_BYTES:
        raise ProbeFailed(f"{domain}: public DNS reply is too large.")
    try:
        result = json.loads(payload)
    except (ValueError, UnicodeError):
        raise ProbeFailed(f"{domain}: invalid public DNS response.") from None
    if not isinstance(result, dict) or result.get("Status") != 0 or result.get("TC") is not False:
        raise ProbeFailed(f"{domain}: public DNS error or truncated reply.")
    answers = result.get("Answer", [])
    if not isinstance(answers, list):
        raise ProbeFailed(f"{domain}: malformed DNS answer.")
    records: list[tuple[int, str]] = []
    for item in answers:
        if not isinstance(item, dict):
            raise ProbeFailed(f"{domain}: malformed DNS item.")
        if item.get("type") != 15:
            continue
        if str(item.get("name", "")).lower().rstrip(".") != domain:
            raise ProbeFailed(f"{domain}: unexpected MX record owner.")
        words = str(item.get("data", "")).split()
        if len(words) != 2 or not words[0].isascii() or not words[0].isdecimal():
            raise ProbeFailed(f"{domain}: malformed MX record.")
        records.append((int(words[0]), words[1].lower().rstrip(".")))
    found = tuple(sorted(records))
    if found != EXPECTED_MX:
        raise ProbeFailed(
            f"{domain}: MX no longer matches the five saved registrar hosts; "
            "no message sent to this route."
        )
    return found


def make_message(domain: str, test_id: str, now: dt.datetime) -> tuple[str, EmailMessage]:
    if domain not in DOMAINS or re.fullmatch(r"[a-f0-9]{32}", test_id) is None:
        raise ValueError("Invalid test domain or identifier.")
    recipient = f"setup-check-{now:%Y%m%d}-{test_id}@{domain}"
    message = EmailMessage(policy=SMTP_POLICY)
    message["From"] = f"Mail setup check <postmaster@{domain}>"
    message["To"] = recipient
    message["Date"] = format_datetime(now)
    message["Message-ID"] = f"<sgp1-old-forward.{test_id}@whispr.dev>"
    message["Subject"] = f"[SGP1 old MX] {domain} - {test_id[:12]}"
    message["Auto-Submitted"] = "auto-generated"
    message["X-SGP1-Setup-Test"] = test_id
    message.set_content(
        "Hello fren! This checks where the OLD registrar MX routes mail.\n\n"
        f"Domain: {domain}\nAddress tested: {recipient}\nTest ID: {test_id}\n\n"
        "This message went through the existing eforward1.registrar-servers.com "
        "MX host.\n"
        "If it reached your tom@whispr.dev Thunderbird mailbox, the old forwarding "
        "route worked for this newly generated address at the time of this test.\n\n"
        "No DNS records were changed. You need not reply.\n",
        charset="us-ascii",
    )
    return recipient, message


def check_smtp(code: int, response: bytes, good: tuple[int, ...], stage: str) -> None:
    if code not in good:
        raise ProbeFailed(f"SMTP {code}: {safe(response)}")


def transmit(domain: str, recipient: str, message: EmailMessage) -> int:
    test_id = str(message.get("X-SGP1-Setup-Test", ""))
    if (
        domain not in DOMAINS
        or re.fullmatch(r"[a-f0-9]{32}", test_id) is None
        or re.fullmatch(
            r"setup-check-[0-9]{8}-" + test_id + "@" + re.escape(domain), recipient
        ) is None
        or str(message.get("To", "")) != recipient
        or message.get_all("Cc")
        or message.get_all("Bcc")
    ):
        raise ProbeFailed("Unexpected message recipient or shape; refusing to send.")
    client: smtplib.SMTP | None = None
    stage = "TCP connection and greeting"
    data_started = False
    accepted = False
    try:
        # The host, not a resolved IP literal, makes smtplib check its TLS name.
        client = smtplib.SMTP(
            PRIMARY, 25, local_hostname="mailcheck.invalid", timeout=SMTP_TIMEOUT
        )
        if client.sock is None:
            raise ProbeFailed("SMTP connection has no socket.")
        say(f"Connected to {PRIMARY}:25 ({client.sock.getpeername()[0]}).")
        stage = "EHLO"
        check_smtp(*client.ehlo(), (250,), stage)
        if not client.has_extn("starttls"):
            raise ProbeFailed("STARTTLS not advertised; refusing plaintext submission.")
        stage = "STARTTLS and hostname validation"
        check_smtp(*client.starttls(context=ssl.create_default_context()), (220,), stage)
        say(f"TLS certificate verified for {PRIMARY}.")
        stage = "encrypted EHLO"
        check_smtp(*client.ehlo(), (250,), stage)
        stage = "MAIL FROM"
        check_smtp(*client.mail(""), (250,), stage)
        stage = "RCPT TO"
        check_smtp(*client.rcpt(recipient), (250, 251), stage)
        stage = "DATA acceptance"
        data_started = True
        code, response = client.data(message.as_bytes(policy=SMTP_POLICY))
        check_smtp(code, response, (250,), stage)
        accepted = True
        say(f"OLD MX SMTP ACCEPTED [{domain}]: {safe(response)}")
        return 0
    except (ProbeFailed, smtplib.SMTPResponseException) as exc:
        detail = (
            str(exc) if isinstance(exc, ProbeFailed)
            else f"SMTP {exc.smtp_code}: {safe(exc.smtp_error)}"
        )
        say(f"STOPPED [{domain}] at {stage}: {safe(detail)}")
        if data_started:
            say("DATA was submitted without confirmed acceptance. Check this ID before retrying.")
            return 3
        say("No DATA submitted for this domain; continuing with the others is safe.")
        return 2
    except (OSError, smtplib.SMTPException, ValueError, socket.timeout) as exc:
        detail = (
            f"TLS verification code {exc.verify_code}"
            if isinstance(exc, ssl.SSLCertVerificationError)
            else type(exc).__name__
        )
        say(f"STOPPED [{domain}] at {stage}: {detail}")
        if data_started:
            say("DELIVERY OUTCOME UNKNOWN. Check the test ID before rerunning.")
            return 3
        say("No DATA submitted; no automatic retry.")
        return 2
    except KeyboardInterrupt:
        say(
            "Interrupted. "
            + (
                "Delivery outcome unknown; check this test ID before rerunning."
                if data_started else "No DATA submitted."
            )
        )
        return 130
    finally:
        if client is not None:
            if accepted:
                try:
                    if client.sock is not None:
                        client.sock.settimeout(3)
                    client.quit()
                except (OSError, smtplib.SMTPException):
                    pass
            client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--send-all",
        action="store_true",
        help="check selected current public MX sets, then send up to four diagnostics",
    )
    parser.add_argument(
        "--skip-domain",
        action="append",
        choices=DOMAINS,
        default=[],
        help="omit one already-tested domain; repeat this option to omit several",
    )
    parser.add_argument("--version", action="version", version=VERSION)
    options = parser.parse_args()
    if sys.version_info < (3, 10):
        parser.error("Python 3.10+ is required.")
    domains = tuple(domain for domain in DOMAINS if domain not in options.skip_domain)
    if not domains:
        parser.error("All four domains were skipped; nothing to check.")
    tests = [
        (domain, *make_message(domain, uuid.uuid4().hex, dt.datetime.now(dt.timezone.utc)))
        for domain in domains
    ]
    say("SGP1 FOUR OLD FORWARDING MX TEST " + VERSION)
    for domain, recipient, message in tests:
        say(f"  {domain} -> {recipient} | {message['Subject']}")
    if not options.send_all:
        say("PREVIEW ONLY: no DNS lookup, email, token or file write.")
        return 0
    say(f"Checking {len(domains)} published MX set(s) before any email...")
    try:
        for domain in domains:
            public_mx(domain)
            say(f"OLD MX VERIFIED: {domain} -> five registrar forwarding hosts.")
    except ProbeFailed as exc:
        say(f"STOPPED BEFORE SMTP: {safe(str(exc))}")
        return 2
    say("Attempting at most one message per domain through its current registrar MX.")
    rejected: list[str] = []
    for index, (domain, recipient, message) in enumerate(tests, 1):
        say(f"[{index:02d}/{len(tests):02d}] {domain} | ID: {message['X-SGP1-Setup-Test']}")
        try:
            public_mx(domain)  # Stop if routing changed between preflight and send.
            result = transmit(domain, recipient, message)
        except ProbeFailed as exc:
            say(f"STOPPED [{domain}]: {safe(str(exc))}")
            return 2
        if result == 2:
            rejected.append(domain)
            continue
        if result != 0:
            say("Any earlier accepted test messages may still be in transit. No auto retry.")
            return result
    if rejected:
        say("PRE-DATA FAILURES (no message submitted): " + ", ".join(rejected))
        say("Check Thunderbird for accepted domains only; other old routes remain unproven.")
        return 4
    say(f"{len(tests)} OLD-MX SMTP ACCEPTANCES. Look for [SGP1 old MX] messages in Thunderbird.")
    say("Only seeing messages there proves old forwarding reached the shared mailbox.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
