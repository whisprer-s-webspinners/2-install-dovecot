#!/usr/bin/env python3
"""Check the public MX for seven zones and send one test per zone from LON1.

Python 3.10+, standard library only. The default prints a local preview and
does no network I/O. On LON1, --send-all first checks all seven public MX
answers, then sends at most seven small messages to new random recipients.

Each message follows the advertised MX, confirms the connected IPv4 is SGP1,
requires STARTTLS and a valid certificate for mail.whispr.dev, and uses an
empty SMTP envelope sender. No credentials, DNS/config changes or retries.

After SMTP accepts a message, check the existing tom@whispr.dev mailbox in
Thunderbird; SMTP acceptance alone does not establish final mailbox delivery.
If a DATA response is lost, inspect the printed test ID before another run.
"""

from __future__ import annotations

import argparse
import datetime as dt
from email.message import EmailMessage
from email.policy import SMTP as SMTP_POLICY
from email.utils import format_datetime
import ipaddress
import json
import re
import smtplib
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

VERSION = "1.0.0"
DOMAINS = (
    "80days.site", "analoglogic.blog", "blairboulevard.website", "gongle.us",
    "showsome.skin", "specter.in.net", "stealingdatais.gay",
)
MAIL_HOST = "mail.whispr.dev"
EXPECTED_IP = "68.183.227.135"
DOH_URL = "https://cloudflare-dns.com/dns-query"
DOH_LIMIT = 64 * 1024
SMTP_TIMEOUT = 30


class CheckFailed(Exception):
    """An expected failure whose message contains no credentials."""


def safe(value: object) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(value))[:350]


def say(value: str) -> None:
    print(value, flush=True)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CheckFailed("Public DNS lookup redirected; no message was sent.")


def published_mx(domain: str) -> str:
    if domain not in DOMAINS:
        raise CheckFailed("Domain outside this seven-zone test.")
    request = urllib.request.Request(
        DOH_URL + "?" + urllib.parse.urlencode({"name": domain, "type": "MX"}),
        headers={"Accept": "application/dns-json",
                 "User-Agent": "sgp1-seven-mx-delivery-test/" + VERSION},
        method="GET",
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=10) as response:
            raw = response.read(DOH_LIMIT + 1)
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
        raise CheckFailed(f"{domain}: public DNS returned HTTPS {status}.") from None
    except (urllib.error.URLError, OSError):
        raise CheckFailed(f"{domain}: public DNS request failed over verified HTTPS.") from None
    if len(raw) > DOH_LIMIT:
        raise CheckFailed(f"{domain}: public DNS response too large.")
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeError):
        raise CheckFailed(f"{domain}: invalid public DNS JSON.") from None
    if (not isinstance(result, dict) or result.get("Status") != 0
            or result.get("TC") is not False):
        raise CheckFailed(f"{domain}: public DNS returned an error or truncated answer.")
    answers = result.get("Answer", [])
    if not isinstance(answers, list):
        raise CheckFailed(f"{domain}: invalid public DNS answer.")
    records: list[tuple[int, str]] = []
    for row in answers:
        if not isinstance(row, dict):
            raise CheckFailed(f"{domain}: malformed public DNS record.")
        if row.get("type") != 15 or str(row.get("name", "")).lower().rstrip(".") != domain:
            continue
        parts = str(row.get("data", "")).split()
        if len(parts) != 2 or not parts[0].isascii() or not parts[0].isdecimal():
            raise CheckFailed(f"{domain}: invalid published MX record.")
        records.append((int(parts[0]), parts[1].lower().rstrip(".")))
    if records != [(10, MAIL_HOST)]:
        raise CheckFailed(f"{domain}: expected one MX 10 {MAIL_HOST}; "
                          "the public answer differs or has not propagated.")
    return MAIL_HOST


def make_message(domain: str, test_id: str, moment: dt.datetime) -> tuple[str, EmailMessage]:
    if domain not in DOMAINS or re.fullmatch(r"[a-f0-9]{32}", test_id) is None:
        raise ValueError("Invalid domain or test ID.")
    recipient = f"setup-check-{moment:%Y%m%d}-{test_id}@{domain}"
    message = EmailMessage(policy=SMTP_POLICY)
    message["From"] = f"Mail setup check <postmaster@{domain}>"
    message["To"] = recipient
    message["Date"] = format_datetime(moment)
    message["Message-ID"] = f"<sgp1-seven-mx.{test_id}@whispr.dev>"
    message["Subject"] = f"[SGP1 seven MX] {domain} - {test_id[:12]}"
    message["Auto-Submitted"] = "auto-generated"
    message["X-SGP1-Setup-Test"] = test_id
    message.set_content(
        "Hello fren! This is one of seven public-MX delivery checks.\n\n"
        f"Domain: {domain}\nAddress tested: {recipient}\nTest ID: {test_id}\n\n"
        "If you can read this in the existing tom@whispr.dev account in Thunderbird,\n"
        "the new random address reached the shared mailbox through public MX.\n\n"
        "LON1 followed the published MX to SGP1 using verified STARTTLS.\n"
        "This test changed no DNS records and did not enable outbound identities.\n"
        "No reply is needed; you may delete the message afterward.\n",
        charset="us-ascii",
    )
    return recipient, message


def require_code(code: int, response: bytes, expected: tuple[int, ...], phase: str) -> None:
    if code not in expected:
        raise CheckFailed(f"{phase}: SMTP {code}: {safe(response)}")


def transmit(domain: str, recipient: str, message: EmailMessage, mx_host: str) -> int:
    test_id = str(message.get("X-SGP1-Setup-Test", ""))
    if (domain not in DOMAINS or mx_host != MAIL_HOST
            or re.fullmatch(r"[a-f0-9]{32}", test_id) is None
            or re.fullmatch(r"setup-check-[0-9]{8}-" + test_id + "@" + re.escape(domain),
                            recipient) is None
            or str(message.get("To", "")) != recipient
            or message.get_all("Cc") or message.get_all("Bcc")):
        raise CheckFailed("Unexpected recipient or message shape; refusing to send.")
    client = None
    phase = "TCP connection and greeting"
    data_started = False
    accepted = False
    try:
        client = smtplib.SMTP(mx_host, 25, local_hostname="mailcheck.invalid",
                              timeout=SMTP_TIMEOUT)
        if client.sock is None:
            raise CheckFailed("SMTP connection did not create a socket.")
        peer = ipaddress.ip_address(client.sock.getpeername()[0])
        source = ipaddress.ip_address(client.sock.getsockname()[0])
        if str(peer) != EXPECTED_IP:
            raise CheckFailed("Connected peer differs from the expected SGP1 IPv4.")
        if str(source) == EXPECTED_IP:
            raise CheckFailed("This appears to run on SGP1; run via the lon1 SSH alias.")
        hello = f"[IPv6:{source}]" if source.version == 6 else f"[{source}]"
        phase = "EHLO"
        require_code(*client.ehlo(hello), (250,), phase)
        if not client.has_extn("starttls"):
            raise CheckFailed("STARTTLS was not advertised.")
        phase = "STARTTLS and certificate validation"
        require_code(*client.starttls(context=ssl.create_default_context()), (220,), phase)
        phase = "encrypted EHLO"
        require_code(*client.ehlo(hello), (250,), phase)
        phase = "MAIL FROM"
        require_code(*client.mail(""), (250,), phase)
        phase = "RCPT TO"
        require_code(*client.rcpt(recipient), (250, 251), phase)
        phase = "DATA and final acceptance"
        data_started = True
        code, response = client.data(message.as_bytes(policy=SMTP_POLICY))
        require_code(code, response, (250,), phase)
        accepted = True
        say(f"SMTP ACCEPTED [{domain}]: {safe(response)}")
        return 0
    except (CheckFailed, smtplib.SMTPResponseException) as exc:
        detail = str(exc) if isinstance(exc, CheckFailed) else f"SMTP {exc.smtp_code}: {safe(exc.smtp_error)}"
        say(f"STOPPED [{domain}] at {phase}: {safe(detail)}")
        say("No confirmed acceptance for this message; no automatic retry.")
        return 2
    except (OSError, smtplib.SMTPException, ValueError) as exc:
        detail = (f"TLS verification code {exc.verify_code}" if isinstance(exc, ssl.SSLCertVerificationError)
                  else type(exc).__name__)
        say(f"STOPPED [{domain}] at {phase}: {detail}")
        if data_started:
            say("DELIVERY OUTCOME UNKNOWN. Check this test ID in Thunderbird before any retry.")
            return 3
        say("No message DATA submitted; no automatic retry.")
        return 2
    except KeyboardInterrupt:
        say("Interrupted. " + ("Delivery may have occurred; check this test ID first."
                               if data_started else "No message DATA submitted."))
        return 130
    finally:
        if client is not None:
            if accepted:
                try:
                    if client.sock is not None:
                        client.sock.settimeout(3)
                    client.quit()
                except (OSError, smtplib.SMTPException):
                    pass  # A failed QUIT does not erase an acknowledged 250.
            client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--send-all", action="store_true", help="send exactly one test per zone after seven public MX checks")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    if sys.version_info < (3, 10):
        parser.error("Python 3.10+ is required.")
    probes = [(domain, *make_message(domain, uuid.uuid4().hex,
                                    dt.datetime.now(dt.timezone.utc))) for domain in DOMAINS]
    say("SGP1 SEVEN PUBLIC-MX DELIVERY TEST " + VERSION)
    say("Target: MX 10 " + MAIL_HOST + " (SGP1 " + EXPECTED_IP + ")")
    for domain, recipient, message in probes:
        say("  " + domain + " -> " + recipient + " | " + str(message["Subject"]))
    if not args.send_all:
        say("PREVIEW ONLY: no network or email. Run --send-all from LON1 to check public MX and send seven tests.")
        return 0
    say("Checking all seven public MX answers before any email...")
    try:
        for domain in DOMAINS:
            published_mx(domain)
            say("PUBLIC MX VERIFIED: " + domain + " -> 10 " + MAIL_HOST)
    except CheckFailed as exc:
        say("STOPPED BEFORE SMTP: " + str(exc))
        return 2
    say("Sending at most one test to each domain with verified TLS; no credentials or DNS changes.")
    for index, (domain, recipient, message) in enumerate(probes, 1):
        say(f"[{index:02d}/07] {domain} | ID: {message['X-SGP1-Setup-Test']}")
        result = transmit(domain, recipient, message, MAIL_HOST)
        if result != 0:
            say("Previous SMTP ACCEPTED lines may already appear in Thunderbird. Do not rerun blindly.")
            return result
    say("SEVEN SMTP ACCEPTANCES: check Thunderbird for one message from each domain (Inbox or Junk).")
    say("Seeing all seven messages confirms these newly published routes reach the shared mailbox.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
