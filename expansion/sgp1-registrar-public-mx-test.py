#!/usr/bin/env python3
"""Send ONE test via the selected registrar domain's NEW public MX from LON1.

Python 3.10+, standard library only. Default: show a preview, no network traffic.
Actual test: python3 sgp1-registrar-public-mx-test.py --domain botforum.dev --send

The script queries the selected domain's MX through Cloudflare's public DNS-over-HTTPS
resolver. It sends only if there is exactly one MX: priority 10,
mail.whispr.dev, which resolves to the previously tested SGP1 IPv4
68.183.227.135. The sole recipient is a fresh random address at that domain.
STARTTLS and a certificate valid for the MX hostname are required. No SMTP
login is used: public delivery to a receiving domain uses port 25.

The message has a null envelope sender (no failure-mail loop), a visible From
of postmaster@the-tested-domain, and Auto-Submitted: auto-generated. It does not enable
outbound identities or test DKIM/SPF/DMARC alignment.

No config changes, installs, DNS changes, queue flushes, or automatic retries.
Exit 0: preview completed or SGP1 accepted the message; verify receipt in
Thunderbird. Exit 2: test failed/rejected. Exit 3: delivery outcome uncertain.
Exit 130: interrupted. After uncertainty, look for the printed test ID before
rerunning, because the server may have accepted the first copy.
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
MAIL_HOST = "mail.whispr.dev"
EXPECTED_IP = "68.183.227.135"
DOMAINS = ("botforum.dev", "lickyour.skin", "showmesome.skin", "showmeyour.skin")
RECIPIENT_DOMAIN = ""  # Set from --domain allowlist in main().
TIMEOUT = 30
DOH_URL = "https://cloudflare-dns.com/dns-query"
DOH_LIMIT = 64 * 1024


class TestFailure(Exception):
    """Failure before message acceptance, with a safe diagnostic string."""


def safe(value: object) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(value))[:600]


def say(value: str = "") -> None:
    print(value, flush=True)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise TestFailure("Public MX lookup redirected; no email sent.")


def published_mx() -> str:
    url = DOH_URL + "?" + urllib.parse.urlencode({"name": RECIPIENT_DOMAIN, "type": "MX"})
    req = urllib.request.Request(url, headers={
        "Accept": "application/dns-json", "User-Agent": "sgp1-registrar-public-mx-test/" + VERSION,
    }, method="GET")
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=10) as response:
            raw = response.read(DOH_LIMIT + 1)
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
        raise TestFailure(f"Public MX lookup returned HTTPS {status}; no email sent.") from None
    except (urllib.error.URLError, OSError):
        raise TestFailure("Public MX lookup could not finish over verified HTTPS; no email sent.") from None
    if len(raw) > DOH_LIMIT:
        raise TestFailure("Public MX response exceeded the limit; no email sent.")
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError):
        raise TestFailure("Public MX response is not valid JSON; no email sent.") from None
    if not isinstance(data, dict) or data.get("Status") != 0 or data.get("TC") is not False:
        raise TestFailure("Public MX response returned an error or was truncated; no email sent.")
    answers = data.get("Answer", [])
    if not isinstance(answers, list):
        raise TestFailure("Public MX response has an invalid answer; no email sent.")
    records = []
    for row in answers:
        if not isinstance(row, dict):
            raise TestFailure("Public MX response has an invalid record; no email sent.")
        if row.get("type") != 15 or str(row.get("name", "")).lower().rstrip(".") != RECIPIENT_DOMAIN:
            continue
        parts = str(row.get("data", "")).split()
        if len(parts) != 2 or not parts[0].isascii() or not parts[0].isdecimal():
            raise TestFailure("Public MX has an invalid priority or hostname; no email sent.")
        records.append((int(parts[0]), parts[1].lower().rstrip(".")))
    if records != [(10, MAIL_HOST)]:
        raise TestFailure("Public MX differs from the sole expected SGP1 record; no email sent.")
    return records[0][1]


def make_message(test_id: str, now: dt.datetime) -> tuple[str, EmailMessage]:
    if not re.fullmatch(r"[a-f0-9]{32}", test_id):
        raise ValueError("Invalid test ID.")
    recipient = f"setup-check-{now:%Y%m%d}-{test_id}@{RECIPIENT_DOMAIN}"
    message = EmailMessage(policy=SMTP_POLICY)
    message["From"] = f"Mail setup check <postmaster@{RECIPIENT_DOMAIN}>"
    message["To"] = recipient
    message["Date"] = format_datetime(now)
    message["Message-ID"] = f"<sgp1-registrar-mx.{test_id}@whispr.dev>"
    message["Subject"] = f"[SGP1 MX test] {RECIPIENT_DOMAIN} - {test_id[:12]}"
    message["Auto-Submitted"] = "auto-generated"
    message["X-SGP1-Setup-Test"] = test_id
    message.set_content(
        "Hello fren! This is your public-MX delivery check.\n\n"
        f"Address tested: {recipient}\n"
        f"Test ID: {test_id}\n\n"
        "If you can read this in your existing tom@whispr.dev mailbox,\n"
        f"this newly generated {RECIPIENT_DOMAIN} address reached your shared inbox.\n\n"
        f"LON1 looked up {RECIPIENT_DOMAIN}'s public MX, then followed it to SGP1\n"
        "over SMTP with verified TLS. DNS was not changed by this test.\n"
        "Sending identities and mail authentication are separate setup steps.\n\n"
        "No reply is needed. You may delete this test message afterward.\n",
        charset="us-ascii",
    )
    return recipient, message


def require_code(code: int, response: bytes, expected: tuple[int, ...], phase: str) -> None:
    if code not in expected:
        raise TestFailure(f"{phase}: SMTP {code}: {safe(response)}")


def transmit(recipient: str, message: EmailMessage, mx_host: str) -> int:
    # Do not allow callers to repurpose this as a general mail sender.
    test_id = str(message["X-SGP1-Setup-Test"])
    if (mx_host != MAIL_HOST or not re.fullmatch(r"[a-f0-9]{32}", test_id)
            or not re.fullmatch(r"setup-check-[0-9]{8}-" + test_id + "@" + re.escape(RECIPIENT_DOMAIN), recipient)
            or str(message["To"]) != recipient or message.get_all("Cc") or message.get_all("Bcc")):
        raise TestFailure("Unexpected recipient or message shape; refusing to send.")
    client = None
    phase = "TCP connection and SMTP greeting"
    data_started = False
    accepted = False
    try:
        say("Connecting to public MX " + mx_host + ":25...")
        client = smtplib.SMTP(mx_host, 25, local_hostname="mailcheck.invalid", timeout=TIMEOUT)
        if client.sock is None:
            raise TestFailure("SMTP connection did not create a socket.")
        peer = ipaddress.ip_address(client.sock.getpeername()[0])
        source = ipaddress.ip_address(client.sock.getsockname()[0])
        if str(peer) != EXPECTED_IP:
            raise TestFailure("Connected address differs from expected SGP1 IPv4; no message sent.")
        if str(source) == EXPECTED_IP:
            raise TestFailure("This appears to run on SGP1 itself. Run the supplied command via lon1.")
        hello = f"[IPv6:{source}]" if source.version == 6 else f"[{source}]"
        say("SMTP 220 greeting received from " + str(peer) + ".")
        phase = "EHLO"
        require_code(*client.ehlo(hello), (250,), phase)
        if not client.has_extn("starttls"):
            raise TestFailure("STARTTLS is not advertised; no message sent.")
        phase = "STARTTLS and certificate validation"
        require_code(*client.starttls(context=ssl.create_default_context()), (220,), phase)
        say("TLS certificate verified for " + mx_host + ".")
        phase = "encrypted EHLO"
        require_code(*client.ehlo(hello), (250,), phase)
        phase = "MAIL FROM"
        require_code(*client.mail(""), (250,), phase)
        phase = "RCPT TO"
        require_code(*client.rcpt(recipient), (250, 251), phase)
        say("Random recipient accepted: " + recipient)
        payload = message.as_bytes(policy=SMTP_POLICY)
        phase = "DATA and final acceptance"
        data_started = True
        code, response = client.data(payload)
        require_code(code, response, (250,), phase)
        accepted = True
        say("SMTP ACCEPTED: " + safe(response))
        say("Now check the existing tom@whispr.dev account in Thunderbird (Inbox, then Junk if needed).")
        say("Look for subject: " + str(message["Subject"]))
        say("SMTP acceptance alone is not proof of mailbox delivery; seeing this message confirms receipt.")
        return 0
    except (TestFailure, smtplib.SMTPResponseException) as exc:
        detail = str(exc) if isinstance(exc, TestFailure) else f"SMTP {exc.smtp_code}: {safe(exc.smtp_error)}"
        say("TEST STOPPED at " + phase + ": " + safe(detail))
        say("No successful message acceptance was reported. No automatic retry was performed.")
        if data_started:
            say("DATA was submitted; inspect the test ID before any retry.")
            return 3
        return 2
    except (OSError, ValueError) as exc:
        if isinstance(exc, ssl.SSLCertVerificationError):
            detail = "TLS certificate verification failed (code %s)" % exc.verify_code
        elif isinstance(exc, (TimeoutError, smtplib.SMTPServerDisconnected)):
            detail = type(exc).__name__
        else:
            detail = type(exc).__name__ + ": " + safe(exc)
        say("TEST STOPPED at " + phase + ": " + detail)
        if data_started:
            say("DELIVERY OUTCOME UNKNOWN. Look for the test ID in Thunderbird before rerunning.")
            return 3
        say("Message DATA was not submitted. No automatic retry was performed.")
        return 2
    except KeyboardInterrupt:
        say("Interrupted. " + ("Delivery may have occurred; look for this test ID before retrying."
                             if data_started else "Message DATA was not submitted."))
        return 130
    finally:
        if client is not None:
            if accepted:
                try:
                    if client.sock is not None:
                        client.sock.settimeout(3)
                    client.quit()
                except (OSError, smtplib.SMTPException):
                    pass  # A later QUIT failure does not undo the server's 250 acceptance.
            client.close()


def main() -> int:
    global RECIPIENT_DOMAIN
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--domain", choices=DOMAINS, required=True)
    parser.add_argument("--send", action="store_true", help="Send exactly one test email to the selected catch-all domain.")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    RECIPIENT_DOMAIN = args.domain
    if sys.version_info < (3, 10):
        parser.error("Python 3.10+ is required.")
    test_id = uuid.uuid4().hex
    recipient, message = make_message(test_id, dt.datetime.now(dt.timezone.utc))
    say("SGP1 PUBLIC MX DELIVERY TEST " + VERSION)
    say("Domain: " + RECIPIENT_DOMAIN + "; expected MX 10 " + MAIL_HOST + " (" + EXPECTED_IP + ")")
    say("Recipient: " + recipient)
    say("Subject: " + str(message["Subject"]))
    say("Message-ID: " + str(message["Message-ID"]))
    say("Test ID: " + test_id)
    if not args.send:
        say("PREVIEW ONLY: no network connection or email sent. Run with --send on LON1 for one actual test.")
        return 0
    say("Looking up the published MX; sending at most one email. No credentials or configuration changes.")
    try:
        mx_host = published_mx()
    except TestFailure as exc:
        say("TEST STOPPED before SMTP: " + str(exc))
        return 2
    say("Public MX resolved: 10 " + mx_host + ".")
    return transmit(recipient, message, mx_host)


if __name__ == "__main__":
    raise SystemExit(main())
