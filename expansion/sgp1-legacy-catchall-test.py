#!/usr/bin/env python3
"""Send ONE legacy-domain catch-all delivery test from LON1 to SGP1.

Python 3.10+, standard library only. Default: show a preview, no network traffic.
Actual test: python3 sgp1-legacy-catchall-test.py --domain dailystonks.org --send

The destination is fixed: mail.whispr.dev:25, expected IPv4 68.183.227.135.
The sole recipient is a fresh random address at the selected domain. This
tests its prepared receiving route before changing the domain's MX records.
STARTTLS and a valid certificate for mail.whispr.dev are required. No SMTP
login is used: this is delivery to a local receiving domain on port 25.

The message has a null envelope sender (no failure-mail loop), a visible From
of postmaster@the-tested-domain, and Auto-Submitted: auto-generated. It does not enable
outbound identities or test DKIM/SPF/DMARC alignment or inbox placement.

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
import re
import smtplib
import ssl
import sys
import uuid

VERSION = "1.0.0"
MAIL_HOST = "mail.whispr.dev"
EXPECTED_IP = "68.183.227.135"
DOMAINS = (
    "botforum.dev", "dailystonks.org", "fastping.it.com", "litehaus.online",
    "primercrate.rs", "lickyour.skin", "showmesome.skin", "showmeyour.skin",
)
TIMEOUT = 30


class TestFailure(Exception):
    """Failure before message acceptance, with a safe diagnostic string."""


def safe(value: object) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(value))[:600]


def say(value: str = "") -> None:
    print(value, flush=True)


def make_message(domain: str, test_id: str, now: dt.datetime) -> tuple[str, EmailMessage]:
    if domain not in DOMAINS or not re.fullmatch(r"[a-f0-9]{32}", test_id):
        raise ValueError("Invalid recipient domain or test ID.")
    recipient = f"setup-check-{now:%Y%m%d}-{test_id}@{domain}"
    message = EmailMessage(policy=SMTP_POLICY)
    message["From"] = f"Mail setup check <postmaster@{domain}>"
    message["To"] = recipient
    message["Date"] = format_datetime(now)
    message["Message-ID"] = f"<sgp1-legacy-catchall.{test_id}@whispr.dev>"
    message["Subject"] = f"[SGP1 legacy test] {domain} - {test_id[:12]}"
    message["Auto-Submitted"] = "auto-generated"
    message["X-SGP1-Setup-Test"] = test_id
    message.set_content(
        "Hello fren! This is your catch-all delivery check.\n\n"
        f"Address tested: {recipient}\n"
        f"Test ID: {test_id}\n\n"
        "If you can read this in your existing tom@whispr.dev mailbox,\n"
        f"this newly generated {domain} address reached your shared inbox.\n\n"
        "The test was sent directly to SGP1 over SMTP with verified TLS.\n"
        f"It did not use or change {domain}'s public MX records.\n"
        "Sending identities and mail authentication are separate setup steps.\n\n"
        "No reply is needed. You may delete this test message afterward.\n",
        charset="us-ascii",
    )
    return recipient, message


def require_code(code: int, response: bytes, expected: tuple[int, ...], phase: str) -> None:
    if code not in expected:
        raise TestFailure(f"{phase}: SMTP {code}: {safe(response)}")


def transmit(domain: str, recipient: str, message: EmailMessage) -> int:
    # Do not allow callers to repurpose this as a general mail sender.
    test_id = str(message["X-SGP1-Setup-Test"])
    if (domain not in DOMAINS or not re.fullmatch(r"[a-f0-9]{32}", test_id)
            or not re.fullmatch(r"setup-check-[0-9]{8}-" + test_id + "@" + re.escape(domain), recipient)
            or str(message["To"]) != recipient or message.get_all("Cc") or message.get_all("Bcc")):
        raise TestFailure("Unexpected recipient or message shape; refusing to send.")
    client = None
    phase = "TCP connection and SMTP greeting"
    data_started = False
    accepted = False
    try:
        say("Connecting to " + MAIL_HOST + ":25...")
        client = smtplib.SMTP(MAIL_HOST, 25, local_hostname="mailcheck.invalid", timeout=TIMEOUT)
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
        say("TLS certificate verified for " + MAIL_HOST + ".")
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
                except OSError:
                    pass  # A later QUIT failure does not undo the server's 250 acceptance.
            client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--domain", choices=DOMAINS, required=True,
                        help="One of the eight domains with older MX routes.")
    parser.add_argument("--send", action="store_true", help="Send exactly one direct SMTP test email.")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    if sys.version_info < (3, 10):
        parser.error("Python 3.10+ is required.")
    test_id = uuid.uuid4().hex
    recipient, message = make_message(args.domain, test_id, dt.datetime.now(dt.timezone.utc))
    say("SGP1 LEGACY CATCH-ALL DELIVERY TEST " + VERSION)
    say("Target: " + MAIL_HOST + " (" + EXPECTED_IP + "), port 25 with verified STARTTLS")
    say("Recipient: " + recipient)
    say("Subject: " + str(message["Subject"]))
    say("Message-ID: " + str(message["Message-ID"]))
    say("Test ID: " + test_id)
    if not args.send:
        say("PREVIEW ONLY: no network connection or email sent. Run with --send on LON1 for one actual test.")
        return 0
    say("Sending one email. No credentials, DNS changes, or configuration changes.")
    return transmit(args.domain, recipient, message)


if __name__ == "__main__":
    raise SystemExit(main())
