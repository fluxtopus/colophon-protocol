"""Send the built messages through Amazon SES, raw, one message per receiver.

SES keeps the headers of a raw message, adds its own DKIM signature for the sender's domain, and
replaces Message-ID (and Date when absent). The Colophon-Signature is not covered by that
signature, so what the receiver stores tells us what the path did to it."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Sent:
    ses_message_id: str


def client(region: str, profile: str | None = None):
    import boto3

    session = boto3.Session(profile_name=profile, region_name=region)
    return session.client("sesv2")


def send_raw(ses, raw: bytes, sender: str, recipient: str) -> Sent:
    response = ses.send_email(
        FromEmailAddress=sender,
        Destination={"ToAddresses": [recipient]},
        Content={"Raw": {"Data": raw}},
    )
    return Sent(response["MessageId"])


def account_state(ses) -> dict:
    """Whether the account may send outside its verified identities (the SES sandbox)."""
    account = ses.get_account()
    return {
        "production_access": account.get("ProductionAccessEnabled", False),
        "sending_enabled": account.get("SendingEnabled", False),
        "max_per_day": account.get("SendQuota", {}).get("Max24HourSend"),
        "sent_last_day": account.get("SendQuota", {}).get("SentLast24Hours"),
    }
