"""Fetch each message as the receiver stored it.

Every capture returns the message's raw octets. IMAP uses BODY.PEEK[] so the fetch leaves no
trace. Microsoft Graph's `$value` is MIME the service regenerates from its store, so for Graph the
header's state is what Exchange kept, not necessarily the octets on the wire; the report says so."""

from __future__ import annotations

import imaplib
import re
import time
from dataclasses import dataclass
from pathlib import Path

from .receivers import Capture

TOKEN_HEADER = "X-Colophon-Test"
GRAPH_SCOPES = ["Mail.Read"]


@dataclass(frozen=True)
class Captured:
    raw: bytes
    where: str  # folder, object key, or path the message came from
    kind: str


class NotFound(Exception):
    pass


class Unavailable(Exception):
    """The mailbox cannot be read right now (sign-in refused, service down)."""


# ---------------------------------------------------------------- IMAP


def _imap_folders(conn: imaplib.IMAP4) -> list[str]:
    status, data = conn.list()
    if status != "OK":
        return ["INBOX"]
    names = []
    for line in data:
        if isinstance(line, bytes):
            line = line.decode("utf-8", "replace")
        m = re.match(r'\((?P<flags>[^)]*)\)\s+(?:"(?P<sep>[^"]*)"|NIL)\s+(?P<name>.+)$', line)
        if not m or "\\Noselect" in m.group("flags"):
            continue
        name = m.group("name").strip()
        names.append(name)
    inbox_first = sorted(names, key=lambda n: (n.strip('"').upper() != "INBOX", n))
    return inbox_first or ["INBOX"]


def imap(cap: Capture, token: str) -> Captured:
    host, port = cap.options["host"], int(cap.options.get("port", 993))
    user = cap.options["user"]
    password = cap.secret("password")
    try:
        conn = imaplib.IMAP4_SSL(host, port)
    except OSError as err:
        raise Unavailable(f"{host}:{port}: {err}") from err
    try:
        try:
            conn.login(user, password)
        except imaplib.IMAP4.error as err:
            raise Unavailable(f"{host} refused the sign-in for {user}: {err}") from err
        for folder in _imap_folders(conn):
            status, _ = conn.select(folder, readonly=True)
            if status != "OK":
                continue
            # Some servers do not index custom headers; the subject carries the same token.
            for query in (f'HEADER {TOKEN_HEADER} "{token}"', f'SUBJECT "{token}"'):
                status, data = conn.search(None, query)
                if status == "OK" and data and data[0]:
                    uid = data[0].split()[-1]
                    status, parts = conn.fetch(uid, "(BODY.PEEK[])")
                    for part in parts:
                        if isinstance(part, tuple) and len(part) >= 2:
                            return Captured(part[1], folder, "imap")
        raise NotFound(f"{token} not found in any folder of {user}@{host}")
    finally:
        try:
            conn.logout()
        except (imaplib.IMAP4.error, OSError):
            pass  # the fetch is done; a failed logout changes nothing


# ---------------------------------------------------------------- Microsoft Graph


def _graph_token(cap: Capture, cache_path: Path) -> str:
    import msal

    cache = msal.SerializableTokenCache()
    if cache_path.exists():
        cache.deserialize(cache_path.read_text(encoding="utf-8"))
    app = msal.PublicClientApplication(
        cap.options["client_id"],
        authority=f"https://login.microsoftonline.com/{cap.options.get('tenant', 'consumers')}",
        token_cache=cache,
    )
    result = None
    accounts = app.get_accounts()
    if accounts:
        result = app.acquire_token_silent(GRAPH_SCOPES, account=accounts[0])
    if not result:
        flow = app.initiate_device_flow(scopes=GRAPH_SCOPES)
        if "user_code" not in flow:
            raise RuntimeError(f"device flow failed: {flow.get('error_description', flow)}")
        print(flow["message"], flush=True)
        result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        raise RuntimeError(result.get("error_description", "no token"))
    if cache.has_state_changed:
        cache_path.write_text(cache.serialize(), encoding="utf-8")
        cache_path.chmod(0o600)
    return result["access_token"]


def graph(cap: Capture, token: str, cache_path: Path) -> Captured:
    import urllib.parse
    import urllib.request

    access = _graph_token(cap, cache_path)
    headers = {"Authorization": f"Bearer {access}", "Accept": "application/json"}
    search = urllib.parse.quote(f'"{token}"')
    url = f"https://graph.microsoft.com/v1.0/me/messages?$search={search}&$select=id,subject,parentFolderId&$top=5"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        import json

        found = json.loads(resp.read().decode("utf-8")).get("value", [])
    if not found:
        raise NotFound(f"{token} not found through Graph")
    message_id = found[0]["id"]
    req = urllib.request.Request(
        f"https://graph.microsoft.com/v1.0/me/messages/{message_id}/$value", headers=headers
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read()
    return Captured(raw, found[0].get("parentFolderId", ""), "graph")


# ---------------------------------------------------------------- S3 (SES inbound)


def s3(cap: Capture, token: str, since: float) -> Captured:
    """Objects SES stored since `since`, newest first, until one carries the token."""
    import boto3

    session = boto3.Session(
        profile_name=cap.options.get("profile"), region_name=cap.options.get("region")
    )
    client = session.client("s3")
    bucket, prefix = cap.options["bucket"], cap.options.get("prefix", "")
    paginator = client.get_paginator("list_objects_v2")
    candidates = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            if obj["LastModified"].timestamp() >= since - 60:
                candidates.append(obj)
    candidates.sort(key=lambda o: o["LastModified"], reverse=True)
    needle = token.encode()
    for obj in candidates:
        body = client.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
        if needle in body:
            return Captured(body, obj["Key"], "s3")
    raise NotFound(
        f"{token} not in s3://{bucket}/{prefix} ({len(candidates)} objects since {int(since)})"
    )


# ---------------------------------------------------------------- local file


EXPORT_SUFFIXES = (".eml", ".txt", ".mime")


def normalise(raw: bytes) -> bytes:
    """Exported files come with LF, CRLF or mixed line endings; the verifier wants CRLF."""
    return raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")


def file(cap: Capture, token: str, default_dir: Path) -> Captured:
    """A message exported by hand from a provider's "show original" or "save as", dropped as a
    file into the receiver's export directory. Found by the token in its subject or tracking
    header, whatever the file is called."""
    root = Path(cap.options.get("path") or default_dir)
    if root.is_file():
        paths = [root]
    elif root.is_dir():
        paths = sorted(
            q for q in root.iterdir() if q.is_file() and q.name.lower().endswith(EXPORT_SUFFIXES)
        )
    else:
        raise NotFound(f"no export directory {root}; create it and drop the exported message there")
    needle = token.encode()
    for path in paths:
        data = path.read_bytes()
        if needle in data:
            return Captured(normalise(data), str(path), "file")
    raise NotFound(f"{token} not in {root} ({len(paths)} exported files)")


def fetch(cap: Capture, token: str, *, since: float, state_dir: Path, export_dir: Path) -> Captured:
    if cap.kind == "imap":
        return imap(cap, token)
    if cap.kind == "graph":
        return graph(cap, token, state_dir / f".graph-token-cache-{cap.options['client_id']}")
    if cap.kind == "s3":
        return s3(cap, token, since)
    if cap.kind == "file":
        return file(cap, token, export_dir)
    raise ValueError(f"unknown capture kind {cap.kind!r}")


def wait_for(
    cap: Capture,
    token: str,
    *,
    since: float,
    state_dir: Path,
    export_dir: Path,
    timeout: float,
    every: float = 20,
) -> Captured:
    deadline = time.time() + timeout
    while True:
        try:
            return fetch(cap, token, since=since, state_dir=state_dir, export_dir=export_dir)
        except NotFound:
            if time.time() >= deadline:
                raise
            time.sleep(every)
