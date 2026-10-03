"""Small bounded HTTP transport. Never disable certificate verification."""

import os
import ssl
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .errors import IntegrationError


def checked_url(value: str, *, internal_hosts: tuple[str, ...] = ()) -> str:
    parsed = urlsplit(value)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise IntegrationError("Invalid service URL")
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and parsed.hostname in internal_hosts
    ):
        raise IntegrationError("HTTPS is required for this service")
    if not parsed.hostname:
        raise IntegrationError("Service URL is not configured")
    return value.rstrip("/")


def client(*, timeout: float = 5, transport=None) -> httpx.Client:
    context = ssl.create_default_context()
    ca_file = os.environ.get("ACCESSOPS_CA_FILE", "")
    if ca_file:
        if not Path(ca_file).is_file():
            raise IntegrationError("Local CA certificate is unavailable")
        context.load_verify_locations(cafile=ca_file)
    return httpx.Client(
        verify=context,
        timeout=httpx.Timeout(timeout, connect=min(timeout, 3)),
        follow_redirects=False,
        trust_env=False,
        transport=transport,
        limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
    )


def json_response(response: httpx.Response, *, limit: int = 1_048_576):
    if len(response.content) > limit:
        raise IntegrationError("Service response exceeds size limit")
    try:
        return response.json()
    except ValueError as exc:
        raise IntegrationError("Service returned invalid JSON") from exc
