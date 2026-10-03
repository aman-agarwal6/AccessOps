"""AuthZEN client; server-side state must be supplied by the caller."""

import os

import httpx

from .errors import IntegrationError
from .transport import checked_url, client, json_response


class PolicyClient:
    def __init__(self, base_url=None, token=None, *, http=None):
        self.base_url = checked_url(
            base_url or os.getenv("AUTHZEN_URL", "http://policy:8182"),
            internal_hosts=("policy", "127.0.0.1", "localhost"),
        )
        self.token = token or os.getenv("AUTHZEN_TOKEN", "")
        self.http = http or client(timeout=3)

    def evaluate(self, data: dict) -> dict:
        denied = {"allow": False, "reason": "policy_unavailable", "policy_version": "unknown"}
        if not isinstance(self.token, str) or len(self.token) < 32:
            return denied
        try:
            subject = dict(data.get("subject") or {})
            resource = dict(data.get("resource") or {})
            context = dict(data.get("context") or {})
            context["request"] = data.get("request")
            body = {
                "subject": {
                    "type": "identity",
                    "id": str(subject.pop("id", "")),
                    "properties": subject,
                },
                "action": {"name": data.get("action", "")},
                "resource": {
                    "type": "accessops-resource",
                    "id": str(resource.pop("id", "global")),
                    "properties": resource,
                },
                "context": context,
            }
            response = self.http.post(
                self.base_url + "/access/v1/evaluation",
                json=body,
                headers={"Authorization": "Bearer " + self.token},
            )
            if response.status_code != 200:
                return denied
            result = json_response(response, limit=16_384)
            if type(result.get("decision")) is not bool:
                return denied
            ctx = result.get("context", {})
            if not isinstance(ctx, dict) or not isinstance(ctx.get("policy_version"), str):
                return denied
            return {
                "allow": result["decision"],
                "reason": str(ctx.get("reason", "denied"))[:128],
                "policy_version": ctx["policy_version"],
                "bundle_sha256": ctx.get("bundle_sha256", ""),
            }
        except (httpx.HTTPError, IntegrationError, TypeError, ValueError, AttributeError):
            return denied


def evaluate(data: dict) -> dict:
    policy = PolicyClient()
    try:
        return policy.evaluate(data)
    finally:
        policy.http.close()
