"""Narrow AuthZEN evaluation adapter. No policy-management API is exposed."""

import hashlib
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .transport import client, json_response

POLICY_VERSION = "accessops-v1"
ACTIONS = {
    "snapshot",
    "request",
    "approve",
    "execute",
    "reconcile",
    "review",
    "agent_tool",
    "resource_read",
    "departure_close",
    "departure_intake",
}


def normalize(body):
    if not isinstance(body, dict) or set(body) - {"subject", "action", "resource", "context"}:
        raise ValueError("Invalid evaluation")
    for name in ("subject", "action", "resource", "context"):
        if not isinstance(body.get(name), dict):
            raise ValueError("Missing evaluation object")
    subject, action, resource, context = (
        body[k] for k in ("subject", "action", "resource", "context")
    )
    if action.get("name") not in ACTIONS or set(action) != {"name"}:
        raise ValueError("Unknown action")
    for obj, expected in ((subject, "identity"), (resource, "accessops-resource")):
        if (
            obj.get("type") != expected
            or not isinstance(obj.get("id"), str)
            or not 1 <= len(obj["id"]) <= 200
        ):
            raise ValueError("Invalid identifier")
        if not isinstance(obj.get("properties", {}), dict):
            raise ValueError("Invalid properties")
        if set(obj) - {"type", "id", "properties"}:
            raise ValueError("Unknown attribute")
    result = {
        "action": action["name"],
        "subject": {**subject.get("properties", {}), "id": subject["id"]},
        "resource": {**resource.get("properties", {}), "id": resource["id"]},
        "request": context.get("request"),
        "context": {k: v for k, v in context.items() if k != "request"},
    }
    if result["subject"].get("kind") not in ("human", "agent", "service") or result["subject"].get(
        "status"
    ) not in ("active", "suspended", "offboarded"):
        raise ValueError("Invalid subject state")
    for field in ("roles", "project_ids"):
        values = result["subject"].get(field, [])
        if (
            not isinstance(values, list)
            or len(values) > 100
            or any(not isinstance(v, str) or len(v) > 200 for v in values)
        ):
            raise ValueError("Invalid scope")
    for flag in ("approval_valid", "grant_active", "sponsor_active", "within_budget"):
        if flag in context and type(context[flag]) is not bool:
            raise ValueError("Invalid boolean")
    projects = context.get("identity_project_ids", [])
    if (
        not isinstance(projects, list)
        or len(projects) > 100
        or any(not isinstance(v, str) or not 1 <= len(v) <= 200 for v in projects)
    ):
        raise ValueError("Invalid identity project scope")
    if context.get("request") is not None and not isinstance(context["request"], dict):
        raise ValueError("Invalid request context")
    return result


def decide(body, http):
    normalized = normalize(body)
    response = http.post(
        os.getenv("OPA_URL", "http://opa:8181") + "/v1/data/accessops/decision",
        json={"input": normalized},
    )
    if response.status_code != 200:
        raise RuntimeError("Policy engine unavailable")
    data = json_response(response, limit=16_384).get("result")
    if (
        not isinstance(data, dict)
        or type(data.get("allow")) is not bool
        or data.get("policy_version") != POLICY_VERSION
    ):
        raise RuntimeError("Policy decision unavailable")
    # This is the actual immutable bundle file mounted into the OPA process, not
    # a claimed digest of another checkout or of an unexecuted build.
    bundle = Path(os.getenv("POLICY_BUNDLE_FILE", "/policy-bundle/bundle.tar.gz"))
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    return {
        "decision": data["allow"],
        "context": {
            "reason": data.get("reason", "denied"),
            "policy_version": POLICY_VERSION,
            "bundle_sha256": digest,
        },
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "AccessOps"

    def log_message(self, *_args):
        pass  # Request bodies and authentication headers never enter logs.

    def reply(self, status, body):
        raw = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/health":
            self.reply(200, {"status": "ready"})
        else:
            self.reply(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/access/v1/evaluation":
            return self.reply(404, {"error": "not_found"})
        expected = os.environ.get("AUTHZEN_TOKEN", "")
        if len(expected) < 32 or not hmac.compare_digest(
            self.headers.get("Authorization", ""), "Bearer " + expected
        ):
            return self.reply(401, {"error": "unauthorized"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if (
                self.headers.get("Content-Type", "").split(";")[0] != "application/json"
                or not 0 < size <= 65536
                or self.headers.get("Transfer-Encoding")
            ):
                return self.reply(400, {"error": "invalid_request"})
            self.connection.settimeout(5)
            body = json.loads(self.rfile.read(size))
            with client(timeout=2) as http:
                output = decide(body, http)
            self.reply(200, output)
        except (ValueError, TypeError):
            self.reply(400, {"error": "invalid_request"})
        except Exception:
            self.reply(503, {"decision": False, "error": "policy_unavailable"})


if __name__ == "__main__":
    if len(os.environ.get("AUTHZEN_TOKEN", "")) < 32:
        raise SystemExit("AUTHZEN_TOKEN must be configured")
    ThreadingHTTPServer(("0.0.0.0", 8182), Handler).serve_forever()
