"""Verify the host loopback front door without changing DNS or OS certificate trust."""

import http.client
import json
import socket
import ssl
from pathlib import Path

from check_report import CheckReport, report_arguments


class LoopbackHTTPS(http.client.HTTPSConnection):
    def connect(self):
        # Routing is fixed loopback. Certificate identity and SNI remain the real
        # configured hostname; no global resolver or TLS verification is changed.
        raw = socket.create_connection(("127.0.0.1", 8443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def get(hostname, path, context):
    http = LoopbackHTTPS(hostname, port=8443, timeout=5, context=context)
    try:
        http.request("GET", path, headers={"Host": hostname + ":8443"})
        response = http.getresponse()
        data = response.read(1_048_577)
        if len(data) > 1_048_576:
            raise ValueError("Response exceeded limit")
        return response.status, data
    finally:
        http.close()


def main():
    args = report_arguments(__doc__).parse_args()
    report = CheckReport(
        "host-loopback-tls",
        driver="host Python/OpenSSL with fixed loopback routing and verified SNI",
        limitations=[
            "Public CA certificate is supplied per process; OS trust and hosts configuration are not changed.",
            "The application health route measures reachability, not every dependency or browser interaction.",
        ],
        source_files=["scripts/host_health.py", "scripts/check_report.py", "infra/Caddyfile"],
    )
    try:
        ca = Path(__file__).resolve().parents[1] / ".local/tls/root.crt"
        context = ssl.create_default_context(cafile=str(ca))
        with report.case("application front door serves connected UI over verified host TLS"):
            status, data = get("accessops.test", "/", context)
            if status != 200 or b"<html" not in data.lower():
                raise AssertionError("UI unavailable")
        with report.case("application health route reachable over verified host TLS"):
            status, data = get("accessops.test", "/api/v1/health", context)
            if status != 200 or json.loads(data) != {"status": "ok", "mode": "connected"}:
                raise AssertionError("Health unavailable")
        with report.case("operator discovery has exact issuer over verified host TLS"):
            status, data = get(
                "id.accessops.test",
                "/realms/accessops-operators/.well-known/openid-configuration",
                context,
            )
            if (
                status != 200
                or json.loads(data).get("issuer")
                != "https://id.accessops.test:8443/realms/accessops-operators"
            ):
                raise AssertionError("Issuer mismatch")
        with report.case("Keycloak administration is not exposed through the host front door"):
            status, _ = get("id.accessops.test", "/admin/", context)
            if status != 404:
                raise AssertionError("Unexpected administration exposure")
        with report.case("unconfigured TLS server name is rejected"):
            try:
                get("wrong.accessops.test", "/", context)
            except ssl.SSLError:
                pass
            else:
                raise AssertionError("Unconfigured TLS server name was accepted")
    except Exception as error:
        report.record_error(error)
    return report.finish(args)


if __name__ == "__main__":
    raise SystemExit(main())
