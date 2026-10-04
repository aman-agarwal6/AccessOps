"""Bounded live checks for the unique directory fixture; no secret output."""

import ssl

from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, NONE, Connection, Server, Tls
from ldap3.core.exceptions import (
    LDAPCertificateError,
    LDAPInsufficientAccessRightsResult,
    LDAPNoSuchAttributeResult,
    LDAPSocketOpenError,
)

from integrations.ad import ADDirectoryConnector, normalize_binding, verified_result
from integrations.errors import ConnectorError


def before_checks(report, fixture):
    binding = normalize_binding(fixture["binding"])
    with report.case(
        "actual LDAP transport rejects a wrong expected hostname and an unrelated trusted CA"
    ):
        for host, ca in (
            ("dc", "/run/accessops-ad-ca/ca.crt"),
            ("dc.adlab.test", "/run/accessops-ca/root.crt"),
        ):
            tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca, version=None, sni=host)
            client = Connection(
                Server(host, port=636, use_ssl=True, tls=tls, get_info=NONE, connect_timeout=5),
                receive_timeout=5,
                auto_referrals=False,
                raise_exceptions=True,
            )
            try:
                try:
                    client.open()
                except (LDAPCertificateError, LDAPSocketOpenError) as error:
                    detail = str(error).casefold()
                    if "certificate" not in detail and "doesn't match" not in detail:
                        raise AssertionError(
                            "Expected certificate verification denial unavailable"
                        ) from None
                else:
                    raise AssertionError("Invalid certificate transport was accepted")
            finally:
                client.unbind()
    with ADDirectoryConnectorContext() as connector:
        with report.case(
            "actual verified LDAPS GUID binding observes enabled fixture and backed membership"
        ):
            observed = connector.validate_binding(binding)
            if observed["active"] is not True or any(
                group["member"] is not True for group in observed["groups"]
            ):
                raise AssertionError("Directory fixture initial state unavailable")
        with report.case("application scope rejects a canary GUID before any directory mutation"):
            try:
                connector.offboard(binding | {"userGuid": fixture["canary"]["userGuid"]})
            except ConnectorError:
                pass
            else:
                raise AssertionError("Canary mapping was accepted")
        with report.case(
            "actual connector delegation denies out-of-scope canary account disable and member removal"
        ):
            for target, change in (
                (
                    "<GUID=" + fixture["canary"]["userGuid"] + ">",
                    {"userAccountControl": [(MODIFY_REPLACE, [514])]},
                ),
                (
                    "<GUID=" + fixture["canary"]["groupGuid"] + ">",
                    {"member": [(MODIFY_DELETE, ["<GUID=" + fixture["canary"]["userGuid"] + ">"])]},
                ),
            ):
                connector._budget()
                try:
                    accepted = connector.connection.modify(target, change)
                except LDAPInsufficientAccessRightsResult:
                    accepted = False
                if accepted or connector.connection.result.get("result") != 50:
                    raise AssertionError("Scoped connector delegation denial unavailable")
        with report.case(
            "actual atomic old-value account flag assertion rejects a stale flag without mutation"
        ):
            _, user, _ = connector._collect(binding)
            old = user["flags"]
            connector._budget()
            try:
                accepted = connector.connection.modify(
                    "<GUID=" + binding["userGuid"] + ">",
                    {"userAccountControl": [(MODIFY_DELETE, [old | 2]), (MODIFY_ADD, [old | 2])]},
                )
            except LDAPNoSuchAttributeResult:
                accepted = False
            if accepted or connector.connection.result.get("result") != 16:
                raise AssertionError("Atomic stale account flag assertion unavailable")
            _, user, _ = connector._collect(binding)
            if user["flags"] != old:
                raise AssertionError("Stale account flag operation changed the fixture")


def after_checks(report, fixture):
    with ADDirectoryConnectorContext() as connector:
        with report.case(
            "actual scoped directory account is disabled and every enrolled group explicitly excludes its GUID"
        ):
            binding = normalize_binding(fixture["binding"])
            if not verified_result(binding, connector.validate_binding(binding)):
                raise AssertionError("Directory containment incomplete")
        with report.case(
            "actual directory replay converges read-first without adding membership or enabling account"
        ):
            if connector.offboard(fixture["binding"])["verified"] is not True:
                raise AssertionError("Directory replay incomplete")


class ADDirectoryConnectorContext:
    def __enter__(self):
        self.connector = ADDirectoryConnector()
        return self.connector

    def __exit__(self, *args):
        self.connector.close()
