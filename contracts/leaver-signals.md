# Leaver signals for a SOC receiver

AccessOps tells a security operations tool when a departing person's access has
been contained, and when that person's account is used after the departure. The
signals are Security Event Tokens (RFC 8417) in the Shared Signals Framework
1.0 format, delivered by polling (RFC 8936). The receiver pulls; AccessOps never
connects out.

## Endpoints

| Purpose | Method and path | Authentication |
| --- | --- | --- |
| Transmitter metadata | `GET /.well-known/ssf-configuration` | None |
| Signing keys | `GET /api/v1/ssf/jwks` | None |
| Poll and acknowledge | `POST /api/v1/ssf/poll` | `Authorization: Bearer <receiver token>` |

The issuer is `https://accessops.test:8443`. In the lab, a receiver on the same
Windows host connects to `127.0.0.1:8443` with TLS server name `accessops.test`
and verifies the certificate against the lab CA at `.local/tls/root.crt` (a
public certificate). No hosts-file or trust-store change is needed; see
`scripts/host_health.py` for the same loopback-with-SNI pattern. The receiver
token is `SSF_RECEIVER_TOKEN` in `.local/ssf-receiver.env`. Copy it into the
receiver's own secret store; never log, commit or display it.

## Polling

Request (all fields optional):

```json
{"maxEvents": 10, "returnImmediately": true, "ack": ["<jti>"], "setErrs": {"<jti>": {"err": "invalid_key", "description": "..."}}}
```

Response:

```json
{"sets": {"<jti>": "<compact JWS>"}, "moreAvailable": false}
```

`maxEvents` is 0–50. Acknowledge a `jti` only after the event is stored. Every
unacknowledged event is offered again (at-least-once delivery), so deduplicate
by `jti`. Report a token you cannot accept in `setErrs`; it is then not offered
again. Polls are always answered immediately and are rate limited per address.

## Token format

Header: `{"typ": "secevent+jwt", "alg": "ES256", "kid": "<RFC 7638 thumbprint>"}`.

```json
{
  "iss": "https://accessops.test:8443",
  "aud": "urn:accessops:soc-receiver",
  "iat": 1791172800,
  "jti": "32 lowercase hex characters",
  "txn": "stable per source fact",
  "sub_id": {
    "format": "iss_sub",
    "iss": "https://id.accessops.test:8443/realms/accessops-workforce",
    "sub": "<Keycloak user ID>"
  },
  "events": {"<event type URI>": {"event_timestamp": 1791172790}}
}
```

Verify the signature with the published key (accept only ES256 and a known
`kid`; refetch keys at most once per minute on an unknown one), then check
`typ`, `iss` and `aud` exactly. The subject is the workforce account's issuer
and immutable ID; tokens carry no names, emails or IP addresses.

| Event type | Sent when | Meaning |
| --- | --- | --- |
| `https://schemas.openid.net/secevent/risc/event-type/account-disabled` | Containment verified | Keycloak reported the account disabled at `event_timestamp` |
| `https://schemas.openid.net/secevent/caep/event-type/session-revoked` | Containment verified | Keycloak listed no session for the account (`initiating_entity: policy`) |
| `https://schemas.openid.net/secevent/caep/event-type/session-established` | A sign-in after departure was read | Keycloak recorded a successful sign-in or token use at `event_timestamp` |

## Suggested detection

Treat a subject as departed from its `account-disabled` event. Any
`session-established` for that subject with a later `event_timestamp`, or any
authentication by that `iss` and `sub` in the receiver's own telemetry, is
access after departure and deserves a high-severity case. AccessOps already
blocks closure of that departure until its owner records an investigation.

## Producing test signals

The lab's own check, `scripts/live_leaver_assurance.py`, normally acts as the
receiver and acknowledges everything. Run it with `--external-receiver` while
another receiver is polling: it then leaves every signal queued, including a
`session-established` for a sign-in after departure, and checks them on the case
instead. Its `Test-Lab.ps1` form drains the queue, so don't run both at once.

## Limits

There is no SSF stream-management API: one receiver, one stream, configured by
the lab. Events are kept until acknowledged. The lab's Keycloak keeps sign-in
events for one day, so AccessOps reads them for 24 hours after a departure.
