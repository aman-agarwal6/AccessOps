"""Atlas lab app back-channel logout rules; signature checks are stubbed here and
covered for real tokens by integrations/tests/test_boundaries.py."""

import importlib
import sys
import time
from pathlib import Path
from urllib.parse import urlencode

import pytest

from integrations.errors import TokenValidationError

FORM = "application/x-www-form-urlencoded"
EVENT = {"http://schemas.openid.net/event/backchannel-logout": {}}


@pytest.fixture
def atlas(monkeypatch):
    monkeypatch.setenv(
        "WORKFORCE_ISSUER", "https://id.accessops.test:8443/realms/accessops-workforce"
    )
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "scripts"))
    module = importlib.import_module("atlas_app")
    module = importlib.reload(module)
    yield module
    sys.modules.pop("atlas_app", None)


def claims(**changes):
    value = {"iss": "issuer", "aud": "atlas-app", "iat": int(time.time()), "jti": "j1"}
    value.update(events=EVENT, sid="sid-1", sub="sub-1")
    value.update(changes)
    return {key: item for key, item in value.items() if item is not None}


def body(*tokens):
    return urlencode([("logout_token", token) for token in tokens]).encode()


def accept(module, monkeypatch, value):
    monkeypatch.setattr(module, "_decode", lambda token, issuer, audience, logout: value)
    return module.logout_claims(FORM, body("signed-token"))


def test_valid_logout_token_is_accepted_once(atlas, monkeypatch):
    assert accept(atlas, monkeypatch, claims())["sid"] == "sid-1"
    with pytest.raises(ValueError, match="Replayed"):
        accept(atlas, monkeypatch, claims())


@pytest.mark.parametrize(
    "value",
    [
        claims(events=None),
        claims(events={"other": {}}),
        claims(nonce="n"),
        claims(jti=None),
        claims(iat=int(time.time()) - 600),
        claims(sid=None, sub=None),
    ],
)
def test_invalid_logout_events_are_refused(atlas, monkeypatch, value):
    with pytest.raises((ValueError, KeyError, TypeError)):
        accept(atlas, monkeypatch, value)


def test_logout_requires_form_encoding_and_exactly_one_token(atlas, monkeypatch):
    monkeypatch.setattr(atlas, "_decode", lambda *args, **kwargs: claims())
    with pytest.raises(ValueError):
        atlas.logout_claims("application/json", body("signed-token"))
    for tokens in ((), ("a", "b")):
        with pytest.raises(ValueError):
            atlas.logout_claims(FORM, body(*tokens))


def test_unverifiable_logout_token_is_refused(atlas, monkeypatch):
    def reject(*args, **kwargs):
        raise TokenValidationError("Token verification failed")

    monkeypatch.setattr(atlas, "_decode", reject)
    with pytest.raises(TokenValidationError):
        atlas.logout_claims(FORM, body("forged"))


def test_sid_ends_only_that_session_and_sub_ends_all_of_the_subject(atlas):
    atlas.sessions.update(
        {
            "a" * 24: {"sub": "sub-1", "sid": "sid-1"},
            "b" * 24: {"sub": "sub-1", "sid": "sid-2"},
            "c" * 24: {"sub": "sub-2", "sid": "sid-3"},
        }
    )
    assert atlas.end_sessions({"sid": "sid-1", "sub": "sub-1"}) == 1
    assert set(atlas.sessions) == {"b" * 24, "c" * 24}
    assert atlas.ended["a" * 24] == "backchannel_logout"
    assert atlas.end_sessions({"sub": "sub-1"}) == 1
    assert set(atlas.sessions) == {"c" * 24}


# Revocation signals from AccessOps' Atlas stream; real ES256 signatures.
CAEP_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
WORKFORCE = "https://id.accessops.test:8443/realms/accessops-workforce"


@pytest.fixture
def signals(atlas, monkeypatch):
    import jwt
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setattr(atlas, "signal_key", lambda kid: key.public_key())
    monkeypatch.setattr(atlas, "SIGNAL_TOKEN", "t" * 40)

    def sign(stamp, *, aud="urn:accessops:atlas", iss=WORKFORCE, typ="secevent+jwt", sub="w1"):
        payload = {
            "iss": "https://accessops.test:8443",
            "aud": aud,
            "iat": int(time.time()),
            "jti": "a" * 32,
            "sub_id": {"format": "iss_sub", "iss": iss, "sub": sub},
            "events": {CAEP_REVOKED: {"event_timestamp": stamp}},
        }
        return jwt.encode(payload, key, algorithm="ES256", headers={"typ": typ, "kid": "k1"})

    atlas.feed["readAt"] = time.monotonic()
    return sign


def token_claims(atlas, iat, sub="w1"):
    return {"sub": sub, "iat": iat, "exp": iat + 120}


def test_a_revocation_signal_refuses_tokens_issued_before_it(atlas, signals):
    stamp = atlas.STARTED + 50
    atlas.record_revocation(atlas.signal_claims(signals(stamp)))
    assert atlas.local_verdict(token_claims(atlas, stamp - 30)) == "revoked"
    assert atlas.local_verdict(token_claims(atlas, stamp)) == "revoked"
    assert atlas.local_verdict(token_claims(atlas, stamp + 1)) == "accept"
    assert atlas.local_verdict(token_claims(atlas, stamp - 30, sub="w2")) == "accept"


@pytest.mark.parametrize(
    "changes",
    [{"aud": "urn:accessops:soc-receiver"}, {"iss": "https://elsewhere.test"}, {"typ": "JWT"}],
)
def test_signals_for_another_audience_issuer_or_type_are_refused(atlas, signals, changes):
    import jwt

    with pytest.raises((jwt.PyJWTError, ValueError)):
        atlas.signal_claims(signals(atlas.STARTED, **changes))


def test_without_a_current_stream_or_for_older_tokens_atlas_asks_keycloak(atlas, signals):
    fresh = token_claims(atlas, atlas.STARTED + 5)
    assert atlas.local_verdict(fresh) == "accept"
    assert atlas.local_verdict(token_claims(atlas, atlas.STARTED - 1)) == "ask"
    atlas.feed["readAt"] = time.monotonic() - atlas.FRESH - 1
    assert atlas.local_verdict(fresh) == "ask"
    atlas.feed["readAt"] = None
    assert atlas.local_verdict(fresh) == "ask"
    assert atlas.signal_state() == "stale"


def test_unreadable_signal_keys_never_count_as_an_invalid_event(atlas, monkeypatch):
    class Unavailable:
        status_code = 503

        def json(self):
            return {}

    class Client:
        def __init__(self, timeout):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url):
            return Unavailable()

    monkeypatch.setattr(atlas, "client", Client)
    monkeypatch.setattr(atlas, "json_response", lambda response, limit: response.json())
    with pytest.raises(LookupError):
        atlas.signal_key("k1")
