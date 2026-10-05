import hashlib
from datetime import timedelta

import jwt
from authlib.integrations.django_client import OAuth
from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.contrib.sessions.models import Session
from django.db import transaction
from django.http import JsonResponse
from django.shortcuts import redirect
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.decorators.http import require_GET, require_POST
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from . import audit
from .models import LogoutReplay, Principal, SessionBinding
from .services import policy_state


def oidc_client():
    oauth = OAuth()
    return oauth.register(
        "operator",
        client_id=settings.OIDC_CLIENT_ID,
        client_secret=settings.OIDC_CLIENT_SECRET,
        server_metadata_url=settings.OIDC_ISSUER + "/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile", "code_challenge_method": "S256", "timeout": 5},
    )


@require_GET
def oidc_login(request):
    from .rate_limit import allowed

    if not allowed(request, "login"):
        return JsonResponse(
            {
                "error": {
                    "code": "rate_limited",
                    "message": "Login rate limit reached. Retry later.",
                }
            },
            status=429,
        )
    # State, nonce and verifier live only in the short-lived server session.
    request.session.set_expiry(300)
    try:
        return oidc_client().authorize_redirect(
            request, settings.OIDC_REDIRECT_URI, acr_values=settings.OIDC_REQUIRED_ACR
        )
    except Exception:
        return JsonResponse(
            {
                "error": {
                    "code": "identity_unavailable",
                    "message": "The identity provider is unavailable.",
                }
            },
            status=503,
        )


@require_GET
def oidc_callback(request):
    try:
        from .rate_limit import allowed

        if not allowed(request, "callback") or any(
            len(request.GET.get(k, "")) > 4096 for k in ("code", "state")
        ):
            raise ValueError("Callback limits exceeded")
        token = oidc_client().authorize_access_token(
            request,
            claims_options={"iss": {"essential": True, "value": settings.OIDC_ISSUER}},
            leeway=5,
        )
        encoded_id = token.get("id_token")
        if not isinstance(encoded_id, str) or not 1 <= len(encoded_id) <= 16384:
            raise ValueError("Signed ID token required")
        header = jwt.get_unverified_header(encoded_id)
        if header.get("alg") != "RS256" or any(k in header for k in ("jku", "x5u", "jwk", "crit")):
            raise ValueError("Unsupported ID token header")
        claims = token.get("userinfo")  # Authlib validates the signed ID token, nonce and claims.
        if (
            not isinstance(claims, dict)
            or claims.get("nonce_supported") is False
            or claims.get("iss") != settings.OIDC_ISSUER
            or not isinstance(claims.get("sub"), str)
            or not 1 <= len(claims["sub"]) <= 255
        ):
            raise ValueError("Invalid operator identity")
        # Whatever was requested, only a second-factor sign-in opens a session.
        if claims.get("acr") != settings.OIDC_REQUIRED_ACR:
            raise ValueError("Second factor required")
        roles = claims.get("accessops_roles", [])
        projects = claims.get("accessops_projects", [])
        if (
            not isinstance(roles, list)
            or not roles
            or not set(roles).issubset({"operator", "approver", "auditor", "resource_owner"})
        ):
            raise ValueError("Invalid role assignment")
        if (
            not isinstance(projects, list)
            or not projects
            or any(not isinstance(p, str) or not 1 <= len(p) <= 80 for p in projects)
        ):
            raise ValueError("Invalid project assignment")
        with transaction.atomic():
            policy_state(lock=True)
            principal = (
                Principal.objects.select_for_update()
                .filter(issuer=claims["iss"], subject=claims["sub"], kind="human")
                .first()
            )
            # Explicit enrollment: no username/email linking and no automatic admin.
            if (
                not principal
                or principal.status != "active"
                or principal.workforce_identity_id
                and principal.workforce_identity.status != "active"
            ):
                raise ValueError("Operator not enrolled")
            if not principal.user_id:
                user = get_user_model().objects.create(
                    username=hashlib.sha256(
                        (claims["iss"] + "\0" + claims["sub"]).encode()
                    ).hexdigest()
                )
                user.set_unusable_password()
                user.save(update_fields=["password"])
                principal.user = user
            principal.roles, principal.project_ids = roles, projects
            principal.save(update_fields=["user", "roles", "project_ids", "updated_at"])
            request.session.cycle_key()
            login(request, principal.user, backend="django.contrib.auth.backends.ModelBackend")
            request.session.set_expiry(1800)
            request.session.save()
            SessionBinding.objects.create(
                session_key=request.session.session_key,
                principal=principal,
                oidc_sid=str(claims.get("sid", ""))[:255],
                expires_at=timezone.now() + timedelta(minutes=30),
            )
            audit.append(
                principal,
                "session.created",
                principal.pk,
                {"issuer": settings.OIDC_ISSUER, "acr": claims["acr"]},
            )
        return redirect(settings.OIDC_POST_LOGOUT_URI)
    except Exception:
        logout(request)
        return JsonResponse(
            {
                "error": {
                    "code": "login_rejected",
                    "message": "Operator login could not be verified.",
                }
            },
            status=401,
        )


@require_POST
@csrf_protect
def oidc_logout(request):
    with transaction.atomic():
        policy_state(lock=True)
        binding = SessionBinding.objects.filter(session_key=request.session.session_key).first()
        if binding:
            audit.append(binding.principal, "session.logout", binding.principal_id, {})
            binding.revoked = True
            binding.save(update_fields=["revoked"])
        logout(request)
    return JsonResponse({"result": {"loggedOut": True}})


@csrf_exempt
@require_POST
def backchannel_logout(request):
    try:
        from integrations.security import verify_logout_token

        claims = verify_logout_token(request.POST.get("logout_token", ""))
        if claims.get("iss") != settings.OIDC_ISSUER or not (
            claims.get("sid") or claims.get("sub")
        ):
            raise ValueError("Invalid logout target")
        with transaction.atomic():
            policy_state(lock=True)
            LogoutReplay.objects.filter(expires_at__lt=timezone.now()).delete()
            if LogoutReplay.objects.filter(jti=claims["jti"]).exists():
                return JsonResponse({"result": {"accepted": True}})
            LogoutReplay.objects.create(
                jti=claims["jti"], expires_at=timezone.now() + timedelta(minutes=5)
            )
            sessions = SessionBinding.objects.filter(principal__issuer=settings.OIDC_ISSUER)
            if claims.get("sid"):
                sessions = sessions.filter(oidc_sid=claims["sid"])
            if claims.get("sub"):
                sessions = sessions.filter(principal__subject=claims["sub"])
            keys = list(sessions.values_list("session_key", flat=True))
            sessions.update(revoked=True)
            Session.objects.filter(session_key__in=keys).delete()
            audit.append("oidc-backchannel", "session.revoked", "operators", {"count": len(keys)})
        return JsonResponse({"result": {"accepted": True}})
    except Exception:
        return JsonResponse(
            {
                "error": {
                    "code": "logout_rejected",
                    "message": "Logout message could not be verified.",
                }
            },
            status=400,
        )


class ExecutorAuthentication(BaseAuthentication):
    def authenticate(self, request):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer ") or len(header) > 16400:
            raise AuthenticationFailed("A valid executor credential is required.")
        try:
            from integrations.security import ExecutorClient, verify_executor_token

            token = header[7:]
            claims = verify_executor_token(
                token,
                dpop_proof=request.headers.get("DPoP"),
                method=request.method,
                url=request.build_absolute_uri(),
            )
            client = ExecutorClient()
            try:
                introspection = client.introspect(token)
            finally:
                client.http.close()
            if introspection.get("active") is not True or introspection.get("sub") != claims["sub"]:
                raise ValueError("Inactive credential")
            actor = Principal.objects.get(
                issuer=claims["iss"], subject=claims["sub"], kind="agent", status="active"
            )
            return actor, claims
        except Exception:
            raise AuthenticationFailed("Executor authentication failed.") from None

    def authenticate_header(self, request):
        return "Bearer"


class OptionalExecutorAuthentication(ExecutorAuthentication):
    def authenticate(self, request):
        if not request.headers.get("Authorization"):
            return None
        return super().authenticate(request)
