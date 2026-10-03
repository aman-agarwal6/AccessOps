from django.contrib.auth import logout
from django.utils import timezone

from .models import SessionBinding


class SessionValidityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            binding = (
                SessionBinding.objects.filter(
                    session_key=request.session.session_key,
                    principal__user=request.user,
                    revoked=False,
                    expires_at__gt=timezone.now(),
                    principal__status="active",
                )
                .select_related("principal__workforce_identity")
                .first()
            )
            if (
                not binding
                or binding.principal.workforce_identity_id
                and binding.principal.workforce_identity.status != "active"
            ):
                logout(request)
        response = self.get_response(request)
        if request.path.startswith(("/api/", "/auth/")):
            response["Cache-Control"] = "no-store"
            response["Pragma"] = "no-cache"
        return response
