from core import auth, enrollment, views
from django.urls import path

urlpatterns = [
    path("api/v1/identities", enrollment.identities),
    path(
        "api/v1/identities/<uuid:identity_id>/transfer-department", enrollment.transfer_department
    ),
    path("api/v1/session", views.session),
    path("api/v1/health", views.health),
    path("api/v1/snapshot", views.snapshot),
    path("api/v1/requests", views.requests),
    path("api/v1/requests/<uuid:request_id>/<str:action>", views.request_action),
    path("api/v1/reviews/<uuid:review_id>/<str:action>", views.review_action),
    path("api/v1/reconcile", views.reconcile),
    path("api/v1/evidence/<uuid:run_id>", views.evidence),
    path("api/v1/agent/tasks/<uuid:task_id>/tools", views.agent_tools),
    path("api/v1/resources/<uuid:resource_id>/read", views.resource_read),
    path("auth/login", auth.oidc_login),
    path("auth/callback", auth.oidc_callback),
    path("auth/logout", auth.oidc_logout),
    path("auth/backchannel-logout", auth.backchannel_logout),
]
