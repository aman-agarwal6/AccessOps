import os
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR.parent))
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "")
if not SECRET_KEY:
    raise ImproperlyConfigured("DJANGO_SECRET_KEY must be generated for this installation.")
DEBUG = False
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1,backend").split(",")
ROOT_URLCONF = "accessops.urls"
WSGI_APPLICATION = "accessops.wsgi.application"
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "rest_framework",
    "core",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "core.middleware.SessionValidityMiddleware",
]
db = urlparse(os.environ.get("DATABASE_URL", "postgresql://accessops@127.0.0.1:5432/accessops"))
if db.scheme not in ("postgres", "postgresql"):
    raise ImproperlyConfigured(
        "Connected lab requires PostgreSQL. Use accessops.test_settings for disposable SQLite tests."
    )
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": unquote(db.path.lstrip("/")),
        "USER": unquote(db.username or ""),
        "PASSWORD": unquote(db.password or ""),
        "HOST": db.hostname or "127.0.0.1",
        "PORT": db.port or 5432,
        "CONN_MAX_AGE": 0,
        "OPTIONS": {"connect_timeout": 5},
    }
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
USE_TZ = True
TIME_ZONE = "UTC"
SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_COOKIE_NAME = "accessops_session"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_TRUSTED_ORIGINS = os.environ.get("CSRF_TRUSTED_ORIGINS", "https://localhost:8443").split(",")
SESSION_COOKIE_AGE = 1800
SESSION_SAVE_EVERY_REQUEST = False
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
# Enable only when backend is reachable exclusively through the private Caddy
# network; Caddy must replace forwarded headers from the browser.
if os.environ.get("ACCESSOPS_TRUST_PRIVATE_PROXY") == "1":
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
X_FRAME_OPTIONS = "DENY"
# Match the private HTTPS edge's bounded request ceiling; canonical case reports
# retain their stricter 100 KB/100-observation validation.
DATA_UPLOAD_MAX_MEMORY_SIZE = 131072
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["rest_framework.authentication.SessionAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "EXCEPTION_HANDLER": "core.errors.exception_handler",
    "UNAUTHENTICATED_USER": None,
}
OIDC_ISSUER = os.environ.get(
    "OIDC_ISSUER", "https://localhost:8443/realms/accessops-operators"
).rstrip("/")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "accessops-console")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
OIDC_REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI", "https://localhost:8443/auth/callback")
OIDC_POST_LOGOUT_URI = os.environ.get("OIDC_POST_LOGOUT_URI", "https://localhost:8443/")
WORKFORCE_ISSUER = os.environ.get(
    "WORKFORCE_ISSUER", "https://localhost:8443/realms/accessops-workforce"
).rstrip("/")
POLICY_VERSION = os.environ.get("POLICY_VERSION", "accessops-v1")
# Signed HR leaver feed (Standard Webhooks HMAC). Without a secret the endpoint
# refuses every event.
HR_WEBHOOK_SECRET = os.environ.get("HR_WEBHOOK_SECRET", "")
HR_INTAKE_ISSUER = "https://hr-intake.accessops.internal"
HR_INTAKE_SOURCE = "northstar-hr"
# Read-only Keycloak events client for the post-departure activity watch.
EVENTS_CLIENT_SECRET = os.environ.get("EVENTS_CLIENT_SECRET", "")
# Shared Signals transmitter: signed leaver events, collected by RFC 8936 polling.
SSF_ISSUER = os.environ.get("SSF_ISSUER", "https://accessops.test:8443")
SSF_AUDIENCE = os.environ.get("SSF_AUDIENCE", "urn:accessops:soc-receiver")
SSF_SIGNING_KEY_FILE = os.environ.get("SSF_SIGNING_KEY_FILE", "/run/ssf/signing.pem")
SSF_RECEIVER_TOKEN = os.environ.get("SSF_RECEIVER_TOKEN", "")
# A second stream for the Atlas lab app, which refuses tokens issued before a
# revocation instead of trusting them until they expire.
SSF_ATLAS_AUDIENCE = "urn:accessops:atlas"
SSF_ATLAS_TOKEN = os.environ.get("ATLAS_SIGNAL_TOKEN", "")
INTERNAL_API_URL = os.environ.get("INTERNAL_API_URL", "https://localhost:8443").rstrip("/")
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": "WARNING"},
}
