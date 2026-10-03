import os

os.environ.setdefault("DJANGO_SECRET_KEY", "test-only-not-a-real-secret")
from .settings import *  # noqa: F403

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
if os.environ.get("ACCESSOPS_TEST_DATABASE_URL"):
    test_db = urlparse(os.environ["ACCESSOPS_TEST_DATABASE_URL"])
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": unquote(test_db.path.lstrip("/")),
            "USER": unquote(test_db.username or ""),
            "PASSWORD": unquote(test_db.password or ""),
            "HOST": test_db.hostname,
            "PORT": test_db.port or 5432,
        }
    }
ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
