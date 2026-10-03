import hashlib
import hmac
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import RateBucket
from .services import policy_state


def allowed(request, action, limit=20):
    now = timezone.now()
    # Private proxy deployment has a deliberately aggregate login budget. Do
    # not trust a caller-supplied forwarded IP or persist raw client addresses.
    address = request.META.get("REMOTE_ADDR", "unknown")
    material = f"{action}:{address}:{int(now.timestamp()) // 60}"
    key = hmac.new(settings.SECRET_KEY.encode(), material.encode(), hashlib.sha256).hexdigest()
    with transaction.atomic():
        policy_state(lock=True)
        RateBucket.objects.filter(expires_at__lt=now).delete()
        bucket, _ = RateBucket.objects.get_or_create(
            key=key, defaults={"expires_at": now + timedelta(minutes=2)}
        )
        if bucket.count >= limit:
            return False
        bucket.count += 1
        bucket.save(update_fields=["count"])
    return True
