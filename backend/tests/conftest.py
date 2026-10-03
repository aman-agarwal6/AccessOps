from datetime import timedelta

import pytest
from core.management.commands.seed_demo import uid
from core.models import Principal, Resource, Review, SessionBinding
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.utils import timezone
from rest_framework.test import APIClient


@pytest.fixture
def org(db, monkeypatch):
    call_command("seed_demo", verbosity=0)
    monkeypatch.setattr(
        "integrations.policy.evaluate",
        lambda data: {
            "allow": True,
            "reason": "test_policy",
            "policy_version": data["context"]["policy_version"],
        },
    )
    return {
        "alice": Principal.objects.get(pk=uid("operator-alice")),
        "bob": Principal.objects.get(pk=uid("operator-bob")),
        "clara": Principal.objects.get(pk=uid("operator-clara")),
        "employee": Principal.objects.get(pk=uid("alice-morgan")),
        "sponsor": Principal.objects.get(pk=uid("bob-chen")),
        "agent": Principal.objects.get(pk=uid("review-assistant")),
        "atlas": Resource.objects.get(pk=uid("atlas-workspace")),
        "pulse": Resource.objects.get(pk=uid("pulse-workspace")),
        "review": Review.objects.get(pk=uid("quarterly-review")),
    }


@pytest.fixture
def client_for(org):
    def create(actor, csrf=False):
        user = (
            get_user_model().objects.create_user(username=str(actor.pk))
            if not actor.user_id
            else actor.user
        )
        actor.user = user
        actor.save(update_fields=["user"])
        client = APIClient(enforce_csrf_checks=csrf)
        client.force_login(user)
        SessionBinding.objects.create(
            session_key=client.session.session_key,
            principal=actor,
            expires_at=timezone.now() + timedelta(minutes=30),
        )
        return client

    return create
