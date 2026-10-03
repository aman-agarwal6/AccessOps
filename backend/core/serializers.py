from rest_framework import serializers


class StrictSerializer(serializers.Serializer):
    def to_internal_value(self, data):
        if not isinstance(data, dict) or set(data) - set(self.fields):
            raise serializers.ValidationError({"non_field_errors": ["Unexpected input fields."]})
        return super().to_internal_value(data)


class EmptyInput(StrictSerializer):
    pass


class RequestInput(StrictSerializer):
    identityId = serializers.UUIDField()
    resourceId = serializers.UUIDField(required=False, allow_null=True)
    action = serializers.ChoiceField(choices=["grant", "revoke", "offboard", "transfer"])
    reason = serializers.CharField(min_length=8, max_length=255, trim_whitespace=True)
    permission = serializers.ChoiceField(choices=["read"], default="read")
    newSponsorId = serializers.UUIDField(required=False, allow_null=True)

    def validate(self, data):
        if data["action"] in ("grant", "revoke") and not data.get("resourceId"):
            raise serializers.ValidationError("A resource is required.")
        if data["action"] == "transfer" and not data.get("newSponsorId"):
            raise serializers.ValidationError("A successor is required.")
        if data["action"] != "transfer" and data.get("newSponsorId"):
            raise serializers.ValidationError("A successor only applies to transfer.")
        return data


class ReviewInput(StrictSerializer):
    mode = serializers.ChoiceField(choices=["deterministic"])


class ProposeInput(StrictSerializer):
    identityId = serializers.UUIDField()
    resourceId = serializers.UUIDField()
    reason = serializers.CharField(min_length=8, max_length=255)


class ToolInput(StrictSerializer):
    tool = serializers.ChoiceField(choices=["list_entitlements", "read_evidence", "create_draft"])
    resourceId = serializers.UUIDField(required=False)


def validate(cls, data):
    serializer = cls(data=data)
    serializer.is_valid(raise_exception=True)
    return serializer.validated_data
