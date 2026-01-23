from rest_framework import serializers
from .models import WorkspaceModel, WorkspaceMemberModel, RoleModel
import re
import json


class WorkspaceSerializer(serializers.ModelSerializer):
    class Meta:
        model = WorkspaceModel
        fields = ["workspace_id", "name", "description", "owner"]
        extra_kwargs = {"owner": {"read_only": True}}


class RoleSerializer(serializers.ModelSerializer):
    permissions = serializers.JSONField(required=False, default=list)

    class Meta:
        model = RoleModel
        fields = ("role_id", "workspace", "role_name", "permissions", "created_at")
        read_only_fields = ("role_id", "created_at")

    def create(self, validated_data):
        if "permissions" not in validated_data:
            validated_data["permissions"] = []
        return super().create(validated_data)

    def validate_permissions(self, value):
        """Validate permissions list structure"""
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                raise serializers.ValidationError("Invalid JSON format for permissions")

        if not isinstance(value, list):
            raise serializers.ValidationError("Permissions must be a list")

        for permission in value:
            if not isinstance(permission, str):
                raise serializers.ValidationError(
                    f"Permission '{permission}' must be a string"
                )

            if not re.match(r"^[a-z_]+$", permission):
                raise serializers.ValidationError(
                    f"Permission '{permission}' must contain only lowercase letters and underscores"
                )

        return value


class WorkspaceMemberSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)
    email = serializers.CharField(source="user.email", read_only=True)
    role_name = serializers.CharField(source="role.role_name", read_only=True)

    class Meta:
        model = WorkspaceMemberModel
        fields = (
            "workspace_member_id",
            "workspace",
            "username",
            "email",
            "role",
            "role_name",
            "joined_at",
        )
        read_only_fields = ("workspace_member_id", "joined_at")


class WorkspaceMemberListSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)
    email = serializers.CharField(source="user.email", read_only=True)
    role_name = serializers.CharField(source="role.role_name", read_only=True)

    class Meta:
        model = WorkspaceMemberModel
        fields = ("workspace_member_id", "username", "email", "role_name", "joined_at")


class WorkspaceInviteSerializer(serializers.Serializer):
    """Serializer for sending invitations"""

    email = serializers.EmailField()
    workspace_id = serializers.IntegerField()
    role_id = serializers.IntegerField()


class WorkspaceInviteAcceptSerializer(serializers.Serializer):
    """Serializer for accepting invitations"""

    token = serializers.CharField()
