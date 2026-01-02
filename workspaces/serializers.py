from rest_framework import serializers
from .models import WorkspaceModel, WorkspaceMemberModel


class WorkspaceSerializer(serializers.ModelSerializer):
    class Meta:
        model = WorkspaceModel
        fields = ["workspace_id", "name", "owner"]
        extra_kwargs = {"owner": {"read_only": True}}


class WorkspaceMemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = WorkspaceMemberModel
        fields = ["workspace_member_id", "workspace", "user", "role"]
