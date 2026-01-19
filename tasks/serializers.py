# serializers.py
from rest_framework import serializers
from .models import TaskModel, StageModel
from workspaces.models import WorkspaceMemberModel


class AssignedMemberSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)

    class Meta:
        model = WorkspaceMemberModel
        fields = ("workspace_member_id", "username")

class TaskReadSerializer(serializers.ModelSerializer):
    task_id = serializers.IntegerField(read_only=True)
    stage = serializers.SerializerMethodField()
    members = AssignedMemberSerializer(
        source="assigned_to", many=True, read_only=True
    )
    created_by = serializers.CharField(source="created_by.username", read_only=True)

    class Meta:
        model = TaskModel
        fields = (
            "task_id",
            "title",
            "description",
            "stage",
            "members",
            "is_due",
            "due",
            "created_by",
            "created_at",
            "updated_at",
        )

    def get_stage(self, obj):
        return obj.stage.stage_id if obj.stage else None

class TaskCreateUpdateSerializer(serializers.ModelSerializer):
    workspace_id = serializers.IntegerField(write_only=True)
    stage_id = serializers.IntegerField(required=False, allow_null=True)
    assigned_to = serializers.ListField(
        child=serializers.IntegerField(), required=False
    )

    class Meta:
        model = TaskModel
        fields = (
            "workspace_id",
            "title",
            "description",
            "stage_id",
            "assigned_to",
            "is_due",
            "due",
        )

class StageSerializer(serializers.ModelSerializer):
    class Meta:
        model = StageModel
        fields = ["stage_id", "name", "description"]

