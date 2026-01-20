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

# class StageSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = StageModel
#         fields = ["stage_id", "name", "description"]

class StageSerializer(serializers.ModelSerializer):
    class Meta:
        model = StageModel
        fields = ["stage_id", "name", "description"]


class StageListSerializer(StageSerializer):
    """Serializer for listing stages - includes workspace info"""
    workspace_name = serializers.CharField(source='workspace.name', read_only=True)
    task_count = serializers.SerializerMethodField()
    
    class Meta(StageSerializer.Meta):
        fields = StageSerializer.Meta.fields + ["workspace_name", "task_count", "created_at", "updated_at"]
    
    def get_task_count(self, obj):
        return obj.tasks.count()


class StageCreateSerializer(serializers.ModelSerializer):
    workspace_id = serializers.IntegerField(write_only=True, required=True)
    
    class Meta:
        model = StageModel
        fields = ["name", "description", "workspace_id"]
    
    def validate_workspace_id(self, value):
        """Validate that workspace exists"""
        try:
            workspace = WorkspaceModel.objects.get(workspace_id=value)
        except WorkspaceModel.DoesNotExist:
            raise serializers.ValidationError("Workspace does not exist")
        return value
    
    def create(self, validated_data):
        workspace_id = validated_data.pop('workspace_id')
        workspace = WorkspaceModel.objects.get(workspace_id=workspace_id)
        return StageModel.objects.create(workspace=workspace, **validated_data)


class StageUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = StageModel
        fields = ["name", "description"]
        extra_kwargs = {
            'name': {'required': False},
            'description': {'required': False}
        }


class StageDetailSerializer(StageSerializer):
    """Serializer for detailed stage view"""
    workspace = serializers.PrimaryKeyRelatedField(read_only=True)
    workspace_name = serializers.CharField(source='workspace.name', read_only=True)
    created_at = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    updated_at = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    
    class Meta(StageSerializer.Meta):
        fields = StageSerializer.Meta.fields + ["workspace", "workspace_name", "created_at", "updated_at"]