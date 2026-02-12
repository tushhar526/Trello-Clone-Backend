from .models import *
from datetime import timedelta
from django.shortcuts import render
from backend.helper import permissions
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet
from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.types import OpenApiTypes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from workspaces.models import WorkspaceModel, WorkspaceMemberModel
from rest_framework_simplejwt.authentication import JWTAuthentication
from backend.helper.custom_exception import (
    AppException,
    PermissionDeniedError,
    WorkspaceError,
    TasksError,
    StageError,
)
from .serializers import *

# Create your views here.


class StageAPI(ViewSet):
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        """Return different serializer based on action"""
        if self.action == "list":
            return StageListSerializer
        elif self.action == "create":
            return StageCreateSerializer
        elif self.action == "retrieve":
            return StageDetailSerializer
        elif self.action in ["partial_update", "update"]:
            return StageUpdateSerializer
        return StageSerializer

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="workspace_id",
                type=OpenApiTypes.INT,
                location="query",
                description="Workspace ID to filter tasks",
                required=True,
            )
        ],
        responses=StageSerializer(many=True),
    )
    def list(self, request):
        workspace_id = request.query_params.get("workspace_id")
        if not workspace_id:
            raise AppException("workspace_id is required")

        try:
            workspace = WorkspaceModel.objects.get(workspace_id=workspace_id)
        except WorkspaceModel.DoesNotExist:
            raise WorkspaceError("No such Workspace Found")

        if not permissions.has_permission(request.user, workspace, "view_stage"):
            raise PermissionDeniedError("No permission")

        stages = StageModel.objects.filter(workspace=workspace)
        serializer = StageSerializer(stages, many=True)
        return Response(serializer.data)

    def create(self, request):
        workspace_id = request.data.get("workspace_id")
        if not workspace_id:
            raise AppException("workspace_id is required")

        try:
            workspace = WorkspaceModel.objects.get(workspace_id=workspace_id)
        except WorkspaceModel.DoesNotExist:
            raise WorkspaceError("No such Workspace Found")

        if not permissions.has_permission(request.user, workspace, "add_stage"):
            raise PermissionDeniedError("No permission")

        serializer = StageSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        stage = serializer.save(workspace=workspace)
        return Response(StageSerializer(stage).data, status=201)

    def partial_update(self, request, pk=None):
        try:
            stage = StageModel.objects.get(stage_id=pk)
        except StageModel.DoesNotExist:
            raise StageError("No such Stage Found")

        workspace = stage.workspace

        if not permissions.has_permission(request.user, workspace, "edit_stage"):
            raise PermissionDeniedError("No permission")

        serializer = StageSerializer(stage, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data)

    def destroy(self, request, pk=None):
        try:
            stage = StageModel.objects.get(stage_id=pk)
        except StageModel.DoesNotExist:
            raise StageError("No such Stage Found")
        workspace = stage.workspace

        if not permissions.has_permission(request.user, workspace, "delete_stage"):
            raise PermissionDeniedError("No permission")

        stage.delete()
        return Response(status=204)


class TasksAPI(ViewSet):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="workspace_id",
                type=OpenApiTypes.INT,
                location="query",
                description="Workspace ID to filter tasks",
                required=True,
            )
        ],
        responses=TaskReadSerializer(many=True),
    )
    def list(self, request):
        user = request.user
        workspace_id = request.query_params.get("workspace_id")

        if not workspace_id:
            raise AppException("Workspace Id is required")

        try:
            workspace = WorkspaceModel.objects.get(workspace_id=workspace_id)
        except WorkspaceModel.DoesNotExist:
            raise WorkspaceError("No such Workspace is Found")

        stages = StageModel.objects.filter(workspace=workspace)

        grouped_tasks = {}
        for stage in stages:
            tasks = (
                TaskModel.objects.filter(workspace=workspace, stage=stage)
                .select_related("created_by")
                .prefetch_related("assigned_to__user")
                .order_by("-created_at")
            )

            grouped_tasks[stage.stage_id] = [
                {
                    "task_id": task.task_id,
                    "title": task.title,
                    "description": task.description,
                    "stage": stage.stage_id,
                    "assigned_to": [
                        {
                            "workspace_member_id": member.workspace_member_id,
                            "username": member.user.username,
                        }
                        for member in task.assigned_to.all()
                    ],
                    "is_due": task.is_due,
                    "due": task.due,
                    "created_by": task.created_by.username,
                    "created_at": task.created_at,
                    "updated_at": task.updated_at,
                }
                for task in tasks
            ]

        return Response(
            {
                "status": 200,
                "stages": [
                    {
                        "stage_id": s.stage_id,
                        "name": s.name,
                        "description": s.description,
                    }
                    for s in stages
                ],
                "tasks": grouped_tasks,
            },
            status=200,
        )

    @extend_schema(responses=TaskReadSerializer)
    def retrieve(self, request, pk=None):
        try:
            task = (
                TaskModel.objects.prefetch_related("assigned_to__user")
                .select_related("created_by", "stage")
                .get(task_id=pk)
            )
        except TaskModel.DoesNotExist:
            raise TasksError("No such Task Exist")

        return Response(
            {
                "status": 200,
                "task": {
                    "task_id": task.task_id,
                    "title": task.title,
                    "description": task.description,
                    "stage": task.stage.stage_id if task.stage else None,
                    "members": [
                        {
                            "workspace_member_id": m.workspace_member_id,
                            "username": m.user.username,
                        }
                        for m in task.assigned_to.all()
                    ],
                    "isdue": task.is_due,
                    "due": task.due,
                    "created_by": task.created_by.username,
                    "created_at": task.created_at,
                    "updated_at": task.updated_at,
                },
            },
            status=200,
        )

    @extend_schema(
        request=TaskCreateUpdateSerializer, responses=TaskCreateUpdateSerializer
    )
    def create(self, request):
        user = request.user
        data = request.data

        workspace_id = data.get("workspace_id")
        title = data.get("title")
        description = data.get("description", "")
        stage_id = data.get("stage_id")
        assigned_to_ids = data.get("assigned_to", [])

        if not workspace_id or not title:
            raise AppException("workspace_id and title are required")

        try:
            workspace = WorkspaceModel.objects.get(workspace_id=workspace_id)
        except WorkspaceModel.DoesNotExist:
            raise AppException("No such workspace Found")

        if not permissions.has_permission(user, workspace, "add_task"):
            raise PermissionDeniedError(
                "Your role does not have permission to add Task"
            )

        if not WorkspaceMemberModel.objects.filter(
            workspace=workspace, user=user
        ).exists():
            raise WorkspaceError("You are not a member of this workspace")

        task_stage = None
        if stage_id:
            try:
                task_stage = StageModel.objects.get(stage_id=stage_id)
            except StageModel.DoesNotExist:
                raise StageError("No such Stage found")

        task = TaskModel.objects.create(
            workspace=workspace,
            title=title,
            description=description,
            stage=task_stage,
            created_by=user,
        )

        if assigned_to_ids:
            members = WorkspaceMemberModel.objects.filter(
                workspace=workspace,
                workspace_member_id__in=assigned_to_ids,
            )

            if members.count() != len(assigned_to_ids):
                task.delete()
                return Response(
                    {"status": 400, "message": "One or more assignees are invalid"},
                    status=400,
                )

            task.assigned_to.set(members)

        return Response(
            {
                "message": "Task created successfully",
                "task": {
                    "task_id": task.task_id,
                    "title": task.title,
                    "description": task.description,
                    "workspace_id": workspace.workspace_id,
                    "stage": task.stage.name if task.stage else None,
                    "assigned_to": [
                        {
                            "workspace_member_id": m.workspace_member_id,
                            "user_id": m.user.id,
                            "username": m.user.username,
                        }
                        for m in task.assigned_to.select_related("user")
                    ],
                    "is_due": task.is_due,
                    "due": task.due,
                    "created_by": user.username,
                    "created_at": task.created_at,
                },
            },
            status=201,
        )

    @extend_schema(
        request=TaskCreateUpdateSerializer, responses=TaskCreateUpdateSerializer
    )
    def partial_update(self, request, pk=None):
        user = request.user
        data = request.data

        try:
            task = (
                TaskModel.objects.select_related("workspace", "stage")
                .prefetch_related("assigned_to")
                .get(task_id=pk)
            )
        except TaskModel.DoesNotExist:
            raise TasksError("No such Task Found")

        workspace = task.workspace

        if not permissions.has_permission(user, workspace, "edit_task"):
            raise PermissionDeniedError(
                "You do not have permission to update this task"
            )

        if "title" in data:
            task.title = data["title"]

        if "description" in data:
            task.description = data["description"]

        if "stage" in data:
            if data["stage"] is None:
                task.stage = None
            else:
                try:
                    task.stage = StageModel.objects.get(
                        stage_id=data["stage"],
                        workspace=workspace,
                    )
                except StageModel.DoesNotExist:
                    raise StageError("No such stage exists")

        if "assigned_to" in data:
            task_members = data["assigned_to"]
            member_ids = [member["workspace_member_id"] for member in task_members]

            members = WorkspaceMemberModel.objects.filter(
                workspace=workspace,
                workspace_member_id__in=member_ids,
            )

            if members.count() != len(member_ids):
                raise TasksError("One or more assignees are invalid")

            task.assigned_to.set(members)

        if "is_due" in data:
            task.is_due = data["is_due"]

        task.save()

        return Response(
            {
                "message": "Task updated successfully",
                "task": {
                    "task_id": task.task_id,
                    "title": task.title,
                    "description": task.description,
                    "stage": task.stage.stage_id if task.stage else None,
                    "assigned_to": [
                        {
                            "workspace_member_id": m.workspace_member_id,
                            "user_id": m.user.user_id,
                            "username": m.user.username,
                        }
                        for m in task.assigned_to.select_related("user")
                    ],
                    "is_due": task.is_due,
                    "due": task.due,
                    "updated_at": task.updated_at,
                },
            },
            status=200,
        )

    @extend_schema(responses={204: None})
    def destroy(self, request, pk=None):
        user = request.user

        try:
            task = TaskModel.objects.select_related("workspace").get(
                task_id=pk,
            )
        except TaskModel.DoesNotExist:
            raise TasksError("No such Task Found")

        workspace = task.workspace

        if not permissions.has_permission(user, workspace, "delete_task"):
            raise PermissionDeniedError("You Do not have permission to Delete the task")

        task.delete()

        return Response(
            {
                "status": 200,
                "message": "Task deleted successfully",
            },
            status=200,
        )

    def get_serializer_class(self):
        if self.action in ["list", "retrieve"]:
            return TaskReadSerializer
        return TaskCreateUpdateSerializer
