from .models import *
from datetime import timedelta
from django.shortcuts import render
from backend.helper import permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from workspaces.models import WorkspaceModel, WorkspaceMemberModel
from rest_framework_simplejwt.authentication import JWTAuthentication
from backend.helper.custom_exception import (
    AppException,
    PermissionDeniedError,
    WorkspaceError,
)

# Create your views here.


class StatusAPI(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = request.user
            data = request.data

            workspace_id = data.get("workspace_id")

            if not workspace_id:
                return Response(
                    {"status": 400, "message": "Workspace id is required"}, status=400
                )

            try:
                workspace = WorkspaceModel.objects.get(workspace_id=workspace_id)
            except WorkspaceModel.DoesNotExist:
                return Response({"status": 400, "message": "No such workspace Exists"})

            status_list = StatusModel.objects.filter(workspace=workspace)

            return Response(
                {
                    "status": 200,
                    "status": [
                        {
                            "status_id": status.status_id,
                            "name": status.name,
                            "color": status.color,
                        }
                        for status in status_list
                    ],
                }
            )
        except Exception as e:
            return Response(
                {"status": 500, "message": "Something went Wrong"}, status=500
            )


class TasksAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = request.user
            data = request.data

            workspace_id = data.get("workspace_id")

            if not workspace_id:
                raise AppException("Workspace id is required")

            try:
                workspace = WorkspaceModel.objects.get(workspace_id=workspace_id)
            except WorkspaceModel.DoesNotExist:
                raise WorkspaceError("No Such workspace exists")

            tasks = (
                TaskModel.objects.filter(workspace=workspace)
                .select_related("status", "created_by")
                .prefetch_related("assigned_to__user")
                .order_by("-created_at")
            )

            return Response(
                {
                    "status": 200,
                    "tasks": [
                        {
                            "task_id": task.task_id,
                            "title": task.title,
                            "description": task.description,
                            "status": task.status.name if task.status else None,
                            "members": [
                                {
                                    "workspace_member_id": member.workspace_member_id,
                                    "username": member.user.username,
                                }
                                for member in task.assigned_to.all()
                            ],
                            "created_by": task.created_by.username,
                            "created_at": task.created_at,
                            "updated_at": task.updated_at,
                        }
                        for task in tasks
                    ],
                },
                status=200,
            )
        except Exception as e:
            return Response(
                {"status": 500, "message": "Something went Wrong"}, status=500
            )

    def post(self, request):
        try:
            user = request.user
            data = request.data

            workspace_id = data.get("workspace_id")
            title = data.get("title")
            description = data.get("description", "")
            status_id = data.get("status_id")
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

            task_status = None
            if status_id:
                try:
                    task_status = StatusModel.objects.get(id=status_id)
                except StatusModel.DoesNotExist:
                    return Response(
                        {"Status": 400, "message": "Invalid status"},
                        status=400,
                    )

            task = TaskModel.objects.create(
                workspace=workspace,
                title=title,
                description=description,
                status=task_status,
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
                        "status": task.status.name if task.status else None,
                        "assigned_to": [
                            {
                                "workspace_member_id": m.workspace_member_id,
                                "user_id": m.user.id,
                                "username": m.user.username,
                            }
                            for m in task.assigned_to.select_related("user")
                        ],
                        "created_by": user.username,
                        "created_at": task.created_at,
                    },
                },
                status=201,
            )
        except Exception as e:
            return Response(
                {"status": 500, "message": "Something went Wrong"}, status=500
            )
