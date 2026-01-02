from django.conf import settings
from django.shortcuts import render
from tasks.models import StatusModel
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import WorkspaceMemberModel, WorkspaceModel, RoleModel
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import WorkspaceSerializer, WorkspaceMemberSerializer

# Create your views here.


class WorkspaceAPI(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = request.user

            memberships = WorkspaceMemberModel.objects.filter(user=user).select_related(
                "workspace"
            )

            return Response(
                {
                    "status": 200,
                    "workspace": [
                        {
                            "workspace_id": membership.workspace.workspace_id,
                            "name": membership.workspace.name,
                            # "owner": membership.workspace.owner.username,
                            # "role": membership.role.role_name,
                            # "permissions": membership.role.permissions.get(
                            #     membership.role.role_name, []
                            # ),
                        }
                        for membership in memberships
                    ],
                },
                status=200,
            )
        except Exception as e:
            return Response(
                {"status": 500, "message": "Something went wrong"}, status=500
            )

    def post(self, request):
        try:
            workspace_name = request.data.get("name")

            if not workspace_name:
                return Response(
                    {"status": 400, "message": "Workspace name is required"}, status=400
                )

            user = request.user

            serializer = WorkspaceSerializer(data=workspace_name)

            if not serializer.is_valid():
                return Response(
                    {"status": 400, "message": serializer.errors}, status=400
                )

            workspace = WorkspaceModel.objects.create(name=workspace_name, owner=user)

            for role_name, perms in settings.DEFAULT_ROLES.items():
                RoleModel.objects.create(
                    workspace=workspace,
                    role_name=role_name,
                    permissions={role_name: perms},
                    is_default=True,
                )

            for status in enumerate(settings.DEFAULT_STATUSES):
                StatusModel.objects.create(
                    workspace=workspace, name=status["name"], color=status["color"]
                )

            owner_role = RoleModel.objects.get(workspace=workspace, role_name="owner")
            WorkspaceMemberModel.objects.create(
                user=user, workspace=workspace, role=owner_role
            )

        except Exception as e:
            return Response(
                {"status": 500, "message": "Something went wrong"}, status=500
            )


class WorkspaceMemberAPI(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            workspace_name = request.data.get("workspace_name")

            try:
                workspace = WorkspaceModel.objects.get(name=workspace_name)
            except WorkspaceModel.DoesNotExist:
                return Response(
                    {"status": 400, "message": "No such workspace Found"}, status=400
                )

            members = WorkspaceMemberModel.objects.filter(
                workspace=workspace
            ).select_related("user")

            return Response(
                {
                    "status": 200,
                    "members": [
                        {
                            "member_id": member.workspace_member_id,
                            "name": member.user.username,
                        }
                        for member in members
                    ],
                }
            )
        except Exception as e:
            return Response(
                {"status": 500, "message": "Something went wrong"}, status=500
            )
