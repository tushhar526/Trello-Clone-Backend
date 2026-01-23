from django.conf import settings
from django.shortcuts import render
from tasks.models import StageModel
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import WorkspaceMemberModel, WorkspaceModel, RoleModel
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import *
from api.models import UserModel
from backend.helper.custom_exception import AppException, WorkspaceError
from backend.helper.token import *
from django.core.mail import send_mail
from drf_spectacular.utils import extend_schema, OpenApiParameter
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from drf_spectacular.types import OpenApiTypes
from backend.helper.custom_exception import PermissionDeniedError
from backend.helper.email import sendInvite

# Create your views here.
BASE_URL = os.getenv("BASE_URL")


class WorkspaceAPI(ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = WorkspaceSerializer

    def list(self, request):
        user = request.user

        memberships = WorkspaceMemberModel.objects.filter(user=user).select_related(
            "workspace", "role"
        )

        return Response(
            {
                "status": 200,
                "workspace": [
                    {
                        "workspace_id": m.workspace.workspace_id,
                        "name": m.workspace.name,
                        "description":m.workspace.description,
                        "role": m.role.role_name,
                        "permissions": m.role.permissions.get(m.role.role_name, []),
                    }
                    for m in memberships
                ],
            }
        )

    def create(self, request):
        serializer = WorkspaceSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        workspace = serializer.save(owner=request.user)

        for role_name, perms in settings.DEFAULT_ROLES.items():
            RoleModel.objects.create(
                workspace=workspace,
                role_name=role_name,
                permissions={role_name: perms},
                is_default=True,
            )

        for stage in settings.DEFAULT_STAGES:
            StageModel.objects.create(
                workspace=workspace,
                name=stage["name"],
                description=stage["description"],
            )

        owner_role = RoleModel.objects.get(workspace=workspace, role_name="owner")

        WorkspaceMemberModel.objects.create(
            user=request.user,
            workspace=workspace,
            role=owner_role,
        )

        return Response(
            {"status": 201, "message": "Workspace created"},
            status=201,
        )

    def partial_update(self, request, pk=None):
        try:
            workspace = WorkspaceModel.objects.get(workspace_id=pk)
        except WorkspaceModel.DoesNotExist:
            raise WorkspaceError("No such Workspace exist")

        serializer = WorkspaceSerializer(workspace, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({"status": 200, "message": "Workspace updated"})

    def destroy(self, request, pk=None):
        try:
            workspace = WorkspaceModel.objects.get(workspace_id=pk)
        except WorkspaceModel.DoesNotExist:
            raise WorkspaceError("No such Workspace exist")

        workspace.delete()

        return Response({"status": 204, "message": "Workspace deleted"})


class RoleViewSet(ViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = RoleSerializer

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="workspace_id",
                type=OpenApiTypes.INT,
                location="query",
                description="Workspace ID to filter roles",
                required=True,
            )
        ],
        responses=RoleSerializer(many=True),
    )
    def list(self, request):
        """List all roles for a workspace"""
        workspace_id = request.query_params.get("workspace_id")

        if not workspace_id:
            raise AppException("workspace_id is required")

        try:
            workspace = WorkspaceModel.objects.get(workspace_id=workspace_id)
        except WorkspaceModel.DoesNotExist:
            raise AppException("Workspace not found")

        # Check if user is member of workspace
        if (
            not WorkspaceMemberModel.objects.filter(
                workspace=workspace, user=request.user
            ).exists()
            and workspace.owner != request.user
        ):
            raise PermissionDeniedError("You are not a member of this workspace")

        roles = RoleModel.objects.filter(workspace=workspace)
        serializer = RoleSerializer(roles, many=True)
        return Response({"status": 200, "roles": serializer.data}, status=200)

    @extend_schema(
        request=RoleSerializer, responses=RoleSerializer  # Add this for Swagger
    )
    def create(self, request):
        """Create a new role"""
        user = request.user
        data = request.data

        workspace_id = data.get("workspace")
        role_name = data.get("role_name")
        permissions = data.get("permissions", [])

        if not all([workspace_id, role_name]):
            raise AppException("workspace_id and role_name are required")

        try:
            workspace = WorkspaceModel.objects.get(workspace_id=workspace_id)
        except WorkspaceModel.DoesNotExist:
            raise AppException("Workspace not found")

        if workspace.owner != user:
            raise PermissionDeniedError("Only workspace owner can create roles")

        if RoleModel.objects.filter(workspace=workspace, role_name=role_name).exists():
            raise AppException("Role already exists in this workspace")

        # Use serializer for validation
        serializer = RoleSerializer(
            data={
                "workspace": workspace.workspace_id,
                "role_name": role_name,
                "permissions": permissions,
            }
        )

        if not serializer.is_valid():
            raise AppException(str(serializer.errors))

        role = serializer.save()

        return Response(
            {
                "status": 201,
                "message": "Role created successfully",
                "role": serializer.data,
            },
            status=201,
        )

    def retrieve(self, request, pk=None):
        """Get a specific role"""
        try:
            role = RoleModel.objects.get(role_id=pk)
        except RoleModel.DoesNotExist:
            raise AppException("Role not found")

        # Check if user has access to this role's workspace
        workspace = role.workspace
        if (
            not WorkspaceMemberModel.objects.filter(
                workspace=workspace, user=request.user
            ).exists()
            and workspace.owner != request.user
        ):
            raise PermissionDeniedError("You don't have access to this role")

        serializer = RoleSerializer(role)
        return Response({"status": 200, "role": serializer.data}, status=200)

    @extend_schema(request=RoleSerializer, responses=RoleSerializer)  # For Swagger
    def partial_update(self, request, pk=None):
        """Update a role"""
        user = request.user

        try:
            role = RoleModel.objects.get(role_id=pk)
        except RoleModel.DoesNotExist:
            raise AppException("Role not found")

        workspace = role.workspace
        if workspace.owner != user:
            raise PermissionDeniedError("Only workspace owner can update roles")

        # Partial update - only update provided fields
        serializer = RoleSerializer(role, data=request.data, partial=True)
        if not serializer.is_valid():
            raise AppException(str(serializer.errors))

        serializer.save()

        return Response(
            {
                "status": 200,
                "message": "Role updated successfully",
                "role": serializer.data,
            },
            status=200,
        )

    def destroy(self, request, pk=None):
        """Delete a role"""
        user = request.user

        try:
            role = RoleModel.objects.get(role_id=pk)
        except RoleModel.DoesNotExist:
            raise AppException("Role not found")

        workspace = role.workspace
        if workspace.owner != user:
            raise PermissionDeniedError("Only workspace owner can delete roles")

        # Check if any members are using this role
        if WorkspaceMemberModel.objects.filter(role=role).exists():
            raise AppException("Cannot delete role: Members are assigned to this role")

        role.delete()

        return Response(
            {"status": 200, "message": "Role deleted successfully"},
            status=200,
        )


class WorkspaceMemberViewSet(ViewSet):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="workspace_id",
                type=OpenApiTypes.INT,
                location="query",
                description="Workspace ID to filter members",
                required=True,
            )
        ],
        responses=WorkspaceMemberListSerializer(many=True),
    )
    def list(self, request):
        """List all members of a workspace"""
        workspace_id = request.query_params.get("workspace_id")

        if not workspace_id:
            raise AppException("workspace_id is required")

        try:
            workspace = WorkspaceModel.objects.get(workspace_id=workspace_id)
        except WorkspaceModel.DoesNotExist:
            raise AppException("Workspace not found")

        if (
            not WorkspaceMemberModel.objects.filter(
                workspace=workspace, user=request.user
            ).exists()
            and workspace.owner != request.user
        ):
            raise PermissionDeniedError("You are not a member of this workspace")

        members = WorkspaceMemberModel.objects.filter(
            workspace=workspace
        ).select_related("user", "role")
        serializer = WorkspaceMemberListSerializer(members, many=True)
        return Response({"status": 200, "members": serializer.data}, status=200)

    def retrieve(self, request, pk=None):
        """Get a specific workspace member"""
        try:
            member = WorkspaceMemberModel.objects.select_related("user", "role").get(
                workspace_member_id=pk
            )
        except WorkspaceMemberModel.DoesNotExist:
            raise AppException("Member not found")

        if (
            not WorkspaceMemberModel.objects.filter(
                workspace=member.workspace, user=request.user
            ).exists()
            and member.workspace.owner != request.user
        ):
            raise PermissionDeniedError("You don't have access to this member")

        serializer = WorkspaceMemberSerializer(member)
        return Response({"status": 200, "member": serializer.data}, status=200)

    @extend_schema(request=WorkspaceInviteSerializer)
    def create(self, request):
        """Send workspace invitation"""
        user = request.user
        data = request.data

        email = data.get("email")
        workspace_id = data.get("workspace_id")
        role_id = data.get("role_id")

        if not all([email, workspace_id, role_id]):
            raise AppException("email, workspace_id, and role_id are required")

        try:
            workspace = WorkspaceModel.objects.get(workspace_id=workspace_id)
        except WorkspaceModel.DoesNotExist:
            raise AppException("Workspace not found")

        if workspace.owner != user:
            raise PermissionDeniedError("Only workspace owner can invite members")

        try:
            role = RoleModel.objects.get(role_id=role_id, workspace=workspace)
        except RoleModel.DoesNotExist:
            raise AppException("Role not found in this workspace")

        try:
            target_user = UserModel.objects.get(email=email)
        except UserModel.DoesNotExist:
            raise AppException("User with this email does not exist")

        # Check if user is already a member
        if WorkspaceMemberModel.objects.filter(
            workspace=workspace, user=target_user
        ).exists():
            raise AppException("User is already a member of this workspace")

        # Generate invitation token
        token = generate_invite_token(email, workspace_id, role_id)

        if not sendInvite(
            email, target_user.username, token, workspace.name, user.username
        ):
            raise AppException("An error occured in sending the invite link")

        print("token sent to the another user = ", token)

        return Response(
            {"status": 200, "message": "Invitation sent successfully"}, status=200
        )

    @extend_schema(request=WorkspaceInviteAcceptSerializer)
    @action(detail=False, methods=["post"], url_path="accept-invite")
    def accept_invite(self, request):
        """Accept workspace invitation via token"""
        data = request.data
        token = data.get("token")

        if not token:
            raise AppException("Token is required")

        # Verify token
        payload = verify_invite_token(token)

        email = payload.get("email")
        workspace_id = payload.get("workspace_id")
        role_id = payload.get("role_id")

        try:
            workspace = WorkspaceModel.objects.get(workspace_id=workspace_id)
            role = RoleModel.objects.get(role_id=role_id, workspace=workspace)
            target_user = UserModel.objects.get(email=email)
        except (
            WorkspaceModel.DoesNotExist,
            RoleModel.DoesNotExist,
            UserModel.DoesNotExist,
        ):
            raise AppException("Invalid invitation data")

        # Check if already a member
        if WorkspaceMemberModel.objects.filter(
            workspace=workspace, user=target_user
        ).exists():
            raise AppException("User is already a member of this workspace")

        # Add user to workspace
        member = WorkspaceMemberModel.objects.create(
            workspace=workspace, user=target_user, role=role
        )

        serializer = WorkspaceMemberSerializer(member)
        return Response(
            {
                "status": 201,
                "message": "Successfully joined the workspace",
                "member": serializer.data,
            },
            status=201,
        )

    def partial_update(self, request, pk=None):
        """Update member role"""
        user = request.user
        data = request.data

        try:
            member = WorkspaceMemberModel.objects.get(workspace_member_id=pk)
        except WorkspaceMemberModel.DoesNotExist:
            raise AppException("Member not found")

        workspace = member.workspace

        # Only workspace owner can update roles
        if workspace.owner != user:
            raise PermissionDeniedError("Only workspace owner can update member roles")

        if "role_id" in data:
            try:
                new_role = RoleModel.objects.get(
                    role_id=data["role_id"], workspace=workspace
                )
                member.role = new_role
                member.save()
            except RoleModel.DoesNotExist:
                raise AppException("Role not found in this workspace")

        serializer = WorkspaceMemberSerializer(member)
        return Response(
            {
                "status": 200,
                "message": "Member role updated successfully",
                "member": serializer.data,
            },
            status=200,
        )

    def destroy(self, request, pk=None):
        """Remove member from workspace"""
        user = request.user

        try:
            member = WorkspaceMemberModel.objects.get(workspace_member_id=pk)
        except WorkspaceMemberModel.DoesNotExist:
            raise AppException("Member not found")

        workspace = member.workspace

        # Only workspace owner can remove members (or member can remove themselves)
        if workspace.owner != user and member.user != user:
            raise PermissionDeniedError(
                "You don't have permission to remove this member"
            )

        member.delete()
        return Response(
            {"status": 200, "message": "Member removed successfully"}, status=200
        )
