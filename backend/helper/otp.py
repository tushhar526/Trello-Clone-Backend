import pyotp
from workspaces.models import *
from api.models import UserModel
from tasks.models import StageModel
from django.conf import settings


def generate_OTP():
    otp = pyotp.TOTP(pyotp.random_base32(), digits=4, interval=120)
    return otp.now()


def create_user_with_default_workspace(data):
    user = UserModel.objects.create(
        username=data["username"], email=data["email"], password=data["password"]
    )
    user.save()

    workspace = WorkspaceModel.objects.create(
        name=f"{data["username"]}'s Workspace", owner=user
    )

    for role_name, perms in settings.DEFAULT_ROLES.items():
        RoleModel.objects.create(
            workspace=workspace, role_name=role_name, permissions={role_name: perms}
        )

    for stage in settings.DEFAULT_STAGES:
        StageModel.objects.create(
            workspace=workspace, name=stage["name"], description=stage["description"]
        )

    owner_role = RoleModel.objects.get(workspace=workspace, role_name="owner")
    WorkspaceMemberModel.objects.create(workspace=workspace, user=user, role=owner_role)

    return user, workspace


def isemail(email):
    return "@gmail.com" in email
