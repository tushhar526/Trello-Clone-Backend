from ...workspaces.models import WorkspaceMemberModel


def has_permission(user, workspace, permission):
    try:
        member = WorkspaceMemberModel.objects.get(user=user, workspace=workspace)
        role_permissions = member.role.permissions.get(member.role.role_name, [])
        return permission in role_permissions or "full_access" in role_permissions
    except WorkspaceMemberModel.DoesNotExist:
        return False


def get_user_role_in_workspace(user, workspace):
    try:
        member = WorkspaceMemberModel.objects.get(user=user, workspace=workspace)
        return member.role.role_name
    except WorkspaceMemberModel.DoesNotExist:
        return None
