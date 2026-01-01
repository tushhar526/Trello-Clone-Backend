from django.db import models

# Create your models here.


class WorkspaceModel(models.Model):
    workspace_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50, blank=False, null=False, unique=True)
    owner = models.ForeignKey(
        "api.UserModel", on_delete=models.CASCADE, related_name="owned_workspace"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class RoleModel(models.Model):
    role_id = models.AutoField(primary_key=True)
    workspace = models.ForeignKey(
        WorkspaceModel, on_delete=models.CASCADE, related_name="roles"
    )
    role_name = models.CharField(max_length=50)
    permissions = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("workspace", "role_name")

    def __str__(self):
        return self.role_name


class WorkspaceMemberModel(models.Model):
    workspace_member_id = models.AutoField(primary_key=True)
    workspace = models.ForeignKey(
        WorkspaceModel, on_delete=models.CASCADE, related_name="members"
    )
    user = models.ForeignKey(
        "api.UserModel", on_delete=models.CASCADE, related_name="workspace_member"
    )
    role = models.ForeignKey(RoleModel, on_delete=models.SET_NULL, null=True)
    joined_at = models.DateTimeField(auto_now_add=True)
