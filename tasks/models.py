from django.db import models

# Create your models here.


class StatusModel(models.Model):
    status_id = models.AutoField(primary_key=True)
    workspace = models.ForeignKey(
        "workspaces.WorkspaceModel", on_delete=models.CASCADE, related_name="statuses"
    )
    name = models.CharField(max_length=50, blank=False, null=False)
    color = models.CharField(max_length=7, default="#3b82f6")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("workspace", "name")

    def __str__(self):
        return f"{self.name} in {self.workspace.name}"


class TaskModel(models.Model):
    task_id = models.AutoField(primary_key=True)
    workspace = models.ForeignKey(
        "workspaces.WorkspaceModel", on_delete=models.CASCADE, related_name="tasks"
    )
    title = models.CharField(max_length=200, blank=False, null=False)
    description = models.TextField(blank=True, null=True)
    status = models.ForeignKey(
        StatusModel, on_delete=models.SET_NULL, null=True, related_name="tasks"
    )
    assigned_to = models.ManyToManyField(
        "workspaces.WorkspaceMemberModel",
        blank=True,
        related_name="assigned_tasks",
    )
    created_by = models.ForeignKey(
        "api.UserModel", on_delete=models.CASCADE, related_name="created_tasks"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} in {self.workspace.name}"
