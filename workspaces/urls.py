from rest_framework.routers import DefaultRouter
from django.urls import path, include
from .views import WorkspaceAPI, RoleViewSet, WorkspaceMemberViewSet

# Create a single router for all ViewSets
router = DefaultRouter()
router.register(r"workspace", WorkspaceAPI, basename="workspace")
router.register(r"roles", RoleViewSet, basename="roles")
router.register(r"members", WorkspaceMemberViewSet, basename="members")

urlpatterns = [
    path("", include(router.urls)),
]
