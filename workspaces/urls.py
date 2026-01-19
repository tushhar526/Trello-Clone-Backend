# from rest_framework.routers import DefaultRouter
# from django.urls import path, include
# from .views import *

# router = DefaultRouter()
# router.register(r"roles", RoleViewSet, basename="roles")
# router.register(r"members", WorkspaceMemberViewSet, basename="members")

# urlpatterns = [
#     path("list/", WorkspaceAPI.as_view(), name="workspace_related_URL"),
#     path("", include(router.urls)),
#     path(
#         "members/accept-invite/",
#         WorkspaceMemberViewSet.as_view({"post": "accept_invite"}),
#         name="accept-invite",
#     ),
# ]
from rest_framework.routers import DefaultRouter
from django.urls import path, include
from .views import WorkspaceAPI, RoleViewSet, WorkspaceMemberViewSet

router = DefaultRouter()
router.register(r"", WorkspaceAPI, basename="workspace")
router.register(r"roles", RoleViewSet, basename="roles")
router.register(r"members", WorkspaceMemberViewSet, basename="members")

urlpatterns = [
    path("", include(router.urls)),
    path(
        "members/accept-invite/",
        WorkspaceMemberViewSet.as_view({"post": "accept_invite"}),
        name="accept-invite",
    ),
]
