from django.contrib import admin
from django.urls import path, include
from .views import *

urlpatterns = [
    path("list/", WorkspaceAPI.as_view(), name="workspace_related_URL"),
]
