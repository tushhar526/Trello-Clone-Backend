from rest_framework.routers import DefaultRouter
from django.urls import path, include
from .views import TasksAPI, StageAPI

router = DefaultRouter()
router.register(r"tasks", TasksAPI, basename="tasks")
router.register(r"stage", StageAPI, basename="stage")

urlpatterns = [
    path("", include(router.urls)),
]
