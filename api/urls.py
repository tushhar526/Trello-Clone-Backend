from django.contrib import admin
from django.urls import path, include
from .views import *

urlpatterns = [
    path("register/", RegisterUserAPI.as_view(), name="register_new_user"),
    # path('getUser/', getUser),
    # path('createUser/',createUser),
]
