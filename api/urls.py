from django.contrib import admin
from django.urls import path, include
from .views import *

urlpatterns = [
    path("auth/register/", RegisterUserAPI.as_view(), name="register_new_user"),
    path("auth/login/", LoginUserAPI.as_view(), name="login_user"),
    path("auth/verify_otp/", VerifyOTPAPI.as_view(), name="login_user"),
    path("auth/resend_otp/", ResendOTPAPI.as_view(), name="login_user"),
]
