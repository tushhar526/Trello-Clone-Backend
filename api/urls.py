from django.contrib import admin
from django.urls import path, include
from .views import *

urlpatterns = [
    path("auth/register/", RegisterUserAPI.as_view(), name="register_new_user_URL"),
    path("auth/login/", LoginUserAPI.as_view(), name="login_user_URL"),
    path("auth/verify-otp/", VerifyOTPAPI.as_view(), name="verify_OTP_URL"),
    path(
        "auth/forgot-password/", ForgotPasswordAPI.as_view(), name="forgot_password_URL"
    ),
    path(
        "auth/reset-password/", ResetPasswordAPI.as_view(), name="reset_password_URL"
    ),
    path(
        "auth/magic-login/", MagicLoginAPI.as_view(), name="magic_login_URL"
    ),
    path("auth/resend-otp/", ResendOTPAPI.as_view(), name="resend_OTP_URL"),
]
