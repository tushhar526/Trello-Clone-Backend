from django.contrib import admin
from django.urls import path, include
from .views import *

urlpatterns = [
    path("register/", RegisterUserAPI.as_view(), name="register_new_user_URL"),
    path("login/", LoginUserAPI.as_view(), name="login_user_URL"),
    path("verify-otp/", VerifyOTPAPI.as_view(), name="verify_OTP_URL"),
    path("forgot-password/", ForgotPasswordAPI.as_view(), name="forgot_password_URL"),
    path("reset-password/", ResetPasswordAPI.as_view(), name="reset_password_URL"),
    path("magic-login/", MagicLoginAPI.as_view(), name="magic_login_URL"),
    path("resend-otp/", ResendOTPAPI.as_view(), name="resend_OTP_URL"),
]
