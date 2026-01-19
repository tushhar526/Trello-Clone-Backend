from rest_framework import serializers
from .models import *
from .auth_middlewares import auth_middleware
from .redis import *
import re


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        min_length=8,
        error_messages={
            "required": "Password is Required",
            "min_length": "Password should be at least 8 character long",
        },
    )

    class Meta:
        model = UserModel
        fields = ["user_id", "username", "email", "password"]
        extra_kwargs = {
            "username": {
                "required": True,
                "error_messages": {"required": "Username is required"},
            }
        }

    def validate_username(self, value):
        if UserModel.objects.filter(username=value).exists():
            raise serializers.ValidationError("User name is already registered")
        return value

    def validate_email(self, value):
        if not value:
            raise serializers.ValidationError("Email or Number is required")

        if not re.search("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value):
            raise serializers.ValidationError("Enter a valid email")

        if UserModel.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email Already registered")

        return value


class LoginSerializer(serializers.Serializer):
    identifier = serializers.CharField(help_text="Username or email")
    password = serializers.CharField(
        write_only=True,
        required=True,
        min_length=8,
        error_messages={
            "required": "Password is Required",
            "min_length": "Password should be at least 8 character long",
        },
    )


class VerifyOTPSerializer(serializers.Serializer):
    otp = serializers.CharField(required=True)

    def validate(self, attrs):
        otp = attrs["otp"]
        token = self.context["token"]

        cache = getCache(token["username"])

        if not cache or "otp" not in cache:
            raise serializers.ValidationError("OTP not found or expired")

        if cache["otp"] != otp:
            raise serializers.ValidationError("Entered Invalid OTP")

        attrs["cache"] = cache
        return attrs
