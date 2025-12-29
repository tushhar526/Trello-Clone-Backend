from rest_framework import serializers
from .models import *
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
    identifier = serializers.CharField(write_only=True)

    class Meta:
        model = UserModel
        fields = ["user_id", "username", "identifier", "password"]
        extra_kwargs = {
            "username": {
                "required": True,
                "error_message": {"required": "Username is required"},
            }
        }

    def validate_username(self, data):
        username = data["username"]

        if UserModel.objects.filter(username=username).exists():
            raise serializers.ValidationError("User name is already registered")

    def validate_identifier(self, value):
        value.strip()
        if not value:
            raise serializers.ValidationError("Email or Number is required")

        value.strip()
        if not value:
            raise serializers.ValidationError("Email or Number is required")

        if "@" in value:
            if "@gmail.com" not in value:
                raise serializers.ValidationError("Email is not Valid")
            if UserModel.objects.filter(email=value).exists():
                raise serializers.ValidationError("Email Already registered")
        else:
            digits = re.sub("r'^\d{10}$", value)
            if not digits:
                raise serializers.ValidationError("Invalid Phone Number")
            if UserModel.objects.filter(email=value).exists():
                raise serializers.ValidationError("Phone Number is already Registered")


class VerificationUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = VerificationUserModel
        fields = [
            "username",
            "email",
            "phonenumber",
            "password",
            "otp",
            "expires_at",
            "resent_count",
            "last_resent_at",
        ]
        read_only_fields = ["otp"]
        extra_kwargs = {"password": {"write_only": True}}

    def validate(self, data):
        if not data.get("email") and not data.get("phonenumber"):
            raise serializers.ValidationError(
                "Either email or phone number is required"
            )
        return data
