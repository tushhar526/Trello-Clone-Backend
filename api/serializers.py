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


class UserSettingsSerializer(serializers.ModelSerializer):
    current_password = serializers.CharField(write_only=True, required=False)
    password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = UserModel
        fields = ["username", "email", "password", "current_password"]

    def validate_username(self, value):
        user = self.instance
        if value != user.username and UserModel.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username is already taken.")
        return value

    def validate(self, data):
        if "password" in data:
            current_password = data.get("current_password")
            if not current_password:
                raise serializers.ValidationError(
                    {"current_password": "Current password is required to change password."}
                )
            if not self.instance.check_password(current_password):
                raise serializers.ValidationError({"current_password": "Current password is incorrect."})
        return data

    def update(self, instance, validated_data):
        # Username
        if "username" in validated_data:
            instance.username = validated_data["username"]

        # Password
        if "password" in validated_data:
            instance.set_password(validated_data["password"])

        instance.save()
        return instance


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

    def __init__(self, *args, token=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.token_data = token

    def validate(self, attrs):
        otp = attrs["otp"]

        if not self.token_data:
            raise serializers.ValidationError("OTP token missing")

        cache = getCache(self.token_data["username"])

        if not cache or "otp" not in cache:
            raise serializers.ValidationError("OTP not found or expired")

        if cache["otp"] != otp:
            raise serializers.ValidationError("Entered Invalid OTP")

        attrs["cache"] = cache
        return attrs


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(
        required=True,
        error_messages={
            "required": "Email is required",
            "invalid": "Enter a valid email address"
        }
    )
    
    def validate_email(self, value):
        # Optional: Check if email exists in your system
        # You can remove this if you want to avoid email enumeration
        from .models import UserModel
        if not UserModel.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user found with this email")
        return value


class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        min_length=8,
        error_messages={
            "required": "Password is required",
            "min_length": "Password must be at least 8 characters long"
        }
    )
    confirm_password = serializers.CharField(
        write_only=True,
        required=True,
        min_length=8,
        error_messages={
            "required": "Confirm password is required",
            "min_length": "Password must be at least 8 characters long"
        }
    )
    
    def validate(self, attrs):
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')
        
        if password != confirm_password:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match"})
        
        # Add additional password strength validation if needed
        # if not re.search(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password):
        #     raise serializers.ValidationError({
        #         "password": "Password must contain at least one uppercase letter, one lowercase letter, one number and one special character"
        #     })
        
        return attrs


class MagicLoginTokenSerializer(serializers.Serializer):
    def __init__(self, *args, **kwargs):
        self.token_data = kwargs.pop('token_data', None)
        super().__init__(*args, **kwargs)
    
    def validate(self, attrs):
        if not self.token_data:
            raise serializers.ValidationError("Token is required")
        
        if self.token_data.get('token_type') != 'magic_login':
            raise serializers.ValidationError("Invalid token type")
        
        # Check if token is expired
        # Add your token expiration logic here if needed
        
        return attrs


class ResendOTPSerializer(serializers.Serializer):
    def __init__(self, *args, **kwargs):
        self.token_data = kwargs.pop('token_data', None)
        super().__init__(*args, **kwargs)
    
    def validate(self, attrs):
        if not self.token_data:
            raise serializers.ValidationError("Token is required")
        
        # Validate token type
        valid_token_types = ['signup', 'update_email', 'magic_login']
        if self.token_data.get('token_type') not in valid_token_types:
            raise serializers.ValidationError(f"Invalid token type. Must be one of: {', '.join(valid_token_types)}")
        
        return attrs