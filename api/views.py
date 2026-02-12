from django.shortcuts import render
from .models import *
from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.types import OpenApiTypes
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import timedelta
from django.contrib.auth.hashers import make_password
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from .serializers import *
from backend.helper.otp import *
from .redis import *
from .auth_middlewares import *
from backend.helper.custom_exception import AuthenticationError
from backend.helper.token import generate_token
from backend.helper.email import sendOTP, sentLink
from rest_framework.permissions import IsAuthenticated

# Create your views here.


class RegisterUserAPI(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        request=UserSerializer,
        responses={200: {"type": "object"}},
        description="Sign up",
    )
    def post(self, request):
        serializer = UserSerializer(data=request.data)

        if not serializer.is_valid():
            first_error_field = list(serializer.errors.keys())[0]
            first_error_message = serializer.errors[first_error_field][0]
            return Response(
                {"status": 400, "message": str(first_error_message)}, status=400
            )

        data = serializer.validated_data
        data["password"] = make_password(data["password"])
        otp = generate_OTP()

        if not sendOTP(data["email"], data["username"], otp):
            raise AppException("An error occured in sending the otp")

        token = generate_token("signup", data["username"])
        cache = {"data": data, "otp": otp}
        setCache(data["username"], cache)

        return Response(
            {
                "status": 200,
                "token": token,
                "message": "An OTP is sent to your provided contact",
            }
        )


class UserSettingsView(APIView):
    permission_classes = [IsAuthenticated]
    serializers = UserSettingsSerializer

    @extend_schema(
        request=UserSettingsSerializer,
        responses={200: {"type": "object"}},
        description="Update User Info",
    )
    def get(self, request):
        serializer = UserSettingsSerializer(request.user)
        return Response(serializer.data)

    @extend_schema(
        request=UserSettingsSerializer,
        responses={200: UserSettingsSerializer},
        description="User Info update",
    )
    def patch(self, request):
        user = request.user
        data = request.data.copy()

        if "email" in data:
            new_email = data.pop("email")

            if UserModel.objects.filter(email=new_email).exists():
                raise AppException("Email is already in use")

            otp = generate_OTP()

            if not sendOTP(new_email, user.username, otp):
                raise AppException("An error occured in sending the otp")
            token = generate_token("update_email", user.username)
            cache = {"data": {"email": new_email}, "otp": otp}

            setCache(user.username, cache)

            return Response(
                {
                    "status": 200,
                    "message": "OTP sent to the new email. Verify to update.",
                    "verification_token": token,
                }
            )

        serializer = UserSettingsSerializer(user, data=data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {
                "status": 200,
                "message": "Settings updated successfully",
            }
        )


class LoginUserAPI(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        request=LoginSerializer,
        responses={200: {"type": "object"}},
        description="Login with username or email",
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)

        if not serializer.is_valid():
            raise AppException(str(serializer.errors))

        identifier = request.data.get("identifier")
        password = request.data.get("password")

        if not identifier or not password:
            raise AuthenticationError("Identifier and password both are required")

        try:
            user = UserModel.objects.get(username=identifier)
        except UserModel.DoesNotExist:
            try:
                user = UserModel.objects.get(email=identifier)
            except UserModel.DoesNotExist:
                raise AuthenticationError("No User found")

        if not user.check_password(password):
            raise AuthenticationError("Password didn't match")

        refresh = RefreshToken.for_user(user)

        return Response(
            {
                "status": 200,
                "user": {
                    "id": user.user_id,
                    "username": user.username,
                    "email": user.email,
                },
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "message": "Login successfull",
            },
            status=200,
        )


class ResendOTPAPI(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="X-OTP-Token",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.HEADER,
                required=True,
                description="Custom OTP verification token",
            )
        ],
        responses={200: {"type": "object"}},
        description="Resend OTP with verification token",
    )
    def post(self, request):
        token_data = auth_middleware(request)

        serializer = ResendOTPSerializer(data={}, token_data=token_data)
        if not serializer.is_valid():
            raise AppException(str(serializer.errors))

        username = token_data["username"]
        cache = getCache(username)
        otp = generate_OTP()
        cache["otp"] = otp
        setCache(username, cache)

        if token_data["token_type"] == "signup":
            email = cache["data"]["email"]
        else:
            email = UserModel.objects.values_list("email", flat=True).get(
                username=username
            )

        if not sendOTP(email, username, otp):
            return Response(
                {
                    "status": 400,
                    "message": "Couldn't send the otp at the given email",
                },
                status=400,
            )

        new_token = generate_token(token_data["token_type"], username)

        return Response(
            {
                "status": 200,
                "token": new_token,
                "message": "OTP resent successfully",
            },
            status=200,
        )


class MagicLoginAPI(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="X-Verification-Token",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.HEADER,
                required=True,
                description="Magic login verification token",
            )
        ],
        responses={200: {"type": "object"}},
        description="Magic login with verification token",
    )
    def post(self, request):
        token_data = auth_middleware(request)

        serializer = MagicLoginTokenSerializer(data={}, token_data=token_data)
        if not serializer.is_valid():
            raise AppException(str(serializer.errors))

        try:
            user = UserModel.objects.get(username=token_data["username"])
        except UserModel.DoesNotExist:
            return Response(
                {"status": 400, "message": "No user Found with that username"}
            )

        refresh = RefreshToken.for_user(user)

        return Response(
            {
                "status": 200,
                "message": "SuccessFull magic login",
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "user": {
                    "id": user.user_id,
                    "username": user.username,
                    "email": user.email,
                },
            }
        )


class ForgotPasswordAPI(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        request=ForgotPasswordSerializer,
        responses={200: {"type": "object"}},
        description="Request password reset link",
    )
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if not serializer.is_valid():
            raise AppException(str(serializer.errors))

        email = serializer.validated_data["email"]

        try:
            user = UserModel.objects.get(email=email)
        except UserModel.DoesNotExist:
            raise AppException("No Such User Found")

        token = generate_token("magic_login", user.username)

        if not sentLink(email, user.username, token):
            return Response(
                {"status": 400, "message": "Couldn't send the link"}, status=400
            )

        return Response(
            {"status": 200, "message": "Password reset link sent to your email"},
            status=200,
        )


class ResetPasswordAPI(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []  # Custom authentication

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="X-Verification-Token",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.HEADER,
                required=True,
                description="Password reset verification token",
            )
        ],
        request=ResetPasswordSerializer,
        responses={200: {"type": "object"}},
        description="Reset password with verification token",
    )
    def post(self, request):
        token_data = auth_middleware(request)

        serializer = ResetPasswordSerializer(data=request.data)
        if not serializer.is_valid():
            raise AppException(str(serializer.errors))

        password = serializer.validated_data["password"]

        try:
            user = UserModel.objects.get(username=token_data["username"])
        except UserModel.DoesNotExist:
            return Response({"status": 400, "message": "No user Found"})

        user.password = make_password(password)
        user.save()

        refresh = RefreshToken.for_user(user)

        return Response(
            {
                "status": 200,
                "message": "Password reset Successfull",
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user": {
                    "id": user.user_id,
                    "username": user.username,
                    "email": user.email,
                },
            }
        )


class VerifyOTPAPI(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="X-Verification-Token",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.HEADER,
                required=True,
                description="Custom OTP verification token",
            )
        ],
        request=VerifyOTPSerializer,
        responses={200: {"type": "object"}},
        description="Verify OTP with token",
    )
    def post(self, request):
        token_data = auth_middleware(request)

        serializer = VerifyOTPSerializer(data=request.data, token=token_data)
        serializer.is_valid(raise_exception=True)

        cache = serializer.validated_data["cache"]
        token_type = token_data["token_type"]

        if token_type == "update_email":
            user = UserModel.objects.get(username=token_data["username"])
            user.email = cache["data"]["email"]
            user.save()

            return Response(
                {"status": 200, "message": "Email updated successfully"},
                status=200,
            )

        elif token_type == "signup":

            user, _ = create_user_with_default_workspace(cache["data"])
            refresh = RefreshToken.for_user(user)

            return Response(
                {
                    "status": 200,
                    "message": "Verification successful",
                    "user": {
                        "id": user.user_id,
                        "username": user.username,
                        "email": user.email,
                    },
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                },
                status=200,
            )

        raise AppException("Invalid Token Type")
