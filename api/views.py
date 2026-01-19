from django.shortcuts import render
from .models import *
from drf_spectacular.utils import extend_schema, OpenApiParameter
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
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


# Create your views here.


class RegisterUserAPI(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        request=UserSerializer,
        responses={200: {"type": "object"}},
        description="Sign up",
    )
    def post(self, request):
        try:
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
                return Response(
                    {"status": 400, "message": "an error occured in sending you otp"},
                    status=400,
                )

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
        except AppException:
            raise
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            raise AppException("Something went wrong")


class LoginUserAPI(GenericAPIView):
    permission_classes = [AllowAny]

    @extend_schema(
        request=LoginSerializer,
        responses={200: {"type": "object"}},
        description="Login with username or email",
    )
    def post(self, request):
        try:
            serializer = LoginSerializer(data=request.data)

            if not serializer.is_valid():
                raise AppException(str(serializer.errors))

            identifier = request.data.get("identifier")
            password = request.data.get("password")

            if not identifier or not password:
                return Response(
                    {
                        "status": 400,
                        "message": "Identifier and password both are required",
                    },
                    status=400,
                )

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
        except AppException as e:
            print(f"Unexpected error: {str(e)}")
            raise
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            raise AppException("Something went wrong")


class ResendOTPAPI(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            token = auth_middleware(request)

            username = token["username"]
            cache = getCache(username)
            otp = generate_OTP()
            cache["otp"] = otp
            setCache(username, cache)

            if token["token_type"] == "signup":
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

            new_token = generate_token(token["token_type"], username)

            return Response({"status": 200, token: new_token}, status=200)

        except AuthenticationError as e:
            raise AuthenticationError(message=str(e))
        except AppException:
            raise
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            raise AppException("Something went wrong")


class MagicLoginAPI(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            token = auth_middleware(request)

            if not token["token_type"] == "magic_login":
                return Response(
                    {"status": 400, "message": "Invalid Token Type"}, status=400
                )

            try:
                user = UserModel.objects.get(username=token["username"])
            except UserModel.DoesNotExist:
                return Response(
                    {"status": 400, "message": "No user Found with that username"}
                )

            token = RefreshToken.for_user(user)

            return Response(
                {
                    "status": 200,
                    "message": "SuccessFull magic login",
                    "access": str(token.access_token),
                    "refresh": str(token),
                }
            )
        except AuthenticationError as e:
            raise AuthenticationError(message=str(e))
        except AppException:
            raise
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            raise AppException("Something went wrong")


class ForgotPasswordAPI(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            email = request.data.get("email")

            if not email:
                return Response(
                    {"status": 400, "message": "Email is required"}, status=400
                )

            try:
                user = UserModel.objects.get(email=email)
            except UserModel.DoesNotExist:
                return Response(
                    {"status": 400, "message": "No user Found with that email"}
                )

            token = generate_token("magic_login", user.username)

            if not sentLink(email, user.username, token):
                return Response(
                    {"status": 400, "message": "Couldn't send the link"}, status=400
                )

            return Response(
                {"status": 200, "message": "Link sent to provided Email"}, status=200
            )
        except AppException:
            raise
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            raise AppException("Something went wrong")


class ResetPasswordAPI(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            token = auth_middleware(request)
            password = request.data.get("password")

            if not password:
                return Response(
                    {"status": 400, "message": "Password is Required"}, status=400
                )

            try:
                user = UserModel.objects.get(username=token["username"])
            except UserModel.DoesNotExist:
                return Response({"status": 400, "message": "No user Found"})

            user.password = make_password(password)
            user.save()

            token = RefreshToken.for_user(user)

            return Response(
                {
                    "status": 200,
                    "message": "Password reset Successfull",
                    "refresh": str(token),
                    "access": str(token.access_token),
                    "user": {"id": user.user_id, "username": user.username},
                }
            )

        except AuthenticationError as e:
            raise AuthenticationError(message=str(e))
        except AppException:
            raise
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            raise AppException("Something went wrong")


class VerifyOTPAPI(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="X-OTP-Token",
                type=str,
                location=OpenApiParameter.HEADER,
                required=True,
                description="Custom OTP verification token",
            )
        ],
        request=VerifyOTPSerializer,
        responses={200: {"type": "object"}},
    )
    def post(self, request):

        token = request.headers.get("X-OTP-Token")
        if not token:
            raise AuthenticationError("OTP token missing")

        token_data = auth_middleware(token)

        serializer = VerifyOTPSerializer(
            data=request.data,
            context={"token": token_data},
        )
        serializer.is_valid(raise_exception=True)

        token = serializer.validated_data["token"]
        cache = serializer.validated_data["cache"]
        token_type = token["token_type"]

        if token_type == "update_email":
            user = UserModel.objects.get(username=token["username"])
            user.email = cache["data"]["email"]
            user.save()

            return Response(
                {"status": 200, "message": "Verification successful"},
                status=200,
            )

        elif token_type in ("signup", "invite"):

            if token_type == "invite":
                pass  # invite logic later

            user, _ = create_user_with_default_workspace(cache["data"])

            refresh = RefreshToken.for_user(user)

            return Response(
                {
                    "status": 200,
                    "message": "Verification successful",
                    "user": {
                        "id": user.user_id,
                        "username": user.username,
                    },
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                },
                status=200,
            )

        raise AppException("Invalid Token Type")
