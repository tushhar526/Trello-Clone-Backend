from django.shortcuts import render
from .models import *
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from datetime import timedelta
from django.contrib.auth.hashers import make_password, check_password
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from .serializers import *
from .helpers import *
from .redis import *
from .auth_middlewares import *
from .custom_exception import *

# Create your views here.


class RegisterUserAPI(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            serializer = UserSerializer(data=request.data)

            if not serializer.is_valid():
                print("ERROR = ", serializer.error_messages)
                return Response(
                    {"status": 400, "message": serializer.errors}, status=400
                )

            data = serializer.validated_data
            data["password"] = make_password(data["password"])
            otp = generate_OTP()

            if not sendOTP(data["email"], data["username"], otp):
                return Response(
                    {"status": 400, "message": "an error occured in sending you otp"},
                    status=400,
                )

            token = generate_token("signup", data["email"])
            cache = {"data": data, "otp": otp}
            setCache(data["email"], cache)

            return Response(
                {
                    "status": 200,
                    "token": token,
                    "message": "An OTP is sent to your provided contact",
                }
            )
        except Exception as e:
            return Response(
                {"status": 500, "message": "Internal server error"}, status=500
            )


class LoginUserAPI(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
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
                    return Response(
                        {"status": 404, "message": "No User found"},
                        status=404,
                    )

            if not user.check_password(password):
                return Response(
                    {"status": 401, "message": "Password didn't match"},
                    status=401,
                )

            refresh = RefreshToken.for_user(user)

            return Response(
                {
                    "status": 200,
                    "user": {"id": user.user_id, "username": user.username},
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                    "message": "Login successfull",
                },
                status=200,
            )

        except Exception as e:
            return Response(
                {"status": 500, "message": "something went wrong"}, status=500
            )


class ResendOTPAPI(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            token = auth_middleware(request)

            email = token["data"]["email"]
            otp = generate_OTP()

            if not sendOTP(email, token["data"]["username"], otp):
                return Response(
                    {
                        "status": 400,
                        "message": "Couldn't send the otp at the given email",
                    },
                    status=400,
                )

            new_token = generate_token(token["token_type"], token["data"], otp)

            return Response({"status": 200, token: new_token}, status=200)

        except AuthenticationError as e:
            return Response({"status": 401, "message": str(e)}, status=401)

        except Exception as e:
            return Response(
                {"status": 500, "message": "Internal Server Error"}, status=500
            )


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
                user = UserModel.objects.get(user_id=token["identifier"])
            except UserModel.DoesNotExist:
                return Response(
                    {"status": 400, "message": "No user Found with that email"}
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
            return Response({"status": 401, "message": str(e)})
        except Exception as e:
            return Response(
                {"status": 500, "message": "Internal Server Error"}, status=500
            )


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

            token = generate_token("magic_login", user.user_id)

            if not sentLink(email, user.username, token):
                return Response(
                    {"status": 400, "message": "Couldn't send the link"}, status=400
                )

            return Response(
                {"status": 200, "message": "Link sent to provided Email"}, status=200
            )
        except Exception as e:
            return Response(
                {"status": 500, "message": "Internal Server error"}, status=500
            )


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
                user = UserModel.objects.get(user_id=token["user_id"])
            except UserModel.DoesNotExist:
                return Response({"status": 400, "message": "No user Found"})

            user.password = make_password(password)

            token = RefreshToken.for_user(user)

            return Response(
                {
                    "status": 200,
                    "message": "Password reset Successfull",
                    "refresh": str(token),
                    "access": str(token.access_token),
                    "user": {"user_id": user.user_id, "username": user.username},
                }
            )

        except AuthenticationError as e:
            print("Error here", str(e))
            return Response({"status": 400, "message": str(e)}, status=400)

        except Exception as e:
            print("Reset password error = ", str(e))
            return Response(
                {"status": 500, "message": "Internal Server error"}, status=500
            )


class VerifyOTPAPI(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            token = auth_middleware(request)
            otp = request.data.get("otp")

            if not otp:
                return Response(
                    {"status": 400, "message": "OTP is required for verification"},
                    status=400,
                )

            cache = getCache(token["identifier"])

            if cache["otp"] != otp:
                return Response(
                    {"status": 400, "message": "Entered Invalid OTP"}, status=400
                )

            if token["token_type"] == "update_email":
                user = UserModel.objects.get(user_id=token["identifier"])

                user.email = cache["data"]["email"]
                user.save()

                response = {"status": 200, "message": "Verification successful"}

            elif token["token_type"] == "signup":
                user = UserModel.objects.create(
                    {
                        "username": cache["data"]["username"],
                        "password": make_password(cache["data"]["password"]),
                        "email": cache["data"]["email"],
                    }
                )
                token = RefreshToken.for_user(user)
                response = {
                    "status": 200,
                    "message": "Verification successful",
                    "user": {
                        "user_id": user.user_id,
                        "username": user.username,
                    },
                    "refresh": str(token),
                    "access": str(token.access_token),
                }
                user.save()

            else:
                return Response({"status": 400, "message": "Invalid Token Type"})

            return Response(response, status=200)

        except AuthenticationError as e:
            return Response({"status": 401, "message": str(e)}, status=401)

        except Exception as e:
            return Response(
                {"status": 500, "message": "An Error occured while verifying your OTP"},
                status=500,
            )
