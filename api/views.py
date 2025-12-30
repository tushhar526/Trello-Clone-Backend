from django.shortcuts import render
from .models import *
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import timedelta
from django.contrib.auth.hashers import make_password, check_password
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from .serializers import *
from .helpers import *
from .redis import *
from .auth_middlewares import *
from .custom_exception import *
import uuid

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

            token = generate_token("signup", data, otp)

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
            print(request.data)
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
                    try:
                        user = UserModel.objects.get(phonenumber=identifier)
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


class ForgotPasswordAPI(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
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

            login_token = RefreshToken.for_user(user)
            data = {"user_id": user.user_id, "username": user.username}
            reset_token = generate_token("password_reset", data)

            reset_link = reset_token
            login_link = login_token
            if not sentLink(email, user.username, reset_link, login_link, reset_link):
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

            if check_password(token["otp"], otp):
                return Response(
                    {"status": 400, "message": "Entered Invalid OTP"}, status=400
                )

            if token["token_type"] == "update_email":
                user = UserModel.objects.get(user_id=token["data"]["user_id"])

                user.email = token["data"]["email"]

                base_response = {"status": 200, "message": "Verification successful"}

            if token["token_type"] == "signup":
                user = UserModel.create(
                    {
                        "username": token["data"]["username"],
                        "password": token["data"]["password"],
                        "email": token["data"]["email"],
                    }
                )
                token = RefreshToken.for_user(user)
                response = {
                    **base_response,
                    "user": {
                        "user_id": user.user_id,
                        "username": user.username,
                    },
                    "token": {"access": str(token.access_token), "refresh": str(token)},
                }

            user.save()

            return Response(response, status=200)

        except AuthenticationError as e:
            return Response({"status": 401, "message": str(e)}, status=401)

        except Exception as e:
            return Response(
                {"status": 500, "message": "An Error occured while verifying your OTP"},
                status=500,
            )
