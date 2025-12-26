from django.shortcuts import render
from .models import UserModel
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from .serializers import *

# Create your views here.


class RegisterUserAPI(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            serializer = UserSerializer(data=request.data)

            if not serializer.is_valid():
                return Response(
                    {
                        "status": 403,
                        "error": serializer.errors,
                        "message": "Error Occured while registering the user",
                    }
                )

            serializer.save()
            user = UserModel.objects.get(username=serializer.data["username"])
            refresh = RefreshToken.for_user(user)

            return Response(
                {
                    "status": 201,
                    "user": {"user_id": user.user_id, "username": user.username},
                    "tokens": {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                    },
                    "message": "Successfully Registered the user",
                }
            )
        except Exception as e:
            error_msg = str(e).lower()
            if "unique" in error_msg or "duplicate" in error_msg:
                return Response(
                    {"status": 409, "message": "Username or email already exists"},
                )

            return Response(
                {
                    "status": 500,
                    "message": "Something went Wrong",
                },
            )


class LoginUserAPI(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            username = request.data.get("username")
            password = request.data.get("password")

            if not username or not password:
                return Response(
                    {"status": 400, "message": "username and password are required"}
                )

            userobj = UserModel.objects.get(username=serializer.data["username"])

            if not userobj.exists():
                return Response({"status": 404, "message": "No such User found"})

            user = UserModel.objects.get(username=serializer.data["username"])
            refresh = RefreshToken(user)

            return Response(
                {
                    "status": 200,
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                }
            )

        except Exception as e:
            return Response({"status": 500, "message": "something went wrong"})
