from django.shortcuts import render
from .models import *
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import timedelta
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from .serializers import *
from .helpers import *

# Create your views here.


class RegisterUserAPI(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            serializer = UserSerializer(data=request.data)

            if not serializer.is_valid():
                return Response(
                    {"status": 400, "message": serializer.errors}, status=400
                )

            data = serializer.validated_data
            identifier = data["identifier"].strip()

            email = None
            phonenumber = None
            verification_method = None
            otp = generate_OTP()

            if "@" in identifier:
                email = identifier
                verification_method = "email"
            else:
                phonenumber = identifier
                verification_method = "phonenumber"
                otp = "1111"

            Verification_user = VerificationUserModel.objects.create(
                username=data["username"],
                email=email,
                phonenumber=phonenumber,
                password=make_password(data["password"]),
                otp=otp,
                verification_purpose="signup",
                expires_at=timezone.now() + timedelta(minutes=2),
            )

            if verification_method == "email":
                if not sendOTP(email, data["username"], otp):
                    Verification_user.delete()
                    return Response(
                        {"status": 500, "message": "Couldn't send the email"},
                        status=500,
                    )
            else:
                """SENDING OTP THROUGH SMS"""

            return Response(
                {
                    "status": 200,
                    "user_id": Verification_user.id,
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
            user_id = request.data.get("user_id")

            if not user_id:
                return Response(
                    {"status": 400, "message": "User ID is required"},
                    status=400,
                )

            try:
                verification = VerificationUserModel.objects.get(id=user_id)
            except VerificationUserModel.DoesNotExist:
                return Response(
                    {"status": 403, "message": "Invalid verification record"},
                    status=403,
                )

            # Check if last OTP was sent less than 30 seconds ago (anti-spam)
            if (
                verification.otp_sent_at
                and (timezone.now() - verification.otp_sent_at).seconds < 30
            ):
                return Response(
                    {
                        "status": 429,
                        "message": "Please wait before requesting another OTP",
                    },
                    status=429,
                )

            # Generate new OTP
            new_otp = verification.resend_OTP if verification.email else "1111"
            verification.expires_at = timezone.now() + timedelta(minutes=5)
            verification.last_resent_at = timezone.now()
            verification.save()

            # Send OTP
            if verification.email:
                if not sendOTP(verification.email, verification.username, new_otp):
                    return Response(
                        {"status": 500, "message": "Failed to send OTP"},
                        status=500,
                    )
            else:
                """RESENDING OTP to phone number"""
                # if not sendSMS(verification.phonenumber, f"Your OTP is: {new_otp}"):
                #     return Response(
                #         {"status": 500, "message": "Failed to send OTP"},
                #         status=500,
                #     )

            return Response(
                {
                    "status": 200,
                    "message": "OTP resent successfully",
                },
                status=200,
            )

        except Exception as e:
            return Response(
                {"status": 500, "message": "Error resending OTP"}, status=500
            )


class ForgotPasswordAPI(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            identifier = request.data['identifier']

            try:
                user = UserModel.objects.get(email=identifier)
                response = {
                    'status':200,}
            except UserModel.DoesNotExist:
                try:
                    user = UserModel.objects.get(phonenumber=identifier)
                except UserModel.DoesNotExist:
                    return Response(
                        {"status": 404, "message": "No User found"},
                        status=404,
                    )
        except Exception as e:
            return Response({'status':500,'message':"An Error Occured"},status=500)


class VerifyOTPAPI(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            id = request.data["id"]
            user_id = request.data["user_id"]
            otp = request.data["otp"]

            if not otp or not id:
                return Response(
                    {"status": 400, "message": "OTP is required for verification"},
                    status=400,
                )

            verification = VerificationUserModel.objects.filter(id=id)

            if not verification:
                return Response({"status": 403, "message": "Invalid or Expired OTP"})

            if verification.otp != otp:
                return Response({"status": 400, "message": "Invalid OTP entered"})

            if verification.verification_purpose == "signup":
                user = UserModel.objects.create(
                    username=verification.username,
                    password=verification.password,
                    email=verification.email,
                    phonenumber=verification.phonenumber,
                )

                if verification.email:
                    user.email_verified = True
                else:
                    user.phonenumber_verified = True

                refresh = RefreshToken.for_user(user)
                response = {
                    "status": 200,
                    "user": {"user_id": user.user_id, "username": user.username},
                    "message": "OTP Verified successfully",
                    "token": {
                        "refresh_token": str(refresh),
                        "access": str(refresh.access_token),
                    },
                }
                
            # else:
                

            user.save()

            return Response(response, status=200)

        except Exception as e:
            return Response(
                {"status": 500, "message": "An Error occured while verifying your OTP"},
                status=500,
            )
