import jwt
import os
from dotenv import load_dotenv
from backend.helper.custom_exception import *
from datetime import datetime, timedelta, timezone
from django.contrib.auth.hashers import make_password

load_dotenv()


secret_key = os.getenv("SECRET_KEY")
algorithm = os.getenv("ALGORITHM")


def auth_middleware(request):
    token = request.headers.get("X-Verification-Token")

    if not token:
        raise AuthenticationError("Missing X-Verification-Token header")

    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
    except jwt.ExpiredSignatureError:
        raise AuthenticationError("Token has expired")
    except jwt.InvalidTokenError as e:
        print("Token error =", str(e))
        raise AuthenticationError("Invalid token provided")

    return payload
