import jwt
import os
import json
from dotenv import load_dotenv
from backend.helper.custom_exception import *
from datetime import datetime, timedelta, timezone
from django.contrib.auth.hashers import make_password

load_dotenv()


secret_key = os.getenv("SECRET_KEY")
algorithm = os.getenv("ALGORITHM")


def generate_token(token_type, username):
    payload = {
        "token_type": token_type,
        "username": username,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }

    token = jwt.encode(payload, secret_key, algorithm)
    return token


def auth_middleware(request):
    data = json.loads(request.body)
    token = data.get("token")

    if not token:
        raise AuthenticationError("Invalid Authorization header format")

    # decoding the token

    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])

    except jwt.ExpiredSignatureError:
        raise AuthenticationError("Token has expired")
    except jwt.InvalidTokenError as e:
        print("Token error = ", str(e))
        raise AuthenticationError("Invalid Token has been provided")

    return payload
