import jwt
import os
from dotenv import load_dotenv
from .custom_exception import *
from datetime import datetime, timedelta, timezone
from django.contrib.auth.hashers import make_password

load_dotenv()


secret_key = os.getenv("SECRET_KEY")
algorithm = os.getenv("ALGORITHM")


def generate_token(token_type, identifier):
    payload = {
        "token_type": token_type,
        "identifier": identifier,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=2),
    }

    token = jwt.encode(payload, secret_key, algorithm)

    return token


def auth_middleware(request):
    auth_headers = request.headers.get("Authorization")

    if not auth_headers:
        raise AuthenticationError("Authentication header is required")

    try:
        token = auth_headers.split(" ")[1]

    except IndexError:
        raise AuthenticationError("Invalid Authorization header format")

    # decoding the token

    try:
        payload = jwt.decode(token, secret_key, algorithm)

    except jwt.ExpiredSignatureError:
        raise AuthenticationError("Token has expired")
    except jwt.InvalidTokenError:
        raise AuthenticationError("Invalid Token has been provided")

    return payload
