from datetime import datetime, timezone, timedelta
import json
import jwt
import os
from django.conf import settings
from backend.helper.custom_exception import AuthenticationError

secret_key = os.getenv("SECRET_KEY")
algorithm = os.getenv("ALGORITHM")

def generate_invite_token(email, workspace_id, role_id):
    """Generate invitation token"""
    payload = {
        "token_type": "workspace_invite",
        "email": email,
        "workspace_id": workspace_id,
        "role_id": role_id,
        "exp": datetime.now(timezone.utc) + timedelta(hours=24),
    }
    token = jwt.encode(payload, secret_key, algorithm=algorithm)
    return token

def verify_invite_token(token):
    """Verify invitation token"""
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        if payload.get("token_type") != "workspace_invite":
            raise AuthenticationError("Invalid token type")
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthenticationError("Invitation link has expired")
    except jwt.InvalidTokenError:
        raise AuthenticationError("Invalid invitation token")