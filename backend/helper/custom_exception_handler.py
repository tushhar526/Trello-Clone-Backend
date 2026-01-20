from rest_framework.response import Response
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework.exceptions import NotAuthenticated
from .custom_exception import AppException


def custom_exception_handler(exc, context):
    # JWT token errors
    if isinstance(exc, InvalidToken):
        return Response(
            {
                "error": "token_invalid",
                "message": "Access token expired or invalid",
            },
            status=401,
        )

    if isinstance(exc, NotAuthenticated):
        return Response(
            {
                "error": "authentication_error",
                "message": "Authentication credentials were not provided",
            },
            status=401,
        )

    # App-level custom exceptions
    if isinstance(exc, AppException):
        return Response(
            {
                "error": exc.error_code,
                "message": exc.message,
            },
            status=exc.status_code,
        )

    # Let DRF handle everything else (500, validation, etc.)
    return None
    # return custom_exception_handler(exc, context)
