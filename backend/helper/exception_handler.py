# helpers/exception_handler.py
from rest_framework.response import Response
from custom_exception import AppException

def custom_exception_handler(exc, context):
    if isinstance(exc, AppException):
        return Response(
            {
                "error": exc.error_code,
                "message": exc.message,
            },
            status=exc.status_code,
        )

    return None
