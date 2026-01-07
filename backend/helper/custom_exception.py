class AppException(Exception):
    """
    Base exception for the entire project.
    All custom exceptions MUST inherit from this.
    """

    default_message = "An application error occurred"
    status_code = 400
    error_code = "app_error"

    def __init__(self, message=None):
        super().__init__(message or self.default_message)
        self.message = message or self.default_message


class AuthenticationError(AppException):
    default_message = "Authentication failed"
    status_code = 401
    error_code = "authentication_error"


class PermissionDeniedError(AppException):
    default_message = "Permission denied"
    status_code = 402
    error_code = "permission_denied"


class WorkspaceError(AppException):
    default_message = "Workspace Error"
    status_code = 402
    error_code = "workspace_error"
