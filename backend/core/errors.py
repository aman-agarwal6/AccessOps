from rest_framework.exceptions import APIException
from rest_framework.views import exception_handler as drf_exception_handler


class DomainError(APIException):
    status_code = 400
    default_code = "invalid_request"

    def __init__(self, code, message, status=400):
        self.status_code = status
        self.code = code
        self.message = message
        super().__init__(message, code=code)


def exception_handler(exc, context):
    response = drf_exception_handler(exc, context)
    if response is not None:
        code = getattr(exc, "code", getattr(exc, "default_code", "invalid_request"))
        message = getattr(
            exc,
            "message",
            "The request was rejected. Check authentication, permissions, and input.",
        )
        response.data = {"error": {"code": str(code), "message": str(message)}}
    return response
