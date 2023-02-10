"""Handles error"""
import json
from http import HTTPStatus
from typing import Optional, Any
from starlette.requests import Request
from starlette.responses import Response
from exceptions import RequestError
from utils.enrollment_utils import ENROLLMENT_ERROR_XML


_BAD_REQUEST: int = 400


class Error:
    """Global error handler"""

    def __init__(self, status: int, detail: Optional[str] = None) -> None:
        self.status = status
        self.detail = detail
        self.reason = HTTPStatus(self.status).phrase

    @property
    def xml_response(self) -> Response:
        """Return the error response"""
        return Response(content=self.detail, status_code=self.status)


async def request_error(_: Request, exc: RequestError) -> Response:
    """return the corresponding response for different exceptions"""

    detail: str = ENROLLMENT_ERROR_XML.format(exc.msg_id, exc.subcode, exc.detail)
    return Error(_BAD_REQUEST, detail).xml_response
