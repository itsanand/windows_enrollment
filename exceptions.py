"""Handles exception"""
from typing import Optional


class RequestError(Exception):
    """Request error"""

    def __init__(
        self, detail: Optional[str] = None, msg_id: Optional[str] = None
    ) -> None:
        super().__init__()
        self.detail = detail
        self.msg_id = msg_id


class InvalidEnrollmentDataError(RequestError):
    """Data Validation error for enrollment"""

    subcode: str = "InvalidEnrollmentData"
    hresult: str = "80180019"


class InvalidSecurityError(RequestError):
    """Invalid security header error"""

    subcode: str = "InvalidSecurity"
    hresult: str = "80180007"


