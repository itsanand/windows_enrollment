""" Windows enrollment Service """
from typing import Any, Final


class WindowsEnrollmentService:
    """Handles federated enrollment service for windows device"""


    _OID_REFERENCE_NAME: Final[str] = "Basic EFS"

    def get_discovery_xml(self, payload: dict[str, Any], portal_id: str) -> str:
        """Create an xml which contains below urls
        1. Authentication Service Url
        2. Enrollment policy web service url
        3. Enrollment web service url
        In case of Errors(Validation, Xml error)
        """

        raise NotImplementedError()

    def get_policy_service_xml(self, payload: dict[str, Any]) -> str:
        """creates a xml containing identity certificate constraints
        NOTE: Security token validation can be handled here
        You can pass your custom certificate constraints
        """

        raise NotImplementedError()

    async def get_enrollment_service_xml(
        self, payload: dict[str, Any], portal_id: str
    ) -> str:
        """1. Extract device details and security token from request body
        2. creates an provisional xml containing identity certificate along with root
        certificate and DMCLient information to manage devices
        """

        raise NotImplementedError()