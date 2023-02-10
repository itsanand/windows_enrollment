""" Windows enrollment Service """
from typing import Any, Final
from datetime import datetime, timezone, timedelta
from OpenSSL.crypto import Error  # type: ignore
from utils.enrollment_utils import (
    DISCOVERY_XML,
    POLICY_SERVICE_XML,
    ENROLLMENT_SERVICE_XML,
    create_provisional_xml
)
from exceptions import InvalidSecurityError


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

        msg_id: str = payload["s:Envelope"]["s:Header"]["a:MessageID"]
        # NOTE: device_type and application_type can be used to validate enrollment

        device_type: str = payload["s:Envelope"]["s:Body"]["Discover"]["request"][
            "DeviceType"
        ]
        application_version: str = payload["s:Envelope"]["s:Body"]["Discover"][
            "request"
        ]["ApplicationVersion"]

        enrollment_service_url: str = "https://localhost:8000/EnrollmentWebServiceUrl"
        policy_service_url: str = "https://localhost:8000/PolicyWebServiceUrl"
        # enrollment server url will be defined here
        authentication_service_url: str = "https://localhost:8000/AuthenticationServiceUrl"
        return DISCOVERY_XML.format(
            msg_id,
            policy_service_url,
            enrollment_service_url,
            authentication_service_url,
        )

    def get_policy_service_xml(self, payload: dict[str, Any]) -> str:
        """creates a xml containing identity certificate constraints
        NOTE: Security token validation can be handled here
        You can pass your custom certificate constraints
        """

        msg_id: str = payload["s:Envelope"]["s:Header"]["a:MessageID"]
        return POLICY_SERVICE_XML.format(msg_id, self._OID_REFERENCE_NAME)

    async def get_enrollment_service_xml(
        self, payload: dict[str, Any], portal_id: str
    ) -> str:
        """1. Extract device details and security token from request body
        2. creates an provisional xml containing identity certificate along with root
        certificate and DMCLient information to manage devices
        """

        try:
            request_security_token: dict[str, Any] = payload["s:Envelope"]["s:Body"][
                "wst:RequestSecurityToken"
            ]
            msg_id: str = payload["s:Envelope"]["s:Header"]["a:MessageID"]

            # device details can be stored in a database
            additional_context: dict[str, str] = {
                detail["@Name"]: detail["ac:Value"]
                for detail in request_security_token["ac:AdditionalContext"][
                    "ac:ContextItem"
                ]
            }
            provisional_xml: str = create_provisional_xml(request_security_token)
            return ENROLLMENT_SERVICE_XML.format(
                msg_id,
                datetime.now(timezone.utc).isoformat(),
                (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
                provisional_xml,
            )
        except Error as error:
            reason: str = "Cannot parse the security header."
            raise InvalidSecurityError(msg_id, reason) from error
