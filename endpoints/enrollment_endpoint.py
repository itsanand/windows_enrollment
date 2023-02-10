"""Handling endpoints related to enrollment"""
from typing import Any, Final
import xmltodict
from starlette.requests import Request
from starlette.responses import Response
from services.enrollment_service import WindowsEnrollmentService
from exceptions import InvalidEnrollmentDataError
from utils.enrollment_utils import AUTHENTICATION_SERVICE_XML


class WindowsEnrollment:
    """Class to handle windows federated authenticated device enrollment
    For InvalidEnrollmentDataError using default msg_id in error xml 
    as server failed to decode payload body
    """

    _DEFAULT_MSG_ID: Final[str] = "9876543210"
    _DEFAULT_REASON: Final[str] = "Data provided bywindows enrollment server is is not valid"
    _WINDOWS_MEDIA_TYPE: Final[str] = ""

    _SVC: WindowsEnrollmentService = WindowsEnrollmentService()

    async def handle_discovery_service(self, request: Request) -> Response:
        """MDM server url is given in 'Enroll in Device Management` option at the Device End.
        This will be considered as the url for discovery service. Device will ping
        this url to get details of the urls needed for the consequent steps of
        enrollment.
        Response will contain below urls
        1. Authentication Service Url
        2. Enrollment policy web service url
        3. Enrollment web service url
        In case of Errors(Validation, Xml error)
        1.Response contains error xml
        """

        try:
            body: bytes = await request.body()
            payload: dict[str, Any] = xmltodict.parse(str(body, "utf-8"))
            discovery_xml: str = self._SVC.get_discovery_xml(payload)
        except (xmltodict.expat.ExpatError, KeyError) as error:
            raise InvalidEnrollmentDataError(
                self._DEFAULT_MSG_ID,self._DEFAULT_REASON
            ) from error
        else:
            return Response(discovery_xml, media_type=self._WINDOWS_MEDIA_TYPE)

    async def handle_authentication_service(self, request: Request) -> Response:
        """Device will ping this url to validate user details and get special
        token which will be used for further validation
        """
        
        app_uri: str = request.query_params["appru"]
        auth_service: str = AUTHENTICATION_SERVICE_XML.format(app_uri)
        return Response(auth_service, media_type="text/html; charset=UTF-8")        

    async def handle_policy_web_service(self, request: Request) -> Response:
        """Device will ping this url to get details about
        certificate constraints that are to be set
        NOTE: Policy service is optional. By default, if no policies
            are specified, the minimum key length is 2k and the hash algorithm is SHA-1
        """

        try:
            body: bytes = await request.body()
            payload: dict[str, Any] = xmltodict.parse(str(body, "utf-8"))
            policy_service_xml: str = self._SVC.get_policy_service_xml(payload)
        except (xmltodict.expat.ExpatError, KeyError) as error:
            raise InvalidEnrollmentDataError(
                self._DEFAULT_MSG_ID,self._DEFAULT_REASON
            ) from error
        else:
            return Response(policy_service_xml, media_type=self._WINDOWS_MEDIA_TYPE)

    async def handle_enrollment_web_service(self, request: Request) -> Response:
        """This web service implements the MS-WSTEP protocol
        1.Device will ping this url to get the identity certificate,private key
            along with the DMClient session details.
        2.Identity certificate is generated using crypto library and
          root certificate(a certificate issued by a trusted certificate authority (CA))
        """

        try:
            body: bytes = await request.body()
            payload: dict[str, Any] = xmltodict.parse(str(body, "utf-8"))
            enrollment_service_xml: str = await self._SVC.get_enrollment_service_xml(
                payload
            )
        except (xmltodict.expat.ExpatError, KeyError) as error:
            raise InvalidEnrollmentDataError(
                self._DEFAULT_MSG_ID,self._DEFAULT_REASON
            ) from error
        else:
            return Response(enrollment_service_xml, media_type=self._WINDOWS_MEDIA_TYPE)
