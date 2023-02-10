"""Handles checkin application"""
from typing import Any
from starlette.applications import Starlette
from starlette.routing import Route
from endpoints.enrollment_endpoint import WindowsEnrollment


routes: list[Route] = [
    Route(
        "/EnrollmentServer/Discovery.svc",
        WindowsEnrollment().handle_discovery_service,
        methods=["POST"]
    ),
    Route(
        "/AuthenticationServiceUrl",
        WindowsEnrollment().handle_authentication_service,
        methods=["GET"]
    ),
    Route(
        "/PolicyWebServiceUrl",
        WindowsEnrollment().handle_policy_web_service,
        methods=["GET"]
    ),
    Route(
        "/EnrollmentWebServiceUrl",
        WindowsEnrollment().handle_enrollment_web_service,
        methods=["GET"]
    )
]

app: Starlette = Starlette(routes=routes)
