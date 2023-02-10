"""Handles enrollment related utils"""
import base64
import datetime
import re
import urllib.parse
from typing import Any, Final
from OpenSSL import crypto  # type: ignore

_YEAR_1: Final[int] = 365  # 365 days
_CERTIFICATE_VALIDITY_PERIOD: Final[int] = _YEAR_1 * 10  # 10 years
_MANAGEMENT_SERVER_URl: Final[str] = "MDM management server url"
_ROOT_CA_CERT: Final[str] = "Root CA Certificate"
_ROOT_CA_KEY: Final[str] = "Root CA Public Key"

DISCOVERY_XML: Final[
    str
] = """
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing">
    <s:Header>
        <a:Action s:mustUnderstand="1">
        http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/DiscoverResponse
        </a:Action>
        <ActivityId>
        d9eb2fdd-e38a-46ee-bd93-aea9dc86a3b8
        </ActivityId>
        <a:RelatesTo>{}</a:RelatesTo>
    </s:Header>
    <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema">
        <DiscoverResponse
        xmlns="http://schemas.microsoft.com/windows/management/2012/01/enrollment">
        <DiscoverResult>
            <AuthPolicy>Federated</AuthPolicy>
            <EnrollmentVersion>3.0</EnrollmentVersion>
            <EnrollmentPolicyServiceUrl>{}</EnrollmentPolicyServiceUrl>
            <EnrollmentServiceUrl>{}</EnrollmentServiceUrl>
            <AuthenticationServiceUrl>{}</AuthenticationServiceUrl>
        </DiscoverResult>
        </DiscoverResponse>
    </s:Body>
</s:Envelope>
"""

POLICY_SERVICE_XML: Final[
    str
] = """
<s:Envelope
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse</a:Action>
        <a:RelatesTo>{}</a:RelatesTo>
    </s:Header>
    <s:Body>
        <GetPoliciesResponse
            xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"
            xmlns:xsd="http://www.w3.org/2001/XMLSchema"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <response>
                <policyFriendlyName xsi:nil="true"></policyFriendlyName>
                <nextUpdateHours xsi:nil="true"></nextUpdateHours>
                <policiesNotChanged xsi:nil="true"></policiesNotChanged>
                <policies>
                    <policy>
                        <policyOIDReference>0</policyOIDReference>
                        <cAS xsi:nil="true"></cAS>
                        <attributes>
                            <policySchema>3</policySchema>
                            <privateKeyAttributes>
                                <minimalKeyLength>2048</minimalKeyLength>
                                <keySpec xsi:nil="true"></keySpec>
                                <keyUsageProperty xsi:nil="true"></keyUsageProperty>
                                <permissions xsi:nil="true"></permissions>
                                <algorithmOIDReference xsi:nil="true"></algorithmOIDReference>
                                <cryptoProviders xsi:nil="true"></cryptoProviders>
                            </privateKeyAttributes>
                            <supersededPolicies xsi:nil="true"></supersededPolicies>
                            <privateKeyFlags xsi:nil="true"></privateKeyFlags>
                            <subjectNameFlags xsi:nil="true"></subjectNameFlags>
                            <enrollmentFlags xsi:nil="true"></enrollmentFlags>
                            <generalFlags xsi:nil="true"></generalFlags>
                            <hashAlgorithmOIDReference>0</hashAlgorithmOIDReference>
                            <rARequirements xsi:nil="true"></rARequirements>
                            <keyArchivalAttributes xsi:nil="true"></keyArchivalAttributes>
                            <extensions xsi:nil="true"></extensions>
                        </attributes>
                    </policy>
                </policies>
            </response>
            <cAS xsi:nil="true"></cAS>
            <oIDs>
                <oID>
                    <value>1.3.14.3.2.29</value>
                    <group>1</group>
                    <oIDReferenceID>0</oIDReferenceID>
                    <defaultName>{}</defaultName>
                </oID>
            </oIDs>
        </GetPoliciesResponse>
    </s:Body>
</s:Envelope>
"""

_PROVISIONAL_XML: Final[
    str
] = """
    <wap-provisioningdoc version="1.1">
    <characteristic type="CertificateStore">
        <characteristic type="Root">
            <characteristic type="System">
                <characteristic type="{}">
                    <parm name="EncodedCertificate" value="{}"/>
                </characteristic>
            </characteristic>
        </characteristic>
        <characteristic type="My">
            <characteristic type="User">
                <characteristic type="{}">
                    <parm name="EncodedCertificate" value="{}"/>
                    <characteristic type="PrivateKeyContainer"/></characteristic>
            </characteristic>
        </characteristic>
    </characteristic>
    <characteristic type="APPLICATION">
        <parm name="APPID" value="w7"/>
        <parm name="PROVIDER-ID" value="TestMDM"/>
        <parm name="NAME" value="Test"/>
        <parm name="ADDR" value="{}"/>
        <parm name="CRLCheck" value="0"/>
        <parm name="CONNRETRYFREQ" value="6"/>
        <parm name="INIT"/>
        <parm name="USEHWDEVID"/>
        <parm name="BACKCOMPATRETRYDISABLED"/>
        <parm name="DEFAULTENCODING" value="application/vnd.syncml.dm+xml"/>
        <parm name="SSLCLIENTCERTSEARCHCRITERIA" value="Subject={}"/>
        <characteristic type="APPAUTH">
            <parm name="AAUTHLEVEL" value="CLIENT"/>
            <parm name="AAUTHTYPE" value="DIGEST"/>
            <parm name="AAUTHSECRET" value="dummy"/>
            <parm name="AAUTHDATA" value="dummy"/>
        </characteristic>
        <characteristic type="APPAUTH">
            <parm name="AAUTHLEVEL" value="APPSRV"/>
            <parm name="AAUTHTYPE" value="DIGEST"/>
            <parm name="AAUTHNAME" value="DM Client"/>
            <parm name="AAUTHSECRET" value="dummy"/>
            <parm name="AAUTHDATA" value="dummy"/>
        </characteristic>
    </characteristic>
    <characteristic type="DMClient">
        <characteristic type="Provider">
            <characteristic type="TestMDM">
                <parm datatype="string" name="EntDeviceName" value="WP8Device"/>
                <characteristic type="Poll">
                    <parm name="NumberOfFirstRetries" value="8" datatype="integer" />
                    <parm name="IntervalForFirstSetOfRetries" value="15" datatype="integer" />
                    <parm name="NumberOfSecondRetries" value="5" datatype="integer" />
                    <parm name="IntervalForSecondSetOfRetries" value="3" datatype="integer" />
                    <parm name="NumberOfRemainingScheduledRetries" value="0" datatype="integer" />
                    <parm name="IntervalForRemainingScheduledRetries" value="1560" datatype="integer" />
                    <parm name="PollOnLogin" value="true" datatype="boolean" />
                </characteristic>
            </characteristic>
        </characteristic>
    </characteristic>
</wap-provisioningdoc>
"""

ENROLLMENT_SERVICE_XML: Final[
    str
] = """
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep</a:Action>
        <a:RelatesTo>{}</a:RelatesTo>
        <o:Security xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" s:mustUnderstand="1">
            <u:Timestamp u:Id="_0">
                <u:Created>{}</u:Created>
                <u:Expires>{}</u:Expires>
            </u:Timestamp>ß
        </o:Security>
    </s:Header>
    <s:Body>
        <RequestSecurityTokenResponseCollection xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
            <RequestSecurityTokenResponse>
                <TokenType>http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken</TokenType>
                <DispositionMessage xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment"></DispositionMessage>
                <RequestedSecurityToken>
                    <BinarySecurityToken xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                    ValueType="http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentProvisionDoc"
                    EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">"{}"</BinarySecurityToken>
                </RequestedSecurityToken>
                <RequestID xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">0</RequestID>
            </RequestSecurityTokenResponse>
        </RequestSecurityTokenResponseCollection>
    </s:Body>
</s:Envelope>
"""

ENROLLMENT_ERROR_XML: Final[
    str
] = """
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
    <s:Header>
        <a:Action s:mustunderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/rstrc/wstep</a:Action>
        <Activityid correlationid="2493ee37-beeb-4cb9-833c-cadde9067645" xmlns="http://schemas.microsoft.com/2004/09/servicemodel/diagnostics">2493ee37-beeb-4cb9-833c-cadde9067645</Activityid>
        <a:Relatesto>{}</a:Relatesto>
    </s:Header>
    <s:Body>
        <s:Fault>
            <s:Code>
                <s:Value>s:Receiver</s:Value>
                <s:Subcode>
                    <s:Value>s:{}</s:Value>
                </s:Subcode>
            </s:Code>
            <s:Reason>
                <s:Text xml:lang="en-us">{}</s:Text>
            </s:Reason>
            <s:Detail>
                <Deviceenrollmentserviceerror xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">
                    <Errortype></Errortype>
                    <Message></Message>
                    <Traceid>2493ee37-beeb-4cb9-833c-cadde9067645</Traceid>
                </Deviceenrollmentserviceerror>
            </s:Detail>
        </s:Fault>
    </s:Body>
</s:Envelope>
"""

AUTHENTICATION_SERVICE_XML: Final[str] = """
<!DOCTYPE>
<html>
   <head>
      <title>Working...</title>
      <script>
         function formSubmit() {{
            document.forms[0].submit();
         }}
           window.onload=formSubmit;
      </script>
   </head>
   <body>
      <form method="post" action="{}">
         <p><input type="hidden" name="wresult" value="TokenWhichVerifiesAuth"/></p>
         <input type="submit"/>
      </form>
   </body>
</html>
"""


_SSL_CRITERIA: Final[str] = "CN%3D{}&amp;Stores=MY%5CUser"
_CERT_COMMON_NAME: Final[str] = "Certificate Common Name"


def create_provisional_xml(request_security_token: dict[str, Any]) -> str:
    """Creating a identity certificate using root ca certificate.
    1. Identity Certificate subject name and public key will be decoded from
        binary security token provided by device in request body.
    2. Creating a provisional xml file with dmclient details
        and certificates.
        Provisional Xml contain
        1. Root CA certificate md5 fingerprint
        2. Root CA certificate
        3. Identity certificate md5 fingerprint
        4. Identity certificate
        5. SSLCRITERIA ( contains information which will be used by device to
            identify certificate that will be used for dm session
        )
        6. App details (used for communication with device)
        7. DMClient session details(app name, server name, sync interval time)
    3. Encoding provisional xml in base64 bytes
    """

    raise NotImplementedError()