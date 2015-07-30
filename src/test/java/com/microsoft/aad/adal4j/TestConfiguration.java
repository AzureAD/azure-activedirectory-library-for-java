/*******************************************************************************
 * Copyright © Microsoft Open Technologies, Inc.
 * 
 * All Rights Reserved
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 * 
 * See the Apache License, Version 2.0 for the specific language
 * governing permissions and limitations under the License.
 ******************************************************************************/
package com.microsoft.aad.adal4j;

public final class TestConfiguration {

    public final static String AAD_HOST_NAME = "login.windows.net";
    public final static String AAD_TENANT_NAME = "aaltests.onmicrosoft.com";
    public final static String AAD_TENANT_ENDPOINT = "https://" + AAD_HOST_NAME
            + "/" + AAD_TENANT_NAME + "/";
    public final static String AAD_CLIENT_ID = "9083ccb8-8a46-43e7-8439-1d696df984ae";
    public final static String AAD_CLIENT_SECRET = "client_secret";
    public final static String AAD_RESOURCE_ID = "b7a671d8-a408-42ff-86e0-aaf447fd17c4";
    public final static String AAD_CERTIFICATE_PATH = "/test-certificate.pfx";
    public final static String AAD_MEX_RESPONSE_FILE = "/mex-response.xml";
    public final static String AAD_MEX_2005_RESPONSE_FILE = "/mex-2005-response.xml";
    public final static String AAD_TOKEN_ERROR_FILE = "/token-error.xml";
    public final static String AAD_TOKEN_SUCCESS_FILE = "/token.xml";
    public final static String AAD_CERTIFICATE_PASSWORD = "password";
    public final static String AAD_DEFAULT_REDIRECT_URI = "https://non_existing_uri.windows.com/";
    public final static String AAD_REDIRECT_URI_FOR_CONFIDENTIAL_CLIENT = "https://non_existing_uri_for_confidential_client.com/";

    public final static String ADFS_HOST_NAME = "fs.ade2eadfs30.com";
    public final static String ADFS_TENANT_ENDPOINT = "https://"
            + ADFS_HOST_NAME + "/adfs/";
    public final static String AAD_UNKNOWN_TENANT_ENDPOINT = "https://lgn.windows.net/"
            + AAD_TENANT_NAME + "/";

    public final static String HTTP_RESPONSE_FROM_AUTH_CODE = "{\"access_token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6I"
            + "k5HVEZ2ZEstZnl0aEV1THdqcHdBSk9NOW4tQSJ9.eyJhdWQiOiJiN2E2NzFkOC1hNDA4LTQyZmYtODZlMC1hYWY0NDdmZDE3YzQiLCJpc3MiOiJod"
            + "HRwczovL3N0cy53aW5kb3dzLm5ldC8zMGJhYTY2Ni04ZGY4LTQ4ZTctOTdlNi03N2NmZDA5OTU5NjMvIiwiaWF0IjoxMzkzODQ0NTA0LCJuYmYiOj"
            + "EzOTM4NDQ1MDQsImV4cCI6MTM5Mzg0ODQwNCwidmVyIjoiMS4wIiwidGlkIjoiMzBiYWE2NjYtOGRmOC00OGU3LTk3ZTYtNzdjZmQwOTk1OTYzIiwi"
            + "b2lkIjoiNGY4NTk5ODktYTJmZi00MTFlLTkwNDgtYzMyMjI0N2FjNjJjIiwidXBuIjoiYWRtaW5AYWFsdGVzdHMub25taWNyb3NvZnQuY29tIiwidW"
            + "5pcXVlX25hbWUiOiJhZG1pbkBhYWx0ZXN0cy5vbm1pY3Jvc29mdC5jb20iLCJzdWIiOiJqQ0ttUENWWEFzblN1MVBQUzRWblo4c2VONTR3U3F0cW1R"
            + "MkpGbW14SEF3IiwiZmFtaWx5X25hbWUiOiJBZG1pbiIsImdpdmVuX25hbWUiOiJBREFMVGVzdHMiLCJhcHBpZCI6IjkwODNjY2I4LThhNDYtNDNlNy"
            + "04NDM5LTFkNjk2ZGY5ODRhZSIsImFwcGlkYWNyIjoiMSIsInNjcCI6InVzZXJfaW1wZXJzb25hdGlvbiIsImFjciI6IjEifQ.lUfDlkLdNGuAGUukg"
            + "TnS_uWeSFXljbhId1l9PDrr7AwOSbOzogLvO14TaU294T6HeOQ8e0dUAvxEAMvsK_800A-AGNvbHK363xDjgmu464ye3CQvwq73GoHkzuxILCJKo0D"
            + "HO-TUj0_XsCpQ4TdkPepuhzaGc-zYsfMU1POuIOB87pzW7e_VDpCdxcN1fuk-7CECPQb8nrO0L8Du8y-TZDdTSe-i_A0Alv48Zll-6tDY9cxfAR0Uy"
            + "YKl_Kf45kuHAphCWwPsjUxv4rGHhgXZPRlKFq7bkXP2Es4ixCQzb3bVLLrtQaZjkQ1yn37ngJro8NR63EbHHjHTA9lRmf8KIQ\",\"token_type\""
            + ":\"Bearer\",\"expires_in\":\"3600\",\"expires_on\":\"1393848404\",\"resource\":\"b7a671d8-a408-42ff-86e0-aaf447fd1"
            + "7c4\",\"refresh_token\":\"AwABAAAAvPM1KaPlrEqdFSBzjqfTGPW9BlsxWYtD0DS9hJNOPHPnq8QYbv6_FKJ3MxSHbPAIekKwJ04TnZI1NnRj"
            + "CMhphmsy5ZFjWtLy3WN2E67b3aW2MTQ9lN06B-HdRdU0Rxi9EalB8kAlgb92Ob0zuhB90zWm3RbxshOW0vkHS3lNAV6_LQ8fZKeLTB1AuuRgLXsy-9"
            + "2h0yYuEQw_Uvs80IbGx59j1z3hJrCMEMrqh-Hf42OnckN-uR113zMircfEOMm0qzhrQdtLleTHELS79B18647OiG6e8k8saVIvJmjpIuy79_aN-Bk5"
            + "PRkkab-QAwn_R68via4nK0zpKHBCl0xoEvK59mqerNDEKJNY168_FHDYPiZyECaZCdlWdEqd3dLohFlnKv9zc0CnuvB_QSQHHNScqWkX53s_Us9I45"
            + "QlRDaUPB89QXzQQaT2wZ8i3wTOb7mnEUMzrNrpsor6E4ckiviMx6WoepZmqQEZV-Yd-UUgAA\",\"scope\":\"user_impersonation\",\""
            + "id_token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiI5MDgzY2NiOC04YTQ2LTQzZTctODQzOS0xZDY5NmRmOTg0YWUiLCJpc"
            + "3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8zMGJhYTY2Ni04ZGY4LTQ4ZTctOTdlNi03N2NmZDA5OTU5NjMvIiwiaWF0IjoxMzkzODQ0NTA0LCJ"
            + "uYmYiOjEzOTM4NDQ1MDQsImV4cCI6MTM5Mzg0ODQwNCwidmVyIjoiMS4wIiwidGlkIjoiMzBiYWE2NjYtOGRmOC00OGU3LTk3ZTYtNzdjZmQwOTk1O"
            + "TYzIiwib2lkIjoiNGY4NTk5ODktYTJmZi00MTFlLTkwNDgtYzMyMjI0N2FjNjJjIiwidXBuIjoiYWRtaW5AYWFsdGVzdHMub25taWNyb3NvZnQuY29"
            + "tIiwidW5pcXVlX25hbWUiOiJhZG1pbkBhYWx0ZXN0cy5vbm1pY3Jvc29mdC5jb20iLCJzdWIiOiJCczVxVG4xQ3YtNC10VXIxTGxBb3pOS1NRd0Fjb"
            + "m4ydHcyQjlmelduNlpJIiwiZmFtaWx5X25hbWUiOiJBZG1pbiIsImdpdmVuX25hbWUiOiJBREFMVGVzdHMifQ.\"}";

    public final static String HTTP_ERROR_RESPONSE = "{\"error\":\"invalid_request\",\"error_description\":\"AADSTS90011: Request "
            + "is ambiguous, multiple application identifiers found. Application identifiers: 'd09bb6da-4d46-4a16-880c-7885d8291fb9"
            + ", 216ef81d-f3b2-47d4-ad21-a4df49b56dee'.\r\nTrace ID: 428a1f68-767d-4a1c-ae8e-f710eeaf4e9b\r\nCorrelation ID: 1e0955"
            + "88-68e4-4bb4-a54e-71ad81e7f013\r\nTimestamp: 2014-03-11 20:19:02Z\"}";

}
