/**
 * Copyright 2014 Microsoft Open Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.microsoft.aad.adal4j.interactive;

public class OAuthGrantType {
    public static final String AuthorizationCode = "authorization_code";
    public static final String RefreshToken = "refresh_token";
    public static final String ClientCredentials = "client_credentials";
    public static final String Saml11Bearer = "urn:ietf:params:oauth:grant-type:saml1_1-bearer";
    public static final String Saml20Bearer = "urn:ietf:params:oauth:grant-type:saml2-bearer";
    public static final String JwtBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    public static final String Password = "password";
}
