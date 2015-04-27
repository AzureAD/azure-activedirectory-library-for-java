/**
 * Copyright 2014 Microsoft Open Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.microsoft.aad.adal4j.interactive;

public class OAuthReservedClaim
{
    public static final String Code = "code";
    public static final String TokenType = "token_type";
    public static final String AccessToken = "access_token";
    public static final String RefreshToken = "refresh_token";
    public static final String Resource = "resource";
    public static final String IdToken = "id_token";
    public static final String CreatedOn = "created_on";
    public static final String ExpiresOn = "expires_on";
    public static final String ExpiresIn = "expires_in";
    public static final String Error = "error";
    public static final String ErrorDescription = "error_description";
    public static final String ErrorCodes = "error_codes";
}