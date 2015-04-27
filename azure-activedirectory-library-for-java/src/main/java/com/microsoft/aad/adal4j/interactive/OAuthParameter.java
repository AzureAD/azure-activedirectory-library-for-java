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

public class OAuthParameter {
    public static final String responseType = "response_type";
    public static final String grantType = "grant_type";
    public static final String clientId = "client_id";
    public static final String clientSecret = "client_secret";
    public static final String clientAssertion = "client_assertion";
    public static final String clientAssertionType = "client_assertion_type";
    public static final String refreshToken = "refresh_token";
    public static final String redirectUri = "redirect_uri";
    public static final String resource = "resource";
    public static final String code = "code";
    public static final String scope = "scope";
    public static final String assertion = "assertion";
    public static final String requestedTokenUse = "requested_token_use";
    public static final String username = "username";
    public static final String password = "password";

    public static final String formsAuth = "amr_values";
    public static final String loginHint = "login_hint"; // login_hint is not standard oauth2 parameter
    public static final String correlationId = OAuthHeader.correlationId; // correlation id is not standard oauth2 parameter
    public static final String prompt = "prompt"; // prompt is not standard oauth2 parameter
}