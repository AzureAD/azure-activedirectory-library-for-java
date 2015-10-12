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

import java.io.IOException;
import java.net.URL;
import java.util.Map;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.URLUtils;

/**
 * Extension for TokenRequest to support additional header values like
 * correlation id.
 */
class AdalTokenRequest {

    private final URL uri;
    private final ClientAuthentication clientAuth;
    private final AdalAuthorizatonGrant authzGrant;
    private final Map<String, String> headerMap;

    AdalTokenRequest(final URL uri, final ClientAuthentication clientAuth,
            final AdalAuthorizatonGrant authzGrant,
            final Map<String, String> headerMap) {
        this.clientAuth = clientAuth;
        this.authzGrant = authzGrant;
        this.uri = uri;
        this.headerMap = headerMap;
    }

    /**
     * 
     * @param request
     * @return
     * @throws ParseException
     * @throws AuthenticationException
     * @throws SerializeException
     * @throws IOException
     * @throws java.text.ParseException
     */
    AuthenticationResult executeOAuthRequestAndProcessResponse()
            throws ParseException, AuthenticationException, SerializeException,
            IOException, java.text.ParseException {

        AuthenticationResult result = null;
        HTTPResponse httpResponse = null;
        final AdalOAuthRequest adalOAuthHttpRequest = this.toOAuthRequest();
        httpResponse = adalOAuthHttpRequest.send();

        if (httpResponse.getStatusCode() == HTTPResponse.SC_OK) {
            final AdalAccessTokenResponse response = AdalAccessTokenResponse
                    .parseHttpResponse(httpResponse);

            String refreshToken = null;
            if (response.getRefreshToken() != null) {
                refreshToken = response.getRefreshToken().getValue();
            }

            UserInfo info = null;
            if (response.getIDToken() != null) {
                info = UserInfo.createFromIdTokenClaims(response.getIDToken()
                        .getJWTClaimsSet());
            }

            result = new AuthenticationResult(
                        response.getAccessToken().getType().getValue(),
                        response.getAccessToken().getValue(),
                        refreshToken,
                        response.getAccessToken().getLifetime(),
                        response.getIDTokenString(),
                        info,
                        !StringHelper.isBlank(response.getResource()));
        } else {
            final TokenErrorResponse errorResponse = TokenErrorResponse
                    .parse(httpResponse);
            throw new AuthenticationException(errorResponse.toJSONObject()
                    .toJSONString());
        }

        return result;
    }

    /**
     * 
     * @return
     * @throws SerializeException
     */
    AdalOAuthRequest toOAuthRequest() throws SerializeException {

        if (this.uri == null) {
            throw new SerializeException("The endpoint URI is not specified");
        }

        final AdalOAuthRequest httpRequest = new AdalOAuthRequest(
                HTTPRequest.Method.POST, this.uri, headerMap);
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
        final Map<String, String> params = this.authzGrant.toParameters();
        httpRequest.setQuery(URLUtils.serializeParameters(params));
        if (this.clientAuth != null) {
            this.clientAuth.applyTo(httpRequest);
        }

        return httpRequest;
    }
}
