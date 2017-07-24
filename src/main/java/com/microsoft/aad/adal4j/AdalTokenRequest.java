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

import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.Proxy;
import java.net.URL;
import java.util.Map;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

/**
 * Extension for TokenRequest to support additional header values like
 * correlation id.
 */
class AdalTokenRequest {

    private final URL uri;
    private final ClientAuthentication clientAuth;
    private final AdalAuthorizatonGrant authzGrant;
    private final Map<String, String> headerMap;
    private final Proxy proxy;
    private final SSLSocketFactory sslSocketFactory;

    AdalTokenRequest(final URL uri, final ClientAuthentication clientAuth,
            final AdalAuthorizatonGrant authzGrant,
            final Map<String, String> headerMap, final Proxy proxy,
            final SSLSocketFactory sslSocketFactory) {
        this.clientAuth = clientAuth;
        this.authzGrant = authzGrant;
        this.uri = uri;
        this.headerMap = headerMap;
        this.proxy = proxy;
        this.sslSocketFactory = sslSocketFactory;
    }

    /**
     *
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

            OIDCTokens tokens = response.getOIDCTokens();
            String refreshToken = null;
            if (tokens.getRefreshToken() != null) {
                refreshToken = tokens.getRefreshToken().getValue();
            }

            UserInfo info = null;
            if (tokens.getIDToken() != null) {
                info = UserInfo.createFromIdTokenClaims(tokens.getIDToken()
                        .getJWTClaimsSet());
            }

            result = new AuthenticationResult(tokens.getAccessToken()
                    .getType().getValue(),
                    tokens.getAccessToken().getValue(), refreshToken,
                    tokens.getAccessToken().getLifetime(),
                    tokens.getIDTokenString(), info,
                    !StringHelper.isBlank(response.getResource()));
        }
        else {
            final TokenErrorResponse errorResponse = TokenErrorResponse
                    .parse(httpResponse);
            if(HTTPResponse.SC_BAD_REQUEST == errorResponse.getErrorObject().getHTTPStatusCode() &&
                    "interaction_required".equals(errorResponse.getErrorObject().getCode())){
                throw new AdalClaimsChallengeException(errorResponse.toJSONObject()
                        .toJSONString(), getClaims(httpResponse.getContent()));
            }
            else {
                throw new AuthenticationException(errorResponse.toJSONObject()
                        .toJSONString());
            }
        }

        return result;
    }

    private String getClaims(String httpResponseContentStr) {
        JsonElement root = new JsonParser().parse(httpResponseContentStr);

        JsonElement claims = root.getAsJsonObject().get("claims");

        return claims != null ? claims.getAsString() : null;
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
                HTTPRequest.Method.POST, this.uri, headerMap, this.proxy,
                this.sslSocketFactory);
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
        final Map<String, String> params = this.authzGrant.toParameters();
        httpRequest.setQuery(URLUtils.serializeParameters(params));
        if (this.clientAuth != null) {
            this.clientAuth.applyTo(httpRequest);
        }

        return httpRequest;
    }
}
