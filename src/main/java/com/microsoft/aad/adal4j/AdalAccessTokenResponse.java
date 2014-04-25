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

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.OIDCAccessTokenResponse;

/**
 * 
 */
class AdalAccessTokenResponse extends OIDCAccessTokenResponse {

    private String resource;

    AdalAccessTokenResponse(final AccessToken accessToken,
            final RefreshToken refreshToken, final String idToken) {
        super(accessToken, refreshToken, idToken);
    }

    AdalAccessTokenResponse(final AccessToken accessToken,
            final RefreshToken refreshToken, final String idToken,
            final String resource) {
        this(accessToken, refreshToken, idToken);
        this.resource = resource;
    }

    String getResource() {
        return resource;
    }

    /**
     * 
     * @param httpResponse
     * @return
     * @throws ParseException
     */
    static AdalAccessTokenResponse parseHttpResponse(
            final HTTPResponse httpResponse) throws ParseException {

        httpResponse.ensureStatusCode(HTTPResponse.SC_OK);

        final JSONObject jsonObject = httpResponse.getContentAsJSONObject();

        return parseJsonObject(jsonObject);
    }

    /**
     * 
     * @param jsonObject
     * @return
     * @throws ParseException
     */
    static AdalAccessTokenResponse parseJsonObject(final JSONObject jsonObject)
            throws ParseException {

        final AccessToken accessToken = AccessToken.parse(jsonObject);
        final RefreshToken refreshToken = RefreshToken.parse(jsonObject);

        String idTokenValue = null;
        if (jsonObject.containsKey("id_token")) {
            idTokenValue = JSONObjectUtils.getString(jsonObject, "id_token");
        }

        // Parse value
        String resourceValue = null;
        if (jsonObject.containsKey("resource")) {
            resourceValue = JSONObjectUtils.getString(jsonObject, "resource");
        }

        return new AdalAccessTokenResponse(accessToken, refreshToken,
                idTokenValue, resourceValue);
    }
}
