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

import java.io.Serializable;

/**
 * Contains the results of one token acquisition operation.
 */
public final class AuthenticationResult implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String accessTokenType;
    private final long expiresOn;
    private final UserInfo userInfo;
    private final String accessToken;
    private final String refreshToken;
    private final boolean isMultipleResourceRefreshToken;

    public AuthenticationResult(final String accessTokenType,
            final String accessToken, final String refreshToken,
            final long expiresOn, final UserInfo userInfo,
            final boolean isMultipleResourceRefreshToken) {
        this.accessTokenType = accessTokenType;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiresOn = expiresOn;
        this.userInfo = userInfo;
        this.isMultipleResourceRefreshToken = isMultipleResourceRefreshToken;
    }

    public String getAccessTokenType() {
        return accessTokenType;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public long getExpiresOn() {
        return expiresOn;
    }

    public UserInfo getUserInfo() {
        return userInfo;
    }

    public boolean isMultipleResourceRefreshToken() {
        return isMultipleResourceRefreshToken;
    }
}
