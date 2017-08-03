// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package com.microsoft.aad.adal4j;

import java.io.Serializable;
import java.util.Date;

/**
 * Contains the results of one token acquisition operation.
 */
public final class AuthenticationResult implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String accessTokenType;
    private final long expiresIn;
    private final Date expiresOn;
    private final String idToken;
    private final UserInfo userInfo;
    private final String accessToken;
    private final String refreshToken;
    private final boolean isMultipleResourceRefreshToken;

    public AuthenticationResult(final String accessTokenType,
            final String accessToken, final String refreshToken,
            final long expiresIn, final String idToken,
            final UserInfo userInfo,
            final boolean isMultipleResourceRefreshToken) {
        this.accessTokenType = accessTokenType;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;

        Date now = new Date();
        now.setTime(now.getTime() + (expiresIn * 1000));
        this.expiresOn = now;

        this.idToken = idToken;
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

    @Deprecated
    public long getExpiresOn() {
        return expiresIn;
    }

    public long getExpiresAfter() {
        return expiresIn;
    }

    public Date getExpiresOnDate() {
        if (expiresOn != null) {
            return (Date)expiresOn.clone();
        } else {
            return null;
        }
    }

    public String getIdToken() {
        return idToken;
    }

    public UserInfo getUserInfo() {
        return userInfo;
    }

    public boolean isMultipleResourceRefreshToken() {
        return isMultipleResourceRefreshToken;
    }
}
