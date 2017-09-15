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
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import com.nimbusds.jwt.JWTClaimsSet;

/**
 * Contains information of a single user.
 */
public class UserInfo implements Serializable {

    private static final long serialVersionUID = 1L;
    String uniqueId;
    String displayableId;
    String givenName;
    String familyName;
    String identityProvider;
    String passwordChangeUrl;
    Date passwordExpiresOn;
    String tenantId;

    private UserInfo() {
    }

    public String getDisplayableId() {
        return displayableId;
    }

    /**
     * Get user id
     * 
     * @return String value
     */
    public String getUniqueId() {
        return uniqueId;
    }

    /**
     * Get given name
     * 
     * @return String value
     */
    public String getGivenName() {
        return givenName;
    }

    /**
     * Get family name
     * 
     * @return String value
     */
    public String getFamilyName() {
        return familyName;
    }

    /**
     * Get identity provider
     * 
     * @return String value
     */
    public String getIdentityProvider() {
        return identityProvider;
    }

    public String getPasswordChangeUrl() {
        return passwordChangeUrl;
    }

    public Date getPasswordExpiresOn() {
        if (passwordExpiresOn != null) {
            return (Date)passwordExpiresOn.clone();
        } else {
            return null;
        }
    }

    /**
     * Get tenant id
     *
     * @return String value
     */
    public String getTenantId() {
        return tenantId;
    }

    static UserInfo createFromIdTokenClaims(final JWTClaimsSet claims)
            throws java.text.ParseException {

        if (claims == null || claims.getClaims().size() == 0) {
            return null;
        }

        String uniqueId = null;
        String displayableId = null;

        if (!StringHelper.isBlank(claims
                .getStringClaim(AuthenticationConstants.ID_TOKEN_OBJECT_ID))) {
            uniqueId = claims
                    .getStringClaim(AuthenticationConstants.ID_TOKEN_OBJECT_ID);
        }
        else if (!StringHelper.isBlank(claims
                .getStringClaim(AuthenticationConstants.ID_TOKEN_SUBJECT))) {
            uniqueId = claims
                    .getStringClaim(AuthenticationConstants.ID_TOKEN_SUBJECT);
        }

        if (!StringHelper.isBlank(claims
                .getStringClaim(AuthenticationConstants.ID_TOKEN_UPN))) {
            displayableId = claims
                    .getStringClaim(AuthenticationConstants.ID_TOKEN_UPN);
        }
        else if (!StringHelper.isBlank(claims
                .getStringClaim(AuthenticationConstants.ID_TOKEN_EMAIL))) {
            displayableId = claims
                    .getStringClaim(AuthenticationConstants.ID_TOKEN_EMAIL);
        }

        final UserInfo userInfo = new UserInfo();
        userInfo.uniqueId = uniqueId;
        userInfo.displayableId = displayableId;
        userInfo.familyName = claims
                .getStringClaim(AuthenticationConstants.ID_TOKEN_FAMILY_NAME);
        userInfo.givenName = claims
                .getStringClaim(AuthenticationConstants.ID_TOKEN_GIVEN_NAME);
        userInfo.identityProvider = claims
                .getStringClaim(AuthenticationConstants.ID_TOKEN_IDENTITY_PROVIDER);
        userInfo.tenantId = claims
                .getStringClaim(AuthenticationConstants.ID_TOKEN_TENANTID);

        if (!StringHelper
                .isBlank(claims
                        .getStringClaim(AuthenticationConstants.ID_TOKEN_PASSWORD_CHANGE_URL))) {
            userInfo.passwordChangeUrl = claims
                    .getStringClaim(AuthenticationConstants.ID_TOKEN_PASSWORD_CHANGE_URL);
        }

        if (claims
                .getClaim(AuthenticationConstants.ID_TOKEN_PASSWORD_EXPIRES_ON) != null) {
            int claimExpiry = Integer.parseInt(
                    (String)claims.getClaim(AuthenticationConstants.ID_TOKEN_PASSWORD_EXPIRES_ON));
            // pwd_exp returns seconds to expiration time
            // it returns in seconds. Date accepts milliseconds.
            if (claimExpiry > 0) {
                Calendar expires = new GregorianCalendar();
                expires.add(Calendar.SECOND, claimExpiry);
                userInfo.passwordExpiresOn = expires.getTime();
            }
        }

        return userInfo;
    }

}
