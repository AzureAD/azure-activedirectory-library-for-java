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
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;

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
        return passwordExpiresOn;
    }

    static UserInfo createFromIdTokenClaims(final ReadOnlyJWTClaimsSet claims)
            throws java.text.ParseException {

        if (claims == null || claims.getAllClaims().size() == 0) {
            return null;
        }

        String uniqueId = null;
        String displayableId = null;

        if (!StringHelper.isBlank(claims
                .getStringClaim(AuthenticationConstants.ID_TOKEN_OBJECT_ID))) {
            uniqueId = claims
                    .getStringClaim(AuthenticationConstants.ID_TOKEN_OBJECT_ID);
        } else if (!StringHelper.isBlank(claims
                .getStringClaim(AuthenticationConstants.ID_TOKEN_SUBJECT))) {
            uniqueId = claims
                    .getStringClaim(AuthenticationConstants.ID_TOKEN_SUBJECT);
        }

        if (!StringHelper.isBlank(claims
                .getStringClaim(AuthenticationConstants.ID_TOKEN_UPN))) {
            displayableId = claims
                    .getStringClaim(AuthenticationConstants.ID_TOKEN_UPN);
        } else if (!StringHelper.isBlank(claims
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

        if (!StringHelper
                .isBlank(claims
                        .getStringClaim(AuthenticationConstants.ID_TOKEN_PASSWORD_CHANGE_URL))) {
            userInfo.passwordChangeUrl = claims
                    .getStringClaim(AuthenticationConstants.ID_TOKEN_PASSWORD_CHANGE_URL);
        }

        if (claims
                .getClaim(AuthenticationConstants.ID_TOKEN_PASSWORD_EXPIRES_ON) != null) {
            int claimExpiry = Integer
                    .valueOf((String) claims
                            .getClaim(AuthenticationConstants.ID_TOKEN_PASSWORD_EXPIRES_ON));
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
