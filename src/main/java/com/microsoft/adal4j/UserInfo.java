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
package com.microsoft.adal4j;

import java.io.Serializable;

import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;

/**
 * Contains information of a single user.
 */
public class UserInfo implements Serializable {

    private static final long serialVersionUID = 1L;
    private final String userId;
    private final String givenName;
    private final String familyName;
    private final String identityProvider;
    private final boolean isUserIdDisplayable;

    private UserInfo(final String userId, final String givenName,
            final String familyName, final String identityProvider,
            final boolean isDisplayable) {
        this.userId = userId;
        this.givenName = givenName;
        this.familyName = familyName;
        this.identityProvider = identityProvider;
        this.isUserIdDisplayable = isDisplayable;
    }

    /**
     * Get user id
     * 
     * @return String value
     */
    public String getUserId() {
        return userId;
    }

    /**
     * Returns flag is user id is displayable.
     * 
     * @return boolean value
     */
    public boolean isUserIdDisplayable() {
        return isUserIdDisplayable;
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

    static UserInfo createFromIdTokenClaims(final ReadOnlyJWTClaimsSet claims)
            throws java.text.ParseException {

        if (claims == null || claims.getAllClaims().size() == 0) {
            return null;
        }

        boolean isDisplayable = false;
        String userId = null;
        if (!StringHelper.isBlank(claims
                .getStringClaim(AuthenticationConstants.ID_TOKEN_UPN))) {

            userId = claims
                    .getStringClaim(AuthenticationConstants.ID_TOKEN_UPN);
            isDisplayable = true;
        } else if (!StringHelper.isBlank(claims
                .getStringClaim(AuthenticationConstants.ID_TOKEN_EMAIL))) {
            userId = claims
                    .getStringClaim(AuthenticationConstants.ID_TOKEN_EMAIL);
            isDisplayable = true;
        } else if (!StringHelper.isBlank(claims.getSubject())) {
            userId = claims.getSubject();
        }
        final UserInfo userInfo = new UserInfo(
                userId,
                claims.getStringClaim(AuthenticationConstants.ID_TOKEN_GIVEN_NAME),
                claims.getStringClaim(AuthenticationConstants.ID_TOKEN_FAMILY_NAME),
                claims.getStringClaim(AuthenticationConstants.ID_TOKEN_IDENTITY_PROVIDER),
                isDisplayable);

        return userInfo;

    }

}
