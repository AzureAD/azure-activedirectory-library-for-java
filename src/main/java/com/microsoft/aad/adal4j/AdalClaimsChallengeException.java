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

/**
 * The exception type thrown when a claims challenge error occurs during token acquisition.
 */
public class AdalClaimsChallengeException extends AuthenticationException {

    /**
     * Constructor
     *
     * @param message
     * @param claims
     */
    public AdalClaimsChallengeException(String message, String claims) {
        super(message);

        this.claims = claims;
    }

    private final String claims;

    /**
     *
     * @return claims challenge value
     */
    public String getClaims() {
        return claims;
    }
}
