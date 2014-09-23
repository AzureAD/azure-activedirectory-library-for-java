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

/***
 * Credential type containing an assertion of type
 * "urn:ietf:params:oauth:token-type:jwt".
 */
public final class ClientAssertion {

    public enum AssertionType {
        JWT,
        SAML1_1,
        SAML2
    }
    
    private final String assertion;
    private final AssertionType type;
    
    /**
     * Constructor to create credential with a jwt token encoded as a base64 url
     * encoded string.
     * 
     * @param assertion
     *            The jwt used as credential.
     */
    public ClientAssertion(final String assertion) {
        this(assertion, AssertionType.JWT);
    }


    public ClientAssertion(final String assertion, final AssertionType type) {

        if (StringHelper.isBlank(assertion)) {
            throw new NullPointerException("assertion");
        }

        this.assertion = assertion;
        this.type = type;
    }
    
    /**
     * Gets the assertion.
     * 
     * @return string value
     */
    public String getAssertion() {
        return assertion;
    }


    /**
     * Gets the assertion type.
     * 
     * @return assertion value
     */
    public AssertionType getAssertionType() {
        return type;
    }
}
