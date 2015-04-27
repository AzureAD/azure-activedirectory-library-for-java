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
 * Credential including client id and secret.
 */
public final class ClientCredential {

    private final String clientId;
    private final String clientSecret;

    /**
     * Constructor to create credential with client id and secret
     * 
     * @param clientId
     *            Identifier of the client requesting the token.
     * @param clientSecret
     *            Secret of the client requesting the token.
     */
    public ClientCredential(final String clientId, final String clientSecret) {

        if (StringHelper.isBlank(clientId)) {
            throw new IllegalArgumentException("clientId is null or empty");
        }
        if (StringHelper.isBlank(clientSecret)) {
            throw new IllegalArgumentException("clientSecret is null or empty");
        }

        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    /**
     * Gets the identifier of the client requesting the token.
     * 
     * @return string client id value
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * Gets the secret of the client requesting the token.
     * 
     * @return string client secret value
     */
    public String getClientSecret() {
        return clientSecret;
    }
}
