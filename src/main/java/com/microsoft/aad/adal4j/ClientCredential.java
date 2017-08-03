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
