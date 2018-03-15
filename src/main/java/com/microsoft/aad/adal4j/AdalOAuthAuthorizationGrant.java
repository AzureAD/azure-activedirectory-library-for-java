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

import java.util.LinkedHashMap;
import java.util.Map;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;

/**
 * 
 */
class AdalOAuthAuthorizationGrant implements AdalAuthorizationGrant {

    private final AuthorizationGrant grant;
    private final Map<String, String> params;

    /**
     * 
     * @param grant
     * @param resource
     */
    AdalOAuthAuthorizationGrant(final AuthorizationGrant grant, final String resource) {
        this.grant = grant;
        params = new LinkedHashMap<>();
        if (!StringHelper.isBlank(resource)) {
            params.put("resource", resource);
        }
    }

    /**
     * 
     * @param grant
     * @param params
     */
    AdalOAuthAuthorizationGrant(final AuthorizationGrant grant,
                                final Map<String, String> params) {
        this.grant = grant;
        this.params = params;
    }

    @Override
    public Map<String, String> toParameters() {

        final Map<String, String> outParams = new LinkedHashMap<String, String>();
        if (this.params != null) {
            outParams.putAll(this.params);
        }

        outParams.put("scope", "openid");
        outParams.putAll(grant.toParameters());
        return outParams;
    }

    AuthorizationGrant getAuthorizationGrant() {
        return this.grant;
    }

    Map<String, String> getCustomParameters() {
        return params;
    }
}
