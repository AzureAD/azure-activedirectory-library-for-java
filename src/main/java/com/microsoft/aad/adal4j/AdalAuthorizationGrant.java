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

import java.util.LinkedHashMap;
import java.util.Map;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;

/**
 * 
 */
class AdalAuthorizationGrant {

    private final AuthorizationGrant grant;
    private final Map<String, String> params;

    /**
     * 
     * @param grant
     * @param resource
     */
    AdalAuthorizationGrant(final AuthorizationGrant grant, final String resource) {
        this.grant = grant;
        params = new LinkedHashMap<String, String>();
        if (!StringHelper.isBlank(resource)) {
            params.put("resource", resource);
        }
    }

    /**
     * 
     * @param grant
     * @param params
     */
    AdalAuthorizationGrant(final AuthorizationGrant grant,
            final Map<String, String> params) {
        this.grant = grant;
        this.params = params;
    }

    Map<String, String> toParameters() {

        final Map<String, String> outParams = new LinkedHashMap<String, String>();
        if (this.params != null) {
            outParams.putAll(this.params);
        }
        outParams.putAll(grant.toParameters());
        return outParams;
    }

}
