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

import java.util.Map;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.SAML2BearerGrant;

class SAML11BearerGrant extends SAML2BearerGrant {

    /**
     * The grant type.
     */
    public static GrantType grantType = new GrantType(
            "urn:ietf:params:oauth:grant-type:saml1_1-bearer");

    public SAML11BearerGrant(Base64URL assertion) {
        super(assertion);
    }

    @Override
    public Map<String, String> toParameters() {

        Map<String, String> params = super.toParameters();
        params.put("grant_type", grantType.getValue());
        return params;
    }
}
