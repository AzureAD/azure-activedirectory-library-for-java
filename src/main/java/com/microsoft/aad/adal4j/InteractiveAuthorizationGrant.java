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

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GrantType;

import java.util.LinkedHashMap;
import java.util.Map;

public class InteractiveAuthorizationGrant extends AuthorizationGrant {

    // TODO: add constructor parameters so we have enough state to do our job inside processPasswordGrant()
    public InteractiveAuthorizationGrant() {
        super(GrantType.AUTHORIZATION_CODE);
    }

    @Override
    public Map<String, String> toParameters() {
        final LinkedHashMap<String, String> params = new LinkedHashMap<String, String>();
        return params;
    }
}
