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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;

/**
 *
 */
public class AdalAuthorizatonGrantTest {

    @Test
    public void testConstructor() {
        final AdalAuthorizatonGrant grant = new AdalAuthorizatonGrant(null,
                new HashMap<String, String>());
        Assert.assertNotNull(grant);
    }

    @Test
    public void testToParameters() throws URISyntaxException {
        final AdalAuthorizatonGrant grant = new AdalAuthorizatonGrant(
                new AuthorizationCodeGrant(new AuthorizationCode("grant"),
                        new URI("http://microsoft.com")),
                (Map<String, String>) null);
        Assert.assertNotNull(grant);
        Assert.assertNotNull(grant.toParameters());
    }
}
