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

import java.util.ArrayList;
import java.util.List;

import net.minidev.json.JSONObject;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 *
 */
public class AdalJWTClaimsSetTest extends AbstractAdalTests {

    @Test
    public void testNullAudience() {

        final AdalJWTClaimsSet obj = new AdalJWTClaimsSet();
        obj.setAudience((String)null);
        final JSONObject jo = obj.toJSONObject();
        Assert.assertFalse(jo.containsKey(AdalJWTClaimsSet.AUDIENCE_CLAIM));
    }

    @Test
    public void testEmptyAudience() {

        final AdalJWTClaimsSet obj = new AdalJWTClaimsSet();
        obj.setAudience(new ArrayList<String>());
        obj.setIssuer("issuer");
        JSONObject jo = obj.toJSONObject();
        jo = obj.toJSONObject();
        Assert.assertFalse(jo.containsKey(AdalJWTClaimsSet.AUDIENCE_CLAIM));
    }

    @Test
    public void testPopulatedAudience() {

        final AdalJWTClaimsSet obj = new AdalJWTClaimsSet();
        List<String> aud = new ArrayList<String>();
        aud.add("aud1");
        obj.setAudience(aud);
        obj.setIssuer("issuer");
        JSONObject jo = obj.toJSONObject();
        jo = obj.toJSONObject();
        Assert.assertTrue(jo.containsKey(AdalJWTClaimsSet.AUDIENCE_CLAIM));
    }
}
