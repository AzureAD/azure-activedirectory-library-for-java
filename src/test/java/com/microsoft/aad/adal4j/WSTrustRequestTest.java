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

import org.testng.Assert;
import org.testng.annotations.Test;

@Test(groups = { "checkin" })
public class WSTrustRequestTest {

    @Test
    public void buildMessage_cloudAudienceUrnNotNull() throws Exception {
        String msg = WSTrustRequest.buildMessage("address", "username",
                "password", WSTrustVersion.WSTRUST2005, "cloudAudienceUrn").toString();

        Assert.assertTrue(msg.contains("<a:EndpointReference><a:Address>cloudAudienceUrn</a:Address></a:EndpointReference>"));
    }

    @Test
    public void buildMessage_cloudAudienceUrnNull() throws Exception {
        String msg = WSTrustRequest.buildMessage("address", "username",
                "password", WSTrustVersion.WSTRUST2005, null).toString();

        Assert.assertTrue(msg.contains("<a:EndpointReference><a:Address>" + WSTrustRequest.DEFAULT_APPLIES_TO + "</a:Address></a:EndpointReference>"));
    }

    @Test
    public void buildMessage_cloudAudienceUrnEmpty() throws Exception {
        String msg = WSTrustRequest.buildMessage("address", "username",
                "password", WSTrustVersion.WSTRUST2005, "").toString();

        Assert.assertTrue(msg.contains("<a:EndpointReference><a:Address>" + WSTrustRequest.DEFAULT_APPLIES_TO + "</a:Address></a:EndpointReference>"));
    }
}
