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

import java.net.MalformedURLException;
import java.net.URL;

import org.testng.annotations.Test;

@Test(groups = { "end-to-end" })
public class WSTrustRequestTest extends AbstractAdalTests {

    @Test
    public void testAcquireToken()
    {
    	URL wsTrustUrl = null;
    	try {
    		wsTrustUrl = new URL("https://msft.sts.microsoft.com/adfs/services/trust/13/usernamemixed");
    	}catch (MalformedURLException e)
    	{
    		
    	}
    	WSTrustRequest wsTrustRequest = new WSTrustRequest(wsTrustUrl);
    	WSTrustResponse wsTrustResponse = wsTrustRequest.acquireToken("gongchen@microsoft.com", "mypassword", null);
    	System.out.println(wsTrustResponse.getToken());
    }

}
