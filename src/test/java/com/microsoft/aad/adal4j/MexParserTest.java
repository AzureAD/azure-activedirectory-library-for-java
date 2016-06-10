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

import java.io.BufferedReader;
import java.io.FileReader;

import org.testng.Assert;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

@Test(groups = { "checkin" })
public class MexParserTest {

    @BeforeTest
    public void setup(){
        System.setProperty("javax.xml.parsers.DocumentBuilderFactory","com.sun.org.apache.xerces.internal.jaxp.DocumentBuilderFactoryImpl");
    }
    
    @AfterTest
    public void cleanup(){
        System.clearProperty("javax.xml.parsers.DocumentBuilderFactory");
    }
    
    @Test
    public void testMexParsing() throws Exception {

        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(
                (this.getClass().getResource(
                        TestConfiguration.AAD_MEX_RESPONSE_FILE).getFile())))) {
            String line = br.readLine();

            while (line != null) {
                sb.append(line);
                sb.append(System.lineSeparator());
                line = br.readLine();
            }
        }
        BindingPolicy endpoint = MexParser.getWsTrustEndpointFromMexResponse(sb
                .toString());
        Assert.assertEquals(endpoint.getUrl(),
                "https://msft.sts.microsoft.com/adfs/services/trust/13/usernamemixed");
    }
    
    @Test
    public void testMexParsingWs2005() throws Exception {

        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(
                this.getClass().getResource(
                TestConfiguration.AAD_MEX_2005_RESPONSE_FILE).getFile()))) {
            String line = br.readLine();

            while (line != null) {
                sb.append(line);
                sb.append(System.lineSeparator());
                line = br.readLine();
            }
        }
        BindingPolicy endpoint = MexParser.getWsTrustEndpointFromMexResponse(sb
                .toString());
        Assert.assertEquals(endpoint.getUrl(),"https://msft.sts.microsoft.com/adfs/services/trust/2005/usernamemixed");
    }

}
