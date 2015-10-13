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

import static org.testng.Assert.assertNotNull;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

import org.apache.tools.ant.filters.StringInputStream;
import org.easymock.EasyMock;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.http.HTTPRequest.Method;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

@Test(groups = { "checkin" })
@PrepareForTest({ AdalOAuthRequest.class })
public class AdalOAuthRequestTest extends AbstractAdalTests {

    @Test
    public void testConstructor() throws MalformedURLException {
        final AdalOAuthRequest request = new AdalOAuthRequest(Method.POST,
                new URL("http://login.windows.net"), null);
        assertNotNull(request);
    }


    @Test(expectedExceptions = IOException.class, expectedExceptionsMessageRegExp = "Couldn't parse Content-Type header: Invalid Content-Type value: Expected '/', got null")
    public void testCreateResponseContentTypeParsingFailure()
            throws Exception {

        final AdalOAuthRequest request = new AdalOAuthRequest(Method.GET,
                new URL("https://" + TestConfiguration.AAD_HOST_NAME), null);
        final HttpURLConnection conn = PowerMock
                .createMock(HttpURLConnection.class);
        EasyMock.expect(conn.getResponseCode()).andReturn(200).times(1);
        EasyMock.expect(conn.getHeaderField("Location"))
                .andReturn("https://location.pl").times(1);
        EasyMock.expect(conn.getContentType()).andReturn("invalid-content")
                .times(1);
        PowerMock.replay(conn);
        Whitebox.invokeMethod(request, "createResponse", conn, null);

    }

    @Test
    public void testCreateResponseLocationNull()
            throws Exception {
        final AdalOAuthRequest request = new AdalOAuthRequest(Method.GET,
                new URL("https://" + TestConfiguration.AAD_HOST_NAME), null);
        final HttpURLConnection conn = PowerMock
                .createMock(HttpURLConnection.class);
        EasyMock.expect(conn.getResponseCode()).andReturn(200).times(1);
        EasyMock.expect(conn.getHeaderField("Location")).andReturn(null)
                .times(1);
        EasyMock.expect(conn.getContentType())
                .andReturn("application/x-www-form-urlencoded").times(1);
        EasyMock.expect(conn.getHeaderField("Cache-Control")).andReturn("cc")
                .times(1);
        EasyMock.expect(conn.getHeaderField("Pragma")).andReturn("pragma")
                .times(1);
        EasyMock.expect(conn.getHeaderField("WWW-Authenticate"))
                .andReturn("www-a").times(1);
        PowerMock.replay(conn);
        final HTTPResponse response = Whitebox.invokeMethod(request,
                "createResponse", conn, "content");
        PowerMock.verifyAll();
        Assert.assertNotNull(response);
        Assert.assertEquals(response.getCacheControl(), "cc");
        Assert.assertEquals(response.getPragma(), "pragma");
        Assert.assertEquals(response.getWWWAuthenticate(), "www-a");
        Assert.assertNull(response.getLocation(), "location.pl");
        Assert.assertEquals(response.getContent(), "content");
    }

    @Test
    public void testCreateResponse() throws Exception {
        final AdalOAuthRequest request = new AdalOAuthRequest(Method.GET,
                new URL("https://" + TestConfiguration.AAD_HOST_NAME), null);
        final HttpURLConnection conn = PowerMock
                .createMock(HttpURLConnection.class);
        EasyMock.expect(conn.getResponseCode()).andReturn(200).times(1);
        EasyMock.expect(conn.getHeaderField("Location"))
                .andReturn("https://location.pl").times(1);
        EasyMock.expect(conn.getContentType())
                .andReturn("application/x-www-form-urlencoded").times(1);
        EasyMock.expect(conn.getHeaderField("Cache-Control")).andReturn("cc")
                .times(1);
        EasyMock.expect(conn.getHeaderField("Pragma")).andReturn("pragma")
                .times(1);
        EasyMock.expect(conn.getHeaderField("WWW-Authenticate"))
                .andReturn("www-a").times(1);
        PowerMock.replay(conn);
        final HTTPResponse response = Whitebox.invokeMethod(request,
                "createResponse", conn, null);
        PowerMock.verifyAll();
        Assert.assertNotNull(response);
        Assert.assertEquals(response.getCacheControl(), "cc");
        Assert.assertEquals(response.getPragma(), "pragma");
        Assert.assertEquals(response.getWWWAuthenticate(), "www-a");
        Assert.assertEquals(response.getLocation().getAuthority(),
                "location.pl");
        Assert.assertEquals(response.getLocation().getProtocol(), "https");
        Assert.assertNull(response.getContent());
    }
    
    @Test
    public void testCreateResponseFor404() throws Exception {
        final AdalOAuthRequest request = new AdalOAuthRequest(Method.GET,
                new URL("https://" + TestConfiguration.AAD_HOST_NAME), null);
        final HttpURLConnection conn = PowerMock
                .createMock(HttpURLConnection.class);
        EasyMock.expect(conn.getResponseCode()).andReturn(404);
        EasyMock.expect(conn.getErrorStream()).andReturn(null);
        InputStream stream = new StringInputStream("stream");
        EasyMock.expect(conn.getInputStream()).andReturn(stream);
        PowerMock.replay(conn);
        final String response = Whitebox.invokeMethod(request,
                "processAndReadResponse", conn);
        Assert.assertEquals(response, "stream");
        PowerMock.verifyAll();
    }
}
