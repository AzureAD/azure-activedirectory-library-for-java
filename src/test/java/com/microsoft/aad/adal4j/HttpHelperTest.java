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

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URL;

import org.apache.tools.ant.util.ReaderInputStream;
import org.easymock.EasyMock;
import org.powermock.api.easymock.PowerMock;
import org.testng.annotations.Test;

/**
 *
 */

@Test(groups = { "checkin" })
public class HttpHelperTest extends AbstractAdalTests {

    @Test(expectedExceptions = AuthenticationException.class,
            expectedExceptionsMessageRegExp = "Server returned HTTP response code: 403 for URL : https://some.url, Error details : error info")
    public void testReadResponseFromConnection_ResponseCodeNot200()
            throws Exception {
        final HttpsURLConnection connection = PowerMock
                .createMock(HttpsURLConnection.class);
        EasyMock.expect(connection.getResponseCode()).andReturn(403).times(2);
        EasyMock.expect(connection.getURL()).andReturn(new URL("https://some.url"));

        String testInput = "error info";
        StringReader reader = new StringReader(testInput);
        InputStream is = new ReaderInputStream(reader);

        EasyMock.expect(connection.getErrorStream()).andReturn(is).times(1);

        PowerMock.replayAll(connection);

        HttpHelper.readResponseFromConnection(connection);
    }
}
