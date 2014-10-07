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

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;

import org.easymock.EasyMock;
import org.powermock.api.easymock.PowerMock;
import org.testng.annotations.Test;

/**
 *
 */

@Test(groups = { "checkin" })
public class HttpHelperTest extends AbstractAdalTests {

    @Test(expectedExceptions = IOException.class, expectedExceptionsMessageRegExp = "Failed: HTTP error code 403")
    public void testReadResponseFromConnection_ResponseCodeNot200()
            throws Exception {
        final HttpURLConnection connection = PowerMock
                .createMock(HttpURLConnection.class);
        EasyMock.expect(connection.getResponseCode()).andReturn(403).times(2);
        final InputStream is = PowerMock.createMock(InputStream.class);
        is.close();
        EasyMock.expectLastCall();
        EasyMock.expect(connection.getInputStream()).andReturn(is);
        PowerMock.replayAll(connection, is);
        HttpHelper.readResponseFromConnection(connection);
    }
}
