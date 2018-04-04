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

import java.net.Proxy;
import java.net.URL;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.slf4j.Logger;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;

import javax.net.ssl.SSLSocketFactory;

import static com.microsoft.aad.adal4j.TestConfiguration.*;

@Test(groups = { "checkin" })
@PrepareForTest({HttpHelper.class, AuthenticationContext.class })
public class DeviceCodeFlowTest {
    private AuthenticationContext ctx = null;
    private ExecutorService service = null;

    @BeforeTest
    public void setup() {
        service = Executors.newFixedThreadPool(1);
    }

    @AfterTest
    public void cleanup() {
        if (service != null) {
            service.shutdown();
        }
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    public static Map<String, String> getQueryMap(String query)
    {
        Map<String, String> map = new HashMap<>();
        for (String param : query.split("&"))
        {
            map.put(param.split("=")[0], param.split("=")[1]);
        }
        return map;
    }

    String deviceCodeJsonResponse = "{\n" +
            "  \"user_code\": \"DW83JNP2P\",\n" +
            "  \"device_code\": \"DAQABAAEAAADRNYRQ3dhRFEeqWvq-yi6QodK2pb1iAA\",\n" +
            "  \"verification_url\": \"https://aka.ms/devicelogin\",\n" +
            "  \"expires_in\": \"900\",\n" +
            "  \"interval\": \"5\",\n" +
            "  \"message\": \"To sign in, use a web browser to open the page https://aka.ms/devicelogin and enter the code DW83JNP2P to authenticate.\"\n" +
            "}";

    @Test
    public void deviceCodeFlowTest() throws Exception {
        ctx = PowerMock.createPartialMock(AuthenticationContext.class,
                new String[] { "acquireTokenCommon" }, AAD_TENANT_ENDPOINT, true, service);

        Capture<ClientDataHttpHeaders> capturedClientDataHttpHeaders = Capture.newInstance();

        PowerMock.expectPrivate(ctx, "acquireTokenCommon",
                EasyMock.isA(AdalDeviceCodeAuthorizationGrant.class),
                EasyMock.isA(ClientAuthentication.class),
                EasyMock.capture(capturedClientDataHttpHeaders)).andReturn(
                new AuthenticationResult("bearer", "accessToken",
                        "refreshToken", new Date().getTime(), "idToken", null,
                        false));

        PowerMock.mockStatic(HttpHelper.class);

        Capture<String> capturedUrl = Capture.newInstance();

        EasyMock.expect(
                HttpHelper.executeHttpGet(EasyMock.isA(Logger.class), EasyMock.capture(capturedUrl),
                        EasyMock.isA(Map.class), EasyMock.isNull(Proxy.class), EasyMock.isNull(SSLSocketFactory.class)))
                .andReturn(deviceCodeJsonResponse);

        PowerMock.replay(HttpHelper.class);

        Future<DeviceCode> result = ctx.acquireDeviceCode(AAD_CLIENT_ID, AAD_RESOURCE_ID, null);
        DeviceCode deviceCode = result.get();

        // validate HTTP GET request used to get device code
        URL url = new URL(capturedUrl.getValue());
        Assert.assertEquals(url.getAuthority(), AAD_HOST_NAME);
        Assert.assertEquals(url.getPath(),
                "/" + AAD_TENANT_NAME + AuthenticationAuthority.DEVICE_CODE_ENDPOINT);

        Map<String, String> expectedQueryParams = new HashMap<>();
        expectedQueryParams.put("client_id", AAD_CLIENT_ID);
        expectedQueryParams.put("resource", AAD_RESOURCE_ID);

        Assert.assertEquals(getQueryMap(url.getQuery()), expectedQueryParams);

        // validate returned Device Code object
        Assert.assertNotNull(deviceCode);
        Assert.assertNotNull(deviceCode.getUserCode(), "DW83JNP2P");
        Assert.assertNotNull(deviceCode.getDeviceCode(), "DAQABAAEAAADRNYRQ3dhRFEeqWvq-yi6QodK2pb1iAA");
        Assert.assertNotNull(deviceCode.getVerificationUrl(), "https://aka.ms/devicelogin");
        Assert.assertNotNull(deviceCode.getExpiresIn(), "900");
        Assert.assertNotNull(deviceCode.getInterval(), "5");
        Assert.assertNotNull(deviceCode.getMessage(), "To sign in, use a web browser" +
                " to open the page https://aka.ms/devicelogin and enter the code DW83JNP2P to authenticate.");
        Assert.assertNotNull(deviceCode.getCorrelationId());

        PowerMock.replay(ctx);

        Future<AuthenticationResult> authResult = ctx.acquireTokenByDeviceCode(deviceCode, null);
        authResult.get();

        // make sure same correlation id is used for acquireDeviceCode and acquireTokenByDeviceCode calls
        Assert.assertEquals(capturedClientDataHttpHeaders.getValue().getReadonlyHeaderMap().
                get(ClientDataHttpHeaders.CORRELATION_ID_HEADER_NAME), deviceCode.getCorrelationId());
        Assert.assertNotNull(authResult);

        PowerMock.verifyAll();
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Invalid authority type. Device Flow is not supported by ADFS authority")
    public void executeAcquireDeviceCode_AdfsAuthorityUsed_IllegalArgumentExceptionThrown()
            throws Exception {

        ctx = new AuthenticationContext(ADFS_TENANT_ENDPOINT, false, service);
        ctx.acquireDeviceCode(AAD_CLIENT_ID, AAD_RESOURCE_ID, null);
    }

    @Test
    public void executeAcquireDeviceCode_AuthenticaionPendingErrorReturned_AuthenticationExceptionThrown()
            throws Exception {

        AdalTokenRequest request = PowerMock.createPartialMock(
                AdalTokenRequest.class, new String[]{"toOAuthRequest"},
                new URL("http://login.windows.net"), null, null, null, null, null);

        AdalOAuthRequest adalOAuthHttpRequest = PowerMock
                .createMock(AdalOAuthRequest.class);

        HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST);

        String content = "{\"error\":\"authorization_pending\"," +
                "\"error_description\":\"AADSTS70016: Pending end-user authorization.\\r\\n" +
                "Trace ID: 6c9dd244-0c65-4ea6-b121-0afd1c640200\\r\\n" +
                "Correlation ID: ff60101b-cb23-4a52-82cb-9966f466327a\\r\\n" +
                "Timestamp: 2018-03-14 20:15:43Z\"," +
                "\"error_codes\":[70016],\"timestamp\":\"2018-03-14 20:15:43Z\"," +
                "\"trace_id\":\"6c9dd244-0c65-4ea6-b121-0afd1c640200\"," +
                "\"correlation_id\":\"ff60101b-cb23-4a52-82cb-9966f466327a\"}";

        httpResponse.setContent(content);
        httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);

        EasyMock.expect(request.toOAuthRequest()).andReturn(adalOAuthHttpRequest).times(1);
        EasyMock.expect(adalOAuthHttpRequest.send()).andReturn(httpResponse).times(1);

        PowerMock.replay(request, adalOAuthHttpRequest);

        try {
            request.executeOAuthRequestAndProcessResponse();
            Assert.fail("Expected AuthenticationException was not thrown");
        } catch (AuthenticationException ex) {
            Assert.assertEquals(ex.getErrorCode(), AdalErrorCode.AUTHORIZATION_PENDING);
        }
        PowerMock.verifyAll();
    }
}
